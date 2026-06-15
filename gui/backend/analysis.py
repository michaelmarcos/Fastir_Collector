"""
analysis.py - the AI engine.

Takes the artifacts a run produced, digests them into evidence, and asks Claude
to reason about a likely attack chain: a hypothesis narrative, a MITRE ATT&CK
mapping, a rough timeline, confidence, and recommended next steps.

Design notes:
  * Uses the official Anthropic SDK with claude-opus-4-8 + adaptive thinking,
    streamed so the UI fills in live and we never hit a request timeout.
  * The API key comes from ANTHROPIC_API_KEY (or an override set in the GUI's
    Settings) - never hard-coded, never logged.
  * If no key / SDK is available, it falls back to a deterministic, rule-based
    triage so the feature still produces something useful offline. That output
    is clearly labelled as heuristic, not AI.

Everything here is hypothesis generation for a human analyst. The prompt makes
clear the model must hedge and never assert compromise as fact.
"""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path

MODEL = "claude-opus-4-8"
MAX_EVIDENCE_CHARS = 45_000
MAX_ROWS_PER_ARTIFACT = 25

SYSTEM_PROMPT = """You are a senior DFIR (digital forensics & incident response) analyst.
You are given forensic artifacts collected from a single live Windows host by the FastIR
Collector and its modern-artifact extension. Your job is to reason about whether the
evidence is consistent with malicious activity and, if so, propose a plausible attack chain.

Rules:
- These are HYPOTHESES for a human analyst, not conclusions. Hedge appropriately and never
  state compromise as established fact. Most hosts are benign; say so when that's the case.
- Tie every claim to specific evidence rows you were given. Do not invent artifacts.
- Map suspected behaviours to MITRE ATT&CK techniques (ID + name) where reasonable.
- Be concise and skimmable. A busy responder should grasp it in 60 seconds.

Respond in GitHub-flavoured Markdown with exactly these sections:
## Verdict
One line: benign / suspicious / likely-malicious, plus a confidence (low/medium/high) and a one-sentence why.
## Attack-chain hypothesis
A short ordered narrative (or "No coherent attack chain — findings appear benign."). Reference evidence.
## MITRE ATT&CK mapping
A markdown table: | Tactic | Technique (ID) | Evidence |
## Timeline
A few key timestamped events in order (or "Insufficient timestamped evidence.").
## Recommended next steps
3-6 concrete, prioritised actions for the responder.

After the Markdown, append a single machine-readable block on its own line, wrapped in an HTML
comment so it stays invisible to the reader, with this exact shape:
<!--ATTACK_JSON {"verdict":"benign|suspicious|likely-malicious","confidence":"low|medium|high","techniques":[{"tactic":"...","technique_id":"Txxxx","technique_name":"...","evidence":"...","confidence":"low|medium|high"}]} -->
The techniques array must match your ATT&CK table. Output valid minified JSON; if there are no
techniques, use an empty array.
"""

import re

_ATTACK_RE = re.compile(r"<!--ATTACK_JSON\s*(\{.*?\})\s*-->", re.DOTALL)


def _extract_structured(text: str) -> dict | None:
    m = _ATTACK_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- #
# evidence assembly
# --------------------------------------------------------------------------- #

def _read_csv_digest(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            rows = []
            for i, row in enumerate(reader):
                if i > MAX_ROWS_PER_ARTIFACT:
                    rows.append([f"... (+ more rows truncated)"])
                    break
                rows.append(row)
        if not rows:
            return ""
        header = ",".join(rows[0])
        body = "\n".join(",".join(str(c) for c in r) for r in rows[1:])
        return f"{header}\n{body}"
    except Exception as exc:
        return f"(could not read: {exc})"


def gather_evidence(run) -> str:
    """Build a compact, prioritised text digest of a run's artifacts."""
    out_dir = Path(run.output_dir)
    parts: list[str] = []
    parts.append(f"# Collection {run.id}")
    parts.append(f"engine: {run.options.get('engine', 'fastir')}")
    parts.append(f"packages: {', '.join(run.options.get('packages', []))}")
    parts.append(f"output_type: {run.options.get('output_type')}")
    parts.append("")

    if not out_dir.exists():
        return "\n".join(parts) + "\n(no artifacts were produced)"

    files = sorted(out_dir.rglob("*"))
    # Indicators first — they are the triage signal.
    indicator_files = [f for f in files if f.is_file() and f.stem.lstrip("_") == "indicators"]
    other_files = [f for f in files if f.is_file() and f not in indicator_files]

    for f in indicator_files:
        parts.append(f"## TRIAGE INDICATORS ({f.name})")
        parts.append(_read_csv_digest(f) if f.suffix == ".csv" else f.read_text("utf-8", "replace")[:8000])
        parts.append("")

    for f in other_files:
        rel = f.relative_to(out_dir).as_posix()
        parts.append(f"## ARTIFACT {rel}")
        if f.suffix == ".csv":
            parts.append(_read_csv_digest(f))
        elif f.suffix == ".json":
            parts.append(f.read_text("utf-8", "replace")[:4000])
        else:
            parts.append(f"(binary or log file, {f.stat().st_size} bytes)")
        parts.append("")

    digest = "\n".join(parts)
    if len(digest) > MAX_EVIDENCE_CHARS:
        digest = digest[:MAX_EVIDENCE_CHARS] + "\n\n[evidence truncated to fit context]"
    return digest


# --------------------------------------------------------------------------- #
# availability + key resolution
# --------------------------------------------------------------------------- #

def _api_key(settings: dict | None) -> str | None:
    if settings and settings.get("analysis_api_key"):
        return settings["analysis_api_key"]
    return os.environ.get("ANTHROPIC_API_KEY")


def availability(settings: dict | None = None) -> dict:
    try:
        import anthropic  # noqa: F401
        sdk = True
    except Exception:
        sdk = False
    key = _api_key(settings)
    return {
        "sdk_installed": sdk,
        "has_key": bool(key),
        "ai_ready": sdk and bool(key),
        "model": MODEL,
        "mode": "claude" if (sdk and key) else "heuristic",
    }


# --------------------------------------------------------------------------- #
# the AI call (streamed) + heuristic fallback
# --------------------------------------------------------------------------- #

def _stream_claude(evidence: str, key: str):
    import anthropic
    client = anthropic.Anthropic(api_key=key)
    user = ("Analyse the following forensic evidence from one Windows host and produce the "
            "attack-chain assessment per your instructions.\n\n" + evidence)
    with client.messages.stream(
        model=MODEL,
        max_tokens=4096,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user}],
    ) as stream:
        for text in stream.text_stream:
            yield text


# Lightweight ATT&CK heuristics for the offline fallback.
_HEURISTIC_ATTACK = {
    "pshistory": ("Execution", "T1059.001 PowerShell"),
    "bam": ("Execution", "T1059 Command and Scripting Interpreter"),
    "shimcache": ("Execution", "T1059 Command and Scripting Interpreter"),
    "recall": ("Collection", "T1113 Screen Capture"),
    "aiapps": ("Collection", "T1119 Automated Collection / credential exposure"),
    "crypto": ("Impact", "T1496 Resource Hijacking / wallet theft"),
    "defender": ("Defense Evasion", "T1562.001 Disable or Modify Tools"),
    "jumplists": ("Discovery", "T1083 File and Directory Discovery"),
    "timeline": ("Discovery", "T1083 File and Directory Discovery"),
    "muicache": ("Execution", "T1204 User Execution"),
}


def _heuristic_report(run, evidence: str) -> str:
    """Deterministic triage when no AI is configured. Groups _indicators by severity."""
    out_dir = Path(run.output_dir)
    indicators = []
    for f in out_dir.rglob("_indicators.csv"):
        try:
            with f.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                indicators = list(csv.DictReader(fh))
        except Exception:
            pass
    high = [i for i in indicators if i.get("severity") == "high"]
    med = [i for i in indicators if i.get("severity") == "medium"]
    arts = {i.get("artifact", "?") for i in indicators}

    lines = ["> **Heuristic triage** — no AI key configured, so this is a deterministic "
             "rule-based summary, not an AI hypothesis. Set `ANTHROPIC_API_KEY` for full analysis.\n"]
    verdict = "likely-malicious" if len(high) >= 5 else "suspicious" if (high or med) else "benign"
    conf = "low"
    lines.append("## Verdict")
    lines.append(f"**{verdict}** (confidence: {conf}) — {len(high)} high and {len(med)} medium "
                 f"indicators across {len(arts)} artifact type(s).\n")

    lines.append("## Attack-chain hypothesis")
    if high or med:
        lines.append("Mechanical grouping of flagged findings (no causal inference):")
        for i in (high + med)[:12]:
            lines.append(f"- **[{i.get('severity')}]** ({i.get('artifact')}) {i.get('detail')}")
    else:
        lines.append("No coherent attack chain — findings appear benign.")
    lines.append("")

    lines.append("## MITRE ATT&CK mapping")
    lines.append("| Tactic | Technique (ID) | Evidence |")
    lines.append("|---|---|---|")
    seen = set()
    for i in (high + med):
        art = i.get("artifact", "")
        if art in _HEURISTIC_ATTACK and art not in seen:
            seen.add(art)
            tac, tech = _HEURISTIC_ATTACK[art]
            lines.append(f"| {tac} | {tech} | {art} indicators |")
    if not seen:
        lines.append("| — | — | no mapped indicators |")
    lines.append("")

    lines.append("## Timeline")
    timed = sorted([i for i in (high + med) if i.get("timestamp_utc")],
                   key=lambda x: x["timestamp_utc"], reverse=True)[:6]
    if timed:
        for i in timed:
            lines.append(f"- `{i['timestamp_utc']}` — {i.get('detail')}")
    else:
        lines.append("Insufficient timestamped evidence.")
    lines.append("")

    lines.append("## Recommended next steps")
    lines.append("1. Triage the high-severity indicators above first.")
    lines.append("2. Acquire full artifacts (RAM, Amcache, SRUM) for offline analysis.")
    lines.append("3. Correlate timestamps across execution artifacts (BAM/ShimCache/Prefetch).")
    lines.append("4. If credential or wallet exposure was flagged, rotate secrets and isolate the host.")
    lines.append("5. Configure an `ANTHROPIC_API_KEY` and re-run AI analysis for a richer hypothesis.")
    return "\n".join(lines)


def _heuristic_structured(run) -> dict:
    out_dir = Path(run.output_dir)
    indicators = []
    for f in out_dir.rglob("_indicators.csv"):
        try:
            with f.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                indicators = list(csv.DictReader(fh))
        except Exception:
            pass
    high = [i for i in indicators if i.get("severity") == "high"]
    med = [i for i in indicators if i.get("severity") == "medium"]
    verdict = "likely-malicious" if len(high) >= 5 else "suspicious" if (high or med) else "benign"
    techniques, seen = [], set()
    for i in (high + med):
        art = i.get("artifact", "")
        if art in _HEURISTIC_ATTACK and art not in seen:
            seen.add(art)
            tac, tech = _HEURISTIC_ATTACK[art]
            tid, tname = tech.split(" ", 1)
            techniques.append({"tactic": tac, "technique_id": tid, "technique_name": tname,
                               "evidence": f"{art} indicators",
                               "confidence": "high" if any(x.get("artifact") == art for x in high) else "low"})
    return {"verdict": verdict, "confidence": "low", "techniques": techniques}


def iter_analysis_sse(run, settings: dict | None = None):
    """Yield SSE-formatted chunks of the analysis (Claude if available, else heuristic)."""
    avail = availability(settings)
    yield f"event: meta\ndata: {json.dumps(avail)}\n\n"
    mode = avail["mode"]
    structured: dict | None = None
    try:
        evidence = gather_evidence(run)
        streamed = False
        if avail["ai_ready"]:
            try:
                full = ""
                for text in _stream_claude(evidence, _api_key(settings)):
                    streamed = True
                    full += text
                    yield f"event: delta\ndata: {json.dumps(text)}\n\n"
                structured = _extract_structured(full)
            except Exception as exc:
                if streamed:
                    raise  # mid-stream failure — surface it
                # couldn't even start: fall back to heuristic so the user still gets value
                mode = "heuristic (AI call failed: %s)" % exc
                note = f"> AI call failed ({exc}); showing heuristic triage instead.\n\n"
                report = note + _heuristic_report(run, evidence)
                for i in range(0, len(report), 400):
                    yield f"event: delta\ndata: {json.dumps(report[i:i + 400])}\n\n"
                structured = _heuristic_structured(run)
        else:
            report = _heuristic_report(run, evidence)
            for i in range(0, len(report), 400):
                yield f"event: delta\ndata: {json.dumps(report[i:i + 400])}\n\n"
            structured = _heuristic_structured(run)

        if structured:
            yield f"event: structured\ndata: {json.dumps(structured)}\n\n"
        yield f"event: done\ndata: {json.dumps({'mode': mode})}\n\n"
    except Exception as exc:
        yield f"event: error\ndata: {json.dumps(str(exc))}\n\n"
