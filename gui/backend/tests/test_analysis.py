"""Tests for analysis.py — evidence digest, structured extraction, heuristics, explain."""
import csv

import analysis
import runs


class FakeRun:
    """Minimal stand-in for a runs.Run with artifacts on disk."""
    def __init__(self, out_dir, run_id="testrun"):
        self.id = run_id
        self.output_dir = out_dir
        self.options = {"engine": "modern", "packages": ["bam", "crypto"], "output_type": "csv"}


def _write_indicators(out_dir, rows):
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "_indicators.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["severity", "artifact", "detail", "timestamp_utc"])
        w.writerows(rows)


def test_availability_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    a = analysis.availability({})
    assert a["sdk_installed"] is True       # anthropic is installed in the venv
    assert a["has_key"] is False
    assert a["ai_ready"] is False
    assert a["mode"] == "heuristic"
    assert a["model"] == "claude-opus-4-8"


def test_extract_structured_roundtrip():
    text = ('## Verdict\nbenign\n'
            '<!--ATTACK_JSON {"verdict":"benign","confidence":"low","techniques":[]} -->')
    s = analysis._extract_structured(text)
    assert s == {"verdict": "benign", "confidence": "low", "techniques": []}


def test_extract_structured_absent():
    assert analysis._extract_structured("no machine block here") is None


def test_gather_evidence_includes_indicators(tmp_path):
    out = tmp_path / "out"
    _write_indicators(out, [["high", "crypto", "wallet present: MetaMask", "2026-01-01T00:00:00+00:00"]])
    (out / "muicache.csv").write_text("executable,application_name\nC:\\a.exe,App\n", encoding="utf-8")
    digest = analysis.gather_evidence(FakeRun(out))
    assert "TRIAGE INDICATORS" in digest
    assert "MetaMask" in digest
    assert "muicache.csv" in digest


def test_heuristic_report_and_structured(tmp_path):
    out = tmp_path / "out"
    _write_indicators(out, [
        ["high", "crypto", "Browser wallet extension MetaMask", "2026-01-01T00:00:00+00:00"],
        ["high", "pshistory", "Suspicious PowerShell (-enc): powershell -enc AAAA", ""],
        ["medium", "aiapps", "Local AI/LLM tool present: ollama", ""],
    ])
    run = FakeRun(out)
    report = analysis._heuristic_report(run, "")
    assert "## Verdict" in report
    assert "## MITRE ATT&CK mapping" in report
    structured = analysis._heuristic_structured(run)
    assert structured["verdict"] in ("benign", "suspicious", "likely-malicious")
    tids = {t["technique_id"] for t in structured["techniques"]}
    assert "T1496" in tids          # crypto → Impact
    assert any(t["tactic"] == "Execution" for t in structured["techniques"])


def test_explain_row_heuristic(tmp_path):
    out = tmp_path / "out"
    out.mkdir(parents=True)
    run = FakeRun(out)
    res = analysis.explain_row(
        run, "jumplist_lnk_targets.csv",
        ["target", "arguments"], [r"C:\Users\x\Downloads\evil.exe", "-enc AAAA"], settings={})
    assert res["mode"] == "heuristic"
    assert "LNK" in res["explanation"] or "shortcut" in res["explanation"].lower()
    assert "evil.exe" in res["explanation"]


def test_iter_analysis_sse_heuristic_emits_done(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = tmp_path / "out"
    _write_indicators(out, [["high", "crypto", "wallet", "2026-01-01T00:00:00+00:00"]])
    chunks = list(analysis.iter_analysis_sse(FakeRun(out), settings={}))
    blob = "".join(chunks)
    assert "event: meta" in blob
    assert "event: delta" in blob
    assert "event: structured" in blob
    assert "event: done" in blob


def test_artifact_stem():
    assert analysis._artifact_stem("sub/_indicators.csv") == "indicators"
    assert analysis._artifact_stem("jumplist_lnk_targets.csv") == "jumplist_lnk_targets"


def test_runs_run_is_constructible(tmp_path):
    # sanity: a real runs.Run can stand in for FakeRun in analysis helpers
    opts = {"output_dir": str(tmp_path / "o"), "packages": ["bam"], "output_type": "csv", "engine": "modern"}
    run = runs.Run("rid", ["x"], opts, str(tmp_path))
    assert run.output_dir.name == "o"
