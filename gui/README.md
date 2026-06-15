# FastIR Collector — Console GUI

A fast, fluid local web GUI that drives the **real** [FastIR Collector](../README.md)
CLI. It builds the exact `main.py` command line for you, launches the collector,
streams its output live, and lets you browse the CSV/JSON artifacts it produces —
all from the browser.

> The GUI **wraps** FastIR; it does not reimplement any forensic logic. Every
> collection is a real subprocess call to the collector you point it at.

```
 ┌─ Collection plan ─┐   ┌─ Live console ──────────┐   ┌─ Run history ─┐
 │ packages          │   │ FastIR - INFO - ...      │   │ 161147 ✓      │
 │ dump targets      │   │ FastIR - INFO - ...      │   │ 160147 ✓      │
 │ output csv/json   │   │ ▎(streaming)             │   │               │
 │ $ python main.py… │   └─────────────────────────┘   └───────────────┘
 │ ▶ Run collection  │   ⌗ Browse artifacts → CSV/JSON viewer
 └───────────────────┘
```

## Architecture

| Layer | Stack | Role |
|-------|-------|------|
| `backend/` | FastAPI + Uvicorn (Python 3) | Detects the collector, builds argv, runs it as a subprocess, streams stdout over SSE, serves artifacts |
| `frontend/` | Vite + React + TypeScript + Tailwind + Framer Motion | The console UI |

In production the backend serves the built frontend, so the whole thing is **one
process** on one port.

### How it maps to the FastIR CLI

| UI control | FastIR flag |
|------------|-------------|
| Packages | `--packages fast,health,…` |
| Output format | `--output_type csv\|json` |
| Output directory | `--output_dir <path>` (defaults to a per-run folder) |
| Dump targets (when `dump` selected) | `--dump mft,ram,…` |
| Advanced → Profile | `--profile <file.conf>` |
| Advanced → Homedrive | `--homedrive C:` |

## Two engines

The GUI can drive **two** collectors, switchable from the top of the Collection plan:

### `FastIR` — the original collector
The Python 2 `main.py` (or a compiled `fastIR_x64.exe`). Covers the classic 2015-era
artifacts (fs, health, registry, memory, evt, dump, filecatcher).

### `Modern` — a Python 3 extension for post-2015 artifacts
[`backend/modern_collector.py`](backend/modern_collector.py) is a native Python 3
collector (stdlib only — `winreg` / `sqlite3` / `struct`) that gathers the modern
Windows artifacts FastIR never covered. It runs on the **same Python that powers the
backend**, so it works immediately on a live Windows host — user-level artifacts need
no admin.

| Artifact | What it surfaces | Admin |
|----------|------------------|:-----:|
| `bam` | BAM/DAM — per-user program execution with timestamps | ✓ |
| `shimcache` | AppCompatCache execution/presence (Win8/10/11 parser) | ✓ |
| `muicache` | Names of executed applications | |
| `recentapps` | Search RecentApps — launches, counts, last access | |
| `pshistory` | PSReadLine console history — attacker command lines | |
| `timeline` | Windows Timeline (`ActivitiesCache.db`) activity history | |
| `jumplists` | Recently opened files per application | |
| `defender` | Microsoft Defender exclusions + detection history | ✓ |
| `amcache` / `srum` | Acquire `Amcache.hve` / `SRUDB.dat` for offline analysis | ✓ |
| **`aiapps`** | **Local AI/LLM tools** (Ollama, LM Studio, GPT4All, Jan, ChatGPT/Claude/Cursor/Copilot) **and leaked API keys** (redacted) | |
| **`recall`** | **Windows 11 Recall** snapshot database (`ukg.db`) + image store | |
| **`crypto`** | **Cryptocurrency wallets** (Bitcoin/Electrum/Exodus/Ledger/…) and **browser wallet extensions** (MetaMask, Phantom, …) | |

Every modern run also writes **`_indicators`** — a severity-ranked triage list that
flags suspicious findings (execution from temp/appdata, encoded PowerShell, Defender
exclusions, leaked API keys, crypto wallets, Recall snapshots). The collector is
read-only and never emits secrets in clear text.

**Deep parsing.** Beyond enumeration, the modern engine parses artifacts to their
contents: **Jump Lists** are read as OLE2 compound files and their `DestList` MRU
stream is decoded (v1/v3/v6 layouts) into recent-file paths, access counts, and
timestamps; **Windows Timeline** and **Recall** SQLite databases are read read-only
(`immutable=1`) with Recall's window-capture rows and OCR text extracted; **ShimCache**
is parsed from its binary registry blob.

## AI engine — attack-chain hypothesis

After any run, press **⌬ Analyze (AI)** to have the app reason over the collected
evidence and propose a likely attack chain. It digests the artifacts (indicators +
sampled rows), sends them to **Claude (`claude-opus-4-8`, adaptive thinking)** via the
official Anthropic SDK, and **streams** a structured analyst report back into the panel:

- **Verdict** (benign / suspicious / likely-malicious + confidence)
- **Attack-chain hypothesis** (evidence-linked narrative)
- **MITRE ATT&CK mapping** (tactic · technique · evidence)
- **Timeline** and **Recommended next steps**

Set an API key in **⚙ Settings** (or the `ANTHROPIC_API_KEY` env var). With **no key**,
the panel falls back to a deterministic **heuristic triage** (severity-grouped indicators
with a rule-based ATT&CK mapping) so the feature still works offline. The prompt instructs
the model to produce **hypotheses, not conclusions**, and tie every claim to evidence;
detected API keys are redacted before they ever leave the host.

## Quick start

From this `gui/` folder:

```powershell
# Windows (one command: sets up venv, installs, builds the UI, launches)
./run.ps1
```

```bash
# macOS/Linux (for development against the demo stub)
./run.sh
```

Then open <http://127.0.0.1:8099>.

### Running a *real* collection

FastIR is **Python 2 + Windows + administrator only**. To collect for real:

1. Provision the collector's Python 2 environment (`pip install -r ../reqs.pip`)
   **or** build the standalone `fastIR_x64.exe` (see the main README).
2. Launch this GUI **as administrator**.
3. Open **⚙ Settings** and confirm the readiness checklist is green:
   collector found · windows host · interpreter ready · administrator.
   - For `main.py`: set interpreter to `py -2` (or `python2`).
   - For the binary: point the collector path at `fastIR_x64.exe` and leave the
     interpreter blank.
4. Pick packages and press **▶ Run**.

### Trying it on any machine (demo stub)

You don't need Python 2 or Windows to explore the UI. A bundled stub
([`backend/tests/stub_collector.py`](backend/tests/stub_collector.py)) speaks the
same CLI and emits realistic sample artifacts.

Open **⚙ Settings → "use bundled demo stub (python)" → Save**, then run a
collection. Everything (live streaming, run history, the artifact browser) works
against the stub. The stub collects **nothing real** — it is a demo harness only.

## Manual / dev setup

```powershell
# backend
cd backend
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
./.venv/Scripts/python.exe -m uvicorn app:app --port 8099

# frontend (separate terminal, hot-reload dev server with API proxy)
cd frontend
npm install
npm run dev        # http://127.0.0.1:5173, proxies /api to :8099
```

For a production-style single process, `npm run build` then start uvicorn — the
backend auto-serves `frontend/dist`.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/meta` | Packages, dump options, collector status |
| POST | `/api/settings` | Override collector path / interpreter |
| POST | `/api/preview-command` | Show the argv without running |
| POST | `/api/collections` | Start a collection |
| GET | `/api/collections` | List runs |
| GET | `/api/collections/{id}` | Run detail + artifacts |
| GET | `/api/collections/{id}/stream` | SSE live log stream |
| POST | `/api/collections/{id}/stop` | Terminate a running collection |
| GET | `/api/collections/{id}/artifacts/preview?rel=` | Parsed CSV/JSON preview |
| GET | `/api/collections/{id}/artifacts/download?rel=` | Download an artifact |
| GET | `/api/collections/{id}/analyze/stream` | SSE stream of the AI attack-chain analysis |
| GET | `/api/analysis-info` | Whether AI analysis is ready (SDK + key) or heuristic |

Runs and their output are stored under `backend/_runs/<id>/` (git-ignored).
