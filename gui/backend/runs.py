"""
runs.py - lifecycle + persistence for collection runs.

A "run" is one invocation of the FastIR collector. Each run gets its own
directory under ``gui/backend/_runs/<id>/`` holding:
  * meta.json   - options, argv, status, timestamps, return code
  * console.log - merged stdout/stderr captured live
  * output/     - default output_dir handed to FastIR (artifacts land here)

Subprocess output is read on a background thread and appended to an in-memory
buffer so the SSE endpoint can tail it without touching disk on every poll.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

RUNS_DIR = Path(__file__).resolve().parent / "_runs"
RUNS_DIR.mkdir(exist_ok=True)

# Artifact preview limits so a giant CSV never blows up the browser.
MAX_PREVIEW_ROWS = 500
MAX_PREVIEW_BYTES = 2_000_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Run:
    """One collector invocation. Holds live state + on-disk persistence."""

    def __init__(self, run_id: str, argv: list[str], options: dict, cwd: str):
        self.id = run_id
        self.argv = argv
        self.options = options
        self.cwd = cwd
        self.dir = RUNS_DIR / run_id
        self.output_dir = Path(options["output_dir"])
        self.status = "running"
        self.return_code: int | None = None
        self.created_at = _now()
        self.finished_at: str | None = None
        self.lines: list[str] = []
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None

    # --- persistence ---------------------------------------------------------

    def _meta(self) -> dict:
        return {
            "id": self.id,
            "argv": self.argv,
            "command": " ".join(self.argv),
            "options": self.options,
            "cwd": self.cwd,
            "output_dir": str(self.output_dir),
            "status": self.status,
            "return_code": self.return_code,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "line_count": len(self.lines),
        }

    def _save_meta(self) -> None:
        (self.dir / "meta.json").write_text(json.dumps(self._meta(), indent=2), encoding="utf-8")

    def summary(self) -> dict:
        return self._meta()

    # --- execution -----------------------------------------------------------

    def start(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._save_meta()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _append(self, text: str) -> None:
        with self._lock:
            self.lines.append(text)

    def _run(self) -> None:
        log_path = self.dir / "console.log"
        try:
            self._proc = subprocess.Popen(
                self.argv,
                cwd=self.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            self._append(f"[launcher] failed to start collector: {exc}")
            self._finish(127)
            return
        except Exception as exc:  # noqa: BLE001 - surface anything to the user honestly
            self._append(f"[launcher] error: {exc}")
            self._finish(1)
            return

        self._append(f"[launcher] $ {' '.join(self.argv)}")
        self._append(f"[launcher] cwd: {self.cwd}")
        with log_path.open("w", encoding="utf-8") as logf:
            assert self._proc.stdout is not None
            for raw in self._proc.stdout:
                line = raw.rstrip("\n")
                self._append(line)
                logf.write(line + "\n")
                logf.flush()
            self._proc.wait()
        self._finish(self._proc.returncode)

    def _finish(self, code: int | None) -> None:
        self.return_code = code
        self.status = "completed" if code == 0 else "failed"
        self.finished_at = _now()
        self._append(f"[launcher] process exited with code {code} ({self.status})")
        self._save_meta()

    def stop(self) -> bool:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self._append("[launcher] termination requested by user")
            return True
        return False

    def lines_since(self, cursor: int) -> tuple[list[str], int]:
        with self._lock:
            new = self.lines[cursor:]
            return new, len(self.lines)

    # --- artifacts -----------------------------------------------------------

    def artifacts(self) -> list[dict]:
        results: list[dict] = []
        if not self.output_dir.exists():
            return results
        for path in sorted(self.output_dir.rglob("*")):
            if path.is_file():
                rel = path.relative_to(self.output_dir).as_posix()
                results.append({
                    "name": path.name,
                    "rel": rel,
                    "size": path.stat().st_size,
                    "ext": path.suffix.lstrip(".").lower(),
                })
        return results

    def _resolve_artifact(self, rel: str) -> Path:
        target = (self.output_dir / rel).resolve()
        if os.path.commonpath([target, self.output_dir.resolve()]) != str(self.output_dir.resolve()):
            raise ValueError("Path traversal blocked.")
        if not target.is_file():
            raise FileNotFoundError(rel)
        return target

    def artifact_preview(self, rel: str) -> dict:
        target = self._resolve_artifact(rel)
        size = target.stat().st_size
        ext = target.suffix.lstrip(".").lower()
        if size > MAX_PREVIEW_BYTES:
            return {"rel": rel, "ext": ext, "size": size, "truncated": True,
                    "kind": "binary", "note": "File too large to preview. Download instead."}

        if ext == "csv":
            import csv
            with target.open("r", encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.reader(f)
                rows = []
                for i, row in enumerate(reader):
                    if i >= MAX_PREVIEW_ROWS + 1:
                        break
                    rows.append(row)
            header = rows[0] if rows else []
            body = rows[1:] if len(rows) > 1 else []
            return {"rel": rel, "ext": ext, "size": size, "kind": "csv",
                    "header": header, "rows": body, "truncated": len(body) >= MAX_PREVIEW_ROWS}

        if ext == "json":
            text = target.read_text(encoding="utf-8", errors="replace")
            try:
                data = json.loads(text)
                return {"rel": rel, "ext": ext, "size": size, "kind": "json", "data": data}
            except json.JSONDecodeError:
                return {"rel": rel, "ext": ext, "size": size, "kind": "text", "text": text}

        # log / txt / everything else readable
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
            return {"rel": rel, "ext": ext, "size": size, "kind": "text", "text": text}
        except Exception:
            return {"rel": rel, "ext": ext, "size": size, "kind": "binary",
                    "note": "Binary file. Download to inspect."}

    def artifact_path(self, rel: str) -> Path:
        return self._resolve_artifact(rel)


class RunRegistry:
    """In-memory registry of runs, rehydrated from disk on startup."""

    def __init__(self):
        self._runs: dict[str, Run] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        for meta_file in sorted(RUNS_DIR.glob("*/meta.json")):
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            run = Run.__new__(Run)  # rehydrate without re-running
            run.id = meta["id"]
            run.argv = meta.get("argv", [])
            run.options = meta.get("options", {})
            run.cwd = meta.get("cwd", "")
            run.dir = meta_file.parent
            run.output_dir = Path(meta.get("output_dir", run.dir / "output"))
            # a run still marked "running" on disk after a restart is stale -> failed
            run.status = "failed" if meta.get("status") == "running" else meta.get("status", "completed")
            run.return_code = meta.get("return_code")
            run.created_at = meta.get("created_at", _now())
            run.finished_at = meta.get("finished_at")
            run._lock = threading.Lock()
            run._proc = None
            run._thread = None
            log_path = run.dir / "console.log"
            run.lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines() if log_path.exists() else []
            self._runs[run.id] = run

    @staticmethod
    def new_id() -> str:
        return datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]

    def add(self, run: Run) -> Run:
        self._runs[run.id] = run
        return run

    def get(self, run_id: str) -> Run | None:
        return self._runs.get(run_id)

    def list(self) -> list[dict]:
        return [r.summary() for r in sorted(self._runs.values(),
                                            key=lambda r: r.created_at, reverse=True)]


registry = RunRegistry()
