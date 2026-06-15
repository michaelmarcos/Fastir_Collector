"""
app.py - FastAPI HTTP layer for the FastIR Collector GUI.

Responsibilities are deliberately thin: validate input, build the real command
via collector.py, run/track it via runs.py, and serve the built frontend.
No forensic logic lives here.

Run:  uvicorn app:app  (or use ../run.ps1)
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import collector
import runs

app = FastAPI(title="FastIR Collector GUI", version="1.0.0")

# Permissive CORS so the Vite dev server (5173) can talk to the API in dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Runtime-tunable collector settings (overridable from the UI Settings panel).
SETTINGS: dict = {"collector_override": None, "interpreter_override": None}


def current_status() -> collector.CollectorStatus:
    return collector.detect(SETTINGS["collector_override"], SETTINGS["interpreter_override"])


# --- models ------------------------------------------------------------------

class StartRequest(BaseModel):
    packages: list[str]
    output_type: str = "csv"
    output_dir: str | None = None
    dump: list[str] = []
    profile: str | None = None
    homedrive: str | None = None


class SettingsRequest(BaseModel):
    collector_override: str | None = None
    interpreter_override: list[str] | None = None


# --- meta / settings ---------------------------------------------------------

@app.get("/api/meta")
def meta():
    status = current_status()
    return {
        "packages": collector.PACKAGES,
        "dump_options": collector.DUMP_OPTIONS,
        "output_types": collector.OUTPUT_TYPES,
        "dump_package": collector.DUMP_PACKAGE,
        "status": status.to_dict(),
        "repo_root": str(collector.repo_root()),
    }


@app.post("/api/settings")
def update_settings(req: SettingsRequest):
    SETTINGS["collector_override"] = req.collector_override or None
    SETTINGS["interpreter_override"] = req.interpreter_override or None
    return {"status": current_status().to_dict()}


@app.post("/api/preview-command")
def preview_command(req: StartRequest):
    """Show the exact argv that would run, without launching anything."""
    status = current_status()
    opts = req.model_dump()
    if not opts.get("output_dir"):
        opts["output_dir"] = str(runs.RUNS_DIR / "<run-id>" / "output")
    try:
        argv = collector.build_command(opts, status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"argv": argv, "command": " ".join(argv)}


# --- runs --------------------------------------------------------------------

@app.post("/api/collections")
def start_collection(req: StartRequest):
    status = current_status()
    if not status.collector_found:
        raise HTTPException(status_code=409,
                            detail=f"Collector not found at {status.collector_path}. Set its path in Settings.")

    run_id = runs.registry.new_id()
    opts = req.model_dump()
    if not opts.get("output_dir"):
        opts["output_dir"] = str(runs.RUNS_DIR / run_id / "output")

    try:
        argv = collector.build_command(opts, status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    cwd = str(Path(status.collector_path).resolve().parent)
    run = runs.Run(run_id, argv, opts, cwd)
    runs.registry.add(run)
    run.start()
    return run.summary()


@app.get("/api/collections")
def list_collections():
    return {"runs": runs.registry.list()}


@app.get("/api/collections/{run_id}")
def get_collection(run_id: str):
    run = runs.registry.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    data = run.summary()
    data["artifacts"] = run.artifacts()
    return data


@app.post("/api/collections/{run_id}/stop")
def stop_collection(run_id: str):
    run = runs.registry.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"stopped": run.stop()}


@app.get("/api/collections/{run_id}/stream")
async def stream_collection(run_id: str):
    run = runs.registry.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    async def event_gen():
        cursor = 0
        while True:
            new_lines, cursor = run.lines_since(cursor)
            for line in new_lines:
                yield f"event: log\ndata: {json.dumps(line)}\n\n"
            if run.status != "running":
                yield f"event: done\ndata: {json.dumps(run.summary())}\n\n"
                return
            await asyncio.sleep(0.25)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# --- artifacts ---------------------------------------------------------------

@app.get("/api/collections/{run_id}/artifacts")
def list_artifacts(run_id: str):
    run = runs.registry.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"artifacts": run.artifacts()}


@app.get("/api/collections/{run_id}/artifacts/preview")
def preview_artifact(run_id: str, rel: str):
    run = runs.registry.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    try:
        return run.artifact_preview(rel)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Artifact not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/collections/{run_id}/artifacts/download")
def download_artifact(run_id: str, rel: str):
    run = runs.registry.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    try:
        path = run.artifact_path(rel)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Artifact not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return FileResponse(path, filename=path.name)


# --- static frontend (serve built SPA if present) ----------------------------

_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="spa")


@app.get("/healthz")
def healthz():
    return {"ok": True}
