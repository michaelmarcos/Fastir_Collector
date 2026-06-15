"""
collector.py - thin, faithful wrapper around the real FastIR Collector CLI.

This module never reimplements forensic logic. It only:
  * knows the CLI contract of ``main.py`` (packages / dump options / output type),
  * locates the collector on disk and a usable interpreter,
  * builds the exact argv FastIR expects, and
  * reports whether the host can actually run a collection (Windows + admin).

Keeping this separate from app.py means the HTTP layer stays dumb and the
"what command will run" logic is testable in isolation.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- FastIR CLI contract (mirrors main.py / settings.py upstream) -------------

# --packages accepts these. "all" expands inside FastIR itself.
PACKAGES = [
    {"id": "fast", "label": "fast", "desc": "Everything except dump and filecatcher (recommended quick triage)"},
    {"id": "all", "label": "all", "desc": "Every package including dump and filecatcher"},
    {"id": "health", "label": "health", "desc": "ARP, network, processes, services, tasks, sockets, sessions"},
    {"id": "fs", "label": "fs", "desc": "Browser history, prefetch, recycle bin, startups, named pipes"},
    {"id": "registry", "label": "registry", "desc": "Autoruns, USB history, recent docs, services, shellbags, userassist"},
    {"id": "evt", "label": "evt", "desc": "Windows event logs"},
    {"id": "memory", "label": "memory", "desc": "Clipboard, loaded DLLs, opened files"},
    {"id": "filecatcher", "label": "filecatcher", "desc": "File hunt by MIME / path / YARA (advanced)"},
    {"id": "dump", "label": "dump", "desc": "Raw dumps: MFT, MBR, RAM, disk, registry (advanced)"},
]

# --dump values, from settings.EXTRACT_DUMP
DUMP_OPTIONS = [
    {"id": "mft", "label": "MFT", "desc": "Master File Table"},
    {"id": "mbr", "label": "MBR", "desc": "Master Boot Record"},
    {"id": "ram", "label": "RAM", "desc": "Physical memory image"},
    {"id": "dd", "label": "Disk (dd)", "desc": "Raw disk image"},
    {"id": "registry", "label": "Registry", "desc": "Raw registry hives"},
]

OUTPUT_TYPES = ["csv", "json"]

# Packages whose presence makes --dump meaningful / required.
DUMP_PACKAGE = "dump"
FILECATCHER_PACKAGE = "filecatcher"


def repo_root() -> Path:
    """Repo root = two levels above this file (gui/backend/collector.py)."""
    return Path(__file__).resolve().parents[2]


def _find_interpreter() -> tuple[list[str] | None, str]:
    """
    Find an interpreter able to run the Python 2 collector.

    Returns (argv_prefix, human_label). FastIR is Python 2, so we prefer a real
    py2; if none exists we fall back to whatever the user configures in the UI.
    """
    # Windows launcher with an explicit Python 2 request.
    if shutil.which("py"):
        try:
            out = subprocess.run(
                ["py", "-2", "-c", "import sys;print(sys.version)"],
                capture_output=True, text=True, timeout=8,
            )
            if out.returncode == 0:
                return ["py", "-2"], f"py -2 ({out.stdout.strip().splitlines()[0]})"
        except Exception:
            pass
    for name in ("python2", "python2.7"):
        path = shutil.which(name)
        if path:
            return [path], name
    return None, "not found"


@dataclass
class CollectorStatus:
    collector_path: str
    collector_found: bool
    is_exe: bool
    interpreter: list[str] | None
    interpreter_label: str
    platform: str
    is_windows: bool
    is_admin: bool
    runnable: bool
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "collector_path": self.collector_path,
            "collector_found": self.collector_found,
            "is_exe": self.is_exe,
            "interpreter": self.interpreter,
            "interpreter_label": self.interpreter_label,
            "platform": self.platform,
            "is_windows": self.is_windows,
            "is_admin": self.is_admin,
            "runnable": self.runnable,
            "notes": self.notes,
        }


def is_admin() -> bool:
    """True if the backend process has admin / root rights."""
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def detect(collector_override: str | None = None,
           interpreter_override: list[str] | None = None) -> CollectorStatus:
    """Inspect the host and report whether a real collection can run."""
    default_main = repo_root() / "main.py"
    collector_path = Path(collector_override) if collector_override else default_main
    is_exe = collector_path.suffix.lower() == ".exe"
    found = collector_path.exists()

    if interpreter_override:
        interp, interp_label = interpreter_override, " ".join(interpreter_override)
    elif is_exe:
        interp, interp_label = None, "n/a (standalone .exe)"
    else:
        interp, interp_label = _find_interpreter()

    notes: list[str] = []
    windows = os.name == "nt"
    admin = is_admin()

    if not found:
        notes.append(f"Collector not found at {collector_path}")
    if not is_exe and interp is None:
        notes.append("No Python 2 interpreter found. FastIR is Python 2 — install it "
                     "or point the collector at a compiled fastIR_x64.exe in Settings.")
    if not windows:
        notes.append("Host is not Windows. FastIR only collects from live Windows systems.")
    if not admin:
        notes.append("Not running as administrator. FastIR requires elevation to collect.")

    runnable = found and windows and admin and (is_exe or interp is not None)
    if runnable:
        notes.append("Ready: a real collection can run on this host.")

    return CollectorStatus(
        collector_path=str(collector_path),
        collector_found=found,
        is_exe=is_exe,
        interpreter=interp,
        interpreter_label=interp_label,
        platform=f"{sys.platform} ({os.name})",
        is_windows=windows,
        is_admin=admin,
        runnable=runnable,
        notes=notes,
    )


def build_command(options: dict, status: CollectorStatus) -> list[str]:
    """
    Translate UI options into the exact argv FastIR's main.py expects.

    Raises ValueError on invalid combinations so the API can return a clean 400.
    """
    packages = [p.strip().lower() for p in options.get("packages", []) if p.strip()]
    if not packages:
        raise ValueError("Select at least one package.")
    for p in packages:
        if p not in {pkg["id"] for pkg in PACKAGES}:
            raise ValueError(f"Unknown package: {p}")

    output_type = (options.get("output_type") or "csv").lower()
    if output_type not in OUTPUT_TYPES:
        raise ValueError(f"output_type must be one of {OUTPUT_TYPES}")

    output_dir = options.get("output_dir")
    if not output_dir:
        raise ValueError("output_dir is required.")

    # Base argv: standalone exe, or interpreter + main.py.
    if status.is_exe:
        argv = [status.collector_path]
    else:
        if not status.interpreter:
            raise ValueError("No interpreter configured to run the Python collector.")
        argv = [*status.interpreter, status.collector_path]

    argv += ["--packages", ",".join(packages)]
    argv += ["--output_type", output_type]
    argv += ["--output_dir", output_dir]

    if DUMP_PACKAGE in packages:
        dump = [d.strip().lower() for d in options.get("dump", []) if d.strip()]
        if not dump:
            raise ValueError("The 'dump' package requires at least one dump option (e.g. mft).")
        for d in dump:
            if d not in {o["id"] for o in DUMP_OPTIONS}:
                raise ValueError(f"Unknown dump option: {d}")
        argv += ["--dump", ",".join(dump)]

    profile = options.get("profile")
    if profile:
        argv += ["--profile", profile]

    homedrive = options.get("homedrive")
    if homedrive:
        argv += ["--homedrive", homedrive]

    return argv
