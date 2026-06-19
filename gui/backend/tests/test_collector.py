"""Tests for collector.py — CLI contract, detection, and command building."""
import sys
from pathlib import Path

import pytest

import collector

STUB = str(Path(__file__).parent / "stub_collector.py")


def _stub_status():
    return collector.detect(collector_override=STUB, interpreter_override=[sys.executable])


# --- metadata ---------------------------------------------------------------

def test_packages_and_dump_options_present():
    ids = {p["id"] for p in collector.PACKAGES}
    assert {"all", "fast", "health", "fs", "registry", "evt", "memory", "dump", "filecatcher"} <= ids
    assert {o["id"] for o in collector.DUMP_OPTIONS} == {"mft", "mbr", "ram", "dd", "registry"}
    assert collector.OUTPUT_TYPES == ["csv", "json"]


def test_engines_and_modern_packages():
    assert collector.ENGINES == ["fastir", "modern"]
    modern_ids = collector.MODERN_PACKAGE_IDS
    assert {"bam", "shimcache", "timeline", "jumplists", "aiapps", "recall", "crypto"} <= modern_ids


# --- detection --------------------------------------------------------------

def test_detect_finds_stub():
    s = _stub_status()
    assert s.collector_found is True
    assert s.is_exe is False
    assert s.interpreter == [sys.executable]


def test_detect_default_points_at_main_py():
    s = collector.detect()
    assert s.collector_path.endswith("main.py")


# --- fastir command building ------------------------------------------------

def test_build_command_basic():
    argv = collector.build_command(
        {"packages": ["fast"], "output_type": "csv", "output_dir": "out"}, _stub_status())
    assert argv[0] == sys.executable
    assert argv[1] == STUB
    assert "--packages" in argv and "fast" in argv
    assert argv[argv.index("--output_type") + 1] == "csv"
    assert argv[argv.index("--output_dir") + 1] == "out"


def test_build_command_dump_requires_dump_option():
    with pytest.raises(ValueError):
        collector.build_command(
            {"packages": ["dump"], "output_type": "csv", "output_dir": "out", "dump": []}, _stub_status())


def test_build_command_dump_with_option():
    argv = collector.build_command(
        {"packages": ["dump"], "output_type": "json", "output_dir": "o", "dump": ["mft", "ram"]}, _stub_status())
    assert argv[argv.index("--dump") + 1] == "mft,ram"


def test_build_command_rejects_unknown_package():
    with pytest.raises(ValueError):
        collector.build_command(
            {"packages": ["bogus"], "output_type": "csv", "output_dir": "o"}, _stub_status())


def test_build_command_requires_packages_and_output():
    with pytest.raises(ValueError):
        collector.build_command({"packages": [], "output_type": "csv", "output_dir": "o"}, _stub_status())
    with pytest.raises(ValueError):
        collector.build_command({"packages": ["fast"], "output_type": "csv"}, _stub_status())


def test_build_command_rejects_bad_output_type():
    with pytest.raises(ValueError):
        collector.build_command(
            {"packages": ["fast"], "output_type": "xml", "output_dir": "o"}, _stub_status())


# --- modern command building ------------------------------------------------

def test_build_modern_command():
    argv = collector.build_modern_command(
        {"packages": ["muicache", "timeline"], "output_type": "csv", "output_dir": "o"})
    assert argv[0] == sys.executable
    assert argv[1].endswith("modern_collector.py")
    assert argv[argv.index("--packages") + 1] == "muicache,timeline"


def test_build_modern_command_rejects_unknown():
    with pytest.raises(ValueError):
        collector.build_modern_command(
            {"packages": ["not_a_modern_pkg"], "output_type": "csv", "output_dir": "o"})


def test_modern_status_shape():
    st = collector.modern_status()
    assert set(st) >= {"available", "python", "collector_path", "runnable", "admin_artifacts"}
    assert st["available"] is True
