"""Tests for runs.py — run lifecycle, artifact discovery, preview, path-traversal guard."""
import sys
import time

import pytest

import runs


def _run_quick(tmp_path):
    out = tmp_path / "out"
    opts = {"output_dir": str(out), "packages": ["x"], "output_type": "csv", "engine": "modern"}
    # Write a CSV + a JSON artifact into the cwd (== output_dir) from a child process.
    script = (
        "open('procs.csv','w').write('pid,name\\n4,System\\n680,svchost.exe\\n');"
        "open('data.json','w').write('[{\\\"k\\\": 1}]');"
        "print('FastIR - INFO - done')"
    )
    run = runs.Run("test-lifecycle", [sys.executable, "-c", script], opts, str(out))
    run.start()
    for _ in range(100):
        if run.status != "running":
            break
        time.sleep(0.1)
    return run


def test_run_completes_and_finds_artifacts(tmp_path):
    run = _run_quick(tmp_path)
    assert run.status == "completed"
    assert run.return_code == 0
    rels = {a["rel"] for a in run.artifacts()}
    assert "procs.csv" in rels
    assert "data.json" in rels
    assert any("[launcher]" in line for line in run.lines)


def test_csv_preview(tmp_path):
    run = _run_quick(tmp_path)
    pv = run.artifact_preview("procs.csv")
    assert pv["kind"] == "csv"
    assert pv["header"] == ["pid", "name"]
    assert ["4", "System"] in pv["rows"]


def test_json_preview(tmp_path):
    run = _run_quick(tmp_path)
    pv = run.artifact_preview("data.json")
    assert pv["kind"] == "json"
    assert pv["data"] == [{"k": 1}]


def test_path_traversal_blocked(tmp_path):
    run = _run_quick(tmp_path)
    with pytest.raises(ValueError):
        run.artifact_path("../../../etc/passwd")
    with pytest.raises(FileNotFoundError):
        run.artifact_preview("does_not_exist.csv")


def test_lines_since_cursor(tmp_path):
    run = _run_quick(tmp_path)
    new, cursor = run.lines_since(0)
    assert cursor == len(run.lines)
    assert new == run.lines
    more, cursor2 = run.lines_since(cursor)
    assert more == [] and cursor2 == cursor


def test_registry_new_id_is_unique():
    a, b = runs.RunRegistry.new_id(), runs.RunRegistry.new_id()
    assert a != b
