"""End-to-end API tests via FastAPI's TestClient, driving the demo stub collector."""
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app as app_module

STUB = str(Path(__file__).parent / "stub_collector.py")


@pytest.fixture(scope="module")
def client():
    return TestClient(app_module.app)


@pytest.fixture(scope="module")
def stub_settings(client):
    # Point the fastir engine at the bundled stub so runs are deterministic + cross-platform.
    r = client.post("/api/settings", json={
        "collector_override": STUB,
        "interpreter_override": [sys.executable],
    })
    assert r.status_code == 200
    return r.json()


def test_meta(client):
    m = client.get("/api/meta").json()
    assert "packages" in m and "modern_packages" in m
    assert m["engines"] == ["fastir", "modern"]
    assert m["analysis"]["model"] == "claude-opus-4-8"


def test_preview_command_modern(client):
    r = client.post("/api/preview-command", json={
        "packages": ["muicache"], "engine": "modern", "output_type": "csv"})
    assert r.status_code == 200
    assert "modern_collector.py" in r.json()["command"]


def test_preview_command_validation_error(client):
    r = client.post("/api/preview-command", json={
        "packages": [], "engine": "modern", "output_type": "csv"})
    assert r.status_code == 400


def test_start_validation_error(client, stub_settings):
    r = client.post("/api/collections", json={
        "packages": [], "engine": "fastir", "output_type": "csv"})
    assert r.status_code == 400


def test_get_unknown_run_404(client):
    assert client.get("/api/collections/nope").status_code == 404
    assert client.post("/api/collections/nope/explain",
                       json={"rel": "x.csv", "header": [], "row": []}).status_code == 404


def _run_stub(client) -> str:
    r = client.post("/api/collections", json={
        "packages": ["fast"], "engine": "fastir", "output_type": "csv"})
    assert r.status_code == 200, r.text
    run_id = r.json()["id"]
    for _ in range(150):
        detail = client.get(f"/api/collections/{run_id}").json()
        if detail["status"] != "running":
            break
        time.sleep(0.1)
    return run_id


def test_full_collection_flow(client, stub_settings):
    run_id = _run_stub(client)
    detail = client.get(f"/api/collections/{run_id}").json()
    assert detail["status"] == "completed"
    rels = [a["rel"] for a in detail["artifacts"]]
    assert any(r.endswith(".csv") for r in rels)

    # listing
    assert any(r["id"] == run_id for r in client.get("/api/collections").json()["runs"])

    # artifact preview
    target = next(r for r in rels if r.endswith(".csv"))
    pv = client.get(f"/api/collections/{run_id}/artifacts/preview", params={"rel": target}).json()
    assert pv["kind"] == "csv"

    # download
    dl = client.get(f"/api/collections/{run_id}/artifacts/download", params={"rel": target})
    assert dl.status_code == 200

    # path traversal blocked
    bad = client.get(f"/api/collections/{run_id}/artifacts/preview", params={"rel": "../../secret"})
    assert bad.status_code in (400, 404)


def test_explain_row_endpoint(client, stub_settings):
    run_id = _run_stub(client)
    detail = client.get(f"/api/collections/{run_id}").json()
    target = next(r["rel"] for r in detail["artifacts"] if r["rel"].endswith(".csv"))
    pv = client.get(f"/api/collections/{run_id}/artifacts/preview", params={"rel": target}).json()
    row = pv["rows"][0] if pv.get("rows") else []
    res = client.post(f"/api/collections/{run_id}/explain",
                      json={"rel": target, "header": pv.get("header", []), "row": row}).json()
    assert "explanation" in res
    assert res["mode"] in ("heuristic", "claude")


def test_analyze_stream(client, stub_settings):
    run_id = _run_stub(client)
    r = client.get(f"/api/collections/{run_id}/analyze/stream")
    assert r.status_code == 200
    body = r.text
    assert "event: meta" in body
    assert "event: done" in body


def test_analysis_info(client):
    info = client.get("/api/analysis-info").json()
    assert info["model"] == "claude-opus-4-8"
    assert "mode" in info


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}
