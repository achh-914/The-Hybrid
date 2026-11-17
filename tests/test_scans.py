from pathlib import Path

from fastapi.testclient import TestClient

from hybrid.api import create_app
from hybrid.store import Store

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"
JSON = {"Content-Type": "application/json"}


def make():
    store = Store()
    app = create_app(store)
    _, ka = store.create_tenant("a")
    _, kb = store.create_tenant("b")
    return TestClient(app), {"X-API-Key": ka}, {"X-API-Key": kb}


def upload(c, h, raw=None):
    return c.post("/snapshots", content=raw or SNAP.read_bytes(), headers={**h, **JSON})


def test_upload_ok():
    c, a, _ = make()
    r = upload(c, a)
    assert r.status_code == 201 and len(r.json()["sha256"]) == 64


def test_requires_key():
    c, _, _ = make()
    assert c.post("/snapshots", content=b"{}", headers=JSON).status_code == 401


def test_invalid_snapshot_rejected():
    c, a, _ = make()
    assert upload(c, a, b"not json").status_code == 422
    assert upload(c, a, b'{"foo": 1}').status_code == 422


def test_too_large_rejected():
    c, a, _ = make()
    big = b'{"a": "' + b"x" * (5 * 1024 * 1024 + 1) + b'"}'
    assert upload(c, a, big).status_code == 413


def test_other_tenant_cannot_use_snapshot():
    c, a, b = make()
    sid = upload(c, a).json()["id"]
    r = c.post("/scans", json={"snapshot_id": sid}, headers=b)
    assert r.status_code == 404


def test_scan_without_approved_requirements_is_409():
    c, a, _ = make()
    sid = upload(c, a).json()["id"]
    r = c.post("/scans", json={"snapshot_id": sid}, headers=a)
    assert r.status_code == 409


def test_report_of_unknown_scan_is_404():
    c, a, b = make()
    assert c.get("/scans/sc-nope/report", headers=b).status_code == 404
