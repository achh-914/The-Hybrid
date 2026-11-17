from pathlib import Path

from fastapi.testclient import TestClient

from hybrid.api import create_app
from hybrid.requirements import RequirementProposal
from hybrid.store import Store

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"
JSON = {"Content-Type": "application/json"}


def setup():
    store = Store()
    app = create_app(store)
    ta, ka = store.create_tenant("a")
    _, kb = store.create_tenant("b")
    store.add_proposals(ta, [RequirementProposal(
        tenant_id=ta, id="p-1", clause_id="c-4.2", clause_number="4.2",
        clause_text="x", page=1, data_class="customer_data",
        resource_hint="x", principals_hint=("DataOps role",),
    )])
    c = TestClient(app)
    a, b = {"X-API-Key": ka}, {"X-API-Key": kb}
    c.post("/proposals/p-1/approve", headers=a, json={
        "reviewer": "m", "resource_selector": "bucket:customer-data",
        "allowed_principals": ["role:DataOps"],
    })
    sid = c.post("/snapshots", content=SNAP.read_bytes(),
                 headers={**a, **JSON}).json()["id"]
    return c, a, b, sid


def test_same_snapshot_twice_has_no_drift():
    c, a, _, sid = setup()
    s1 = c.post("/scans", json={"snapshot_id": sid}, headers=a).json()["id"]
    s2 = c.post("/scans", json={"snapshot_id": sid}, headers=a).json()["id"]
    d = c.get(f"/scans/{s1}/diff/{s2}", headers=a).json()
    assert d["new"] == [] and d["resolved"] == [] and d["changed"] == []
    assert len(d["persisting"]) >= 1


def test_diff_is_tenant_isolated():
    c, a, b, sid = setup()
    s1 = c.post("/scans", json={"snapshot_id": sid}, headers=a).json()["id"]
    s2 = c.post("/scans", json={"snapshot_id": sid}, headers=a).json()["id"]
    assert c.get(f"/scans/{s1}/diff/{s2}", headers=b).status_code == 404


def test_diff_unknown_scan_is_404():
    c, a, _, sid = setup()
    s1 = c.post("/scans", json={"snapshot_id": sid}, headers=a).json()["id"]
    assert c.get(f"/scans/{s1}/diff/sc-nope", headers=a).status_code == 404
