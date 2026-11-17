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
        clause_text="Customer data stored in Amazon S3 must be accessible only to DataOps.",
        page=1, data_class="customer_data",
        resource_hint="customer data stored in Amazon S3",
        principals_hint=("DataOps role",),
    )])
    return TestClient(app), {"X-API-Key": ka}, {"X-API-Key": kb}


def test_full_flow():
    c, a, b = setup()
    r = c.post("/proposals/p-1/approve", headers=a, json={
        "reviewer": "meriem",
        "resource_selector": "bucket:customer-data",
        "allowed_principals": ["role:DataOps"],
    })
    assert r.status_code == 200

    sid = c.post("/snapshots", content=SNAP.read_bytes(),
                 headers={**a, **JSON}).json()["id"]

    r = c.post("/scans", json={"snapshot_id": sid}, headers=a)
    assert r.status_code == 201 and r.json()["findings"] >= 1
    scan_id = r.json()["id"]

    md = c.get(f"/scans/{scan_id}/report?format=md", headers=a).text
    assert "role:app-role" in md
    assert "Suggested change:" in md
    assert "What-if:" in md
    assert "human approval required" in md

    js = c.get(f"/scans/{scan_id}/report?format=json", headers=a).json()
    assert js["findings"]

    # عزل: tenant آخر ما كيشوف والو
    assert c.get(f"/scans/{scan_id}/report", headers=b).status_code == 404
    assert c.post("/scans", json={"snapshot_id": sid}, headers=b).status_code == 404
