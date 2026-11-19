import json
from pathlib import Path

import pytest

pytest.importorskip("aegis")

from fastapi.testclient import TestClient  # noqa: E402

from hybrid.api import create_app  # noqa: E402
from hybrid.store import Store  # noqa: E402

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"
JSON = {"Content-Type": "application/json"}

QUOTE = "Customer data stored in Amazon S3 must be accessible only to the DataOps role."
PAYLOAD = {
    "obligations": [{
        "number": "4.2", "text": QUOTE, "page": 1, "data_class": "customer_data",
        "resource_hint": "Amazon S3", "principals_hint": ["DataOps role"],
    }]
}
CONTRACT = QUOTE + " No other identity may read, write or list this data."
APPROVAL = {
    "reviewer": "ignored",
    "resource_selector": "bucket:customer-data",
    "allowed_principals": ["role:DataOps"],
}


class FakeLLM:
    def complete_json(self, prompt, document, schema):
        return PAYLOAD


def make():
    store = Store()
    tenant, admin_key = store.create_tenant("acme")
    keys = {
        "admin": {"X-API-Key": admin_key},
        "reviewer": {"X-API-Key": store.create_key(tenant, "rita", "reviewer")},
        "viewer": {"X-API-Key": store.create_key(tenant, "victor", "viewer")},
    }
    client = TestClient(create_app(store, lambda: FakeLLM()))
    return client, keys, store, tenant


def upload_contract(client, headers):
    return client.post("/contracts", json={"contract_id": "c1", "text": CONTRACT}, headers=headers)


def first_proposal_id(client, headers):
    return client.get("/proposals", headers=headers).json()[0]["id"]


def test_viewer_can_read_but_cannot_write():
    client, keys, _, _ = make()
    v = keys["viewer"]
    assert client.get("/proposals", headers=v).status_code == 200
    assert client.get("/requirements", headers=v).status_code == 200
    assert client.get("/audit", headers=v).status_code == 200
    assert upload_contract(client, v).status_code == 403


def test_viewer_cannot_decide_a_proposal():
    client, keys, _, _ = make()
    upload_contract(client, keys["reviewer"])
    pid = first_proposal_id(client, keys["viewer"])
    assert client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=keys["viewer"]).status_code == 403
    assert client.post(f"/proposals/{pid}/reject", json={"reviewer": "x", "reason": "y"},
                       headers=keys["viewer"]).status_code == 403
    assert client.get("/requirements", headers=keys["viewer"]).json() == []


def test_audit_uses_the_identity_of_the_key_not_the_body():
    client, keys, _, _ = make()
    upload_contract(client, keys["reviewer"])
    pid = first_proposal_id(client, keys["reviewer"])
    assert client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=keys["reviewer"]).status_code == 200
    (entry,) = client.get("/audit", headers=keys["reviewer"]).json()
    assert entry["actor"] == "rita"


def test_reject_is_logged_with_the_key_identity():
    client, keys, _, _ = make()
    upload_contract(client, keys["reviewer"])
    pid = first_proposal_id(client, keys["reviewer"])
    r = client.post(f"/proposals/{pid}/reject",
                    json={"reviewer": "someone-else", "reason": "not relevant"}, headers=keys["reviewer"])
    assert r.status_code == 200
    (entry,) = client.get("/audit", headers=keys["reviewer"]).json()
    assert entry["actor"] == "rita"


def test_reviewer_cannot_upload_snapshots_or_run_scans():
    client, keys, _, _ = make()
    r = client.post("/snapshots", content=SNAP.read_bytes(), headers={**keys["reviewer"], **JSON})
    assert r.status_code == 403
    r = client.post("/scans", json={"snapshot_id": "s-x"}, headers=keys["reviewer"])
    assert r.status_code == 403


def test_viewer_cannot_upload_snapshots_or_run_scans():
    client, keys, _, _ = make()
    r = client.post("/snapshots", content=SNAP.read_bytes(), headers={**keys["viewer"], **JSON})
    assert r.status_code == 403
    r = client.post("/scans", json={"snapshot_id": "s-x"}, headers=keys["viewer"])
    assert r.status_code == 403


def test_admin_can_run_the_whole_flow_and_everyone_can_read_the_report():
    client, keys, _, _ = make()
    upload_contract(client, keys["reviewer"])
    pid = first_proposal_id(client, keys["reviewer"])
    client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=keys["reviewer"])

    s = client.post("/snapshots", content=SNAP.read_bytes(), headers={**keys["admin"], **JSON})
    assert s.status_code == 201
    sc = client.post("/scans", json={"snapshot_id": s.json()["id"]}, headers=keys["admin"])
    assert sc.status_code == 201 and sc.json()["findings"] == 2

    report = client.get(f"/scans/{sc.json()['id']}/report?format=json", headers=keys["viewer"])
    assert report.status_code == 200
    assert len(report.json()["findings"]) == 2


def test_roles_do_not_cross_tenants():
    client, keys, store, _ = make()
    other_tenant, other_admin = store.create_tenant("other")
    upload_contract(client, keys["reviewer"])
    pid = first_proposal_id(client, keys["reviewer"])
    other = {"X-API-Key": other_admin}
    assert client.get("/proposals", headers=other).json() == []
    assert client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=other).status_code == 404


def test_invalid_key_is_unauthorized_and_role_is_not_a_header():
    client, keys, _, _ = make()
    assert client.get("/proposals", headers={"X-API-Key": "nope"}).status_code == 401
    spoof = {**keys["viewer"], "X-Role": "admin"}
    assert upload_contract(client, spoof).status_code == 403


def test_create_key_rejects_an_unknown_role():
    _, _, store, tenant = make()
    with pytest.raises(ValueError):
        store.create_key(tenant, "mallory", "superuser")
