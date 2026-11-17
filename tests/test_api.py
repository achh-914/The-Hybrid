import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from hybrid.api import create_app  # noqa: E402
from hybrid.store import Store  # noqa: E402

CONTRACT = (
    "Customer data stored in Amazon S3 must be accessible only to the DataOps role. "
    "No other identity may read, write or list this data."
)
QUOTE = "Customer data stored in Amazon S3 must be accessible only to the DataOps role."
PAYLOAD = {
    "obligations": [{
        "number": "4.2", "text": QUOTE, "page": 1, "data_class": "customer_data",
        "resource_hint": "Amazon S3", "principals_hint": ["DataOps role"],
    }]
}
APPROVAL = {
    "reviewer": "r1",
    "resource_selector": "bucket:customer-data",
    "allowed_principals": ["role:DataOps"],
}


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload

    def complete_json(self, prompt, document, schema):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


@pytest.fixture
def env():
    store = Store()
    _, key_a = store.create_tenant("A")
    _, key_b = store.create_tenant("B")
    client = TestClient(create_app(store, lambda: FakeLLM(PAYLOAD)))
    return client, {"X-API-Key": key_a}, {"X-API-Key": key_b}, store


def upload(client, headers):
    return client.post("/contracts", json={"contract_id": "c1", "text": CONTRACT}, headers=headers)


def test_requires_a_valid_api_key(env):
    client, a, _, _ = env
    assert client.get("/proposals").status_code == 401
    assert client.get("/proposals", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/proposals", headers=a).status_code == 200


def test_upload_creates_a_pending_proposal(env):
    client, a, _, _ = env
    assert upload(client, a).status_code == 201
    (p,) = client.get("/proposals", headers=a).json()
    assert p["status"] == "pending" and p["clause_number"] == "4.2"


def test_tenants_cannot_see_or_touch_each_other(env):
    client, a, b, _ = env
    upload(client, a)
    pid = client.get("/proposals", headers=a).json()[0]["id"]
    assert client.get("/proposals", headers=b).json() == []
    assert client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=b).status_code == 404
    assert client.post(f"/proposals/{pid}/reject", json={"reviewer": "x", "reason": "y"},
                       headers=b).status_code == 404
    client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=a)
    assert client.get("/requirements", headers=b).json() == []
    assert client.get("/audit", headers=b).json() == []
    assert len(client.get("/requirements", headers=a).json()) == 1


def test_approve_creates_requirement_and_audit_entry(env):
    client, a, _, _ = env
    upload(client, a)
    pid = client.get("/proposals", headers=a).json()[0]["id"]
    r = client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=a)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    (entry,) = client.get("/audit", headers=a).json()
    assert entry["action"] == "requirement.approved"
    assert client.get("/proposals", headers=a).json()[0]["status"] == "approved"


def test_a_proposal_cannot_be_decided_twice(env):
    client, a, _, _ = env
    upload(client, a)
    pid = client.get("/proposals", headers=a).json()[0]["id"]
    assert client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=a).status_code == 200
    assert client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=a).status_code == 409
    assert client.post(f"/proposals/{pid}/reject", json={"reviewer": "x", "reason": "y"},
                       headers=a).status_code == 409


def test_invalid_technical_ids_are_rejected(env):
    client, a, _, _ = env
    upload(client, a)
    pid = client.get("/proposals", headers=a).json()[0]["id"]
    bad = {**APPROVAL, "resource_selector": "customer-data"}
    assert client.post(f"/proposals/{pid}/approve", json=bad, headers=a).status_code == 422


def test_reject_is_logged(env):
    client, a, _, _ = env
    upload(client, a)
    pid = client.get("/proposals", headers=a).json()[0]["id"]
    r = client.post(f"/proposals/{pid}/reject", json={"reviewer": "r1", "reason": "not relevant"},
                    headers=a)
    assert r.status_code == 200
    assert client.get("/audit", headers=a).json()[0]["action"] == "requirement.rejected"


def test_bad_model_output_returns_422():
    store = Store()
    _, key = store.create_tenant("A")
    client = TestClient(create_app(store, lambda: FakeLLM({"unexpected": 1})))
    r = client.post("/contracts", json={"contract_id": "c1", "text": CONTRACT},
                    headers={"X-API-Key": key})
    assert r.status_code == 422


def test_model_outage_returns_502():
    store = Store()
    _, key = store.create_tenant("A")
    client = TestClient(create_app(store, lambda: FakeLLM(RuntimeError("down"))))
    r = client.post("/contracts", json={"contract_id": "c1", "text": CONTRACT},
                    headers={"X-API-Key": key})
    assert r.status_code == 502
