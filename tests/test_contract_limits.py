import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from hybrid.api import create_app  # noqa: E402
from hybrid.ratelimit import RateLimiter  # noqa: E402
from hybrid.store import Store  # noqa: E402

QUOTE = "Customer data stored in Amazon S3 must be accessible only to the DataOps role."
CONTRACT = QUOTE + " No other identity may read, write or list this data."
PAYLOAD = {
    "obligations": [{
        "number": "4.2", "text": QUOTE, "page": 1, "data_class": "customer_data",
        "resource_hint": "Amazon S3", "principals_hint": ["DataOps role"],
    }]
}


class CountingLLM:
    calls = 0

    def __init__(self, payload=PAYLOAD):
        self.payload = payload

    def complete_json(self, prompt, document, schema):
        CountingLLM.calls += 1
        return self.payload


@pytest.fixture(autouse=True)
def reset_calls():
    CountingLLM.calls = 0


def make(payload=PAYLOAD, limit=2):
    store = Store()
    tenant, admin_key = store.create_tenant("acme")
    viewer_key = store.create_key(tenant, "victor", "viewer")
    app = create_app(store, lambda: CountingLLM(payload))
    app.state.contract_limiter = RateLimiter(limit, 3600)
    client = TestClient(app)
    return client, {"X-API-Key": admin_key}, {"X-API-Key": viewer_key}, store


def upload(client, headers, cid="c1"):
    return client.post("/contracts", json={"contract_id": cid, "text": CONTRACT}, headers=headers)


def test_uploads_are_limited_per_tenant_with_retry_after():
    client, admin, _, _ = make(limit=2)
    assert upload(client, admin, "c1").status_code == 201
    assert upload(client, admin, "c2").status_code == 201
    r = upload(client, admin, "c3")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    assert CountingLLM.calls == 2  # the refused request never reached the model


def test_failed_extractions_also_use_the_budget():
    client, admin, _, _ = make(payload={"unexpected": 1}, limit=2)
    assert upload(client, admin, "c1").status_code == 422
    assert upload(client, admin, "c2").status_code == 422
    assert upload(client, admin, "c3").status_code == 429


def test_another_tenant_is_not_affected():
    client, admin, _, store = make(limit=1)
    _, other_key = store.create_tenant("other")
    assert upload(client, admin).status_code == 201
    assert upload(client, admin, "c2").status_code == 429
    assert upload(client, {"X-API-Key": other_key}).status_code == 201


def test_a_forbidden_request_does_not_use_the_budget():
    client, admin, viewer, _ = make(limit=1)
    assert upload(client, viewer).status_code == 403
    assert upload(client, admin).status_code == 201


def test_oversized_body_is_refused_before_the_model_and_auth():
    client, admin, _, _ = make()
    r = client.post(
        "/contracts",
        content=b"x" * 2_000_000,
        headers={**admin, "Content-Type": "application/json"},
    )
    assert r.status_code == 413
    assert CountingLLM.calls == 0


def test_limit_can_be_set_from_the_environment(monkeypatch):
    monkeypatch.setenv("HYBRID_CONTRACTS_PER_HOUR", "1")
    store = Store()
    _, key = store.create_tenant("acme")
    client = TestClient(create_app(store, lambda: CountingLLM()))
    headers = {"X-API-Key": key}
    assert upload(client, headers, "c1").status_code == 201
    assert upload(client, headers, "c2").status_code == 429
