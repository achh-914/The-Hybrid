import json
import logging
from pathlib import Path

import pytest

pytest.importorskip("aegis")

from fastapi.testclient import TestClient  # noqa: E402

from hybrid.api import create_app  # noqa: E402
from hybrid.aws_connect import external_id_for  # noqa: E402
from hybrid.store import Store  # noqa: E402

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"
SECRET = "k" * 48
ROLE = "arn:aws:iam::123456789012:role/HybridReadOnlyRole"
QUOTE = "Customer data stored in Amazon S3 must be accessible only to the DataOps role."
PAYLOAD = {
    "obligations": [{
        "number": "4.2", "text": QUOTE, "page": 1, "data_class": "customer_data",
        "resource_hint": "Amazon S3", "principals_hint": ["DataOps role"],
    }]
}
APPROVAL = {
    "reviewer": "ignored",
    "resource_selector": "bucket:customer-data",
    "allowed_principals": ["role:DataOps"],
}


class FakeLLM:
    def complete_json(self, prompt, document, schema):
        return PAYLOAD


class FakeCollector:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def __call__(self, role_arn, external_id):
        self.calls.append((role_arn, external_id))
        if self.error:
            raise self.error
        return {
            "account_id": "123456789012",
            "collected_at": "x",
            "iam": json.loads(SNAP.read_text()),
            "s3": [{"Name": "customer-data", "Policy": None}],
        }


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("HYBRID_SERVER_SECRET", SECRET)
    monkeypatch.setenv("HYBRID_AWS_ACCOUNT_ID", "111122223333")


def make(collector=None):
    store = Store()
    tenant, admin_key = store.create_tenant("acme")
    keys = {
        "admin": {"X-API-Key": admin_key},
        "reviewer": {"X-API-Key": store.create_key(tenant, "rita", "reviewer")},
        "viewer": {"X-API-Key": store.create_key(tenant, "victor", "viewer")},
    }
    app = create_app(store, lambda: FakeLLM())
    collector = collector or FakeCollector()
    app.state.aws_collector = collector
    return TestClient(app), keys, store, tenant, collector


def approve_requirement(client, keys):
    client.post("/contracts", json={"contract_id": "c1", "text": QUOTE + " No other identity may read."},
                headers=keys["reviewer"])
    pid = client.get("/proposals", headers=keys["reviewer"]).json()[0]["id"]
    assert client.post(f"/proposals/{pid}/approve", json=APPROVAL, headers=keys["reviewer"]).status_code == 200


def connect(client, keys):
    return client.post("/aws/connection", json={"role_arn": ROLE}, headers=keys["admin"])


def test_connection_info_has_the_server_derived_external_id_and_no_role_yet():
    client, keys, _, tenant, _ = make()
    info = client.get("/aws/connection", headers=keys["admin"]).json()
    assert info["external_id"] == external_id_for(tenant, SECRET)
    assert info["role_arn"] is None


def test_register_show_and_remove_a_role():
    client, keys, _, _, _ = make()
    assert connect(client, keys).status_code == 200
    info = client.get("/aws/connection", headers=keys["admin"]).json()
    assert info["role_arn"] == ROLE and info["account_id"] == "123456789012"
    assert client.delete("/aws/connection", headers=keys["admin"]).status_code == 204
    assert client.get("/aws/connection", headers=keys["admin"]).json()["role_arn"] is None


@pytest.mark.parametrize("bad", ["x" * 25, "arn:aws:iam::123:role/R", "arn:aws:s3:::some-bucket-name"])
def test_invalid_role_arn_is_rejected(bad):
    client, keys, _, _, _ = make()
    assert client.post("/aws/connection", json={"role_arn": bad}, headers=keys["admin"]).status_code == 422


def test_the_external_id_cannot_be_supplied_by_the_caller():
    client, keys, _, _, collector = make()
    r = client.post("/aws/connection", json={"role_arn": ROLE, "external_id": "mine"}, headers=keys["admin"])
    assert r.status_code == 422
    assert collector.calls == []


def test_all_aws_routes_are_admin_only():
    client, keys, _, _, collector = make()
    for role in ("reviewer", "viewer"):
        h = keys[role]
        assert client.get("/aws/connection", headers=h).status_code == 403
        assert client.post("/aws/connection", json={"role_arn": ROLE}, headers=h).status_code == 403
        assert client.delete("/aws/connection", headers=h).status_code == 403
        assert client.post("/aws/scan", headers=h).status_code == 403
    assert client.get("/aws/connection").status_code == 401
    assert client.post("/aws/scan").status_code == 401
    assert collector.calls == []


def test_scan_needs_a_connection_and_approved_requirements():
    client, keys, _, _, collector = make()
    assert client.post("/aws/scan", headers=keys["admin"]).status_code == 409
    connect(client, keys)
    assert client.post("/aws/scan", headers=keys["admin"]).status_code == 409
    assert collector.calls == []


def test_scan_uses_the_registered_role_and_the_server_derived_external_id():
    client, keys, _, tenant, collector = make()
    approve_requirement(client, keys)
    connect(client, keys)
    r = client.post("/aws/scan", headers=keys["admin"])
    assert r.status_code == 201 and r.json()["findings"] == 2
    assert collector.calls == [(ROLE, external_id_for(tenant, SECRET))]


def test_a_second_scan_right_away_is_rate_limited():
    client, keys, _, _, collector = make()
    approve_requirement(client, keys)
    connect(client, keys)
    assert client.post("/aws/scan", headers=keys["admin"]).status_code == 201
    r = client.post("/aws/scan", headers=keys["admin"])
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    assert len(collector.calls) == 1


def test_collector_failure_leaks_nothing_in_the_response_or_the_logs(caplog):
    client, keys, _, _, _ = make(FakeCollector(error=RuntimeError("boom-detail 123456789012")))
    approve_requirement(client, keys)
    connect(client, keys)
    with caplog.at_level(logging.DEBUG, logger="hybrid.aws"):
        r = client.post("/aws/scan", headers=keys["admin"])
    assert r.status_code == 502
    for secret in ("boom-detail", ROLE, SECRET, "123456789012"):
        assert secret not in r.text
        assert secret not in caplog.text


def test_unconfigured_server_returns_503_and_never_calls_aws(monkeypatch):
    client, keys, _, _, collector = make()
    approve_requirement(client, keys)
    connect(client, keys)
    monkeypatch.delenv("HYBRID_SERVER_SECRET")
    assert client.get("/aws/connection", headers=keys["admin"]).status_code == 503
    assert client.post("/aws/scan", headers=keys["admin"]).status_code == 503
    assert collector.calls == []


def test_only_the_iam_part_is_stored():
    client, keys, store, tenant, _ = make()
    approve_requirement(client, keys)
    connect(client, keys)
    sid = client.post("/aws/scan", headers=keys["admin"]).json()["snapshot_id"]
    with store._lock:
        (body,) = store._db.execute(
            "SELECT body FROM snapshots WHERE tenant_id = ? AND id = ?", (tenant, sid)
        ).fetchone()
    stored = json.loads(body)
    assert "RoleDetailList" in stored
    assert "s3" not in stored and "account_id" not in stored


def test_connections_do_not_cross_tenants():
    client, keys, store, _, collector = make()
    connect(client, keys)
    _, other_key = store.create_tenant("other")
    other = {"X-API-Key": other_key}
    info = client.get("/aws/connection", headers=other).json()
    assert info["role_arn"] is None
    assert client.post("/aws/scan", headers=other).status_code == 409
    assert collector.calls == []


# ---- audit trail ------------------------------------------------------------

def aws_audit(client, headers):
    entries = client.get("/audit", headers=headers).json()
    return [e for e in entries if e["action"].startswith("aws.")]


def test_connect_replace_and_remove_are_audited_with_the_actor_from_the_key():
    client, keys, store, tenant, _ = make()
    ana = {"X-API-Key": store.create_key(tenant, "ana", "admin")}

    assert client.post("/aws/connection", json={"role_arn": ROLE}, headers=ana).status_code == 200
    assert client.post("/aws/connection", json={"role_arn": ROLE}, headers=keys["admin"]).status_code == 200
    assert client.delete("/aws/connection", headers=ana).status_code == 204

    got = aws_audit(client, keys["admin"])
    assert [e["action"] for e in got] == [
        "aws.connection.set", "aws.connection.set", "aws.connection.removed"]
    assert [e["actor"] for e in got] == ["ana", "admin", "ana"]
    assert [e["details"].get("replaced") for e in got[:2]] == [False, True]
    assert all(e["details"]["account_id"] == "123456789012" for e in got)


def test_removing_nothing_writes_no_audit_entry():
    client, keys, _, _, _ = make()
    assert client.delete("/aws/connection", headers=keys["admin"]).status_code == 204
    assert aws_audit(client, keys["admin"]) == []


def test_a_successful_scan_is_audited_with_its_ids():
    client, keys, _, _, _ = make()
    approve_requirement(client, keys)
    connect(client, keys)
    r = client.post("/aws/scan", headers=keys["admin"]).json()

    done = [e for e in aws_audit(client, keys["admin"]) if e["action"] == "aws.scan.completed"]
    assert len(done) == 1
    assert done[0]["actor"] == "admin"
    assert done[0]["subject_id"] == r["id"]
    assert done[0]["details"] == {
        "account_id": "123456789012", "scan_id": r["id"],
        "snapshot_id": r["snapshot_id"], "findings": r["findings"]}


def test_a_failed_scan_is_audited_by_reason_and_leaks_nothing():
    client, keys, _, _, _ = make(FakeCollector(error=RuntimeError("boom-detail 123456789012")))
    approve_requirement(client, keys)
    connect(client, keys)
    assert client.post("/aws/scan", headers=keys["admin"]).status_code == 502

    failed = [e for e in aws_audit(client, keys["admin"]) if e["action"] == "aws.scan.failed"]
    assert len(failed) == 1
    assert failed[0]["details"] == {"account_id": "123456789012", "reason": "collection_failed"}
    text = json.dumps(aws_audit(client, keys["admin"]))
    for secret in ("boom-detail", ROLE, SECRET):
        assert secret not in text


def test_the_audit_never_contains_the_role_arn_or_the_external_id():
    client, keys, _, tenant, _ = make()
    approve_requirement(client, keys)
    connect(client, keys)
    client.post("/aws/scan", headers=keys["admin"])
    text = json.dumps(aws_audit(client, keys["admin"]))
    assert text and ROLE not in text
    assert external_id_for(tenant, SECRET) not in text


def test_rejected_calls_and_rate_limited_scans_write_nothing_extra():
    client, keys, _, _, _ = make()
    approve_requirement(client, keys)
    for role in ("reviewer", "viewer"):
        client.post("/aws/connection", json={"role_arn": ROLE}, headers=keys[role])
        client.delete("/aws/connection", headers=keys[role])
    client.post("/aws/connection", json={"role_arn": "x" * 25}, headers=keys["admin"])
    assert aws_audit(client, keys["admin"]) == []

    connect(client, keys)
    assert client.post("/aws/scan", headers=keys["admin"]).status_code == 201
    assert client.post("/aws/scan", headers=keys["admin"]).status_code == 429
    actions = [e["action"] for e in aws_audit(client, keys["admin"])]
    assert actions == ["aws.connection.set", "aws.scan.completed"]


def test_aws_audit_entries_do_not_cross_tenants():
    client, keys, store, _, _ = make()
    approve_requirement(client, keys)
    connect(client, keys)
    client.post("/aws/scan", headers=keys["admin"])
    _, other_key = store.create_tenant("other")
    assert aws_audit(client, {"X-API-Key": other_key}) == []
