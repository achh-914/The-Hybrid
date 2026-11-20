import json
import sqlite3

import pytest

from hybrid.admin import main
from hybrid.auth import Role
from hybrid.aws_connections import AwsConnections
from hybrid.requirements import AuditEntry, RequirementProposal
from hybrid.store import Store

ROLE = "arn:aws:iam::123456789012:role/HybridReadOnlyRole"


def _proposal(tenant_id, pid):
    return RequirementProposal(
        tenant_id=tenant_id, id=pid, clause_id="c-4.2", clause_number="4.2",
        clause_text="Customer data stored in Amazon S3 must be accessible only to DataOps.",
        page=1, data_class="customer_data",
        resource_hint="customer data stored in Amazon S3",
        principals_hint=("DataOps role",),
    )


def _fill(store, tenant, marker):
    """Put one row of every kind into the tenant."""
    store.add_proposals(tenant, [_proposal(tenant, "p-1")])
    store.add_audit(tenant, AuditEntry(
        tenant_id=tenant, id="a-1", action="x.y", subject_id="s", actor="admin",
        timestamp="2026-01-01T00:00:00+00:00", details={"note": marker}))
    with store._lock:
        store._db.execute(
            "INSERT INTO snapshots VALUES (?, 's-1', 'sha', '2026-01-01', ?)", (tenant, marker))
        store._db.execute(
            "INSERT INTO scans VALUES (?, 'sc-1', 's-1', '2026-01-01', ?, ?)",
            (tenant, marker, json.dumps({"marker": marker})))
        store._db.execute(
            "INSERT INTO requirements VALUES (?, 'req-1', ?)", (tenant, marker))
        store._db.commit()
    AwsConnections(store).upsert(tenant, ROLE, "123456789012")


def _rows_for(store, tenant):
    """Rows left anywhere that belong to the tenant, found through the schema."""
    left = {}
    with store._lock:
        tables = [r[0] for r in store._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for t in tables:
            cols = {r[1] for r in store._db.execute(f'PRAGMA table_info("{t}")')}
            col = "id" if t == "tenants" else ("tenant_id" if "tenant_id" in cols else None)
            if t == "deleted_tenants" or col is None:
                continue
            n = store._db.execute(
                f'SELECT COUNT(*) FROM "{t}" WHERE {col} = ?', (tenant,)).fetchone()[0]
            if n:
                left[t] = n
    return left


@pytest.fixture
def two():
    store = Store()
    t1, k1 = store.create_tenant("acme")
    t2, k2 = store.create_tenant("globex")
    _fill(store, t1, "MARKER-ACME")
    _fill(store, t2, "MARKER-GLOBEX")
    return store, t1, k1, t2, k2


def test_deleting_a_tenant_removes_every_row_it_owns(two):
    store, t1, _, _, _ = two
    assert _rows_for(store, t1)  # sanity: there is something to delete
    counts = store.delete_tenant(t1, "operator1")
    assert _rows_for(store, t1) == {}
    for table in ("tenants", "api_keys", "proposals", "requirements", "audit",
                  "snapshots", "scans", "aws_connections"):
        assert counts[table] >= 1, table


def test_other_tenants_are_untouched(two):
    store, t1, _, t2, k2 = two
    before = _rows_for(store, t2)
    store.delete_tenant(t1, "operator1")
    assert _rows_for(store, t2) == before
    assert store.principal_for_key(k2).tenant_id == t2
    assert len(store.list_audit(t2)) == 1


def test_keys_of_a_deleted_tenant_stop_working(two):
    store, t1, k1, _, _ = two
    extra = store.create_key(t1, "rita", Role.REVIEWER)
    store.delete_tenant(t1, "operator1")
    assert store.principal_for_key(k1) is None
    assert store.principal_for_key(extra) is None
    assert store.tenant_for_key(k1) is None


def test_only_the_id_the_time_and_the_operator_are_kept(two):
    store, t1, _, _, _ = two
    store.delete_tenant(t1, "operator1")
    (record,) = store.deleted_tenants()
    assert set(record) == {"tenant_id", "deleted_at", "operator"}
    assert record["tenant_id"] == t1 and record["operator"] == "operator1"
    assert "acme" not in json.dumps(record)


def test_unknown_tenant_twice_and_bad_operator_are_refused(two):
    store, t1, _, t2, _ = two
    with pytest.raises(ValueError, match="unknown tenant"):
        store.delete_tenant("t-nope", "operator1")
    with pytest.raises(ValueError, match="invalid operator"):
        store.delete_tenant(t1, "bad operator!")
    assert _rows_for(store, t1)  # a refused call deletes nothing
    store.delete_tenant(t1, "operator1")
    with pytest.raises(ValueError, match="unknown tenant"):
        store.delete_tenant(t1, "operator1")
    assert len(store.deleted_tenants()) == 1


def test_a_table_added_later_is_covered_too(two):
    store, t1, _, t2, _ = two
    with store._lock:
        store._db.execute("CREATE TABLE future (tenant_id TEXT NOT NULL, v TEXT)")
        store._db.execute("INSERT INTO future VALUES (?, 'a'), (?, 'b')", (t1, t2))
        store._db.commit()
    store.delete_tenant(t1, "operator1")
    assert _rows_for(store, t1) == {}
    assert _rows_for(store, t2)["future"] == 1


def test_a_failure_in_the_middle_rolls_everything_back(two):
    store, t1, k1, _, _ = two
    with store._lock:  # a trigger that makes the last step fail
        store._db.execute(
            "CREATE TRIGGER boom BEFORE INSERT ON deleted_tenants "
            "BEGIN SELECT RAISE(ABORT, 'boom'); END")
        store._db.commit()
    before = _rows_for(store, t1)
    with pytest.raises(sqlite3.DatabaseError):
        store.delete_tenant(t1, "operator1")
    assert _rows_for(store, t1) == before
    assert store.principal_for_key(k1) is not None
    assert store.deleted_tenants() == []


def test_deleted_data_does_not_linger_in_the_database_file(tmp_path):
    path = tmp_path / "t.db"
    store = Store(str(path))
    t1, _ = store.create_tenant("acme")
    marker = "ZZ-SECRET-MARKER-" + "x" * 200
    _fill(store, t1, marker)
    store._db.commit()
    assert marker.encode() in path.read_bytes()  # sanity: it was written to disk
    store.delete_tenant(t1, "operator1")
    store._db.close()
    assert marker.encode() not in path.read_bytes()


def _field(output, name):
    return next(l.split(": ", 1)[1] for l in output.splitlines() if l.startswith(name))


def test_cli_needs_the_exact_confirmation_and_an_operator(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HYBRID_DB", str(tmp_path / "cli.db"))
    assert main(["create-tenant", "acme"]) == 0
    tenant = _field(capsys.readouterr().out, "tenant")

    assert main(["delete-tenant", tenant, "--confirm", "t-other", "--operator", "op1"]) == 1
    assert "nothing was deleted" in capsys.readouterr().err
    with pytest.raises(SystemExit):  # --operator is required
        main(["delete-tenant", tenant, "--confirm", tenant])
    capsys.readouterr()
    assert Store(str(tmp_path / "cli.db")).deleted_tenants() == []

    assert main(["delete-tenant", tenant, "--confirm", tenant, "--operator", "op1"]) == 0
    out = capsys.readouterr().out
    assert f"deleted tenant {tenant}" in out and "api_keys: 1 row" in out
    assert "Backups taken before now" in out
    assert main(["delete-tenant", tenant, "--confirm", tenant, "--operator", "op1"]) == 1
    assert "unknown tenant" in capsys.readouterr().err
