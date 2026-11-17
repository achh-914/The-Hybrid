import sqlite3

import pytest

from hybrid.admin import main as admin_main
from hybrid.auth import Role
from hybrid.store import Store, _hash


def test_create_tenant_gives_an_admin_key():
    store = Store()
    tenant_id, key = store.create_tenant("acme")
    p = store.principal_for_key(key)
    assert p is not None
    assert (p.tenant_id, p.user_id, p.role) == (tenant_id, "admin", Role.ADMIN)


def test_unknown_or_empty_key_has_no_principal():
    store = Store()
    store.create_tenant("acme")
    assert store.principal_for_key("hyb_nope") is None
    assert store.principal_for_key("") is None


@pytest.mark.parametrize("role", [Role.ADMIN, Role.REVIEWER, Role.VIEWER])
def test_create_key_keeps_user_and_role(role):
    store = Store()
    tenant_id, _ = store.create_tenant("acme")
    key = store.create_key(tenant_id, "meriem", role)
    p = store.principal_for_key(key)
    assert (p.tenant_id, p.user_id, p.role) == (tenant_id, "meriem", role)


def test_create_key_accepts_role_as_string():
    store = Store()
    tenant_id, _ = store.create_tenant("acme")
    key = store.create_key(tenant_id, "bob", "viewer")
    assert store.principal_for_key(key).role is Role.VIEWER


def test_create_key_rejects_unknown_tenant_role_and_bad_user():
    store = Store()
    tenant_id, _ = store.create_tenant("acme")
    with pytest.raises(ValueError):
        store.create_key("t-missing", "bob", Role.VIEWER)
    with pytest.raises(ValueError):
        store.create_key(tenant_id, "bob", "superuser")
    for bad in ("", " bob", "../x", "a" * 65, "bob\n"):
        with pytest.raises(ValueError):
            store.create_key(tenant_id, bad, Role.VIEWER)


def test_keys_belong_to_their_own_tenant():
    store = Store()
    ta, _ = store.create_tenant("a")
    tb, _ = store.create_tenant("b")
    kb = store.create_key(tb, "bob", Role.REVIEWER)
    assert store.principal_for_key(kb).tenant_id == tb != ta


def test_keys_are_stored_hashed_only():
    store = Store()
    tenant_id, key = store.create_tenant("acme")
    stored = [r[0] for r in store._db.execute("SELECT key_hash FROM api_keys")]
    assert key not in stored
    assert _hash(key) in stored


def test_tenant_for_key_still_works():
    store = Store()
    tenant_id, key = store.create_tenant("acme")
    assert store.tenant_for_key(key) == tenant_id
    assert store.tenant_for_key("hyb_nope") is None


def test_unknown_role_in_database_fails_closed():
    store = Store()
    tenant_id, key = store.create_tenant("acme")
    store._db.execute("UPDATE api_keys SET role = 'root'")
    store._db.commit()
    assert store.principal_for_key(key) is None


def test_legacy_database_keys_keep_working_as_admin(tmp_path):
    path = str(tmp_path / "legacy.db")
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL);"
        "CREATE TABLE api_keys (key_hash TEXT PRIMARY KEY,"
        " tenant_id TEXT NOT NULL REFERENCES tenants(id));"
    )
    db.execute("INSERT INTO tenants VALUES ('t-old', 'old')")
    db.execute("INSERT INTO api_keys VALUES (?, 't-old')", (_hash("hyb_legacy"),))
    db.commit()
    db.close()

    store = Store(path)  # runs the migration
    p = store.principal_for_key("hyb_legacy")
    assert (p.tenant_id, p.user_id, p.role) == ("t-old", "admin", Role.ADMIN)
    # opening it again is a no-op
    assert Store(path).principal_for_key("hyb_legacy") is not None


def test_admin_cli_create_key(tmp_path, monkeypatch, capsys):
    path = str(tmp_path / "cli.db")
    monkeypatch.setenv("HYBRID_DB", path)
    assert admin_main(["create-tenant", "acme"]) == 0
    tenant_id = capsys.readouterr().out.splitlines()[0].split(": ")[1]

    assert admin_main(["create-key", tenant_id, "meriem", "--role", "reviewer"]) == 0
    out = capsys.readouterr().out
    key = out.split("keep it safe): ")[1].strip()
    assert Store(path).principal_for_key(key).role is Role.REVIEWER

    # default role is the least privileged one
    assert admin_main(["create-key", tenant_id, "bob"]) == 0
    out = capsys.readouterr().out
    key = out.split("keep it safe): ")[1].strip()
    assert Store(path).principal_for_key(key).role is Role.VIEWER

    assert admin_main(["create-key", "t-missing", "bob"]) == 1
