import pytest

from hybrid.admin import main
from hybrid.auth import Role
from hybrid.store import Store


@pytest.fixture
def two_tenants():
    store = Store()
    t1, admin1 = store.create_tenant("acme")
    t2, admin2 = store.create_tenant("globex")
    return store, t1, admin1, t2, admin2


def test_revoked_key_stops_working(two_tenants):
    store, t1, _, _, _ = two_tenants
    key = store.create_key(t1, "alice", Role.REVIEWER)
    assert store.principal_for_key(key) is not None
    assert store.revoke_key(t1, "alice") == 1
    assert store.principal_for_key(key) is None
    assert store.tenant_for_key(key) is None


def test_other_keys_keep_working(two_tenants):
    store, t1, admin1, _, _ = two_tenants
    store.create_key(t1, "alice", Role.REVIEWER)
    bob = store.create_key(t1, "bob", Role.VIEWER)
    store.revoke_key(t1, "alice")
    assert store.principal_for_key(bob).user_id == "bob"
    assert store.principal_for_key(admin1) is not None


def test_all_keys_of_the_user_are_revoked(two_tenants):
    store, t1, _, _, _ = two_tenants
    k1 = store.create_key(t1, "alice", Role.VIEWER)
    k2 = store.create_key(t1, "alice", Role.VIEWER)
    assert store.revoke_key(t1, "alice") == 2
    assert store.principal_for_key(k1) is None
    assert store.principal_for_key(k2) is None


def test_cannot_revoke_a_user_of_another_tenant(two_tenants):
    store, t1, _, t2, _ = two_tenants
    key = store.create_key(t2, "alice", Role.REVIEWER)
    assert store.revoke_key(t1, "alice") == 0  # wrong tenant: nothing happens
    assert store.principal_for_key(key) is not None


def test_revoking_an_unknown_user_or_twice_returns_zero(two_tenants):
    store, t1, _, _, _ = two_tenants
    store.create_key(t1, "alice", Role.VIEWER)
    assert store.revoke_key(t1, "nobody") == 0
    assert store.revoke_key(t1, "alice") == 1
    assert store.revoke_key(t1, "alice") == 0


def test_cannot_revoke_the_last_admin_key(two_tenants):
    store, t1, admin1, _, _ = two_tenants
    with pytest.raises(ValueError, match="last active admin"):
        store.revoke_key(t1, "admin")
    assert store.principal_for_key(admin1) is not None


def test_an_admin_can_be_revoked_when_another_admin_exists(two_tenants):
    store, t1, admin1, _, _ = two_tenants
    boss = store.create_key(t1, "boss", Role.ADMIN)
    assert store.revoke_key(t1, "admin") == 1
    assert store.principal_for_key(admin1) is None
    assert store.principal_for_key(boss) is not None


def test_old_database_without_revoked_at_is_migrated(tmp_path):
    path = str(tmp_path / "old.db")
    first = Store(path)
    tenant, admin_key = first.create_tenant("acme")
    first._db.execute("ALTER TABLE api_keys DROP COLUMN revoked_at")  # simulate old DB
    first._db.commit()
    first._db.close()

    store = Store(path)  # opening it must add the column back
    assert store.principal_for_key(admin_key) is not None
    store.create_key(tenant, "boss", Role.ADMIN)
    assert store.revoke_key(tenant, "admin") == 1
    assert store.principal_for_key(admin_key) is None


def _field(output: str, name: str) -> str:
    return next(
        line.split(": ", 1)[1] for line in output.splitlines() if line.startswith(name)
    )


def test_admin_cli_revoke_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HYBRID_DB", str(tmp_path / "cli.db"))
    assert main(["create-tenant", "acme"]) == 0
    tenant = _field(capsys.readouterr().out, "tenant")
    assert main(["create-key", tenant, "alice", "--role", "reviewer"]) == 0
    capsys.readouterr()

    assert main(["revoke-key", tenant, "alice"]) == 0
    assert "revoked 1 key" in capsys.readouterr().out
    assert main(["revoke-key", tenant, "alice"]) == 1  # nothing left to revoke
    assert main(["revoke-key", tenant, "admin"]) == 1  # last admin is protected
    assert "last active admin" in capsys.readouterr().err
