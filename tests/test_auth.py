import pytest
from pydantic import ValidationError

from hybrid.auth import Principal, Role


def test_role_values_are_stable():
    assert {r.value for r in Role} == {"admin", "reviewer", "viewer"}


def test_principal_is_built_from_a_string_role():
    p = Principal(tenant_id="t1", user_id="u1", role="reviewer")
    assert p.role is Role.REVIEWER


def test_principal_rejects_unknown_role():
    with pytest.raises(ValidationError):
        Principal(tenant_id="t1", user_id="u1", role="superuser")


def test_principal_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Principal(tenant_id="t1", user_id="u1", role="admin", is_root=True)


def test_principal_is_immutable():
    p = Principal(tenant_id="t1", user_id="u1", role="admin")
    with pytest.raises(ValidationError):
        p.tenant_id = "t2"
