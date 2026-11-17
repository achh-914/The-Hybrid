from pathlib import Path

import pytest

pytest.importorskip("aegis")

from hybrid.adapters.aegis_adapter import load_paths  # noqa: E402
from hybrid.graph_rules import target_of, unauthorized_access  # noqa: E402
from hybrid.models import Requirement, RequirementStatus  # noqa: E402

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"


def requirement():
    return Requirement(
        tenant_id="t1",
        id="r2",
        clause_id="c-002-4.2",
        data_class="customer_data",
        resource_selector="bucket:customer-data",
        allowed_principals=("role:admin-role",),
        status=RequirementStatus.APPROVED,
    )


def findings():
    req = requirement()
    return unauthorized_access(req, load_paths(SNAP, target_of(req)))


def test_app_role_reaches_bucket_through_admin_role():
    paths = {p.source: p for p in load_paths(SNAP, "s3:customer-data")}
    assert paths["role:app-role"].nodes == (
        "role:app-role", "role:admin-role", "s3:customer-data",
    )


def test_app_role_is_flagged_with_clause_and_path_evidence():
    by_path = {f.attack_path_id: f for f in findings()}
    f = by_path["path:role:app-role->s3:customer-data"]
    assert {e.kind.value for e in f.evidence} == {"clause", "graph_path"}


def test_allowed_role_is_not_flagged():
    assert all(not f.attack_path_id.startswith("path:role:admin-role") for f in findings())
