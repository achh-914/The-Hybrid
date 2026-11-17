from pathlib import Path

import pytest
from pydantic import ValidationError

from hybrid.models import Requirement, RequirementStatus
from hybrid.requirements import (
    Approval,
    RequirementProposal,
    append_audit,
    approve,
)

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"


def proposal():
    return RequirementProposal(
        tenant_id="t1", id="p1", clause_id="c-002-4.2", clause_number="4.2",
        clause_text="Customer data in S3 must be accessible only to the admin role.",
        page=3, data_class="customer_data",
        resource_hint="customer data stored in Amazon S3",
        principals_hint=("admin role",),
    )


def good_approval():
    return Approval(
        reviewer="reviewer-1",
        resource_selector="bucket:customer-data",
        allowed_principals=("role:admin-role",),
    )


def test_approve_binds_proposal_and_logs():
    req, entry = approve(proposal(), good_approval())
    assert req.status == RequirementStatus.APPROVED
    assert req.resource_selector == "bucket:customer-data"
    assert entry.action == "requirement.approved"
    assert entry.details["principals_hint"] == ["admin role"]


def test_approval_rejects_non_technical_ids():
    with pytest.raises(ValidationError):
        Approval(reviewer="r", resource_selector="customer data",
                 allowed_principals=("role:admin-role",))
    with pytest.raises(ValidationError):
        Approval(reviewer="r", resource_selector="bucket:customer-data",
                 allowed_principals=("admin role",))


def test_audit_trail_is_append_only(tmp_path):
    log = tmp_path / "audit.jsonl"
    _, entry = approve(proposal(), good_approval())
    append_audit(log, entry)
    append_audit(log, entry)
    assert len(log.read_text().splitlines()) == 2


def test_unapproved_requirement_cannot_be_checked():
    pytest.importorskip("aegis")
    from hybrid.graph_rules import unauthorized_access

    req = Requirement(
        tenant_id="t1", id="r", clause_id="c", data_class="x",
        resource_selector="bucket:customer-data",
        allowed_principals=("role:admin-role",),
    )
    with pytest.raises(ValueError):
        unauthorized_access(req, [])


def test_clause_to_finding_end_to_end():
    pytest.importorskip("aegis")
    from hybrid.adapters.aegis_adapter import load_paths
    from hybrid.graph_rules import target_of, unauthorized_access

    req, _ = approve(proposal(), good_approval())
    findings = unauthorized_access(req, load_paths(SNAP, target_of(req)))
    assert "path:role:app-role->s3:customer-data" in {f.attack_path_id for f in findings}
