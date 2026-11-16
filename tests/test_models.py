import pytest
from pydantic import ValidationError

from hybrid.models import Evidence, EvidenceKind, Finding, Severity


def ev(kind, tenant="t1"):
    return Evidence(tenant_id=tenant, id=f"e-{kind}", kind=kind, ref="x", hash="h")


def finding(evidence, tenant="t1"):
    return Finding(
        tenant_id=tenant, id="f1", rule_id="EXCESS_ACCESS", severity=Severity.HIGH,
        requirement_id="r1", attack_path_id="p1", evidence=tuple(evidence),
    )


def test_valid_finding():
    finding([ev(EvidenceKind.CLAUSE), ev(EvidenceKind.POLICY)])


def test_finding_without_clause_evidence_is_rejected():
    with pytest.raises(ValidationError):
        finding([ev(EvidenceKind.POLICY)])


def test_finding_without_technical_evidence_is_rejected():
    with pytest.raises(ValidationError):
        finding([ev(EvidenceKind.CLAUSE)])


def test_cross_tenant_evidence_is_rejected():
    with pytest.raises(ValidationError):
        finding([ev(EvidenceKind.CLAUSE), ev(EvidenceKind.POLICY, tenant="t2")])
