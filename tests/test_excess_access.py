import json
from pathlib import Path

from hybrid.models import Requirement
from hybrid.rules import excess_access

BASE = Path(__file__).parent.parent / "fixtures" / "scenario-01"
iam = json.loads((BASE / "iam_export.json").read_text())
expected = json.loads((BASE / "expected.json").read_text())


def make_requirement(allowed=None):
    r = expected["requirement"]
    return Requirement(
        tenant_id="t1",
        id="r1",
        clause_id="c-001-4.2",
        data_class=r["data_class"],
        resource_selector=r["resource_selector"],
        allowed_principals=tuple(allowed if allowed is not None else r["allowed_principals"]),
    )


def test_scenario_01_matches_expected():
    findings = excess_access(make_requirement(), iam)
    got = {(f.rule_id, f.attack_path_id, f.severity.value) for f in findings}
    want = {
        (e["rule_id"], f"path:{e['identity_arn']}->{e['resource_arn']}", e["severity"])
        for e in expected["findings"]
    }
    assert got == want


def test_finding_carries_clause_and_policy_evidence():
    (finding,) = excess_access(make_requirement(), iam)
    kinds = {e.kind.value for e in finding.evidence}
    assert kinds == {"clause", "policy"}


def test_no_findings_when_devadmin_is_allowed():
    allowed = expected["requirement"]["allowed_principals"] + [
        "arn:aws:iam::111122223333:role/DevAdmin"
    ]
    assert excess_access(make_requirement(allowed), iam) == []
