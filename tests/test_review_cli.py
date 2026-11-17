import json

from hybrid.models import RequirementStatus
from hybrid.requirements import RequirementProposal
from hybrid.review_cli import review


def proposal():
    return RequirementProposal(
        tenant_id="t1", id="p1", clause_id="c-001-4.2", clause_number="4.2",
        clause_text="Customer data in S3 must be accessible only to DataOps.",
        page=1, data_class="customer_data",
        resource_hint="customer data in S3", principals_hint=("DataOps role",),
    )


def scripted(answers):
    it = iter(answers)
    return lambda prompt: next(it)


def test_approve_retries_invalid_input_then_logs(tmp_path):
    audit = tmp_path / "audit.jsonl"
    answers = ["a", "customer data", "role:DataOps", "bucket:customer-data", "role:DataOps"]
    (req,) = review([proposal()], "reviewer-1", audit, ask=scripted(answers), say=lambda m: None)
    assert req.status == RequirementStatus.APPROVED
    assert req.resource_selector == "bucket:customer-data"
    lines = audit.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["action"] == "requirement.approved"


def test_reject_logs_and_returns_nothing(tmp_path):
    audit = tmp_path / "audit.jsonl"
    out = review([proposal()], "reviewer-1", audit,
                 ask=scripted(["r", "not a security clause"]), say=lambda m: None)
    assert out == []
    assert json.loads(audit.read_text())["action"] == "requirement.rejected"


def test_skip_does_nothing(tmp_path):
    audit = tmp_path / "audit.jsonl"
    assert review([proposal()], "r", audit, ask=scripted(["s"]), say=lambda m: None) == []
    assert not audit.exists()
