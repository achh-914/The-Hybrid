from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import Field, field_validator

from .models import Frozen, Requirement, RequirementStatus, TenantScoped


class RequirementProposal(TenantScoped):
    """What M1 extracts. Wording is the contract's, not technical IDs."""

    id: str
    clause_id: str
    clause_number: str
    clause_text: str
    page: int = Field(ge=1)
    data_class: str
    resource_hint: str
    principals_hint: tuple[str, ...]


class Approval(Frozen):
    """The human binds the proposal to technical identifiers."""

    reviewer: str = Field(min_length=1)
    resource_selector: str
    allowed_principals: tuple[str, ...] = Field(min_length=1)

    @field_validator("resource_selector")
    @classmethod
    def _selector(cls, v):
        if not v.startswith("bucket:") or len(v) <= len("bucket:"):
            raise ValueError("resource_selector must look like bucket:<name>")
        return v

    @field_validator("allowed_principals")
    @classmethod
    def _principals(cls, v):
        if not all(p.startswith("role:") and len(p) > len("role:") for p in v):
            raise ValueError("allowed_principals must look like role:<name>")
        return v


class AuditEntry(TenantScoped):
    id: str
    action: str
    subject_id: str
    actor: str
    timestamp: str
    details: dict = Field(default_factory=dict)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def approve(proposal: RequirementProposal, approval: Approval) -> tuple[Requirement, AuditEntry]:
    requirement = Requirement(
        tenant_id=proposal.tenant_id,
        id=f"req-{proposal.clause_id}",
        clause_id=proposal.clause_id,
        data_class=proposal.data_class,
        resource_selector=approval.resource_selector,
        allowed_principals=approval.allowed_principals,
        status=RequirementStatus.APPROVED,
    )
    entry = AuditEntry(
        tenant_id=proposal.tenant_id,
        id=f"a-{proposal.id}-approved",
        action="requirement.approved",
        subject_id=requirement.id,
        actor=approval.reviewer,
        timestamp=_now(),
        details={
            "clause": proposal.clause_number,
            "resource_hint": proposal.resource_hint,
            "principals_hint": list(proposal.principals_hint),
            "resource_selector": approval.resource_selector,
            "allowed_principals": list(approval.allowed_principals),
        },
    )
    return requirement, entry


def reject(proposal: RequirementProposal, reviewer: str, reason: str) -> AuditEntry:
    return AuditEntry(
        tenant_id=proposal.tenant_id,
        id=f"a-{proposal.id}-rejected",
        action="requirement.rejected",
        subject_id=proposal.id,
        actor=reviewer,
        timestamp=_now(),
        details={"clause": proposal.clause_number, "reason": reason},
    )


def append_audit(path: Path, entry: AuditEntry) -> None:
    """Append-only JSONL audit trail."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(entry.model_dump_json() + "\n")
