from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TenantScoped(Frozen):
    tenant_id: str = Field(min_length=1)


class RequirementStatus(StrEnum):
    EXTRACTED = "extracted"
    APPROVED = "approved"
    REJECTED = "rejected"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceKind(StrEnum):
    CLAUSE = "clause"
    POLICY = "policy"
    GRAPH_PATH = "graph_path"


class Decision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_INFO = "needs_info"


class Clause(TenantScoped):
    id: str
    contract_id: str
    number: str
    text: str
    page: int | None = None


class Requirement(TenantScoped):
    id: str
    clause_id: str
    data_class: str
    resource_selector: str
    allowed_principals: tuple[str, ...]
    status: RequirementStatus = RequirementStatus.EXTRACTED


class AttackPath(TenantScoped):
    id: str
    identity_arn: str
    resource_arn: str
    hops: tuple[str, ...]


class Evidence(TenantScoped):
    id: str
    kind: EvidenceKind
    ref: str
    hash: str


class Finding(TenantScoped):
    id: str
    rule_id: str
    severity: Severity
    requirement_id: str
    attack_path_id: str
    evidence: tuple[Evidence, ...]

    @model_validator(mode="after")
    def evidence_is_complete(self):
        kinds = {e.kind for e in self.evidence}
        if EvidenceKind.CLAUSE not in kinds:
            raise ValueError("finding needs clause evidence")
        if not kinds & {EvidenceKind.POLICY, EvidenceKind.GRAPH_PATH}:
            raise ValueError("finding needs policy or graph_path evidence")
        if any(e.tenant_id != self.tenant_id for e in self.evidence):
            raise ValueError("evidence belongs to another tenant")
        return self


class Review(TenantScoped):
    id: str
    finding_id: str
    reviewer: str
    decision: Decision
    timestamp: str
