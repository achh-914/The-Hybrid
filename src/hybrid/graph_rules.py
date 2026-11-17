import hashlib
import json

from .adapters.aegis_adapter import AccessPath
from .models import Evidence, EvidenceKind, Finding, Requirement, Severity


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def target_of(requirement: Requirement) -> str:
    kind, _, name = requirement.resource_selector.partition(":")
    if kind != "bucket":
        raise ValueError(f"unsupported selector: {requirement.resource_selector}")
    return f"s3:{name}"


def unauthorized_access(requirement: Requirement, paths: list[AccessPath]) -> list[Finding]:
    allowed = set(requirement.allowed_principals)
    findings = []
    for p in paths:
        if p.source in allowed:
            continue
        external = p.source == "internet" or p.source.startswith("account:")
        path_id = f"path:{p.source}->{p.target}"
        findings.append(
            Finding(
                tenant_id=requirement.tenant_id,
                id=f"f-{_sha(path_id)}",
                rule_id="UNAUTHORIZED_ACCESS_PATH",
                severity=Severity.CRITICAL if external else Severity.HIGH,
                requirement_id=requirement.id,
                attack_path_id=path_id,
                evidence=(
                    Evidence(
                        tenant_id=requirement.tenant_id,
                        id=f"e-clause-{requirement.clause_id}",
                        kind=EvidenceKind.CLAUSE,
                        ref=requirement.clause_id,
                        hash=_sha(requirement.model_dump(mode="json")),
                    ),
                    Evidence(
                        tenant_id=requirement.tenant_id,
                        id=f"e-path-{_sha(path_id)}",
                        kind=EvidenceKind.GRAPH_PATH,
                        ref=" -> ".join(p.nodes),
                        hash=_sha({"nodes": p.nodes, "reasons": p.reasons}),
                    ),
                ),
            )
        )
    return findings
