import hashlib
import json
from fnmatch import fnmatchcase

from .models import Evidence, EvidenceKind, Finding, Requirement, Severity

S3_PROBES = ("s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject")
WILDCARD_ACTIONS = {"*", "s3:*"}


def _as_list(value):
    return [value] if isinstance(value, str) else list(value)


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def _matches_selector(bucket: dict, selector: str) -> bool:
    kind, _, rest = selector.partition(":")
    if kind != "tag":
        raise ValueError(f"unsupported selector: {selector}")
    key, _, value = rest.partition("=")
    return bucket.get("tags", {}).get(key) == value


def _s3_actions_granted(policy: dict, bucket_arn: str) -> list[str]:
    for st in policy["Statement"]:
        if st.get("Effect") != "Allow":
            continue
        resources = _as_list(st["Resource"])
        targets = (bucket_arn, bucket_arn + "/*")
        if not any(fnmatchcase(t, r) for t in targets for r in resources):
            continue
        hit = [
            a for a in _as_list(st["Action"])
            if any(fnmatchcase(p.lower(), a.lower()) for p in S3_PROBES)
        ]
        if hit:
            return hit
    return []


def excess_access(requirement: Requirement, iam: dict) -> list[Finding]:
    """Flag every identity outside allowed_principals that can reach a protected bucket."""
    findings = []
    allowed = set(requirement.allowed_principals)
    buckets = [b for b in iam["buckets"] if _matches_selector(b, requirement.resource_selector)]

    for role in iam["roles"]:
        if role["arn"] in allowed:
            continue
        for bucket in buckets:
            for policy_name in role["policies"]:
                policy = iam["policies"][policy_name]
                actions = _s3_actions_granted(policy, bucket["arn"])
                if not actions:
                    continue
                path_id = f"path:{role['arn']}->{bucket['arn']}"
                severity = Severity.HIGH if WILDCARD_ACTIONS & set(actions) else Severity.MEDIUM
                findings.append(
                    Finding(
                        tenant_id=requirement.tenant_id,
                        id=f"f-{_sha(path_id)}",
                        rule_id="EXCESS_ACCESS",
                        severity=severity,
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
                                id=f"e-policy-{policy_name}",
                                kind=EvidenceKind.POLICY,
                                ref=policy_name,
                                hash=_sha(policy),
                            ),
                        ),
                    )
                )
                break  # one finding per (role, bucket)
    return findings
