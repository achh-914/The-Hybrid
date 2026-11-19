from __future__ import annotations

import hashlib
import hmac
import re

_ROLE_ARN = re.compile(
    r"arn:aws(?:-us-gov|-cn)?:iam::(?P<account>[0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}"
)
MIN_SECRET_LENGTH = 32


class InvalidRoleArn(ValueError):
    pass


def parse_role_arn(arn: str) -> str:
    """Return the account ID of a valid IAM role ARN, or raise InvalidRoleArn."""
    match = _ROLE_ARN.fullmatch(arn)
    if match is None:
        raise InvalidRoleArn("not a valid IAM role ARN")
    return match["account"]


def external_id_for(tenant_id: str, secret: str) -> str:
    """ExternalId is derived by the server, never chosen by the customer.

    It is stable per tenant, so it needs no storage, and it cannot be guessed
    without the server secret.
    """
    if len(secret) < MIN_SECRET_LENGTH:
        raise ValueError(f"server secret must be at least {MIN_SECRET_LENGTH} characters")
    digest = hmac.new(
        secret.encode(), f"hybrid-external-id:{tenant_id}".encode(), hashlib.sha256
    ).hexdigest()
    return "hyb-" + digest[:40]


def connection_info(tenant_id: str, secret: str, hybrid_account_id: str) -> dict:
    if not re.fullmatch(r"[0-9]{12}", hybrid_account_id):
        raise ValueError("hybrid_account_id must be a 12-digit AWS account ID")
    return {
        "hybrid_account_id": hybrid_account_id,
        "external_id": external_id_for(tenant_id, secret),
        "template": "deploy/aws/hybrid-readonly-role.yaml",
        "role_name": "HybridReadOnlyRole",
    }
