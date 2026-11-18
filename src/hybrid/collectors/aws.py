"""Read-only AWS collector.

Assumes a customer-created role (cross-account, with ExternalId) and
collects IAM + S3 configuration metadata. It never reads object data:
the role has no s3:GetObject permission, and only get_/list_ calls are
made here (enforced by a test).
"""

import json
from datetime import datetime, timezone
from typing import Any, Callable

# S3 error codes that just mean "this setting is not configured".
_S3_NOT_CONFIGURED = {
    "NoSuchBucketPolicy",
    "NoSuchPublicAccessBlockConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
}


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


def _jsonable(data: Any) -> Any:
    """Round-trip through JSON so datetimes etc. become plain strings."""
    return json.loads(json.dumps(data, default=str))


def collect_iam(iam: Any) -> dict:
    """Merge all pages of get_account_authorization_details."""
    merged: dict[str, list] = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate():
        for key in merged:
            merged[key].extend(page.get(key, []))
    return _jsonable(merged)


def _optional(call: Callable[[], dict], key: str) -> Any:
    """Run a read call; return None if the setting is simply not configured."""
    try:
        return call().get(key)
    except Exception as exc:
        if _error_code(exc) in _S3_NOT_CONFIGURED:
            return None
        raise


def collect_s3(s3: Any) -> list[dict]:
    buckets = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        policy_raw = _optional(lambda: s3.get_bucket_policy(Bucket=name), "Policy")
        buckets.append(
            {
                "Name": name,
                "Policy": json.loads(policy_raw) if policy_raw else None,
                "PublicAccessBlock": _optional(
                    lambda: s3.get_public_access_block(Bucket=name),
                    "PublicAccessBlockConfiguration",
                ),
                "Encryption": _optional(
                    lambda: s3.get_bucket_encryption(Bucket=name),
                    "ServerSideEncryptionConfiguration",
                ),
                "Acl": s3.get_bucket_acl(Bucket=name).get("Grants", []),
            }
        )
    return _jsonable(buckets)


def _boto_session_from_role(role_arn: str, external_id: str):
    import boto3  # imported lazily so tests run without boto3

    creds = boto3.client("sts").assume_role(
        RoleArn=role_arn,
        RoleSessionName="hybrid-collector",
        ExternalId=external_id,
        DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def collect_snapshot(
    role_arn: str,
    external_id: str,
    session_factory: Callable[[str, str], Any] = _boto_session_from_role,
) -> dict:
    """Assume the customer role and return one JSON-safe snapshot."""
    session = session_factory(role_arn, external_id)
    return {
        "account_id": role_arn.split(":")[4],
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "iam": collect_iam(session.client("iam")),
        "s3": collect_s3(session.client("s3")),
    }
