import json
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from hybrid.collectors.aws import collect_snapshot  # noqa: E402

REGION = "us-east-1"
ROLE_ARN = "arn:aws:iam::123456789012:role/HybridReadOnlyRole"
TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}
S3_ALL = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": ["arn:aws:s3:::customer-data", "arn:aws:s3:::customer-data/*"],
    }],
}


def build_account():
    iam = boto3.client("iam", region_name=REGION)
    iam.create_role(RoleName="admin-role", AssumeRolePolicyDocument=json.dumps(TRUST))
    iam.put_role_policy(RoleName="admin-role", PolicyName="s3-all", PolicyDocument=json.dumps(S3_ALL))
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="customer-data")
    s3.create_bucket(Bucket="empty-bucket")


def collect():
    return collect_snapshot(
        ROLE_ARN, "x" * 16, session_factory=lambda arn, ext: boto3.Session(region_name=REGION)
    )


@moto.mock_aws
def test_collector_reads_roles_and_buckets_from_an_emulated_account():
    build_account()
    snap = collect()
    roles = {r["RoleName"] for r in snap["iam"]["RoleDetailList"]}
    buckets = {b["Name"] for b in snap["s3"]}
    assert "admin-role" in roles
    assert {"customer-data", "empty-bucket"} <= buckets
    json.dumps(snap)  # the snapshot must be JSON-safe


@moto.mock_aws
def test_unconfigured_bucket_settings_become_none_not_errors():
    build_account()
    snap = collect()
    empty = {b["Name"]: b for b in snap["s3"]}["empty-bucket"]
    assert empty["Policy"] is None


@moto.mock_aws
def test_collected_snapshot_is_understood_by_aegis(tmp_path):
    pytest.importorskip("aegis")
    from hybrid.adapters.aegis_adapter import load_paths
    from hybrid.aws_snapshot import to_aegis_input

    build_account()
    out = tmp_path / "snapshot.json"
    out.write_text(json.dumps(to_aegis_input(collect())))
    sources = {p.source for p in load_paths(out, "s3:customer-data")}
    assert "role:admin-role" in sources
