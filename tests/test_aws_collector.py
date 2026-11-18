import json
from datetime import datetime, timezone

from hybrid.collectors.aws import collect_iam, collect_s3, collect_snapshot

ALLOWED_CALLS = {
    "get_account_authorization_details",
    "list_buckets",
    "get_bucket_policy",
    "get_bucket_acl",
    "get_public_access_block",
    "get_bucket_encryption",
}


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class Recorder:
    calls: list[str] = []


class FakeIam:
    class _Paginator:
        def paginate(self):
            Recorder.calls.append("get_account_authorization_details")
            yield {"RoleDetailList": [{"RoleName": "a", "CreateDate": datetime(2026, 1, 1, tzinfo=timezone.utc)}]}
            yield {"RoleDetailList": [{"RoleName": "b"}], "Policies": [{"PolicyName": "p"}]}

    def get_paginator(self, name):
        assert name == "get_account_authorization_details"
        return self._Paginator()


class FakeS3:
    def list_buckets(self):
        Recorder.calls.append("list_buckets")
        return {"Buckets": [{"Name": "customer-data"}, {"Name": "empty"}]}

    def get_bucket_policy(self, Bucket):
        Recorder.calls.append("get_bucket_policy")
        if Bucket == "empty":
            raise FakeClientError("NoSuchBucketPolicy")
        return {"Policy": json.dumps({"Statement": []})}

    def get_public_access_block(self, Bucket):
        Recorder.calls.append("get_public_access_block")
        if Bucket == "empty":
            raise FakeClientError("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}

    def get_bucket_encryption(self, Bucket):
        Recorder.calls.append("get_bucket_encryption")
        if Bucket == "empty":
            raise FakeClientError("ServerSideEncryptionConfigurationNotFoundError")
        return {"ServerSideEncryptionConfiguration": {"Rules": []}}

    def get_bucket_acl(self, Bucket):
        Recorder.calls.append("get_bucket_acl")
        return {"Grants": []}


class FakeSession:
    def client(self, name):
        return {"iam": FakeIam(), "s3": FakeS3()}[name]


def test_iam_pages_are_merged_and_json_safe():
    data = collect_iam(FakeIam())
    assert [r["RoleName"] for r in data["RoleDetailList"]] == ["a", "b"]
    assert data["Policies"] == [{"PolicyName": "p"}]
    json.dumps(data)  # datetimes were converted


def test_s3_unconfigured_settings_become_none():
    buckets = {b["Name"]: b for b in collect_s3(FakeS3())}
    assert buckets["customer-data"]["Policy"] == {"Statement": []}
    assert buckets["empty"]["Policy"] is None
    assert buckets["empty"]["PublicAccessBlock"] is None
    assert buckets["empty"]["Encryption"] is None


def test_unexpected_s3_error_is_not_swallowed():
    class Broken(FakeS3):
        def get_bucket_policy(self, Bucket):
            raise FakeClientError("AccessDenied")

    try:
        collect_s3(Broken())
    except FakeClientError as exc:
        assert exc.response["Error"]["Code"] == "AccessDenied"
    else:
        raise AssertionError("AccessDenied must propagate")


def test_snapshot_shape_and_account_id():
    snap = collect_snapshot(
        "arn:aws:iam::123456789012:role/HybridReadOnlyRole",
        "x" * 16,
        session_factory=lambda arn, ext: FakeSession(),
    )
    assert snap["account_id"] == "123456789012"
    assert set(snap) == {"account_id", "collected_at", "iam", "s3"}


def test_collector_only_makes_allowed_read_calls():
    Recorder.calls = []
    collect_snapshot(
        "arn:aws:iam::123456789012:role/HybridReadOnlyRole",
        "x" * 16,
        session_factory=lambda arn, ext: FakeSession(),
    )
    assert set(Recorder.calls) <= ALLOWED_CALLS
    assert all(c.startswith(("get_", "list_")) for c in Recorder.calls)
