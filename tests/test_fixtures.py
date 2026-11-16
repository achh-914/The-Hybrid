import json
from pathlib import Path

BASE = Path(__file__).parent.parent / "fixtures" / "scenario-01"


def load(name):
    return json.loads((BASE / name).read_text())


def test_fixture_files_exist_and_parse():
    iam = load("iam_export.json")
    expected = load("expected.json")
    assert (BASE / "contract.md").read_text().strip()
    assert iam["roles"] and iam["policies"] and iam["buckets"]
    assert expected["findings"]


def test_expected_references_exist_in_export():
    iam = load("iam_export.json")
    expected = load("expected.json")
    roles = {r["arn"] for r in iam["roles"]}
    buckets = {b["arn"] for b in iam["buckets"]}
    for p in expected["requirement"]["allowed_principals"]:
        assert p in roles
    for f in expected["findings"]:
        assert f["identity_arn"] in roles
        assert f["resource_arn"] in buckets
