import pytest

from hybrid.aws_connect import (
    InvalidRoleArn,
    connection_info,
    external_id_for,
    parse_role_arn,
)

SECRET = "s" * 40


def test_external_id_is_stable_per_tenant():
    assert external_id_for("t-1", SECRET) == external_id_for("t-1", SECRET)


def test_external_id_differs_between_tenants_and_secrets():
    assert external_id_for("t-1", SECRET) != external_id_for("t-2", SECRET)
    assert external_id_for("t-1", SECRET) != external_id_for("t-1", "x" * 40)


def test_external_id_meets_the_template_minimum_length():
    assert len(external_id_for("t-1", SECRET)) >= 16


def test_short_secret_is_refused():
    with pytest.raises(ValueError):
        external_id_for("t-1", "short")


def test_valid_role_arns_return_the_account_id():
    assert parse_role_arn("arn:aws:iam::123456789012:role/HybridReadOnlyRole") == "123456789012"
    assert parse_role_arn("arn:aws:iam::123456789012:role/path/to/Role") == "123456789012"
    assert parse_role_arn("arn:aws-us-gov:iam::123456789012:role/R") == "123456789012"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-an-arn",
        "arn:aws:iam::12345:role/R",
        "arn:aws:iam::123456789012:user/U",
        "arn:aws:iam::123456789012:role/",
        "arn:aws:iam::123456789012:role/R\n",
        "arn:aws:s3:::bucket",
        "arn:aws:iam::123456789012:role/R; rm -rf",
    ],
)
def test_invalid_role_arns_are_rejected(bad):
    with pytest.raises(InvalidRoleArn):
        parse_role_arn(bad)


def test_connection_info_has_what_the_customer_needs():
    info = connection_info("t-1", SECRET, "111122223333")
    assert info["hybrid_account_id"] == "111122223333"
    assert info["external_id"] == external_id_for("t-1", SECRET)


def test_connection_info_rejects_a_bad_hybrid_account_id():
    with pytest.raises(ValueError):
        connection_info("t-1", SECRET, "not-an-account")
