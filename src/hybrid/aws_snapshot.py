from __future__ import annotations


class InvalidSnapshot(ValueError):
    pass


def to_aegis_input(snapshot: dict) -> dict:
    """AEGIS reads the IAM authorization details, so only that part is kept.

    S3 settings are not stored yet: nothing evaluates them, and customer data
    we do not use should not be kept.
    """
    iam = snapshot.get("iam") if isinstance(snapshot, dict) else None
    if not isinstance(iam, dict) or "RoleDetailList" not in iam:
        raise InvalidSnapshot("snapshot has no IAM authorization details")
    return iam
