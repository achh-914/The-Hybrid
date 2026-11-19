from pathlib import Path

import pytest

pytest.importorskip("aegis")

from hybrid.adapters.aegis_adapter import TargetNotFound  # noqa: E402
from hybrid.models import Requirement, RequirementStatus  # noqa: E402
from hybrid.scan_cli import scan  # noqa: E402

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"


def test_bucket_unknown_to_the_snapshot_fails_closed_with_a_clear_error():
    req = Requirement(
        tenant_id="t1", id="r", clause_id="c", data_class="x",
        resource_selector="bucket:no-such-bucket",
        allowed_principals=("role:admin-role",),
        status=RequirementStatus.APPROVED,
    )
    with pytest.raises(TargetNotFound) as e:
        scan([req], SNAP)
    assert "no-such-bucket" in str(e.value)
