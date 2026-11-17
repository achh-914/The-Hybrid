from pathlib import Path

import pytest

pytest.importorskip("aegis")

from hybrid.adapters.aegis_adapter import load_paths  # noqa: E402
from hybrid.remediation import advise  # noqa: E402

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"


def paths():
    return {p.source: p for p in load_paths(SNAP, "s3:customer-data")}


def test_passrole_path_gets_a_passrole_fix_and_the_path_closes():
    advice = advise(SNAP, paths()["role:app-role"])
    assert "iam:PassRole" in advice.change
    assert "no path" in advice.after


def test_direct_access_path_gets_an_s3_fix():
    advice = advise(SNAP, paths()["role:admin-role"])
    assert "S3 permission" in advice.change
    assert "no path" in advice.after


def test_advice_does_not_change_later_results():
    advise(SNAP, paths()["role:app-role"])
    assert "role:app-role" in paths()
