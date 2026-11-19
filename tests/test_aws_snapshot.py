import json
from pathlib import Path

import pytest

from hybrid.aws_snapshot import InvalidSnapshot, to_aegis_input

FIXTURE = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"


def test_returns_the_iam_part_and_drops_s3_settings():
    snap = {
        "account_id": "123456789012",
        "collected_at": "x",
        "iam": {"RoleDetailList": [], "Policies": []},
        "s3": [{"Name": "b"}],
    }
    assert to_aegis_input(snap) == {"RoleDetailList": [], "Policies": []}


@pytest.mark.parametrize("bad", [None, [], {}, {"iam": None}, {"iam": []}, {"iam": {}}, {"s3": []}])
def test_rejects_snapshots_without_iam_details(bad):
    with pytest.raises(InvalidSnapshot):
        to_aegis_input(bad)


def test_converted_collector_snapshot_is_readable_by_aegis(tmp_path):
    pytest.importorskip("aegis")
    from hybrid.adapters.aegis_adapter import load_paths

    wrapped = {
        "account_id": "123456789012",
        "collected_at": "x",
        "iam": json.loads(FIXTURE.read_text()),
        "s3": [],
    }
    out = tmp_path / "snapshot.json"
    out.write_text(json.dumps(to_aegis_input(wrapped)))
    sources = {p.source for p in load_paths(out, "s3:customer-data")}
    assert "role:app-role" in sources
