import json
from pathlib import Path

import pytest

pytest.importorskip("aegis")

from hybrid.adapters.aegis_adapter import load_paths  # noqa: E402
from hybrid.scan_cli import main  # noqa: E402

SNAP = Path(__file__).parent.parent / "fixtures" / "scenario-02" / "iam_real.json"


def write_requirements(path, allowed):
    path.write_text(json.dumps([{
        "tenant_id": "t1",
        "id": "req-1",
        "clause_id": "c-4.2",
        "data_class": "customer_data",
        "resource_selector": "bucket:customer-data",
        "allowed_principals": allowed,
        "status": "approved",
    }]))


def test_scan_flags_unauthorized_paths_and_writes_report(tmp_path):
    req = tmp_path / "requirements.json"
    out = tmp_path / "report.md"
    write_requirements(req, ["role:DataOps"])
    code = main([str(req), "--snapshot", str(SNAP), "--out", str(out)])
    report = out.read_text()
    assert code == 1
    assert "role:app-role" in report
    assert "human approval required" in report


def test_scan_is_clean_when_every_source_is_allowed(tmp_path):
    sources = [p.source for p in load_paths(SNAP, "s3:customer-data")]
    req = tmp_path / "requirements.json"
    out = tmp_path / "report.md"
    write_requirements(req, sources)
    assert main([str(req), "--snapshot", str(SNAP), "--out", str(out)]) == 0
    assert "no unauthorized access path" in out.read_text()


def test_report_has_suggested_change_and_what_if(tmp_path):
    req = tmp_path / "requirements.json"
    out = tmp_path / "report.md"
    write_requirements(req, ["role:DataOps"])
    main([str(req), "--snapshot", str(SNAP), "--out", str(out)])
    report = out.read_text()
    assert "Suggested change:" in report
    assert "What-if:" in report
