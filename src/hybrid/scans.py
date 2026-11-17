import hashlib
import json
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

from .adapters.aegis_adapter import load_graph
from .scan_cli import render_report, scan

MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot_id: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_snapshot(body: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "snapshot.json"
        p.write_text(body)
        g = load_graph(p)
        if not any(n.type == "iam_role" for n in g.nodes.values()):
            raise ValueError("snapshot has no IAM roles")


def register_scan_routes(app, store, current_tenant):
    @app.post("/snapshots", status_code=201)
    async def upload_snapshot(request: Request, tenant: str = Depends(current_tenant)):
        raw = await request.body()
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise HTTPException(413, "snapshot too large")
        try:
            body = raw.decode()
            json.loads(body)
            _validate_snapshot(body)
        except Exception:
            raise HTTPException(422, "invalid snapshot")
        sid = "s-" + secrets.token_hex(6)
        sha = hashlib.sha256(raw).hexdigest()
        with store._lock:
            store._db.execute(
                "INSERT INTO snapshots VALUES (?, ?, ?, ?, ?)",
                (tenant, sid, sha, _now(), body),
            )
            store._db.commit()
        return {"id": sid, "sha256": sha}

    @app.post("/scans", status_code=201)
    def run_scan(payload: ScanIn, tenant: str = Depends(current_tenant)):
        with store._lock:
            row = store._db.execute(
                "SELECT body FROM snapshots WHERE tenant_id = ? AND id = ?",
                (tenant, payload.snapshot_id),
            ).fetchone()
        if not row:
            raise HTTPException(404, "snapshot not found")
        reqs = store.list_requirements(tenant)
        if not reqs:
            raise HTTPException(409, "no approved requirements")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "snapshot.json"
            path.write_text(row[0])
            results = scan(reqs, path)
            md = render_report(results, path).replace(
                str(path), f"snapshot:{payload.snapshot_id}"
            )
        findings = [f.model_dump(mode="json") for _, fs, _ in results for f in fs]
        report_json = json.dumps(
            {"snapshot_id": payload.snapshot_id, "findings": findings}
        )
        scan_id = "sc-" + secrets.token_hex(6)
        with store._lock:
            store._db.execute(
                "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",
                (tenant, scan_id, payload.snapshot_id, _now(), md, report_json),
            )
            store._db.commit()
        return {"id": scan_id, "findings": len(findings)}

    @app.get("/scans/{scan_id}/report")
    def get_report(scan_id: str, format: str = "md", tenant: str = Depends(current_tenant)):
        with store._lock:
            row = store._db.execute(
                "SELECT report_md, report_json FROM scans WHERE tenant_id = ? AND id = ?",
                (tenant, scan_id),
            ).fetchone()
        if not row:
            raise HTTPException(404, "scan not found")
        if format == "json":
            return json.loads(row[1])
        return PlainTextResponse(row[0], media_type="text/markdown")
