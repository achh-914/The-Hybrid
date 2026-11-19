"""AWS connection and scan endpoints. Admin only.

GET    /aws/connection  what the customer needs to deploy the role (External ID...)
POST   /aws/connection  register the role ARN after validating it
DELETE /aws/connection  forget the role
POST   /aws/scan        assume the role, collect IAM, store a snapshot, run a scan

Server configuration (environment):
  HYBRID_SERVER_SECRET   at least 32 characters. External IDs are derived from it:
                         changing it breaks every customer's role trust policy.
  HYBRID_AWS_ACCOUNT_ID  the 12-digit AWS account THE HYBRID runs in.
"""

import hashlib
import json
import logging
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from .adapters.aegis_adapter import TargetNotFound
from .aws_connect import InvalidRoleArn, connection_info, parse_role_arn
from .aws_connections import AwsConnections
from .aws_snapshot import InvalidSnapshot, to_aegis_input
from .collectors.aws import collect_snapshot
from .scan_cli import render_report, scan
from .scans import MAX_SNAPSHOT_BYTES, _validate_snapshot

logger = logging.getLogger("hybrid.aws")

MIN_SCAN_INTERVAL_SECONDS = 60


class ConnectionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_arn: str = Field(min_length=20, max_length=2048)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _info(tenant_id: str) -> dict:
    try:
        return connection_info(
            tenant_id,
            os.getenv("HYBRID_SERVER_SECRET", ""),
            os.getenv("HYBRID_AWS_ACCOUNT_ID", ""),
        )
    except ValueError:
        raise HTTPException(503, "AWS connection is not configured on this server") from None


def _save_snapshot(store, tenant: str, body: str) -> str:
    snapshot_id = "s-" + secrets.token_hex(6)
    sha = hashlib.sha256(body.encode()).hexdigest()
    with store._lock:
        store._db.execute(
            "INSERT INTO snapshots VALUES (?, ?, ?, ?, ?)",
            (tenant, snapshot_id, sha, _now(), body),
        )
        store._db.commit()
    return snapshot_id


def _run_scan(store, tenant: str, reqs, snapshot_id: str, body: str) -> dict:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "snapshot.json"
        path.write_text(body)
        try:
            results = scan(reqs, path)
        except TargetNotFound as exc:
            raise HTTPException(422, str(exc)) from None
        md = render_report(results, path).replace(str(path), f"snapshot:{snapshot_id}")
    findings = [f.model_dump(mode="json") for _, fs, _ in results for f in fs]
    report_json = json.dumps({"snapshot_id": snapshot_id, "findings": findings})
    scan_id = "sc-" + secrets.token_hex(6)
    with store._lock:
        store._db.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",
            (tenant, scan_id, snapshot_id, _now(), md, report_json),
        )
        store._db.commit()
    return {"id": scan_id, "snapshot_id": snapshot_id, "findings": len(findings)}


def register_aws_routes(app, store, admin_tenant) -> None:
    connections = AwsConnections(store)

    @app.get("/aws/connection")
    def get_connection(tenant: str = Depends(admin_tenant)):
        info = _info(tenant)
        conn = connections.get(tenant)
        return {
            **info,
            "role_arn": conn["role_arn"] if conn else None,
            "account_id": conn["account_id"] if conn else None,
            "last_scan_at": conn["last_scan_at"] if conn else None,
        }

    @app.post("/aws/connection")
    def set_connection(body: ConnectionIn, tenant: str = Depends(admin_tenant)):
        try:
            account_id = parse_role_arn(body.role_arn)
        except InvalidRoleArn:
            raise HTTPException(422, "invalid role ARN") from None
        connections.upsert(tenant, body.role_arn, account_id)
        return {"role_arn": body.role_arn, "account_id": account_id}

    @app.delete("/aws/connection", status_code=204)
    def delete_connection(tenant: str = Depends(admin_tenant)):
        connections.delete(tenant)
        return Response(status_code=204)

    @app.post("/aws/scan", status_code=201)
    def aws_scan(request: Request, tenant: str = Depends(admin_tenant)):
        external_id = _info(tenant)["external_id"]
        conn = connections.get(tenant)
        if conn is None:
            raise HTTPException(409, "no AWS connection registered")
        reqs = store.list_requirements(tenant)
        if not reqs:
            raise HTTPException(409, "no approved requirements")

        wait = connections.claim_scan_slot(tenant, MIN_SCAN_INTERVAL_SECONDS)
        if wait > 0:
            raise HTTPException(
                429,
                "scan rate limit reached",
                headers={"Retry-After": str(int(wait) + 1)},
            )

        collector = getattr(request.app.state, "aws_collector", None) or collect_snapshot
        try:
            snapshot = collector(conn["role_arn"], external_id)
        except Exception as exc:
            # Never echo AWS details (ARNs, account IDs, error text) to the caller.
            logger.warning("AWS collection failed for %s: %s", tenant, type(exc).__name__)
            raise HTTPException(
                502,
                "could not read the AWS account: check the role ARN, "
                "the trust policy and the External ID",
            ) from None

        try:
            iam = to_aegis_input(snapshot)
        except InvalidSnapshot:
            raise HTTPException(502, "the AWS account returned no IAM roles to analyse") from None
        body = json.dumps(iam)
        if len(body.encode()) > MAX_SNAPSHOT_BYTES:
            raise HTTPException(502, "AWS snapshot too large")
        try:
            _validate_snapshot(body)
        except Exception:
            raise HTTPException(422, "invalid snapshot") from None

        snapshot_id = _save_snapshot(store, tenant, body)
        return _run_scan(store, tenant, reqs, snapshot_id, body)
