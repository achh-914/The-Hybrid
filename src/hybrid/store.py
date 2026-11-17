from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading

from .models import Requirement
from .requirements import AuditEntry, RequirementProposal

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id));
CREATE TABLE IF NOT EXISTS proposals (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id));
CREATE TABLE IF NOT EXISTS requirements (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id));
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL, body TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id));
CREATE TABLE IF NOT EXISTS scans (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
    created_at TEXT NOT NULL, report_md TEXT NOT NULL, report_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id));
"""


def _hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


class Store:
    """SQLite store. Every read and write is scoped by tenant_id."""

    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    def create_tenant(self, name: str) -> tuple[str, str]:
        tenant_id = "t-" + secrets.token_hex(6)
        api_key = "hyb_" + secrets.token_urlsafe(32)
        with self._lock:
            self._db.execute("INSERT INTO tenants VALUES (?, ?)", (tenant_id, name))
            self._db.execute("INSERT INTO api_keys VALUES (?, ?)", (_hash(api_key), tenant_id))
            self._db.commit()
        return tenant_id, api_key

    def tenant_for_key(self, api_key: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT tenant_id FROM api_keys WHERE key_hash = ?", (_hash(api_key),)
            ).fetchone()
        return row[0] if row else None

    def add_proposals(self, tenant_id: str, proposals: list[RequirementProposal]) -> None:
        with self._lock:
            self._db.executemany(
                "INSERT OR IGNORE INTO proposals (tenant_id, id, status, data) "
                "VALUES (?, ?, 'pending', ?)",
                [(tenant_id, p.id, p.model_dump_json()) for p in proposals],
            )
            self._db.commit()

    def get_proposal(self, tenant_id: str, proposal_id: str):
        with self._lock:
            row = self._db.execute(
                "SELECT status, data FROM proposals WHERE tenant_id = ? AND id = ?",
                (tenant_id, proposal_id),
            ).fetchone()
        if row is None:
            return None
        return row[0], RequirementProposal.model_validate_json(row[1])

    def list_proposals(self, tenant_id: str):
        with self._lock:
            rows = self._db.execute(
                "SELECT status, data FROM proposals WHERE tenant_id = ? ORDER BY rowid",
                (tenant_id,),
            ).fetchall()
        return [(s, RequirementProposal.model_validate_json(d)) for s, d in rows]

    def decide(self, tenant_id, proposal_id, status, requirement: Requirement | None,
               entry: AuditEntry) -> bool:
        """Atomically move a pending proposal to a final status. False if already decided."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE proposals SET status = ? "
                "WHERE tenant_id = ? AND id = ? AND status = 'pending'",
                (status, tenant_id, proposal_id),
            )
            if cur.rowcount == 0:
                self._db.rollback()
                return False
            if requirement is not None:
                self._db.execute(
                    "INSERT INTO requirements (tenant_id, id, data) VALUES (?, ?, ?)",
                    (tenant_id, requirement.id, requirement.model_dump_json()),
                )
            self._db.execute(
                "INSERT INTO audit (tenant_id, data) VALUES (?, ?)",
                (tenant_id, entry.model_dump_json()),
            )
            self._db.commit()
        return True

    def list_requirements(self, tenant_id: str) -> list[Requirement]:
        with self._lock:
            rows = self._db.execute(
                "SELECT data FROM requirements WHERE tenant_id = ? ORDER BY rowid",
                (tenant_id,),
            ).fetchall()
        return [Requirement.model_validate_json(r[0]) for r in rows]

    def list_audit(self, tenant_id: str) -> list[AuditEntry]:
        with self._lock:
            rows = self._db.execute(
                "SELECT data FROM audit WHERE tenant_id = ? ORDER BY seq", (tenant_id,)
            ).fetchall()
        return [AuditEntry.model_validate_json(r[0]) for r in rows]
