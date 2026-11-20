from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import threading

from .auth import Principal, Role
from .models import Requirement
from .requirements import AuditEntry, RequirementProposal

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
    user_id TEXT NOT NULL, role TEXT NOT NULL);
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

_USER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")


def _hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


class Store:
    """SQLite store. Every read and write is scoped by tenant_id."""

    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._migrate_api_keys()
            self._db.commit()

    def _migrate_api_keys(self) -> None:
        """Databases created before roles existed: their keys were all-powerful,
        so they keep working as admin. New keys always get an explicit role."""
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(api_keys)")}
        if "user_id" not in cols:
            self._db.execute(
                "ALTER TABLE api_keys ADD COLUMN user_id TEXT NOT NULL DEFAULT 'admin'"
            )
        if "role" not in cols:
            self._db.execute(
                "ALTER TABLE api_keys ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'"
            )
        if "revoked_at" not in cols:
            self._db.execute("ALTER TABLE api_keys ADD COLUMN revoked_at TEXT")

    def create_tenant(self, name: str) -> tuple[str, str]:
        """Create a tenant and its first key, which is an admin key."""
        tenant_id = "t-" + secrets.token_hex(6)
        api_key = "hyb_" + secrets.token_urlsafe(32)
        with self._lock:
            self._db.execute("INSERT INTO tenants VALUES (?, ?)", (tenant_id, name))
            self._db.execute(
                "INSERT INTO api_keys (key_hash, tenant_id, user_id, role) VALUES (?, ?, ?, ?)",
                (_hash(api_key), tenant_id, "admin", Role.ADMIN.value),
            )
            self._db.commit()
        return tenant_id, api_key

    def create_key(self, tenant_id: str, user_id: str, role: Role | str) -> str:
        """Create an API key for a user of an existing tenant. Shown once, stored hashed."""
        role = Role(role)
        if not _USER_ID.fullmatch(user_id):
            raise ValueError("invalid user_id")
        api_key = "hyb_" + secrets.token_urlsafe(32)
        with self._lock:
            exists = self._db.execute(
                "SELECT 1 FROM tenants WHERE id = ?", (tenant_id,)
            ).fetchone()
            if exists is None:
                raise ValueError("unknown tenant")
            self._db.execute(
                "INSERT INTO api_keys (key_hash, tenant_id, user_id, role) VALUES (?, ?, ?, ?)",
                (_hash(api_key), tenant_id, user_id, role.value),
            )
            self._db.commit()
        return api_key

    def revoke_key(self, tenant_id: str, user_id: str) -> int:
        """Revoke every active key of a user inside one tenant (soft delete).

        Returns how many keys were revoked (0 if there was nothing to revoke).
        Refuses to remove the last active admin key of a tenant, so a tenant
        can never lock itself out: create the new admin first, then revoke."""
        with self._lock:
            targets = self._db.execute(
                "SELECT role FROM api_keys "
                "WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL",
                (tenant_id, user_id),
            ).fetchall()
            if not targets:
                return 0
            if any(row[0] == Role.ADMIN.value for row in targets):
                other_admins = self._db.execute(
                    "SELECT COUNT(*) FROM api_keys "
                    "WHERE tenant_id = ? AND role = ? AND user_id != ? "
                    "AND revoked_at IS NULL",
                    (tenant_id, Role.ADMIN.value, user_id),
                ).fetchone()[0]
                if other_admins == 0:
                    raise ValueError("cannot revoke the last active admin key of a tenant")
            cur = self._db.execute(
                "UPDATE api_keys SET revoked_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
                "WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL",
                (tenant_id, user_id),
            )
            self._db.commit()
            return cur.rowcount

    def principal_for_key(self, api_key: str) -> Principal | None:
        with self._lock:
            row = self._db.execute(
                "SELECT tenant_id, user_id, role FROM api_keys "
                "WHERE key_hash = ? AND revoked_at IS NULL",
                (_hash(api_key),),
            ).fetchone()
        if row is None:
            return None
        try:
            return Principal(tenant_id=row[0], user_id=row[1], role=Role(row[2]))
        except ValueError:
            return None  # unknown role in the database: fail closed

    def tenant_for_key(self, api_key: str) -> str | None:
        principal = self.principal_for_key(api_key)
        return principal.tenant_id if principal else None

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

    def add_audit(self, tenant_id: str, entry: AuditEntry) -> None:
        """Append one audit entry on its own (for actions that are not a decision)."""
        if entry.tenant_id != tenant_id:
            raise ValueError("audit entry belongs to another tenant")
        with self._lock:
            self._db.execute(
                "INSERT INTO audit (tenant_id, data) VALUES (?, ?)",
                (tenant_id, entry.model_dump_json()),
            )
            self._db.commit()

    def list_audit(self, tenant_id: str) -> list[AuditEntry]:
        with self._lock:
            rows = self._db.execute(
                "SELECT data FROM audit WHERE tenant_id = ? ORDER BY seq", (tenant_id,)
            ).fetchall()
        return [AuditEntry.model_validate_json(r[0]) for r in rows]
