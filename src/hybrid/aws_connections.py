"""Per-tenant AWS connection (role ARN) and scan rate limiting.

Plain SQLite on the Store's connection, like the snapshot and scan queries.
Every query is scoped by tenant_id. No FastAPI imports, so it is easy to test.
"""

import time
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS aws_connections (
    tenant_id TEXT PRIMARY KEY,
    role_arn TEXT NOT NULL,
    account_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_scan_at REAL);
"""


class AwsConnections:
    def __init__(self, store) -> None:
        self._store = store
        with store._lock:
            store._db.executescript(SCHEMA)
            store._db.commit()

    def get(self, tenant_id: str) -> dict | None:
        with self._store._lock:
            row = self._store._db.execute(
                "SELECT role_arn, account_id, created_at, last_scan_at "
                "FROM aws_connections WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
        if row is None:
            return None
        last = (
            datetime.fromtimestamp(row[3], timezone.utc).isoformat()
            if row[3] is not None
            else None
        )
        return {
            "role_arn": row[0],
            "account_id": row[1],
            "created_at": row[2],
            "last_scan_at": last,
        }

    def upsert(self, tenant_id: str, role_arn: str, account_id: str) -> None:
        """Register or replace the role. last_scan_at is kept on purpose."""
        now = datetime.now(timezone.utc).isoformat()
        with self._store._lock:
            self._store._db.execute(
                "INSERT INTO aws_connections (tenant_id, role_arn, account_id, created_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET "
                "role_arn = excluded.role_arn, account_id = excluded.account_id",
                (tenant_id, role_arn, account_id, now),
            )
            self._store._db.commit()

    def delete(self, tenant_id: str) -> bool:
        with self._store._lock:
            cur = self._store._db.execute(
                "DELETE FROM aws_connections WHERE tenant_id = ?", (tenant_id,)
            )
            self._store._db.commit()
        return cur.rowcount > 0

    def claim_scan_slot(
        self, tenant_id: str, min_interval: float, now: float | None = None
    ) -> float:
        """Atomically reserve the right to scan.

        Returns 0.0 if the slot was claimed, otherwise the seconds to wait.
        Claimed before calling AWS, so failing attempts count too.
        """
        now = time.time() if now is None else now
        with self._store._lock:
            cur = self._store._db.execute(
                "UPDATE aws_connections SET last_scan_at = ? "
                "WHERE tenant_id = ? AND (last_scan_at IS NULL OR last_scan_at <= ?)",
                (now, tenant_id, now - min_interval),
            )
            self._store._db.commit()
            if cur.rowcount == 1:
                return 0.0
            row = self._store._db.execute(
                "SELECT last_scan_at FROM aws_connections WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
        if row is None or row[0] is None:
            return 0.0
        return max(0.0, row[0] + min_interval - now)
