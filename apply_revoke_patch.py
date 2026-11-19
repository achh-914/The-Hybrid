"""One-shot patch: adds API-key revocation to src/hybrid/store.py.

Run from the repo root:  python3 apply_revoke_patch.py
It keeps a backup (store.py.bak), checks every anchor exists exactly once,
and does nothing if the file is already patched. Delete this script after use.
"""
import sys
from pathlib import Path

PATH = Path("src/hybrid/store.py")
text = PATH.read_text(encoding="utf-8")

if "def revoke_key" in text:
    sys.exit("store.py already contains revoke_key: nothing to do.")

EDITS = []

# 1) migration: add the revoked_at column to old databases
EDITS.append((
    '''        if "role" not in cols:
            self._db.execute(
                "ALTER TABLE api_keys ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'"
            )
''',
    '''        if "role" not in cols:
            self._db.execute(
                "ALTER TABLE api_keys ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'"
            )
        if "revoked_at" not in cols:
            self._db.execute("ALTER TABLE api_keys ADD COLUMN revoked_at TEXT")
''',
))

# 2) revoked keys no longer authenticate
EDITS.append((
    '''                "SELECT tenant_id, user_id, role FROM api_keys WHERE key_hash = ?",
''',
    '''                "SELECT tenant_id, user_id, role FROM api_keys "
                "WHERE key_hash = ? AND revoked_at IS NULL",
''',
))

# 3) the revoke_key method, placed right before principal_for_key
EDITS.append((
    '''    def principal_for_key(self, api_key: str) -> Principal | None:
''',
    '''    def revoke_key(self, tenant_id: str, user_id: str) -> int:
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
''',
))

for i, (old, _) in enumerate(EDITS, 1):
    n = text.count(old)
    if n != 1:
        sys.exit(
            f"Anchor {i} found {n} times (expected 1). store.py was NOT changed. "
            "Send a photo of this error and of the code around it."
        )

Path(str(PATH) + ".bak").write_text(text, encoding="utf-8")
for old, new in EDITS:
    text = text.replace(old, new)
PATH.write_text(text, encoding="utf-8")
print("OK: store.py patched (backup: src/hybrid/store.py.bak).")
