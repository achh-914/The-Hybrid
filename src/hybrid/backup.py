"""Consistent, compressed backups of the SQLite database, with rotation.

    python -m hybrid.backup            # uses HYBRID_DB, HYBRID_BACKUP_DIR, HYBRID_BACKUP_KEEP_DAYS

Uses SQLite's online backup API, so it is safe while the server is running.
Backups contain customer data and are NOT encrypted by this script: keep them on an
encrypted disk or volume, never in the repository. Rotation deletes only files that
match the backup name pattern, and only after a new backup succeeded.
"""

import gzip
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

_NAME = re.compile(r"^hybrid-(\d{8}T\d{6}Z)\.db\.gz$")
_STAMP = "%Y%m%dT%H%M%SZ"


def backup(
    db_path: str | Path,
    dest_dir: str | Path,
    keep_days: int = 30,
    now: datetime | None = None,
) -> Path:
    if keep_days < 1:
        raise ValueError("keep_days must be at least 1")
    db_path = Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError(f"database not found: {db_path}")
    now = now or datetime.now(timezone.utc)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(dest, 0o700)

    final = dest / f"hybrid-{now.strftime(_STAMP)}.db.gz"
    with tempfile.TemporaryDirectory(dir=dest) as tmp:
        raw = Path(tmp) / "copy.db"
        src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            out = sqlite3.connect(raw)
            try:
                src.backup(out)
                if out.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("backup failed the integrity check")
            finally:
                out.close()
        finally:
            src.close()
        tmp_gz = Path(tmp) / "copy.db.gz"
        with raw.open("rb") as f_in, gzip.open(tmp_gz, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.chmod(tmp_gz, 0o600)
        os.replace(tmp_gz, final)

    cutoff = now - timedelta(days=keep_days)
    for f in dest.iterdir():
        m = _NAME.match(f.name)
        if m is None or f == final:
            continue
        taken = datetime.strptime(m.group(1), _STAMP).replace(tzinfo=timezone.utc)
        if taken < cutoff:
            f.unlink()
    return final


def main() -> int:
    try:
        keep = int(os.getenv("HYBRID_BACKUP_KEEP_DAYS", "30"))
        path = backup(
            os.getenv("HYBRID_DB", "hybrid.db"),
            os.getenv("HYBRID_BACKUP_DIR", "backups"),
            keep,
        )
    except (ValueError, FileNotFoundError, RuntimeError, sqlite3.Error) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"backup written: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
