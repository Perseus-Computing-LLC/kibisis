"""SQLite-based atomic concurrency lease coordinator with fencing tokens."""

from __future__ import annotations

from contextlib import contextmanager
import os
try:
    import sqlcipher3
except ImportError:
    import sqlite3 as sqlcipher3
import sqlite3
import threading
import time
from typing import Iterator, Optional
from .keys import resolve_passphrase
from .models import Lease
from .protocols import LeaseConflictError, LeaseCoordinator


class SQLiteLeaseCoordinator(LeaseCoordinator):
    """Atomic concurrency lease coordinator utilizing SQLite IMMEDIATE transactions and monotonic fencing tokens."""

    def __init__(self, db_path: str = ":memory:", passphrase: Optional[str] = None) -> None:
        self.db_path = db_path
        passphrase = resolve_passphrase(passphrase)
        self.passphrase = passphrase
        self._lock = threading.RLock()

        self._conn = sqlcipher3.connect(
            db_path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlcipher3.Row
        if passphrase:
            esc = passphrase.replace("'", "''")
            self._conn.execute("PRAGMA cipher_memory_security = ON;")
            self._conn.execute(f"PRAGMA key = '{esc}';")
            self._conn.execute("PRAGMA secure_delete = ON;")
        self._configure_db()
        self._init_schema()

    def _configure_db(self) -> None:
        self._conn.execute("PRAGMA busy_timeout = 30000")
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")

    @contextmanager
    def _immediate_tx(self) -> Iterator[sqlite3.Cursor]:
        """Execute an atomic BEGIN IMMEDIATE write transaction guarded by a re-entrant thread lock."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                yield cursor
                self._conn.execute("COMMIT")
            except BaseException:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def _init_schema(self) -> None:
        with self._immediate_tx() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS concurrency_leases (
                    resource TEXT PRIMARY KEY,
                    holder_id TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )

    def acquire(self, resource: str, holder_id: str, ttl_seconds: float) -> Lease:
        if not resource or not resource.strip():
            raise ValueError("resource must be a non-empty string")
        if not holder_id or not holder_id.strip():
            raise ValueError("holder_id must be a non-empty string")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        with self._immediate_tx() as cursor:
            now = time.time()
            new_expires_at = now + ttl_seconds
            cursor.execute(
                "SELECT holder_id, fencing_token, expires_at FROM concurrency_leases WHERE resource = ?",
                (resource,),
            )
            row = cursor.fetchone()

            if row is None:
                # Fresh resource lease
                fencing_token = 1
                cursor.execute(
                    """
                    INSERT INTO concurrency_leases (resource, holder_id, fencing_token, acquired_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (resource, holder_id, fencing_token, now, new_expires_at),
                )
            else:
                curr_holder = row["holder_id"]
                curr_fencing = int(row["fencing_token"])
                curr_expires = float(row["expires_at"])

                if curr_expires > now and curr_holder != holder_id:
                    raise LeaseConflictError(
                        f"Resource '{resource}' is already leased by '{curr_holder}' until {curr_expires}"
                    )

                fencing_token = curr_fencing + 1
                cursor.execute(
                    """
                    UPDATE concurrency_leases
                    SET holder_id = ?, fencing_token = ?, acquired_at = ?, expires_at = ?
                    WHERE resource = ? AND fencing_token = ?
                    """,
                    (holder_id, fencing_token, now, new_expires_at, resource, curr_fencing),
                )
                if cursor.rowcount != 1:
                    raise LeaseConflictError(
                        f"Concurrent fencing token update detected on resource '{resource}'"
                    )

        return Lease(
            resource=resource,
            holder_id=holder_id,
            fencing_token=fencing_token,
            acquired_at=now,
            expires_at=new_expires_at,
        )

    def renew(self, lease: Lease, ttl_seconds: float) -> bool:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        with self._immediate_tx() as cursor:
            now = time.time()
            new_expires_at = now + ttl_seconds
            cursor.execute(
                """
                UPDATE concurrency_leases
                SET expires_at = ?
                WHERE resource = ? AND holder_id = ? AND fencing_token = ? AND expires_at > ?
                """,
                (new_expires_at, lease.resource, lease.holder_id, lease.fencing_token, now),
            )
            return cursor.rowcount == 1

    def release(self, lease: Lease) -> bool:
        with self._immediate_tx() as cursor:
            cursor.execute(
                """
                UPDATE concurrency_leases
                SET expires_at = 0
                WHERE resource = ? AND holder_id = ? AND fencing_token = ? AND expires_at > 0
                """,
                (lease.resource, lease.holder_id, lease.fencing_token),
            )
            return cursor.rowcount == 1

    def validate_fencing_token(self, resource: str, holder_id: str, fencing_token: int) -> bool:
        """Return True iff ``holder_id`` currently holds an unexpired lease on ``resource`` with ``fencing_token``."""
        with self._lock:
            now = time.time()
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT 1 FROM concurrency_leases
                WHERE resource = ? AND holder_id = ? AND fencing_token = ? AND expires_at > ?
                """,
                (resource, holder_id, fencing_token, now),
            )
            return cursor.fetchone() is not None

    def get_lease(self, resource: str) -> Optional[Lease]:
        """Inspect the current lease record for ``resource`` (or None if never leased)."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT resource, holder_id, fencing_token, acquired_at, expires_at FROM concurrency_leases WHERE resource = ?",
                (resource,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return Lease(
                resource=row["resource"],
                holder_id=row["holder_id"],
                fencing_token=int(row["fencing_token"]),
                acquired_at=float(row["acquired_at"]),
                expires_at=float(row["expires_at"]),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
