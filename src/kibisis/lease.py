"""SQLite-based atomic concurrency lease coordinator with fencing tokens."""

from __future__ import annotations

import sqlite3
import time
from typing import Optional
from .models import Lease
from .protocols import LeaseConflictError, LeaseCoordinator


class SQLiteLeaseCoordinator(LeaseCoordinator):
    """Atomic concurrency lease coordinator utilizing SQLite transactions and monotonic fencing tokens."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
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
        now = time.time()
        new_expires_at = now + ttl_seconds

        with self._conn:
            cursor = self._conn.cursor()
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
                curr_fencing = row["fencing_token"]
                curr_expires = row["expires_at"]

                if curr_expires >= now and curr_holder != holder_id:
                    raise LeaseConflictError(
                        f"Resource '{resource}' is already leased by '{curr_holder}' until {curr_expires}"
                    )

                fencing_token = curr_fencing + 1
                cursor.execute(
                    """
                    UPDATE concurrency_leases
                    SET holder_id = ?, fencing_token = ?, acquired_at = ?, expires_at = ?
                    WHERE resource = ?
                    """,
                    (holder_id, fencing_token, now, new_expires_at, resource),
                )

        return Lease(
            resource=resource,
            holder_id=holder_id,
            fencing_token=fencing_token,
            acquired_at=now,
            expires_at=new_expires_at,
        )

    def renew(self, lease: Lease, ttl_seconds: float) -> bool:
        now = time.time()
        new_expires_at = now + ttl_seconds

        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                UPDATE concurrency_leases
                SET expires_at = ?
                WHERE resource = ? AND holder_id = ? AND fencing_token = ? AND expires_at >= ?
                """,
                (new_expires_at, lease.resource, lease.holder_id, lease.fencing_token, now),
            )
            return cursor.rowcount > 0

    def release(self, lease: Lease) -> bool:
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                UPDATE concurrency_leases
                SET expires_at = 0
                WHERE resource = ? AND holder_id = ? AND fencing_token = ?
                """,
                (lease.resource, lease.holder_id, lease.fencing_token),
            )
            return cursor.rowcount > 0

    def close(self) -> None:
        self._conn.close()
