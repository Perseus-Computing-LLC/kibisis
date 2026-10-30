"""Audit journal of :class:`kibisis.vault.SQLiteMemoryVault`: the hash-chained event rows, the signed chain head,
their verification, and the mirror of state transitions to the Argus ledger.

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection and keys. Every name here is
also importable from ``kibisis.vault``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

from .models import AuditEvent

# The vault's logger: records keep the name callers filter on.
import kibisis_native as _native

logger = logging.getLogger("kibisis.vault")


#: Journal hash layout this version writes (``audit_journal.format``). Formats 1 and 2 hashed a
#: ``':'``-joined string of eight fields and left ``metadata_json`` out, so a ``':'`` inside a category
#: or key could alias another event and a rewritten reviewer or verdict passed verification. Format 3
#: hashes a canonical JSON array (unambiguous field boundaries) that includes a digest of the metadata,
#: and every append also signs the chain head into ``audit_head`` so a deleted tail is detected.
#: Rows written under an older format keep verifying under their own layout.
JOURNAL_FORMAT = 3


DEFAULT_ARGUS_LEDGER_PATH = "/opt/data/runtime/argus/audit.jsonl"


def _argus_ledger_path() -> Optional[str]:
    """Argus ledger that state transitions are mirrored to; ARGUS_LEDGER_PATH="" turns it off."""
    if "ARGUS_LEDGER_PATH" in os.environ:
        return os.environ["ARGUS_LEDGER_PATH"] or None
    return DEFAULT_ARGUS_LEDGER_PATH if os.path.exists(DEFAULT_ARGUS_LEDGER_PATH) else None


def _argus_append(event_type: str, actor: str, payload: Dict[str, Any]) -> None:
    """Append through the argus_ledger library only, so the hash chain stays valid. Never raises."""
    path = _argus_ledger_path()
    if not path:
        return
    try:
        from argus_ledger import AppendOnlyLedger  # optional dependency
        AppendOnlyLedger(path).append(event_type=event_type, actor=actor, payload=payload)
    except Exception as exc:  # pragma: no cover - best effort mirror
        logger.debug("argus mirror skipped (%s): %s", event_type, exc)


def _event_hash(
    sequence: int,
    timestamp: float,
    action: str,
    category: str,
    key: str,
    scope: str,
    value_sha256: str,
    prev_hash: str,
    author_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
    fmt: int = JOURNAL_FORMAT,
) -> str:
    """SHA-256 of one journal event, which links to the one before it through ``prev_hash``.

    ``fmt`` selects the layout the row was written under (see :data:`JOURNAL_FORMAT`). Formats below 3
    reproduce the legacy ``':'``-joined payload, metadata excluded, so older journals still verify.
    """
    if fmt < 3:
        payload = f"{sequence}:{timestamp:.6f}:{action}:{category}:{key}:{scope}:{value_sha256}:{prev_hash}:{author_id or ''}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    # Format 3 is hashed by the crate (one implementation for the Python vault and the Rust verifier).
    # The metadata goes in canonical form; the crate digests it so the payload stays bounded and
    # independent of how the stored JSON happens to be spaced.
    canonical = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _native.event_hash_v3(int(sequence), float(timestamp), action, category, key, scope, value_sha256,
                                 prev_hash, author_id or None, canonical)


def _head_mac(signing_key: bytes, sequence: int, event_hash: str) -> str:
    """HMAC over the chain head, so the last row cannot be removed or replaced without the signing key.

    Without a passphrase the signing key is not secret (it is derived from the path), so the head
    then catches accidental truncation only; with a passphrase it is derived from the passphrase.
    """
    return _native.head_mac_v1(bytes(signing_key), int(sequence), event_hash)


class AuditJournalMixin:
    """Appends, lists and verifies the vault's audit journal."""

    def _record_audit_event(
        self,
        cursor: sqlite3.Cursor,
        action: str,
        category: str,
        key: str,
        scope: str,
        value_sha256: str,
        author_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Append a tamper-evident audit record chaining from the previous event's hash."""
        now = time.time()
        meta_dict = metadata or {}

        # Read the head inside the caller's write transaction, never from a per-instance cache: other
        # processes append to the same journal, so a cached head goes stale and every later insert
        # reuses an existing sequence. BEGIN IMMEDIATE covers a caller that has not written yet.
        if not self._conn.in_transaction:
            cursor.execute("BEGIN IMMEDIATE")
        cursor.execute("SELECT sequence, event_hash FROM audit_journal ORDER BY sequence DESC LIMIT 1")
        last_row = cursor.fetchone()
        seq, prev_hash = (last_row["sequence"] + 1, last_row["event_hash"]) if last_row else (1, "0" * 64)

        event_hash = _event_hash(
            seq, now, action, category, key, scope, value_sha256, prev_hash, author_id, meta_dict, fmt=JOURNAL_FORMAT
        )
        meta_json = json.dumps(meta_dict, sort_keys=True)

        cursor.execute(
            """
            INSERT INTO audit_journal (
                sequence, timestamp, action, category, key, scope, value_sha256,
                prev_hash, event_hash, author_id, metadata_json, format
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (seq, now, action, category, key, scope, value_sha256, prev_hash, event_hash, author_id, meta_json,
             JOURNAL_FORMAT),
        )
        self._write_audit_head(cursor, seq, event_hash)
        return AuditEvent(
            sequence=seq,
            timestamp=now,
            action=action,
            category=category,
            key=key,
            scope=scope,
            value_sha256=value_sha256,
            prev_hash=prev_hash,
            event_hash=event_hash,
            author_id=author_id,
            metadata=meta_dict,
            format=JOURNAL_FORMAT,
        )

    def _write_audit_head(self, cursor: Any, sequence: int, event_hash: str) -> None:
        """Sign the chain head, in the same transaction as the append it describes."""
        cursor.execute(
            "INSERT OR REPLACE INTO audit_head (id, sequence, event_hash, mac) VALUES (1, ?, ?, ?)",
            (sequence, event_hash, _head_mac(self._signing_key, sequence, event_hash)),
        )

    def list_audit_events(
        self,
        scope: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100,
        key: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Fetch chronological audit records from the tamper-evident hash chain."""
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT sequence, timestamp, action, category, key, scope, value_sha256, "
            "prev_hash, event_hash, author_id, metadata_json, format FROM audit_journal WHERE 1=1"
        )
        params: List[Any] = []
        if scope:
            query_sql += " AND scope = ?"
            params.append(scope)
        if category:
            query_sql += " AND category = ?"
            params.append(category)
        if key:
            query_sql += " AND key = ?"
            params.append(key)
        query_sql += " ORDER BY sequence ASC LIMIT ?"
        params.append(limit)
        cursor.execute(query_sql, params)

        events: List[AuditEvent] = []
        for r in cursor.fetchall():
            events.append(
                AuditEvent(
                    sequence=r["sequence"],
                    timestamp=r["timestamp"],
                    action=r["action"],
                    category=r["category"],
                    key=r["key"],
                    scope=r["scope"],
                    value_sha256=r["value_sha256"],
                    prev_hash=r["prev_hash"],
                    event_hash=r["event_hash"],
                    author_id=r["author_id"],
                    metadata=json.loads(r["metadata_json"]),
                    format=r["format"],
                )
            )
        return events

    def verify_audit_chain(self, scope: Optional[str] = None) -> bool:
        """Verify the append-only mutation journal: every link, every row's hash, and the signed head.

        Each row is recomputed under the layout it was written with (``format``), so journals from
        older versions verify. Once the vault has written a format 3 row, ``audit_head`` must exist,
        carry a valid MAC and name the last row: deleting rows from the tail, or the head itself,
        then fails verification. A journal with only legacy rows and no head verifies on its links
        alone, as it did before the head existed.
        """
        # Always verify the entire hash chain (or records up to limit), because prev_hash links consecutive global events
        events = self.list_audit_events(scope=None, limit=1_000_000)

        expected_prev = "0" * 64
        for ev in events:
            if ev.prev_hash != expected_prev:
                return False
            recomputed = _event_hash(
                ev.sequence, ev.timestamp, ev.action, ev.category, ev.key, ev.scope, ev.value_sha256, ev.prev_hash,
                ev.author_id, ev.metadata, fmt=ev.format,
            )
            if not hmac.compare_digest(recomputed, ev.event_hash):
                return False
            expected_prev = ev.event_hash

        head = self._conn.execute("SELECT sequence, event_hash, mac FROM audit_head WHERE id = 1").fetchone()
        anchored = any(ev.format >= 3 for ev in events)
        if head is None:
            return not anchored
        if not hmac.compare_digest(_head_mac(self._signing_key, head["sequence"], head["event_hash"]), head["mac"]):
            return False
        if not events:
            return False  # a signed head with no rows: the whole journal was removed
        return head["sequence"] == events[-1].sequence and head["event_hash"] == events[-1].event_hash


# K-C: the format-3 path is the crate's; the Python wrappers only canonicalise metadata and keep the
# legacy (format 1/2) layout for rows written before format 3.
_event_hash.__wrapped_native__ = _native.event_hash_v3  # type: ignore[attr-defined]
_head_mac.__wrapped_native__ = _native.head_mac_v1  # type: ignore[attr-defined]
