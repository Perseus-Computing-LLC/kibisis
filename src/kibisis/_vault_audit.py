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


class ChainVerifier:
    """Streaming verifier of a journal: feed the rows in order, then :meth:`finish` with the head.

    Mirrors ``kibisis::journal::verify_chain`` in the crate. Rows must be numbered ``1..=n``, each must
    link to the hash before it and hash to its own ``event_hash`` under the layout its ``format`` names.
    A row whose format is below ``format_floor`` is refused: once a vault is keyed its floor is pinned
    in ``vault_meta`` (under the meta MAC), so a row cannot be rewritten under the keyless legacy
    layout. With ``head_required`` (every keyed vault whose journal has ever held a row) a signed head
    is needed even when no rows are left, so removing the whole journal is detected; otherwise a head
    is needed once any format 3 row exists, as before the floor was recorded. The head's MAC must verify
    under ``signing_key`` and it must name the last row. ``error`` says what failed.
    """

    def __init__(self, signing_key: bytes, *, format_floor: int = 1, head_required: bool = False) -> None:
        self._signing_key = bytes(signing_key)
        self.format_floor = int(format_floor)
        self.head_required = bool(head_required)
        self.expected_prev = "0" * 64
        self.count = 0
        self.last_sequence: Optional[int] = None
        self.anchored = False
        self.error: Optional[str] = None

    def feed(self, ev: AuditEvent) -> bool:
        """Check one row; False (with :attr:`error` set) at the first failure."""
        if self.error is not None:
            return False
        if ev.sequence != self.count + 1:
            self.error = f"row {self.count} has sequence {ev.sequence}, expected {self.count + 1}"
            return False
        if ev.format < self.format_floor:
            self.error = f"row {ev.sequence} is in journal format {ev.format}, below this vault's floor {self.format_floor}"
            return False
        if ev.format > JOURNAL_FORMAT:
            # The crate refuses an unknown format (UnsupportedFormat); so does this verifier, so the two
            # agree and a row cannot be relabelled upward (the hash would still be format 3's).
            self.error = f"row {ev.sequence} claims journal format {ev.format}, which this version does not know"
            return False
        if ev.prev_hash != self.expected_prev:
            self.error = f"row {ev.sequence} does not link to the row before it"
            return False
        recomputed = _event_hash(
            ev.sequence, ev.timestamp, ev.action, ev.category, ev.key, ev.scope, ev.value_sha256, ev.prev_hash,
            ev.author_id, ev.metadata, fmt=ev.format,
        )
        if not hmac.compare_digest(recomputed, ev.event_hash):
            self.error = f"row {ev.sequence} does not hash to its event_hash"
            return False
        self.expected_prev = ev.event_hash
        self.count += 1
        self.last_sequence = ev.sequence
        self.anchored = self.anchored or ev.format >= 3
        return True

    def finish(self, head: Optional[Dict[str, Any]]) -> bool:
        """Check the signed head (``{"sequence", "event_hash", "mac"}`` or None) against the rows fed."""
        if self.error is not None:
            return False
        if head is None:
            if self.head_required or self.anchored:
                self.error = "the journal has no signed head"
                return False
            return True
        if not hmac.compare_digest(_head_mac(self._signing_key, int(head["sequence"]), str(head["event_hash"])),
                                   str(head["mac"])):
            self.error = "the signed head does not verify under this vault's key"
            return False
        if self.last_sequence is None:
            self.error = "a signed head with no rows: the whole journal was removed"
            return False
        if int(head["sequence"]) != self.last_sequence or head["event_hash"] != self.expected_prev:
            self.error = f"the head is signed at sequence {head['sequence']} but the last row is {self.last_sequence}"
            return False
        return True


def verify_journal_rows(
    events: List[AuditEvent],
    head: Optional[Dict[str, Any]],
    signing_key: bytes,
    *,
    format_floor: int = JOURNAL_FORMAT,
    head_required: bool = False,
) -> Optional[str]:
    """Verify plain rows and a head as :meth:`SQLiteMemoryVault.verify_audit_chain` would; None when sound,
    else what failed. The same rows and head give the same verdict as ``kibisis_native.verify_chain``."""
    verifier = ChainVerifier(signing_key, format_floor=format_floor, head_required=head_required)
    for ev in events:
        if not verifier.feed(ev):
            break
    verifier.finish(head)
    return verifier.error


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
        cursor.execute("SELECT sequence, event_hash, format FROM audit_journal ORDER BY sequence DESC LIMIT 1")
        last_row = cursor.fetchone()
        # R7-4: continue only from a journal the signed head and the high-water mark vouch for. An
        # append that started over from an emptied table (sequence 1, prev 0*64) would re-sign the head
        # over the new one-row chain and launder the removal; refuse before anything is written.
        self._refuse_discontinued_journal(cursor, last_row)
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
        self._anchor_journal(cursor)
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
        """Sign the chain head, in the same transaction as the append it describes, and raise the
        vault's journal high-water mark to it (``vault_meta.journal_high_water``, under the meta MAC)
        so the journal can never again be continued from below this sequence (R7-4)."""
        cursor.execute(
            "INSERT OR REPLACE INTO audit_head (id, sequence, event_hash, mac) VALUES (1, ?, ?, ?)",
            (sequence, event_hash, _head_mac(self._signing_key, sequence, event_hash)),
        )
        self._raise_journal_high_water(cursor, sequence)

    def _raise_journal_high_water(self, cursor: Any, sequence: int) -> None:
        """Record ``sequence`` as the journal high-water mark when it is above the stored one, and
        re-sign the meta MAC over it. Only a keyed vault at integrity format 3 keeps the mark (a vault
        without a passphrase has no secret to sign it with; a vault still being upgraded gets it with
        the MAC the upgrade writes)."""
        if not self._keyed or self._integrity_format < 3:
            return
        stored = self._journal_high_water(trusted_only=False)
        if stored is not None and stored >= int(sequence):
            return
        self._set_meta(cursor, "journal_high_water", int(sequence))
        self._write_meta_mac(cursor)

    def _journal_high_water(self, *, trusted_only: bool = True) -> Optional[int]:
        """``vault_meta.journal_high_water`` of a keyed vault as an integer, or None when the vault is
        not keyed, holds no mark, or (with ``trusted_only``) the mark is not covered by the meta MAC
        (a legacy MAC never bound it, so it is unknown until the re-sign at the next writable open)."""
        if not self._keyed:
            return None
        if trusted_only and getattr(self, "_meta_mac_legacy", False):
            return None
        raw = self._meta("journal_high_water")
        if raw is None:
            return None
        try:
            value = int(bytes(raw).decode("ascii") if isinstance(raw, (bytes, bytearray, memoryview)) else raw)
        except (TypeError, ValueError):
            return None
        return value if value >= 0 else None

    def _refuse_discontinued_journal(self, cursor: Any, last_row: Any) -> None:
        """Raise :class:`~kibisis.vault.VaultIntegrityError` unless the journal's last row is the one the
        signed head names and no row below the high-water mark is missing; nothing is written.

        The same rules :class:`ChainVerifier` applies to the head, checked on the write path before
        an append (R7-4): a signed head with no rows, a head that names another row than the last
        one, a head that does not verify, or no head where one is required (a keyed vault whose
        journal has held a row, or a format 3 last row) means rows were removed or replaced under
        it, and an append would start a fresh chain over the hole and re-sign the head above it.
        The high-water mark (``vault_meta.journal_high_water``, under the meta MAC) catches the case
        where the head went with the rows, or an older head and journal were put back: the journal
        must reach at least that sequence.
        """
        from ._vault_crypto import VaultIntegrityError  # circular at import time

        head = cursor.execute("SELECT sequence, event_hash, mac FROM audit_head WHERE id = 1").fetchone()
        # The file's own record, read inside this transaction (not the in-process flag: a rolled-back
        # batch leaves that set while the file's journal is empty and unanchored, legitimately).
        anchored = bool(self._keyed and int(self._meta("journal_anchored") or 0))
        last_sequence = None if last_row is None else int(last_row["sequence"])
        if head is None:
            if last_row is None and anchored:
                raise VaultIntegrityError(
                    f"{self.db_path}: the audit journal has held rows but holds none and has no signed head: the "
                    "whole journal was removed; refusing to start a new chain over it"
                )
            if last_row is not None and (anchored or int(last_row["format"] or 1) >= JOURNAL_FORMAT):
                raise VaultIntegrityError(
                    f"{self.db_path}: the audit journal ends at sequence {last_sequence} but has no signed head; "
                    "refusing to append to a journal whose head was removed"
                )
        else:
            if not hmac.compare_digest(_head_mac(self._signing_key, int(head["sequence"]), str(head["event_hash"])),
                                       str(head["mac"])):
                raise VaultIntegrityError(
                    f"{self.db_path}: the audit journal's signed head does not verify under this vault's key; "
                    "refusing to append"
                )
            if last_row is None:
                raise VaultIntegrityError(
                    f"{self.db_path}: the audit journal's head is signed at sequence {head['sequence']} but the "
                    "journal holds no rows: the whole journal was removed; refusing to start a new chain over it"
                )
            if int(head["sequence"]) != last_sequence or str(head["event_hash"]) != str(last_row["event_hash"]):
                raise VaultIntegrityError(
                    f"{self.db_path}: the audit journal's head is signed at sequence {head['sequence']} but the last "
                    f"row is {last_sequence}: rows were removed or replaced under the head; refusing to append"
                )
        high_water = self._journal_high_water()
        if high_water is not None and (last_sequence is None or last_sequence < high_water):
            raise VaultIntegrityError(
                f"{self.db_path}: the audit journal ends at sequence {last_sequence or 0}, below the signed high-water "
                f"mark {high_water}: rows were removed; refusing to append"
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

        Rows are read in pages, so a journal of any size verifies. Each row is recomputed under the
        layout it was written with (``format``), as long as that format is not below the vault's
        journal format floor: a keyed vault pins the floor in ``vault_meta`` (under the meta MAC) when it
        is upgraded, at the lowest format its journal then held (3 for a vault that never had legacy
        rows), so a row cannot be rewritten under the keyless legacy layout and pass. A keyed vault
        whose journal has ever held a row (``journal_anchored``) must have a signed head that names the
        last row, even when no rows are left: cutting the tail, the head, or the whole journal fails.
        A vault without a passphrase keeps the older rule (a head is needed once a format 3 row exists).
        :attr:`last_chain_error` says what failed.
        """
        verifier = self._chain_verifier()
        after = 0
        page = 10_000
        while True:
            rows = self._conn.execute(
                "SELECT sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, event_hash, "
                "author_id, metadata_json, format FROM audit_journal WHERE sequence > ? ORDER BY sequence ASC LIMIT ?",
                (after, page),
            ).fetchall()
            for r in rows:
                try:
                    metadata = json.loads(r["metadata_json"])
                    if not isinstance(metadata, dict):
                        raise ValueError("metadata is not a JSON object")
                except (TypeError, ValueError) as exc:
                    # A row whose metadata is not JSON cannot be hashed; that is a failed verification,
                    # not an exception for the caller to sort out.
                    self.last_chain_error = f"row {r['sequence']} has unreadable metadata_json ({exc})"
                    return False
                ev = AuditEvent(
                    sequence=r["sequence"], timestamp=r["timestamp"], action=r["action"], category=r["category"],
                    key=r["key"], scope=r["scope"], value_sha256=r["value_sha256"], prev_hash=r["prev_hash"],
                    event_hash=r["event_hash"], author_id=r["author_id"], metadata=metadata,
                    format=r["format"],
                )
                if not verifier.feed(ev):
                    self.last_chain_error = verifier.error
                    return False
                after = ev.sequence
            if len(rows) < page:
                break
        head = self._conn.execute("SELECT sequence, event_hash, mac FROM audit_head WHERE id = 1").fetchone()
        ok = verifier.finish(None if head is None else dict(head))
        self.last_chain_error = verifier.error
        if ok:
            # R7-4: the journal must reach the high-water mark the meta MAC binds, so a journal and head
            # put back from before it, or emptied and restarted, fail even though they are self-consistent.
            high_water = self._journal_high_water()
            reached = verifier.last_sequence or 0
            if high_water is not None and reached < high_water:
                self.last_chain_error = (
                    f"the journal ends at sequence {reached}, below the signed high-water mark {high_water}: "
                    "rows were removed"
                )
                return False
        return ok

    def _chain_verifier(self) -> ChainVerifier:
        """A verifier set up with this vault's floor and anchoring (see :meth:`verify_audit_chain`).

        The floor and the anchoring flag are read whenever the vault is keyed (a ``kdf_salt`` is
        present and keys were derived from it), not only once it reports integrity format 3: a file
        whose ``integrity_format`` was edited down still pins its journal to the floor it recorded.
        """
        floor = 1
        anchored = False
        if self._keyed:
            floor = int(self._meta("journal_format_floor") or 1)
            anchored = getattr(self, "_journal_anchored", False) or bool(int(self._meta("journal_anchored") or 0))
        return ChainVerifier(self._signing_key, format_floor=floor, head_required=anchored)

    def _anchor_journal(self, cursor: Any) -> None:
        """Note in ``vault_meta`` (under the meta MAC) that this keyed vault's journal has held a row, so
        from now on verification demands a signed head. Called inside the appending transaction."""
        if not self._keyed or self._integrity_format < 3 or getattr(self, "_journal_anchored", False):
            return
        if not int(self._meta("journal_anchored") or 0):
            self._set_meta(cursor, "journal_anchored", 1)
            self._write_meta_mac(cursor)
        self._journal_anchored = True


# K-C: the format-3 path is the crate's; the Python wrappers only canonicalise metadata and keep the
# legacy (format 1/2) layout for rows written before format 3.
_event_hash.__wrapped_native__ = _native.event_hash_v3  # type: ignore[attr-defined]
_head_mac.__wrapped_native__ = _native.head_mac_v1  # type: ignore[attr-defined]
