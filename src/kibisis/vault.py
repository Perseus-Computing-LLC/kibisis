"""SQLite and FTS5 memory vault implementation for Kibisis with authenticated envelope encryption and hardened tombstones."""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import json
import logging
import os
try:
    import sqlcipher3
except ImportError:
    import sqlite3 as sqlcipher3
import sqlite3
import string
import threading
import time
from pathlib import Path
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple, Union
from .admission import AdmissionDecision, FactDisposition, MemoryAdmissionGate
from .crypto import AESGCMCryptoEnvelopeProvider, derive_vault_keys, verify_entry, verify_tenant_payload
from .keys import MIN_PASSPHRASE_LENGTH, resolve_passphrase
from .models import (  # noqa: F401  (the search models are re-exported)
    AuditEvent,
    EpistemicState,
    MemoryEntity,
    RecallResult,
    SearchHit,
    SearchResult,
    WithheldEntry,
)
from .protocols import CryptoEnvelopeProvider, EncryptionRequiredError, LeaseConflictError, LeaseCoordinator, MemoryVault
from ._vault_audit import (  # noqa: F401  (re-exported: every name stays importable from kibisis.vault)
    DEFAULT_ARGUS_LEDGER_PATH,
    JOURNAL_FORMAT,
    AuditJournalMixin,
    _argus_append,
    _argus_ledger_path,
    _event_hash,
    _head_mac,
)
from ._vault_crypto import (  # noqa: F401  (re-exported)
    INTEGRITY_FORMAT,
    EntryIntegrityError,
    EntryIntegrityMixin,
    _rekey_metadata,
    canonicalize_text,
    value_digests,
)
from ._vault_review import (  # noqa: F401  (re-exported)
    ORIGIN_CLASSES,
    ORIGINS,
    AdmissionRefused,
    AdmissionReviewMixin,
    Probe,
    _ORIGIN_TO_CLASS,
    _class_rank,
    _entry_ref,
    _row_origin_class,
    _validate_origin,
    origin_class_of,
    row_origin,
)
from ._vault_search import (  # noqa: F401  (re-exported)
    DEFAULT_MIN_COVERAGE_BP,
    DEFAULT_Z_MAX_BP,
    SEARCH_INDEX_FORMAT,
    TERM_INDEX_FORMAT,
    SearchRecallMixin,
    _EDGE_PUNCTUATION,
    _ENTITY_COLUMNS,
    _HIT_COLUMNS,
    _OPERATIONAL_ERRORS,
    _SEARCH_STOPWORDS,
    _WORD,
    _bounded,
    _search_terms,
    _snippet,
    _snippet_patterns,
    _within_bounds,
)
from ._vault_snapshot import SnapshotMixin
from ._vault_tombstone import TombstoneMixin

logger = logging.getLogger(__name__)


#: Metadata keys the vault writes itself and reads back as facts about trust and ownership. A caller's
#: ``metadata`` argument cannot set them: ``_put`` drops them (and logs the drop) unless the write
#: comes from an internal path whose metadata the vault produced (``review_entity``, ``import_snapshot``).
#: ``human_reviews`` is what ``_is_reviewed`` consults, so a caller-supplied value would forge a
#: person's review; ``tenant_id`` and ``principal_id`` bound recall; ``lineage_*`` is reserved.
RESERVED_METADATA_KEYS = frozenset({
    "human_reviews", "tenant_id", "principal_id",
    # K-R1 origin-bound admission: set by the vault from the write path, never from the payload.
    "origin_class", "act_class", "act_class_capped_from", "attestations", "verification_pending",
    "trust_inherited_from", "conflicts_with", "contrasts_with",
})
RESERVED_METADATA_PREFIX = "lineage_"

#: ``inform`` entries may be shown to a model; only ``act`` entries may drive an action (conventions,
#: standing instructions). Agent and external writers are capped at ``inform``.
ACT_CLASSES = ("inform", "act")
#: Distinct principals who must attest before an entry is ``verified`` (K-R1); ``KIBISIS_VERIFICATION_QUORUM``
#: overrides the default for a deployment.
DEFAULT_VERIFICATION_QUORUM = 2


def _reserved_metadata_keys(meta: Dict[str, Any]) -> List[str]:
    return sorted(k for k in meta if k in RESERVED_METADATA_KEYS or str(k).startswith(RESERVED_METADATA_PREFIX))
_ORIGIN_CHECK = "CHECK (origin IN ('user','model','tool','import','unknown'))"




def _sqlcipher_available() -> bool:
    """True when the real sqlcipher3 driver is loaded; the import above falls back to the standard sqlite3."""
    return sqlcipher3 is not sqlite3


class TombstonedValueError(ValueError):
    """Raised when a write carries a value that a tombstone in its scope has rejected."""

    def __init__(
        self,
        message: str,
        *,
        category: str = "",
        key: str = "",
        scope: str = "",
        digest: str = "",
        author_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.key = key
        self.scope = scope
        self.digest = digest
        self.author_id = author_id


class ReviewedEntryError(PermissionError):
    """Raised when a capped (model-originated) write targets an entry a person verified or reviewed."""


class OriginClassError(PermissionError):
    """Raised when a lower-trust writer (K-R1 ``origin_class``) tries to overwrite a higher-trust entry.

    The entry's class is fixed by the vault at write time; a model or tool cannot change it by
    re-writing the key. Write a new key with ``supersedes_key`` to propose a replacement instead.
    """

    def __init__(self, message: str, *, writer_class: str = "", stored_class: str = "") -> None:
        super().__init__(message)
        self.writer_class = writer_class
        self.stored_class = stored_class


class SupersessionRefused(ValueError):
    """Raised when a ``supersedes`` edge cannot be made: the target is missing in the scope, or it is
    already superseded (a retired edge is not re-pointed; supersede the entry that replaced it)."""


class SupersededEntryError(PermissionError):
    """Raised when a write lands on a key that an explicit ``supersedes`` edge has closed (K-R2).

    The closed interval stays closed. A principal may pass ``revive=True`` to open a new version with a
    new ``valid_from``; nothing reopens the old one.
    """


def _require_aad_support(provider: Any) -> None:
    """Fail at open, not at the first write, when a custom provider cannot bind content to its entry."""
    for name in ("encrypt", "decrypt"):
        try:
            params = inspect.signature(getattr(provider, name)).parameters
        except (TypeError, ValueError):
            continue  # not introspectable; rely on the protocol
        if "aad" not in params and not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            raise TypeError(
                f"crypto_provider.{name} must accept an 'aad' keyword argument: Kibisis binds sealed content "
                "to its entry as associated data"
            )


def _is_reviewed(row: Any) -> bool:
    """True for an entry in the verified state or one that carries a person's review."""
    if row["epistemic_state"] == EpistemicState.VERIFIED.value:
        return True
    try:
        meta = json.loads(row["metadata_json"] or "{}")
    except (TypeError, ValueError):
        return False
    return bool(meta.get("human_reviews"))


class SQLiteMemoryVault(
    AuditJournalMixin,
    EntryIntegrityMixin,
    AdmissionReviewMixin,
    SearchRecallMixin,
    TombstoneMixin,
    SnapshotMixin,
    MemoryVault,
):
    """Local SQLite memory vault featuring FTS5 full-text search, WAL mode, entity versioning,
    AES-256-GCM envelope encryption, and evasion-resistant negative memory tombstones."""

    def __init__(
        self,
        db_path: Union[str, Path] = ":memory:",
        crypto_provider: Optional[CryptoEnvelopeProvider] = None,
        passphrase: Optional[str] = None,
        *,
        allow_plaintext: bool = False,
        coordinator: Optional[LeaseCoordinator] = None,
        enforce_fencing: bool = False,
        auto_gate: bool = True,
        memory_security: bool = True,
        cache_mb: Optional[int] = None,
        verification_quorum: Optional[int] = None,
        term_index: bool = True,
    ) -> None:
        """Open a vault. Entry content is encrypted by default.

        ``verification_quorum`` (K-R1) is how many distinct principals must attest to an entry before
        it is stored as ``verified``: the author of a ``origin="user"`` write that asked for
        ``verified`` counts as one, each person reviewing it as ``verified`` counts as one more. It
        defaults to ``KIBISIS_VERIFICATION_QUORUM`` or :data:`DEFAULT_VERIFICATION_QUORUM`.

        The passphrase comes from the argument, then KIBISIS_PASSPHRASE_FILE, then KIBISIS_PASSPHRASE.
        With no passphrase the vault refuses to open (EncryptionRequiredError) unless ``allow_plaintext=True``.
        An in-memory vault never touches disk, so it may run without a passphrase.

        With ``enforce_fencing=True`` (which needs ``coordinator``), every call that adds, changes or
        removes entries must pass the caller's current ``fencing_token`` and ``resource``, and may
        pass ``holder_id``; a missing, stale or expired token raises ``LeaseConflictError`` and
        changes nothing. Without it, a token is checked only when one is passed.

        With SQLCipher and a passphrase, ``memory_security=True`` (the default) turns on SQLCipher's
        ``cipher_memory_security``, which wipes the memory SQLite frees, such as decrypted database pages.
        SQLCipher applies it to every connection in the process, and it costs time: ranked search over
        sealed entries runs several times slower with it. ``memory_security=False`` leaves the setting as
        it is (off unless something in the process turned it on). Either way, text that kibisis returns to
        Python stays in Python's memory until Python frees it, unwiped.

        ``cache_mb`` sets SQLite's page cache for this connection, in MiB (default: SQLite's own, a few MiB).
        Under SQLCipher a page read from outside the cache is decrypted again, so search over a vault larger
        than the cache slows down; a cache that holds the vault's pages removes that cost. The cache holds
        decrypted pages in this process's memory.

        Without SQLCipher, a vault with a passphrase keeps a keyed term index in its file so that search
        does not open every entry (:meth:`_ensure_term_index`; SECURITY.md states what the tokens show).
        ``term_index=False`` keeps no such index, removes one the file has, and searches as before: by
        opening every entry into an index in memory, at a cost that grows with the vault.
        """
        self.db_path = str(db_path)
        if cache_mb is not None and int(cache_mb) <= 0:
            raise ValueError("cache_mb must be a positive number of MiB")
        if crypto_provider is not None:
            _require_aad_support(crypto_provider)  # before anything touches the file
        self.coordinator = coordinator
        self.enforce_fencing = enforce_fencing
        self.auto_gate = auto_gate
        if verification_quorum is None:
            verification_quorum = int(os.environ.get("KIBISIS_VERIFICATION_QUORUM", DEFAULT_VERIFICATION_QUORUM))
        if verification_quorum < 1:
            raise ValueError("verification_quorum must be at least 1")
        self.verification_quorum = int(verification_quorum)
        if enforce_fencing and coordinator is None:
            raise ValueError("enforce_fencing=True needs a lease coordinator: pass coordinator=")
        self._fallback_search_warned = False
        on_disk = self.db_path != ":memory:"
        passphrase = resolve_passphrase(passphrase)
        if passphrase and len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(f"passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")
        if passphrase is None and crypto_provider is None and on_disk and not allow_plaintext:
            raise EncryptionRequiredError(
                "No passphrase supplied. Set KIBISIS_PASSPHRASE_FILE (preferred) or KIBISIS_PASSPHRASE, "
                "pass passphrase=..., or open with allow_plaintext=True to store content unencrypted."
            )
        self.passphrase = passphrase
        self.crypto_provider = crypto_provider

        # Integrity keys. With a passphrase, the signing and digest keys are derived from a PBKDF2 stretch
        # of it once the vault's salt is known (below); _legacy_signing_key checks format 1 signatures
        # during the upgrade. Without a passphrase nothing is secret: signatures catch only accidental
        # damage, and value digests stay plain SHA-256.
        sig_seed = passphrase if passphrase else self.db_path
        self._legacy_signing_key = hashlib.sha256(f"kibisis-tenant-sig:{sig_seed}".encode("utf-8")).digest()
        self._signing_key = self._legacy_signing_key
        self._digest_key: Optional[bytes] = None
        self._term_key: Optional[bytes] = None
        self._keyed = False
        self._integrity_format = 1
        self._converted_to_sqlcipher = False
        self._was_keyed = False
        #: Counts from the integrity upgrade this open performed, or None when none was needed.
        self.integrity_upgrade: Optional[Dict[str, Any]] = None

        # Convert an existing plain SQLite file to SQLCipher when a passphrase is given. Without sqlcipher3 there
        # is nothing to convert with: the file stays plain SQLite and the first open that has sqlcipher3 converts it.
        if on_disk and passphrase and not _sqlcipher_available():
            logger.warning(
                "sqlcipher3 is not installed, so %s is not encrypted as a whole file: entry content is still "
                "sealed, but categories, keys and metadata are stored in plain text",
                self.db_path,
            )
        if (
            on_disk
            and passphrase
            and _sqlcipher_available()
            and os.path.exists(self.db_path)
            and os.path.getsize(self.db_path) > 0
        ):
            with open(self.db_path, "rb") as f:
                hdr = f.read(16)
            if hdr.startswith(b"SQLite format 3"):
                # Migrate existing plaintext SQLite database to encrypted SQLCipher database
                self._migrate_file_to_sqlcipher(self.db_path, passphrase)
                self._converted_to_sqlcipher = True

        self._search_index = False  # True once a SQLCipher vault's entry index is in use
        self._term_index = False  # True once the keyed term index of a vault without SQLCipher is in use
        self._scan_cache: Optional[Tuple[Tuple[int, int], Any]] = None  # in-memory index without SQLCipher
        self._recent_recalls: Deque[Dict[str, Any]] = deque(maxlen=1000)  # K-R5 in-process recall log
        self._tokenizer: Optional[sqlite3.Connection] = None  # FTS5's tokenizer, for the term index
        self._tokenizer_lock = threading.Lock()
        self._conn = sqlcipher3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlcipher3.Row
        self._sqlcipher_active = False
        self._cache_mb = int(cache_mb) if cache_mb is not None else None
        if passphrase:
            escaped_pass = passphrase.replace("'", "''")
            if memory_security:
                self._conn.execute("PRAGMA cipher_memory_security = ON;")
            self._conn.execute(f"PRAGMA key = '{escaped_pass}';")
            # Verify the key immediately by accessing sqlite_master
            try:
                self._conn.execute("SELECT count(*) FROM sqlite_master;").fetchall()
                row = self._conn.execute("PRAGMA cipher_version;").fetchone()
                if row and row[0]:
                    self._sqlcipher_active = True
            except Exception as e:
                self._conn.close()
                raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase") from e
            self._conn.execute("PRAGMA secure_delete = ON;")
        self._configure_db()
        if self._cache_mb is not None:
            self._conn.execute(f"PRAGMA cache_size = -{self._cache_mb * 1024}")
        self._init_schema()
        if passphrase:
            self._was_keyed = self._has_meta_key("kdf_salt")  # written by an earlier open with a passphrase
            salt = self._vault_salt()
            if crypto_provider is None:
                self.crypto_provider = AESGCMCryptoEnvelopeProvider(salt=salt)
            self._signing_key, self._digest_key, self._term_key = derive_vault_keys(passphrase, salt)
            self._keyed = True
            try:
                self._upgrade_integrity()
                if self._sqlcipher_active:
                    self._ensure_search_index()
                elif term_index:
                    self._ensure_term_index()
                elif self._has_meta_key("term_index_format"):
                    with self._write_tx() as cursor:  # opened with term_index=False: leave no tokens behind
                        for trigger in ("entities_search_ai", "entities_search_au", "entities_search_ad"):
                            cursor.execute(f"DROP TRIGGER IF EXISTS {trigger}")
                        cursor.execute("DROP TABLE IF EXISTS entities_search_dirty")
                        self._drop_term_index(cursor)
            except BaseException:
                self._conn.close()
                raise
        if on_disk:
            self._restrict_permissions()

    def _validate_fencing(
        self,
        fencing_token: Optional[int],
        resource: Optional[str],
        holder_id: Optional[str] = None,
    ) -> None:
        """Validate an atomic fencing token against the attached lease coordinator."""
        if self.enforce_fencing and (fencing_token is None or resource is None):
            raise LeaseConflictError("enforce_fencing is enabled on vault, but fencing_token or resource was not provided")

        if fencing_token is None and resource is None:
            return

        if self.coordinator is None:
            raise LeaseConflictError("Fencing token validation requested but no LeaseCoordinator is configured on vault")

        if resource is None or fencing_token is None:
            raise LeaseConflictError(
                f"Both resource and fencing_token must be specified for fencing validation (got resource={resource}, token={fencing_token})"
            )

        if holder_id is not None:
            if not self.coordinator.validate_fencing_token(resource, holder_id, fencing_token):
                raise LeaseConflictError(
                    f"Stale or invalid fencing token {fencing_token} for resource '{resource}' (holder={holder_id})"
                )
        else:
            lease = self.coordinator.get_lease(resource)
            if lease is None:
                raise LeaseConflictError(f"No active lease found for resource '{resource}'")
            if lease.fencing_token != fencing_token:
                raise LeaseConflictError(
                    f"Stale fencing token {fencing_token} for resource '{resource}' (active token is {lease.fencing_token})"
                )
            if lease.expires_at <= time.time():
                raise LeaseConflictError(f"Expired lease with fencing token {fencing_token} for resource '{resource}'")

    def _fence(
        self,
        cursor: Any,
        fencing_token: Optional[int],
        resource: Optional[str],
        holder_id: Optional[str],
    ) -> None:
        """Check the caller's fencing token inside the write transaction, holding the write lock.

        Skipped when no token or resource is passed and ``enforce_fencing`` is off. The caller has
        already taken the write lock through :meth:`_write_tx`, so a write whose token passes is
        ordered before any write by a later lease holder, never after it. This method does not
        begin a transaction itself: taking the lock here, after the caller's reads, is what let a
        tombstone check run unlocked.
        """
        if fencing_token is None and resource is None and not self.enforce_fencing:
            return
        self._validate_fencing(fencing_token, resource, holder_id)

    @contextlib.contextmanager
    def _write_tx(self):
        """Run a mutation under the SQLite write lock, taken before its first read.

        Issues ``BEGIN IMMEDIATE`` when no transaction is open, commits when the block finishes and
        rolls back when it raises. Python's sqlite3 module only begins a transaction before the first
        DML statement, so a method that reads first (the tombstone gate, the reviewed-entry check,
        the audit head) and then writes used to run its reads with no lock; another connection could
        commit a tombstone or a review between the check and the insert. Every mutating method
        enters this first so check-then-write is atomic against other connections.

        Nested use inside an open transaction yields a cursor and leaves commit and rollback to the
        outermost block, so a compound operation (review, then re-write) stays one transaction.
        """
        if self._conn.in_transaction:
            yield self._conn.cursor()
            return
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        try:
            yield cursor
        except BaseException:
            self._conn.rollback()
            raise
        self._conn.commit()

    @staticmethod
    def _migrate_file_to_sqlcipher(path: str, passphrase: str) -> None:
        temp_enc = path + ".tmp_enc"
        if os.path.exists(temp_enc):
            os.unlink(temp_enc)
        escaped_pass = passphrase.replace("'", "''")
        conn_raw = sqlcipher3.connect(path)
        try:
            conn_raw.execute(f"ATTACH DATABASE '{temp_enc}' AS encrypted KEY '{escaped_pass}';")
            conn_raw.execute("SELECT sqlcipher_export('encrypted');")
            conn_raw.execute("DETACH DATABASE encrypted;")
        finally:
            conn_raw.close()
        for ext in ("-wal", "-shm"):
            p = path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        os.replace(temp_enc, path)

    def _restrict_permissions(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = self.db_path + suffix
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o600)
            except OSError:
                pass

    def _configure_db(self) -> None:
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA foreign_keys = ON")

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    version INTEGER NOT NULL DEFAULT 1,
                    archived INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    is_encrypted INTEGER NOT NULL DEFAULT 0,
                    encrypted_envelope_json TEXT DEFAULT NULL,
                    scope TEXT NOT NULL DEFAULT 'default',
                    epistemic_state TEXT NOT NULL DEFAULT 'verified',
                    valid_from REAL DEFAULT NULL,
                    valid_until REAL DEFAULT NULL,
                    tenant_sig TEXT DEFAULT NULL,
                    supersedes TEXT DEFAULT NULL,
                    superseded_by TEXT DEFAULT NULL,
                    origin TEXT NOT NULL DEFAULT 'unknown' CHECK (origin IN ('user','model','tool','import','unknown')),
                    source_ref TEXT DEFAULT NULL,
                    confidence REAL DEFAULT NULL,
                    UNIQUE(category, key, scope)
                )
                """
            )

            # Migration for pre-existing tables lacking columns
            cursor = self._conn.cursor()
            cursor.execute("PRAGMA table_info(entities)")
            cols = {row["name"] for row in cursor.fetchall()}
            if "is_encrypted" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0")
            if "encrypted_envelope_json" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN encrypted_envelope_json TEXT DEFAULT NULL")
            if "scope" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN scope TEXT NOT NULL DEFAULT 'default'")
            if "epistemic_state" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN epistemic_state TEXT NOT NULL DEFAULT 'verified'")
            if "valid_from" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN valid_from REAL DEFAULT NULL")
            if "valid_until" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN valid_until REAL DEFAULT NULL")
            if "tenant_sig" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN tenant_sig TEXT DEFAULT NULL")
            if "supersedes" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN supersedes TEXT DEFAULT NULL")
            if "superseded_by" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN superseded_by TEXT DEFAULT NULL")
            if "origin" not in cols:
                # Rows that predate provenance read as 'unknown'; nothing claims they were a person's.
                self._conn.execute(
                    "ALTER TABLE entities ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown' " + _ORIGIN_CHECK
                )
            if "source_ref" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN source_ref TEXT DEFAULT NULL")
            if "confidence" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN confidence REAL DEFAULT NULL")

            # Covering B-Tree index for bitemporal point-in-time and interval queries
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_entities_bitemporal
                ON entities (scope, category, epistemic_state, valid_from, valid_until)
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_entities_supersedes
                ON entities (scope, category, supersedes)
                """
            )

            self._conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
                    category,
                    key,
                    content,
                    scope,
                    content='entities',
                    content_rowid='id'
                )
                """
            )

            # Triggers to keep FTS5 synchronized with entities
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_ai AFTER INSERT ON entities BEGIN
                    INSERT INTO entities_fts(rowid, category, key, content, scope)
                    VALUES (new.id, new.category, new.key, new.content, new.scope);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_ad AFTER DELETE ON entities BEGIN
                    INSERT INTO entities_fts(entities_fts, rowid, category, key, content, scope)
                    VALUES ('delete', old.id, old.category, old.key, old.content, old.scope);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_au AFTER UPDATE ON entities BEGIN
                    INSERT INTO entities_fts(entities_fts, rowid, category, key, content, scope)
                    VALUES ('delete', old.id, old.category, old.key, old.content, old.scope);
                    INSERT INTO entities_fts(rowid, category, key, content, scope)
                    VALUES (new.id, new.category, new.key, new.content, new.scope);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rejected_value_tombstones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value_sha256 TEXT NOT NULL,
                    canonical_sha256 TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL,
                    author_id TEXT,
                    created_at REAL NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'default',
                    UNIQUE(category, key, value_sha256, scope)
                )
                """
            )
            cursor.execute("PRAGMA table_info(rejected_value_tombstones)")
            tomb_cols = {row["name"] for row in cursor.fetchall()}
            if "canonical_sha256" not in tomb_cols:
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN canonical_sha256 TEXT NOT NULL DEFAULT ''")
            if "scope" not in tomb_cols:
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN scope TEXT NOT NULL DEFAULT 'default'")
            if "sealed_digests" not in tomb_cols:
                # A vault with a passphrase keeps a tombstone's plain digests sealed here, so a snapshot can
                # carry the tombstone to another vault that has the same passphrase.
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN sealed_digests TEXT DEFAULT NULL")

            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_lookup
                ON rejected_value_tombstones(category, key, value_sha256, scope)
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_canonical
                ON rejected_value_tombstones(category, canonical_sha256, scope)
                """
            )
            # A tombstone stops a value under any category or key, so writes look tombstones up
            # by digest alone.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_value ON rejected_value_tombstones(value_sha256)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_canonical_value "
                "ON rejected_value_tombstones(canonical_sha256)"
            )

            # Append-only hash-chained mutation audit journal
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_journal (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    action TEXT NOT NULL,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    value_sha256 TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    author_id TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_journal_scope
                ON audit_journal(scope, category, key)
                """
            )
            # Journal rows written before the column existed used the legacy layout (format 2 at most).
            journal_cols = {r[1] for r in self._conn.execute("PRAGMA table_info(audit_journal)").fetchall()}
            if "format" not in journal_cols:
                self._conn.execute("ALTER TABLE audit_journal ADD COLUMN format INTEGER NOT NULL DEFAULT 2")
            # One row: the sequence and hash of the newest event, signed. Updated with every append.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_head (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    sequence INTEGER NOT NULL,
                    event_hash TEXT NOT NULL,
                    mac TEXT NOT NULL
                )
                """
            )

    def _has_meta_key(self, key: str) -> bool:
        try:
            return self._meta(key) is not None
        except sqlcipher3.OperationalError:
            return False  # no vault_meta table: the vault was never opened with a passphrase

    def _meta(self, key: str) -> Any:
        row = self._conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    @staticmethod
    def _set_meta(cursor: Any, key: str, value: Any) -> None:
        cursor.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value))

    def _put(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
        trust_ceiling: Optional[str] = None,
        origin: Optional[str] = None,
        source_ref: Optional[str] = None,
        confidence: Optional[float] = None,
        act_class: Optional[str] = None,
        revive: bool = False,
        conflicts_with: Optional[List[str]] = None,
        contrasts_with: Optional[List[str]] = None,
        _trusted_metadata: bool = False,
        _review_verdict: bool = False,
    ) -> MemoryEntity:
        """Write path behind :meth:`put`, which journals the tombstone refusals this raises.

        ``_review_verdict`` is set by :meth:`review_entity` only: the state it passes was decided
        under the quorum rule there, with ``attestations`` already in ``metadata``.

        ``_trusted_metadata`` is set only by internal callers whose ``metadata`` the vault itself
        produced; a caller's reserved keys (:data:`RESERVED_METADATA_KEYS`) are dropped otherwise.
        """
        if trust_ceiling is not None and trust_ceiling != EpistemicState.CANDIDATE.value:
            raise ValueError("trust_ceiling supports only 'candidate'")
        _validate_origin(origin)
        if confidence is not None and not (0.0 <= float(confidence) <= 1.0):
            raise ValueError("confidence must be within [0, 1]")
        if act_class is not None and act_class not in ACT_CLASSES:
            raise ValueError(f"act_class must be one of {ACT_CLASSES}, got {act_class!r}")
        if origin == "model":
            # Trust comes from where the write came from, not from what it says about itself.
            trust_ceiling = EpistemicState.CANDIDATE.value
        now = time.time()
        meta = dict(metadata or {})
        if not _trusted_metadata:
            # Trust facts come from the vault's own paths, never from the payload: a caller that writes
            # metadata["human_reviews"] would otherwise count as a person's review in _is_reviewed.
            dropped = _reserved_metadata_keys(meta)
            for k in dropped:
                meta.pop(k)
            if dropped:
                logger.warning("put %s:%s [scope=%s] dropped reserved metadata keys %s", category, key, scope, dropped)
        if author_id:
            # Keep the original author when a reviewer re-writes an entry; the review is in human_reviews.
            meta.setdefault("author_id", author_id)
        if tenant_id:
            meta["tenant_id"] = tenant_id
        if principal_id:
            meta["principal_id"] = principal_id
        if derived_from:
            meta["derived_from"] = derived_from

        # Evaluate write-time admission gate if enabled and epistemic_state not explicitly specified
        gate_enabled = self.auto_gate if auto_gate is None else auto_gate
        if gate_enabled and epistemic_state is None:
            gate = MemoryAdmissionGate()
            decision = gate.evaluate(content, category=category)
            ep_state_str = gate.route_epistemic_state(decision)
            ep_state = EpistemicState(ep_state_str)
            meta["admission_disposition"] = decision.disposition.value
            meta["admission_provenance"] = decision.provenance
            if decision.metadata:
                meta.update(decision.metadata)
            if decision.disposition == FactDisposition.TRANSIENT and valid_until is None:
                valid_until = now + 86400.0  # Default 24h validity for transient states
        else:
            # K-E: a write that states no epistemic state is a candidate. Nothing but a person's
            # review (and the quorum below) mints verified.
            ep_state = EpistemicState(epistemic_state) if epistemic_state else EpistemicState.CANDIDATE

        if trust_ceiling is not None and ep_state in (EpistemicState.VERIFIED, EpistemicState.DISPUTED):
            # Default recall returns verified and disputed entries; a capped write is neither.
            meta["trust_capped_from"] = ep_state.value
            ep_state = EpistemicState.CANDIDATE

        # K-R1: the trust class of this write. A re-write that states no origin keeps the entry's
        # stored origin (and class); that is resolved against the stored row inside the transaction.
        writer_class: Optional[str] = origin_class_of(origin) if origin is not None else None
        requested_verified = ep_state == EpistemicState.VERIFIED and not _review_verdict
        if requested_verified:
            # An explicit "verified" from a principal is that principal's attestation, counted toward
            # the quorum; from anyone else it is a claim and the entry stays a candidate.
            if writer_class != "principal":
                meta["trust_capped_from"] = ep_state.value
                ep_state = EpistemicState.CANDIDATE
            else:
                ep_state = EpistemicState.CANDIDATE  # settled against the quorum below

        # Check explicit superseding target
        supersedes_ref: Optional[str] = None
        if supersedes_key:
            target_cat = supersedes_category or category
            supersedes_ref = f"{target_cat}:{supersedes_key}"
            meta["supersedes"] = supersedes_ref
            if valid_from is None:
                valid_from = now

        meta_str = json.dumps(meta, sort_keys=True)
        val_hash, can_hash = self._digests(content)

        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            cursor.execute(
                "SELECT epistemic_state, metadata_json, origin, superseded_by, valid_until, version "
                "FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            existing = cursor.fetchone()

            # K-R2 bitemporal non-revival: a key closed by a supersedes edge stays closed. Only a
            # principal may revive it, and only forward in time: the new version's valid_from is at or
            # after the closed interval's valid_until, so the old interval is never reopened.
            if existing is not None and existing["superseded_by"]:
                if not revive or origin_class_of(origin) != "principal":
                    raise SupersededEntryError(
                        f"'{category}:{key}' [scope={scope}] was superseded by {existing['superseded_by']}; "
                        "the closed interval is not rewritten. A principal may pass revive=True to open a new one."
                    )
                closed_at = existing["valid_until"] or now
                if valid_from is not None and valid_from < closed_at:
                    raise ValueError("revive cannot backdate valid_from into the closed interval")
                if valid_from is None:
                    valid_from = max(now, closed_at)
                meta["revived_from"] = {"version": int(existing["version"]), "superseded_by": existing["superseded_by"]}

            # K-R5: contradiction check before anything else happens to the write. An explicit
            # ``conflicts_with`` edge is recorded on both sides and journaled; recall withholds a pair of
            # verified entries that conflict until a person resolves it (K-R3).
            existing_meta: Dict[str, Any] = {}
            if existing is not None:
                try:
                    existing_meta = json.loads(existing["metadata_json"] or "{}")
                except (TypeError, ValueError):
                    existing_meta = {}
            conflict_refs = self._record_edges(
                cursor, "conflicts_with", conflicts_with, category, key, scope, now, existing_meta, _trusted_metadata
            )
            if conflicts_with:
                self._record_audit_event(
                    cursor=cursor, action="contradiction", category=category, key=key, scope=scope,
                    value_sha256=val_hash, author_id=author_id, metadata={"with": list(conflicts_with)},
                )
            if conflict_refs:
                meta["conflicts_with"] = conflict_refs
            # Contrast edges name confusables: entries a reader could mistake for each other. Both are
            # returned; the receipt carries the edge so the scaffold can show the distinction.
            contrast_refs = self._record_edges(
                cursor, "contrasts_with", contrasts_with, category, key, scope, now, existing_meta, _trusted_metadata
            )
            if contrast_refs:
                meta["contrasts_with"] = contrast_refs

            # K-R1: origin_class is immutable from below. The stored class is what a lower-trust
            # writer must not change; an equal class keeps it; a principal may raise it.
            stored_class = _row_origin_class(existing) if existing is not None else None
            if writer_class is None:
                writer_class = stored_class or origin_class_of(origin)
            if stored_class is not None and _class_rank(writer_class) < _class_rank(stored_class):
                raise OriginClassError(
                    f"'{category}:{key}' [scope={scope}] is {stored_class}-class; a {writer_class}-class write "
                    "cannot replace it. Write a new key with supersedes_key to propose a replacement.",
                    writer_class=writer_class, stored_class=stored_class,
                )
            entry_class = writer_class
            # Max-untrust along supersedes and derived_from: a non-principal entry is no more trusted
            # than what it replaces or draws on, so trust cannot be laundered through a rewrite.
            if entry_class != "principal":
                inherited: List[str] = []
                links: List[Tuple[str, str]] = []
                if supersedes_key:
                    links.append((supersedes_category or category, supersedes_key))
                for ref in derived_from or []:
                    if ":" in ref:
                        c, k = ref.split(":", 1)
                        links.append((c, k))
                for c, k in links:
                    cursor.execute(
                        "SELECT metadata_json, origin FROM entities WHERE category = ? AND key = ? AND scope = ?",
                        (c, k, scope),
                    )
                    link_row = cursor.fetchone()
                    if link_row is None:
                        continue
                    link_class = _row_origin_class(link_row)
                    if _class_rank(link_class) < _class_rank(entry_class):
                        entry_class = link_class
                        inherited.append(f"{c}:{k}")
                if inherited:
                    meta["trust_inherited_from"] = inherited
            meta["origin_class"] = entry_class
            # act_class: only a principal may mark an entry as one that drives actions.
            wanted_act = act_class or (meta.get("act_class") if _trusted_metadata else None) or "inform"
            if wanted_act == "act" and entry_class != "principal":
                meta["act_class_capped_from"] = "act"
                wanted_act = "inform"
            meta["act_class"] = wanted_act

            # Verification quorum: distinct principals who attested. The author of a principal write
            # that asked for verified is one; review_entity adds reviewers. Below quorum stays candidate.
            if not _review_verdict:
                prior_meta: Dict[str, Any] = {}
                if existing is not None:
                    try:
                        prior_meta = json.loads(existing["metadata_json"] or "{}")
                    except (TypeError, ValueError):
                        prior_meta = {}
                attested = list(prior_meta.get("attestations") or []) if existing is not None else []
                if requested_verified and entry_class == "principal":
                    signer = author_id or principal_id or "principal"
                    if signer not in attested:
                        attested.append(signer)
                if attested:
                    meta["attestations"] = attested
                if requested_verified and entry_class == "principal":
                    if len(attested) >= self.verification_quorum:
                        ep_state = EpistemicState.VERIFIED
                        meta.pop("verification_pending", None)
                    else:
                        meta["verification_pending"] = {"have": len(attested), "need": self.verification_quorum}
            meta_str = json.dumps(meta, sort_keys=True)

            if trust_ceiling is not None:
                # A capped write cannot replace an entry a person verified or reviewed.
                if existing is not None and _is_reviewed(existing):
                    raise ReviewedEntryError(
                        f"'{category}:{key}' [scope={scope}] is verified or reviewed by a person; a capped write "
                        "cannot replace it. Write a new key with supersedes_key to propose a replacement."
                    )

            # K-R2 three-way supersession. Retirement happens only through this explicit edge.
            if supersedes_key:
                target_cat = supersedes_category or category
                cursor.execute(
                    "SELECT id, metadata_json, epistemic_state, origin, superseded_by FROM entities "
                    "WHERE category = ? AND key = ? AND scope = ? AND archived = 0",
                    (target_cat, supersedes_key, scope),
                )
                target_row = cursor.fetchone()
                target_ref = f"{target_cat}:{supersedes_key}"
                if target_row is None:
                    raise SupersessionRefused(f"supersedes target '{target_ref}' [scope={scope}] does not exist")
                if target_row["superseded_by"]:
                    raise SupersessionRefused(
                        f"supersedes target '{target_ref}' [scope={scope}] is already superseded by "
                        f"{target_row['superseded_by']}; supersede that entry instead"
                    )
                target_class = _row_origin_class(target_row)
                confirmed_by = meta.get("supersession_approved_by") if _review_verdict else None
                # Applied when the writer outranks or equals the target's class and the target is not a
                # reviewed entry a non-principal may not retire; a person's approval of a proposal applies it.
                applies = bool(confirmed_by) or entry_class == "principal" or (
                    _class_rank(entry_class) >= _class_rank(target_class) and not _is_reviewed(target_row)
                )
                if not applies:
                    # needs_confirmation: store this entry as a proposal; the target stays active and
                    # carries the pending mark. review_entity applies or clears it.
                    meta.pop("supersedes", None)
                    meta["proposed_supersedes"] = {"category": target_cat, "key": supersedes_key}
                    meta["supersession"] = {"outcome": "needs_confirmation", "target": target_ref}
                    target_meta = json.loads(target_row["metadata_json"] or "{}")
                    pending = list(target_meta.get("pending_supersession_by") or [])
                    if f"{category}:{key}" not in pending:
                        pending.append(f"{category}:{key}")
                    target_meta["pending_supersession_by"] = pending
                    cursor.execute(
                        "UPDATE entities SET metadata_json = ?, updated_at = ? WHERE id = ?",
                        (json.dumps(target_meta, sort_keys=True), now, target_row["id"]),
                    )
                    self._record_audit_event(
                        cursor=cursor, action="supersession", category=target_cat, key=supersedes_key, scope=scope,
                        value_sha256="", author_id=author_id,
                        metadata={"outcome": "needs_confirmation", "proposed_by": f"{category}:{key}",
                                  "writer_class": entry_class, "target_class": target_class},
                    )
                    supersedes_ref = None
                    target_row = None
                else:
                    meta.pop("proposed_supersedes", None)
                    meta["supersession"] = {"outcome": "applied", "target": target_ref}
                    if confirmed_by:
                        meta["supersession"]["confirmed_by"] = confirmed_by
                    self._record_audit_event(
                        cursor=cursor, action="supersession", category=target_cat, key=supersedes_key, scope=scope,
                        value_sha256="", author_id=author_id,
                        metadata={"outcome": "applied", "superseded_by": f"{category}:{key}",
                                  "writer_class": entry_class, "target_class": target_class,
                                  **({"confirmed_by": confirmed_by} if confirmed_by else {})},
                    )
                meta_str = json.dumps(meta, sort_keys=True)
                if target_row is not None:
                    target_meta = json.loads(target_row["metadata_json"] or "{}")
                    target_meta["superseded_by"] = f"{category}:{key}"
                    target_meta.pop("pending_supersession_by", None)
                    cursor.execute(
                        """
                        UPDATE entities
                        SET valid_until = ?, epistemic_state = ?, metadata_json = ?, superseded_by = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            now,
                            EpistemicState.REVOKED.value,
                            json.dumps(target_meta, sort_keys=True),
                            f"{category}:{key}",
                            now,
                            target_row["id"],
                        ),
                    )
                    self._record_audit_event(
                        cursor=cursor,
                        action="supersede",
                        category=target_cat,
                        key=supersedes_key,
                        scope=scope,
                        value_sha256="",
                        author_id=author_id,
                        metadata={"superseded_by": f"{category}:{key}", "superseded_at": now},
                    )
                    if target_row["epistemic_state"] != EpistemicState.REVOKED.value:
                        self._record_state_transition(
                            cursor, target_cat, supersedes_key, scope, target_row["epistemic_state"],
                            EpistemicState.REVOKED.value, row_origin(target_row), author_id, cause="supersede",
                        )
                    self._cascade_invalidate(cursor, scope, target_ref, author_id, now)

            # Skip canonicalization when the vault has no tombstones. Asked of the database on every
            # write: a flag cached at open misses tombstones that other processes add later.
            cursor.execute("SELECT EXISTS (SELECT 1 FROM rejected_value_tombstones)")
            if cursor.fetchone()[0]:
                tomb = self._find_tombstone(cursor, scope, val_hash, can_hash)
                if tomb is not None:
                    raise TombstonedValueError(
                        f"Write rejected by tombstone: entity '{category}:{key}' [scope={scope}] matches rejected tombstone "
                        f"(digest: {val_hash[:12]}..., reason: {tomb['reason']})",
                        category=category,
                        key=key,
                        scope=scope,
                        digest=val_hash,
                        author_id=author_id,
                    )

            if self.crypto_provider is not None and not self.passphrase:
                raise ValueError("Crypto provider configured but no passphrase supplied to SQLiteMemoryVault.")
            # Sealed content is bound to this entry, and its plaintext column stays empty so nothing leaks
            # into the entities table or the FTS index. The signature covers the entry either way.
            stored_content, is_encrypted, envelope_json, tenant_sig = self._seal(
                scope, category, key, content, encrypt=self.crypto_provider is not None
            )

            cursor.execute(
                "SELECT id, version, created_at, supersedes, superseded_by, epistemic_state, origin, source_ref, confidence "
                "FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            row = cursor.fetchone()
            previous_state: Optional[str] = None

            if row is None:
                action = "put"
                cursor.execute(
                    """
                    INSERT INTO entities (
                        category, key, content, metadata_json, version, archived,
                        created_at, updated_at, is_encrypted, encrypted_envelope_json,
                        scope, epistemic_state, valid_from, valid_until, tenant_sig,
                        supersedes, superseded_by, origin, source_ref, confidence
                    )
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                    """,
                    (
                        category, key, stored_content, meta_str, now, now,
                        is_encrypted, envelope_json, scope, ep_state.value, valid_from, valid_until, tenant_sig,
                        supersedes_ref, origin or "unknown", source_ref, confidence
                    ),
                )
                entity_id = cursor.lastrowid
                version = 1
                stored_origin = origin or "unknown"
            else:
                action = "update"
                entity_id = row["id"]
                version = row["version"] + 1
                previous_state = row["epistemic_state"]
                # Provenance belongs to the fact: a re-write that does not state an origin keeps the original.
                stored_origin = origin or row["origin"] or "unknown"
                stored_source_ref = source_ref if source_ref is not None else row["source_ref"]
                stored_confidence = confidence if confidence is not None else row["confidence"]
                cursor.execute(
                    """
                    UPDATE entities
                    SET content = ?, metadata_json = ?, version = ?, archived = 0, updated_at = ?,
                        is_encrypted = ?, encrypted_envelope_json = ?, epistemic_state = ?,
                        valid_from = ?, valid_until = ?, tenant_sig = ?,
                        supersedes = COALESCE(?, supersedes),
                        superseded_by = CASE WHEN ? THEN NULL ELSE superseded_by END,
                        origin = ?, source_ref = ?, confidence = ?
                    WHERE id = ?
                    """,
                    (
                        stored_content, meta_str, version, now, is_encrypted, envelope_json,
                        ep_state.value, valid_from, valid_until, tenant_sig, supersedes_ref,
                        1 if "revived_from" in meta else 0,
                        stored_origin, stored_source_ref, stored_confidence, entity_id
                    ),
                )
            if self._search_index or self._term_index:
                self._index_entry(cursor, entity_id, category, key, content, scope)

            # Record hash-chained mutation audit event
            self._record_audit_event(
                cursor=cursor,
                action=action,
                category=category,
                key=key,
                scope=scope,
                value_sha256=val_hash,
                author_id=author_id,
                metadata={"version": version, "epistemic_state": ep_state.value},
            )
            if previous_state is not None and previous_state != ep_state.value:
                self._record_state_transition(
                    cursor, category, key, scope, previous_state, ep_state.value, stored_origin, author_id,
                    cause="review" if _review_verdict else "write",
                )
                if ep_state == EpistemicState.REVOKED:
                    self._cascade_invalidate(cursor, scope, f"{category}:{key}", author_id, now)
            # Return what was stored, through the same constructor the read paths use, so the write
            # path cannot report a field differently from a later get() or search().
            cursor.execute(f"SELECT {_ENTITY_COLUMNS} FROM entities e WHERE e.id = ?", (entity_id,))
            written = cursor.fetchone()

        return self._entity(written, content)

    def put(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
        trust_ceiling: Optional[str] = None,
        origin: Optional[str] = None,
        source_ref: Optional[str] = None,
        confidence: Optional[float] = None,
        act_class: Optional[str] = None,
        revive: bool = False,
        conflicts_with: Optional[List[str]] = None,
        contrasts_with: Optional[List[str]] = None,
        _trusted_metadata: bool = False,
        _review_verdict: bool = False,
    ) -> MemoryEntity:
        """Insert or update an entity. See ``__init__`` for ``fencing_token``, ``resource`` and ``holder_id``.

        K-R3/K-R5: ``conflicts_with`` names existing entries this one contradicts; the edge is recorded on
        both sides and journaled as a ``contradiction`` before the write. :meth:`recall` withholds two
        verified entries that conflict until a person resolves it.

        K-R2: ``supersedes_key`` is the only way an entry retires another. The outcome is reported in
        ``metadata["supersession"]``: ``applied`` (target revoked and closed), or ``needs_confirmation``
        (this entry is a proposal; a person's ``verified`` review applies it). A missing or already
        superseded target raises :class:`SupersessionRefused`. Retiring an entry marks everything that
        ``derived_from`` it ``disputed`` (cascade). A key closed by supersession refuses writes
        (:class:`SupersededEntryError`) unless a principal passes ``revive=True``.

        K-E/K-R1: a write that states no ``epistemic_state`` is stored as ``candidate``. ``verified``
        is minted only when ``verification_quorum`` distinct principals have attested: a
        ``origin="user"``/``"import"`` write that asks for ``verified`` is its author's attestation,
        :meth:`review_entity` adds a reviewer's. The vault sets ``origin_class`` (``principal``,
        ``agent``, ``external``) from ``origin``; a lower-class writer cannot overwrite a higher-class
        entry (:class:`OriginClassError`), and a non-principal entry inherits the lowest class along
        ``supersedes_key`` and ``derived_from``. ``act_class`` (``inform``/``act``) is capped at
        ``inform`` unless the writer is a principal.

        ``origin`` records where the write came from (:data:`ORIGINS`); ``origin="model"`` implies
        ``trust_ceiling="candidate"``. A re-write that gives no origin keeps the entry's existing one.

        ``trust_ceiling="candidate"`` caps the stored state: a write that the admission gate or the
        ``epistemic_state`` argument would store as ``verified`` or ``disputed`` is stored as
        ``candidate``, and the write cannot replace or supersede an entry a person verified or
        reviewed (it raises :class:`ReviewedEntryError`, or records the supersession as a proposal
        that :meth:`review_entity` applies on approval). Write paths that carry model output (the
        MCP server) set it, so trust comes from the path, not from the payload.

        ``author_id`` is recorded in the entity's metadata and in the audit journal. A write whose
        value a tombstone rejects raises :class:`TombstonedValueError`, and the refusal is journaled.

        Reserved metadata keys (:data:`RESERVED_METADATA_KEYS`, ``lineage_*``) in ``metadata`` are
        dropped and logged; the vault sets them itself (``review_entity``, the ``tenant_id`` and
        ``principal_id`` arguments). ``_trusted_metadata`` is internal.
        """
        try:
            return self._put(
                category=category,
                key=key,
                content=content,
                metadata=metadata,
                epistemic_state=epistemic_state,
                valid_from=valid_from,
                valid_until=valid_until,
                scope=scope,
                author_id=author_id,
                tenant_id=tenant_id,
                principal_id=principal_id,
                derived_from=derived_from,
                fencing_token=fencing_token,
                resource=resource,
                holder_id=holder_id,
                supersedes_key=supersedes_key,
                supersedes_category=supersedes_category,
                auto_gate=auto_gate,
                trust_ceiling=trust_ceiling,
                origin=origin,
                source_ref=source_ref,
                confidence=confidence,
                _trusted_metadata=_trusted_metadata,
                act_class=act_class,
                revive=revive,
                conflicts_with=conflicts_with,
                contrasts_with=contrasts_with,
                _review_verdict=_review_verdict,
            )
        except TombstonedValueError as exc:
            # The write's transaction rolled back; journal the refusal in its own transaction.
            self.record_refusal(
                path="put",
                reason="tombstoned value",
                scope=exc.scope or scope,
                category=exc.category,
                key=exc.key,
                author_id=exc.author_id,
                detail={"value_digest_prefix": exc.digest[:12]},
            )
            raise
        except OriginClassError as exc:
            # Same: the transaction rolled back, so the refusal is journaled on its own.
            self.record_refusal(
                path="put",
                reason="origin_class_refused",
                scope=scope,
                category=category,
                key=key,
                author_id=author_id,
                detail={"writer_class": exc.writer_class, "stored_class": exc.stored_class, "origin": origin or ""},
            )
            raise
        except SupersededEntryError:
            self.record_refusal(
                path="put", reason="superseded_entry", scope=scope, category=category, key=key,
                author_id=author_id, detail={"origin": origin or "", "revive": "yes" if revive else "no"},
            )
            raise

    def store(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
        trust_ceiling: Optional[str] = None,
        origin: Optional[str] = None,
        source_ref: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> MemoryEntity:
        """Alias for put() for ergonomic convenience."""
        return self.put(
            category=category,
            key=key,
            content=content,
            metadata=metadata,
            epistemic_state=epistemic_state,
            valid_from=valid_from,
            valid_until=valid_until,
            scope=scope,
            author_id=author_id,
            tenant_id=tenant_id,
            principal_id=principal_id,
            derived_from=derived_from,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            supersedes_key=supersedes_key,
            supersedes_category=supersedes_category,
            auto_gate=auto_gate,
            trust_ceiling=trust_ceiling,
            origin=origin,
            source_ref=source_ref,
            confidence=confidence,
        )

    def record_refusal(
        self,
        *,
        path: str,
        reason: str,
        scope: str,
        category: str = "",
        key: str = "",
        author_id: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Journal a refused request (action ``refuse``) so refusals are auditable like writes.

        Records the path (for example ``mcp``), the reason, and caller-supplied detail. Never records content.
        """
        meta: Dict[str, Any] = {"path": path, "reason": reason}
        if detail:
            meta["detail"] = detail
        with self._write_tx() as cursor:
            return self._record_audit_event(
                cursor=cursor,
                action="refuse",
                category=category or "",
                key=key or "",
                scope=scope,
                value_sha256="",
                author_id=author_id,
                metadata=meta,
            )

    def supersede(
        self,
        category: str,
        old_key: str,
        new_key: str,
        new_content: str,
        metadata: Optional[Dict[str, Any]] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> MemoryEntity:
        """Atomically revoke old_key and record new_key as its superseding replacement.

        ``origin`` is passed through to :meth:`put`: the replacement asks for ``verified``, which
        under K-R1 is the author's attestation only when the origin is a principal (``user`` or
        ``import``) and is minted once ``verification_quorum`` is met.
        """
        return self.put(
            category=category,
            key=new_key,
            content=new_content,
            metadata=metadata,
            valid_from=valid_from,
            valid_until=valid_until,
            scope=scope,
            author_id=author_id,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            supersedes_key=old_key,
            supersedes_category=category,
            epistemic_state=EpistemicState.VERIFIED.value,
            origin=origin,
        )

    def put_batch(
        self,
        items: Sequence[Union[Dict[str, Any], MemoryEntity]],
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> List[MemoryEntity]:
        """Insert or update several entities, in order, each in its own transaction.

        The batch stops at the first item that fails, and the items before it stay written.
        ``fencing_token``, ``resource`` and ``holder_id`` apply to every item; a dict item may set its own.
        """
        fence = {"fencing_token": fencing_token, "resource": resource, "holder_id": holder_id}
        results: List[MemoryEntity] = []
        with self._conn:
            for item in items:
                if isinstance(item, MemoryEntity):
                    res = self.put(
                        category=item.category,
                        key=item.key,
                        content=item.content,
                        metadata=item.metadata,
                        epistemic_state=item.epistemic_state.value if isinstance(item.epistemic_state, EpistemicState) else str(item.epistemic_state),
                        valid_from=item.valid_from,
                        valid_until=item.valid_until,
                        scope=item.scope,
                        **fence,
                    )
                elif isinstance(item, dict):
                    res = self.put(**{**fence, **item})
                else:
                    raise TypeError(f"Expected dict or MemoryEntity, got {type(item)}")
                results.append(res)
        return results

    def get(
        self,
        category: str,
        key: str,
        scope: str = "default",
    ) -> Optional[MemoryEntity]:
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, category, key, content, metadata_json, version, archived, created_at, updated_at,
                   is_encrypted, encrypted_envelope_json, scope, epistemic_state, valid_from, valid_until, tenant_sig,
                   supersedes, superseded_by, origin, source_ref, confidence
            FROM entities
            WHERE category = ? AND key = ? AND scope = ?
            """,
            (category, key, scope),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        content = self._open_entry(row)  # raises EntryIntegrityError for a tampered or unsigned entry
        return self._entity(row, content)

    def archive(
        self,
        category: str,
        key: str,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> bool:
        now = time.time()
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            cursor.execute(
                """
                UPDATE entities
                SET archived = 1, updated_at = ?
                WHERE category = ? AND key = ? AND scope = ? AND archived = 0
                """,
                (now, category, key, scope),
            )
            archived = cursor.rowcount > 0
            if archived:
                self._record_audit_event(
                    cursor=cursor,
                    action="archive",
                    category=category,
                    key=key,
                    scope=scope,
                    value_sha256="",
                    author_id=author_id,
                )
                self._cascade_invalidate(cursor, scope, f"{category}:{key}", author_id, now)
            return archived

    @staticmethod
    def _entity(r: Any, content: str) -> MemoryEntity:
        """The one row-to-entity constructor, used by every read path and by the write path's return.

        Three hand-written copies of this mapping drifted apart: search and list left out origin,
        source_ref and confidence, so every entry they returned claimed origin 'unknown'. One
        constructor means a column added to the entity is added to every path or to none.
        """
        keys = r.keys()
        return MemoryEntity(
            id=r["id"],
            category=r["category"],
            key=r["key"],
            content=content,
            metadata=json.loads(r["metadata_json"]),
            version=r["version"],
            archived=bool(r["archived"]),
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            epistemic_state=EpistemicState(r["epistemic_state"]) if "epistemic_state" in keys else EpistemicState.VERIFIED,
            valid_from=r["valid_from"] if "valid_from" in keys else None,
            valid_until=r["valid_until"] if "valid_until" in keys else None,
            scope=r["scope"] if "scope" in keys else "default",
            tenant_sig=r["tenant_sig"],
            supersedes=r["supersedes"] if "supersedes" in keys else None,
            superseded_by=r["superseded_by"] if "superseded_by" in keys else None,
            origin=(r["origin"] or "unknown") if "origin" in keys else "unknown",
            source_ref=r["source_ref"] if "source_ref" in keys else None,
            confidence=r["confidence"] if "confidence" in keys else None,
        )

    def list_entities(
        self,
        category: Optional[str] = None,
        include_archived: bool = False,
        scope: str = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
        active_only: bool = False,
    ) -> List[MemoryEntity]:
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT id, category, key, content, metadata_json, version, archived, "
            "created_at, updated_at, is_encrypted, encrypted_envelope_json, "
            "scope, epistemic_state, valid_from, valid_until, tenant_sig, "
            "supersedes, superseded_by, origin, source_ref, confidence FROM entities WHERE 1=1"
        )
        params: List[Any] = []

        if not include_archived:
            query_sql += " AND archived = 0"
        if scope != "*":
            query_sql += " AND scope = ?"
            params.append(scope)
        if category:
            query_sql += " AND category = ?"
            params.append(category)
        if epistemic_state:
            query_sql += " AND epistemic_state = ?"
            params.append(epistemic_state)
        elif not include_unverified:
            query_sql += " AND epistemic_state IN ('verified', 'disputed')"
        if as_of_valid_time is not None:
            query_sql += " AND (valid_from IS NULL OR valid_from <= ?) AND (valid_until IS NULL OR valid_until > ?)"
            params.extend([as_of_valid_time, as_of_valid_time])
        elif active_only:
            now_t = time.time()
            query_sql += " AND (valid_from IS NULL OR valid_from <= ?) AND (valid_until IS NULL OR valid_until > ?)"
            params.extend([now_t, now_t])

        query_sql += " ORDER BY category, key"
        cursor.execute(query_sql, params)

        items = []
        for r in cursor.fetchall():
            content = self._readable_content(r)
            if content is None:
                continue  # failed its integrity check: tampered, damaged, or moved from another entry
            items.append(self._entity(r, content))
        return items

    def set_persona_slot(
        self,
        content: str,
        scope: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        origin: Optional[str] = "user",
    ) -> MemoryEntity:
        """Store or update the dedicated user persona / preference slot.

        The slot is the person's own profile, so ``origin`` defaults to ``"user"``: the write is its
        author's attestation and the slot is ``verified`` once ``verification_quorum`` is met
        (K-R1); below quorum it is stored as a candidate with ``verification_pending``.
        """
        meta = metadata.copy() if metadata else {}
        meta["is_persona_slot"] = True
        return self.put(
            category="persona",
            key="user_profile",
            content=content,
            metadata=meta,
            scope=scope,
            author_id=author_id,
            epistemic_state=EpistemicState.VERIFIED.value,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            origin=origin,
        )

    def get_persona_slot(
        self,
        scope: str = "default",
    ) -> Optional[MemoryEntity]:
        """Fetch the dedicated persona / preference slot for the specified scope."""
        return self.get(category="persona", key="user_profile", scope=scope)

    def get_persona_context_item(
        self,
        scope: str = "default",
        role: str = "system",
    ) -> Optional[Dict[str, Any]]:
        """Fetch persona slot formatted as a pinned Harpe ContextItem dict."""
        ent = self.get_persona_slot(scope=scope)
        if ent is None:
            return None
        return ent.to_context_item(pinned=True, priority=0, role=role)

    def validate_tenant_ownership(self, entity: MemoryEntity, expected_scope: str) -> bool:
        """Validate cryptographic HMAC ownership of an entity against expected scope (MemLeak defense)."""
        if entity.scope != expected_scope:
            return False
        if self._keyed:
            return verify_entry(
                self._signing_key, entity.scope, entity.category, entity.key, entity.content, entity.tenant_sig
            )
        if not entity.tenant_sig:
            return True  # a vault without a passphrase has no secret to sign with
        return verify_tenant_payload(
            self._signing_key,
            entity.scope,
            f"{entity.category}:{entity.key}",
            entity.content,
            entity.tenant_sig,
        )

    def close(self) -> None:
        if self._scan_cache is not None:
            self._scan_cache[1].close()
            self._scan_cache = None
        if self._tokenizer is not None:
            self._tokenizer.close()
            self._tokenizer = None
        self._conn.close()
