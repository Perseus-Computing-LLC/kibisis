"""SQLite and FTS5 memory vault implementation for Kibisis with authenticated envelope encryption and hardened tombstones."""

from __future__ import annotations

import hashlib
import hmac
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
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from .admission import AdmissionDecision, FactDisposition, MemoryAdmissionGate
from .crypto import (
    ENTRY_BINDING,
    ENTRY_SIGNATURE_PREFIX,
    TOMBSTONE_BINDING,
    AESGCMCryptoEnvelopeProvider,
    derive_integrity_keys,
    entry_aad,
    keyed_value_digest,
    sign_entry,
    sign_tenant_payload,
    tombstone_aad,
    verify_entry,
    verify_tenant_payload,
)
from .keys import MIN_PASSPHRASE_LENGTH, resolve_passphrase
from .models import AuditEvent, EncryptedEnvelope, EpistemicState, MemoryEntity, SearchResult
from .protocols import CryptoEnvelopeProvider, EncryptionRequiredError, LeaseConflictError, LeaseCoordinator, MemoryVault

logger = logging.getLogger(__name__)

#: Integrity format this version writes (vault_meta 'integrity_format'). Format 2 binds sealed content
#: to its entry, signs entries with a key derived by PBKDF2, keys the value digests kept in the journal
#: and in tombstones, and refuses entries without a signature. A vault without the marker is upgraded
#: the first time it is opened with its passphrase.
INTEGRITY_FORMAT = 2


def _sqlcipher_available() -> bool:
    """True when the real sqlcipher3 driver is loaded; the import above falls back to the standard sqlite3."""
    return sqlcipher3 is not sqlite3


def canonicalize_text(text: str) -> str:
    """Normalize text for evasion-resistant tombstone matching.

    Transforms text by:
    1. Unicode NFKC normalization (replaces lookalikes, fullwidth chars, compatibility ligatures)
    2. Unicode case folding (.casefold())
    3. Stripping invisible Unicode format/control characters (Cf/Cc, e.g., zero-width spaces/joiners, soft hyphens)
    4. Stripping all Unicode punctuation and symbols (replacing with space separators)
    5. Collapsing all whitespace runs into single spaces and trimming
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    chars: List[str] = []
    for ch in normalized:
        if ch.isspace():
            chars.append(" ")
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc"):
            # Drop invisible format/control characters (e.g. \u200b, \u200c, \u200d, \ufeff, \u00ad)
            continue
        if cat.startswith(("P", "S")):
            chars.append(" ")
        else:
            chars.append(ch)
    return " ".join("".join(chars).split())


def value_digests(content: str) -> Tuple[str, str]:
    """Return the (exact, canonical) SHA-256 digests a tombstone records for a value.

    The canonical digest is empty when the value canonicalizes to nothing (for example
    punctuation only); such values are matched by their exact digest alone.
    """
    exact = hashlib.sha256(content.encode("utf-8")).hexdigest()
    can_text = canonicalize_text(content)
    canonical = hashlib.sha256(can_text.encode("utf-8")).hexdigest() if can_text else ""
    return exact, canonical


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


class EntryIntegrityError(PermissionError):
    """Raised when a stored entry fails its integrity check: it has no signature, its signature does
    not verify, or its sealed content does not belong to it. ``get`` raises it; ``search`` and
    ``list_entities`` leave such an entry out."""


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
) -> str:
    """The journal's hash of one event, as _record_audit_event and verify_audit_chain compute it."""
    payload = f"{sequence}:{timestamp:.6f}:{action}:{category}:{key}:{scope}:{value_sha256}:{prev_hash}:{author_id or ''}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rekey_metadata(metadata: Dict[str, Any], digest_key: bytes) -> bool:
    """Key the plain digest a format 1 journal event keeps in its metadata, and drop digest prefixes."""
    changed = False
    if metadata.get("canonical_sha256"):
        metadata["canonical_sha256"] = keyed_value_digest(digest_key, str(metadata["canonical_sha256"]))
        changed = True
    detail = metadata.get("detail")
    if isinstance(detail, dict) and "value_digest_prefix" in detail:
        del detail["value_digest_prefix"]  # a prefix of a plain digest cannot be keyed, and still leaks
        changed = True
    return changed


def _is_reviewed(row: Any) -> bool:
    """True for an entry in the verified state or one that carries a person's review."""
    if row["epistemic_state"] == EpistemicState.VERIFIED.value:
        return True
    try:
        meta = json.loads(row["metadata_json"] or "{}")
    except (TypeError, ValueError):
        return False
    return bool(meta.get("human_reviews"))


class SQLiteMemoryVault(MemoryVault):
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
    ) -> None:
        """Open a vault. Entry content is encrypted by default.

        The passphrase comes from the argument, then KIBISIS_PASSPHRASE_FILE, then KIBISIS_PASSPHRASE.
        With no passphrase the vault refuses to open (EncryptionRequiredError) unless ``allow_plaintext=True``.
        An in-memory vault never touches disk, so it may run without a passphrase.

        With ``enforce_fencing=True`` (which needs ``coordinator``), every call that adds, changes or
        removes entries must pass the caller's current ``fencing_token`` and ``resource``, and may
        pass ``holder_id``; a missing, stale or expired token raises ``LeaseConflictError`` and
        changes nothing. Without it, a token is checked only when one is passed.
        """
        self.db_path = str(db_path)
        if crypto_provider is not None:
            _require_aad_support(crypto_provider)  # before anything touches the file
        self.coordinator = coordinator
        self.enforce_fencing = enforce_fencing
        self.auto_gate = auto_gate
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

        self._conn = sqlcipher3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlcipher3.Row
        self._sqlcipher_active = False
        if passphrase:
            escaped_pass = passphrase.replace("'", "''")
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
        self._init_schema()
        if passphrase:
            self._was_keyed = self._has_meta_key("kdf_salt")  # written by an earlier open with a passphrase
            salt = self._vault_salt()
            if crypto_provider is None:
                self.crypto_provider = AESGCMCryptoEnvelopeProvider(salt=salt)
            self._signing_key, self._digest_key = derive_integrity_keys(passphrase, salt)
            self._keyed = True
            try:
                self._upgrade_integrity()
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

        Skipped when no token or resource is passed and ``enforce_fencing`` is off. Otherwise the
        vault takes its write lock first (``BEGIN IMMEDIATE``), so a write whose token passes is
        ordered before any write by a later lease holder, never after it.
        """
        if fencing_token is None and resource is None and not self.enforce_fencing:
            return
        if not self._conn.in_transaction:
            cursor.execute("BEGIN IMMEDIATE")
        self._validate_fencing(fencing_token, resource, holder_id)

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

    def _vault_salt(self) -> bytes:
        """One random KDF salt per vault, stored beside the data. A salt is not a secret."""
        with self._conn:
            self._conn.execute("CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            row = self._conn.execute("SELECT value FROM vault_meta WHERE key = 'kdf_salt'").fetchone()
            if row is not None:
                return bytes(row[0])
            salt = os.urandom(16)
            self._conn.execute("INSERT INTO vault_meta (key, value) VALUES ('kdf_salt', ?)", (salt,))
            return salt

    def _restrict_permissions(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = self.db_path + suffix
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o600)
            except OSError:
                pass

    def encryption_status(self) -> Dict[str, int]:
        """Counts of live entries by storage form. ``plaintext`` should be 0 on an encrypted vault."""
        row = self._conn.execute(
            "SELECT COALESCE(SUM(is_encrypted = 1), 0) AS enc, COALESCE(SUM(is_encrypted = 0), 0) AS plain FROM entities"
        ).fetchone()
        return {"encrypted": int(row["enc"]), "plaintext": int(row["plain"])}

    def migrate_plaintext(self) -> Dict[str, int]:
        """Encrypt every plaintext entry in place, then remove the old plaintext from the search index,
        the write-ahead log and free pages. Returns {"migrated": n, "remaining_plaintext": m}."""
        if self.crypto_provider is None or not self.passphrase:
            raise EncryptionRequiredError("migrate_plaintext needs a passphrase.")
        rows = self._conn.execute(
            "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig "
            "FROM entities WHERE is_encrypted = 0"
        ).fetchall()
        refused = 0
        with self._conn:
            for r in rows:
                try:
                    content = self._open_entry(r)  # never seal content that fails its signature check
                except EntryIntegrityError:
                    refused += 1
                    continue
                self._write_sealed(self._conn, r, content, encrypt=True)
        self.scrub()
        return {"migrated": len(rows) - refused, "remaining_plaintext": self.encryption_status()["plaintext"]}

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

        payload_to_hash = (
            f"{seq}:{now:.6f}:{action}:{category}:{key}:{scope}:{value_sha256}:{prev_hash}:{author_id or ''}"
        )
        event_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()
        meta_json = json.dumps(meta_dict, sort_keys=True)

        cursor.execute(
            """
            INSERT INTO audit_journal (
                sequence, timestamp, action, category, key, scope, value_sha256,
                prev_hash, event_hash, author_id, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (seq, now, action, category, key, scope, value_sha256, prev_hash, event_hash, author_id, meta_json),
        )
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
        )

    # Integrity: sealing, signing and checking entries, keyed digests, and the format 2 upgrade.

    def _sign(self, scope: str, category: str, key: str, content: str) -> str:
        if self._keyed:
            return sign_entry(self._signing_key, scope, category, key, content)
        return sign_tenant_payload(self._signing_key, scope, f"{category}:{key}", content)

    def _seal(
        self, scope: str, category: str, key: str, content: str, *, encrypt: bool
    ) -> Tuple[str, int, Optional[str], str]:
        """(stored content, is_encrypted, envelope JSON, signature) for an entry. Sealed content is bound
        to the entry's scope, category and key, and its plaintext column is left empty."""
        signature = self._sign(scope, category, key, content)
        if not encrypt:
            return content, 0, None, signature
        if self.crypto_provider is None or not self.passphrase:
            raise EncryptionRequiredError("Sealing an entry needs a crypto provider and a passphrase.")
        envelope = self.crypto_provider.encrypt(
            content.encode("utf-8"), self.passphrase, aad=entry_aad(scope, category, key)
        )
        return "", 1, envelope.model_copy(update={"binding": ENTRY_BINDING}).model_dump_json(), signature

    def _write_sealed(self, cursor: Any, r: Any, content: str, *, encrypt: bool) -> None:
        """Re-seal and re-sign stored row ``r`` (with id, scope, category and key) to hold ``content``."""
        stored, is_encrypted, envelope_json, signature = self._seal(
            r["scope"], r["category"], r["key"], content, encrypt=encrypt
        )
        cursor.execute(
            "UPDATE entities SET content = ?, is_encrypted = ?, encrypted_envelope_json = ?, tenant_sig = ? WHERE id = ?",
            (stored, is_encrypted, envelope_json, signature, r["id"]),
        )

    def _open_entry(self, r: Any) -> str:
        """Content of a stored row, after its integrity checks.

        Raises :class:`EntryIntegrityError` when the row lacks a valid signature (a vault with a
        passphrase refuses unsigned rows) or its sealed content was not sealed for this entry, and a
        plain ``PermissionError`` when the row is sealed and this vault has no key.
        """
        scope, category, key = r["scope"], r["category"], r["key"]
        where = f"'{category}:{key}' [scope={scope}]"
        if r["is_encrypted"] == 1:
            if self.crypto_provider is None or not self.passphrase:
                raise PermissionError("Entity is encrypted, but vault has no crypto provider or passphrase configured.")
            try:
                envelope = EncryptedEnvelope.model_validate_json(r["encrypted_envelope_json"] or "")
            except ValueError as exc:
                raise EntryIntegrityError(f"Integrity check failed: {where} has no readable sealed content") from exc
            if envelope.binding != ENTRY_BINDING:
                raise EntryIntegrityError(f"Integrity check failed: the sealed content of {where} is not bound to it")
            try:
                content = self.crypto_provider.decrypt(
                    envelope, self.passphrase, aad=entry_aad(scope, category, key)
                ).decode("utf-8")
            except Exception as exc:
                raise EntryIntegrityError(
                    f"Integrity check failed: the sealed content of {where} was not sealed for it, or is damaged"
                ) from exc
        else:
            content = r["content"]
        signature = r["tenant_sig"]
        if self._keyed:
            if not verify_entry(self._signing_key, scope, category, key, content, signature):
                problem = "has no signature" if not signature else "has an invalid signature"
                raise EntryIntegrityError(f"Integrity check failed: {where} {problem}")
        elif signature and not verify_tenant_payload(self._signing_key, scope, f"{category}:{key}", content, signature):
            raise EntryIntegrityError(f"Integrity check failed: {where} has an invalid signature")
        return content

    def _readable_content(self, r: Any) -> Optional[str]:
        """Content for search and listing: None when the row fails its integrity check (leave it out),
        "[ENCRYPTED]" when it is sealed and this vault has no key to open it."""
        try:
            return self._open_entry(r)
        except EntryIntegrityError:
            return None
        except PermissionError:
            return "[ENCRYPTED]"

    def _open_legacy(self, r: Any) -> str:
        """Content of a row as integrity format 1 stored it (sealed without binding). Upgrade use only."""
        if r["is_encrypted"] != 1:
            return r["content"]
        envelope = EncryptedEnvelope.model_validate_json(r["encrypted_envelope_json"] or "")
        aad = entry_aad(r["scope"], r["category"], r["key"]) if envelope.binding == ENTRY_BINDING else None
        assert self.crypto_provider is not None and self.passphrase
        return self.crypto_provider.decrypt(envelope, self.passphrase, aad=aad).decode("utf-8")

    def _digests(self, value: str) -> Tuple[str, str]:
        """(exact, canonical) digests of a value as this vault stores them: keyed when it has a passphrase."""
        exact, canonical = value_digests(value)
        if self._digest_key is None:
            return exact, canonical
        return keyed_value_digest(self._digest_key, exact), keyed_value_digest(self._digest_key, canonical)

    def _digest_key_id(self) -> Optional[str]:
        """Short public identifier of the digest key, so snapshot digests can be matched to their vault."""
        if self._digest_key is None:
            return None
        return hmac.new(self._digest_key, b"kibisis digest key id", hashlib.sha256).hexdigest()[:16]

    def stored_digest(self, sha256_hex: str) -> str:
        """The form in which this vault stores a value's SHA-256 hex digest in its journal and tombstones:
        keyed when the vault has a passphrase, unchanged otherwise."""
        return keyed_value_digest(self._digest_key, sha256_hex) if self._digest_key is not None else sha256_hex

    def _stored_digests(self, exact: str, canonical: str) -> Tuple[str, str]:
        return self.stored_digest(exact), self.stored_digest(canonical)

    def _seal_digests(self, scope: str, category: str, key: str, exact: str, canonical: str) -> Optional[str]:
        """A tombstone's plain digests, sealed and bound to the tombstone, so a snapshot can carry them to
        another vault with the same passphrase. None in a vault without a passphrase."""
        if not self._keyed or self.crypto_provider is None or not self.passphrase:
            return None
        envelope = self.crypto_provider.encrypt(
            json.dumps([exact, canonical]).encode("utf-8"), self.passphrase, aad=tombstone_aad(scope, category, key)
        )
        return envelope.model_copy(update={"binding": TOMBSTONE_BINDING}).model_dump_json()

    def _unseal_digests(self, scope: str, category: str, key: str, sealed: str) -> Optional[Tuple[str, str]]:
        """Plain digests of a sealed tombstone (this vault's, or another's with the same passphrase), or None."""
        if self.crypto_provider is None or not self.passphrase:
            return None
        try:
            envelope = EncryptedEnvelope.model_validate_json(sealed)
            plain = self.crypto_provider.decrypt(envelope, self.passphrase, aad=tombstone_aad(scope, category, key))
            exact, canonical = json.loads(plain)
            return str(exact), str(canonical)
        except Exception:
            return None

    def _has_meta_key(self, key: str) -> bool:
        try:
            return self._meta(key) is not None
        except sqlcipher3.OperationalError:
            return False  # no vault_meta table: the vault was never opened with a passphrase

    def _key_check_value(self) -> str:
        return hmac.new(self._signing_key, b"kibisis key check v2", hashlib.sha256).hexdigest()

    def _meta(self, key: str) -> Any:
        row = self._conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    @staticmethod
    def _set_meta(cursor: Any, key: str, value: Any) -> None:
        cursor.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value))

    def _upgrade_integrity(self) -> None:
        """Bring an older vault up to INTEGRITY_FORMAT, then check the passphrase against the key check."""
        if int(self._meta("integrity_format") or 0) < INTEGRITY_FORMAT:
            self.integrity_upgrade = self._migrate_integrity()
        stored = self._meta("key_check")
        if stored is not None and not hmac.compare_digest(str(stored), self._key_check_value()):
            raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")
        self._integrity_format = INTEGRITY_FORMAT

    def _migrate_integrity(self) -> Optional[Dict[str, Any]]:
        """Upgrade a vault written by Kibisis 0.1.0a5 or earlier to integrity format 2, in one transaction.

        Entries: each entry whose format 1 signature verifies is re-sealed with its scope, category and
        key bound to the ciphertext and signed with the PBKDF2-derived key. An entry without a signature
        is adopted only when the file was SQLCipher-encrypted before this open, because then nothing
        without the passphrase could have removed a signature; otherwise it stays as it is and reads
        refuse it until :meth:`adopt_unsigned_entries`. Entries whose signature fails, or whose content
        does not decrypt, are left untouched and refused. Journal and tombstones: every plain SHA-256
        value digest becomes its keyed form, the journal's hashes are recomputed in order, and digest
        prefixes in refusal records are dropped. A ``migrate`` event records the counts, the old chain
        head and whether the old chain verified. Returns the counts, or None for an empty vault.
        """
        counts: Dict[str, Any] = {
            "entries_resealed": 0,
            "entries_adopted_unsigned": 0,
            "entries_left_unsigned": 0,
            "entries_failed_signature": 0,
            "entries_undecryptable": 0,
            "tombstones_rekeyed": 0,
            "journal_events_rekeyed": 0,
        }
        digest_key = self._digest_key
        assert digest_key is not None
        trust_unsigned = self._sqlcipher_active and not self._converted_to_sqlcipher
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            if int(self._meta("integrity_format") or 0) >= INTEGRITY_FORMAT:
                return None  # another process upgraded it first
            rows = cursor.execute(
                "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities"
            ).fetchall()
            tombstones = cursor.execute(
                "SELECT id, category, key, scope, value_sha256, canonical_sha256 FROM rejected_value_tombstones"
            ).fetchall()
            events = cursor.execute(
                "SELECT sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, event_hash, "
                "author_id, metadata_json FROM audit_journal ORDER BY sequence ASC"
            ).fetchall()
            if not (rows or tombstones or events):
                self._set_meta(cursor, "integrity_format", INTEGRITY_FORMAT)
                self._set_meta(cursor, "key_check", self._key_check_value())
                return None

            # A vault that never had a passphrase holds only plaintext entries, signed (if at all) with a key
            # anyone can compute, so its first open with a passphrase is where trust starts: adopt them.
            # Otherwise decide every entry before changing anything, and stop under a wrong passphrase: an
            # upgrade under the wrong key would re-key the tombstones and the journal beyond repair.
            was_keyed = self._was_keyed or any(r["is_encrypted"] == 1 for r in rows)
            if not was_keyed:
                counts["entries_adopted_from_keyless_vault"] = 0
            reseal: List[Tuple[Any, str]] = []
            opened = verified = 0
            for r in rows:
                try:
                    content = self._open_legacy(r)
                except Exception:
                    counts["entries_undecryptable"] += 1
                    continue
                if not was_keyed:
                    counts["entries_adopted_from_keyless_vault"] += 1
                    reseal.append((r, content))
                    continue
                opened += int(r["is_encrypted"] == 1)
                signature = r["tenant_sig"]
                if signature:
                    entity_id = f"{r['category']}:{r['key']}"
                    if not verify_tenant_payload(self._legacy_signing_key, r["scope"], entity_id, content, signature):
                        counts["entries_failed_signature"] += 1
                        continue
                    verified += 1
                elif trust_unsigned:
                    counts["entries_adopted_unsigned"] += 1
                else:
                    counts["entries_left_unsigned"] += 1
                    continue
                reseal.append((r, content))
            sealed_rows = sum(1 for r in rows if r["is_encrypted"] == 1)
            signed_rows = sum(1 for r in rows if r["tenant_sig"])
            if was_keyed and ((sealed_rows and not opened) or (signed_rows and not verified)):
                raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")

            for r, content in reseal:
                self._write_sealed(cursor, r, content, encrypt=r["is_encrypted"] == 1)
                counts["entries_resealed"] += 1

            for t in tombstones:
                exact, canonical = t["value_sha256"], t["canonical_sha256"] or ""
                cursor.execute(
                    "UPDATE rejected_value_tombstones SET value_sha256 = ?, canonical_sha256 = ?, sealed_digests = ? "
                    "WHERE id = ?",
                    (
                        keyed_value_digest(digest_key, exact),
                        keyed_value_digest(digest_key, canonical),
                        self._seal_digests(t["scope"], t["category"], t["key"], exact, canonical),
                        t["id"],
                    ),
                )
                counts["tombstones_rekeyed"] += 1

            old_head = events[-1]["event_hash"] if events else "0" * 64
            chain_was_valid, expected_prev = True, "0" * 64
            for ev in events:
                recomputed = _event_hash(
                    ev["sequence"], ev["timestamp"], ev["action"], ev["category"], ev["key"], ev["scope"],
                    ev["value_sha256"], ev["prev_hash"], ev["author_id"],
                )
                if ev["prev_hash"] != expected_prev or recomputed != ev["event_hash"]:
                    chain_was_valid = False
                    break
                expected_prev = ev["event_hash"]
            prev_hash = "0" * 64
            for ev in events:
                value = keyed_value_digest(digest_key, ev["value_sha256"])
                metadata = json.loads(ev["metadata_json"] or "{}")
                if _rekey_metadata(metadata, digest_key) or value != ev["value_sha256"]:
                    counts["journal_events_rekeyed"] += 1
                event_hash = _event_hash(
                    ev["sequence"], ev["timestamp"], ev["action"], ev["category"], ev["key"], ev["scope"],
                    value, prev_hash, ev["author_id"],
                )
                cursor.execute(
                    "UPDATE audit_journal SET value_sha256 = ?, prev_hash = ?, event_hash = ?, metadata_json = ? "
                    "WHERE sequence = ?",
                    (value, prev_hash, event_hash, json.dumps(metadata, sort_keys=True), ev["sequence"]),
                )
                prev_hash = event_hash
            if not chain_was_valid:
                logger.warning(
                    "%s: the audit journal did not verify before the integrity upgrade; the upgrade's "
                    "migrate event records this and the old chain head",
                    self.db_path,
                )
            self._record_audit_event(
                cursor=cursor,
                action="migrate",
                category="",
                key="",
                scope="*",
                value_sha256="",
                metadata={
                    "integrity_format": INTEGRITY_FORMAT,
                    "previous_head": old_head,
                    "previous_chain_valid": chain_was_valid,
                    **counts,
                },
            )
            self._set_meta(cursor, "integrity_format", INTEGRITY_FORMAT)
            if opened or verified or self._sqlcipher_active or not was_keyed:
                self._set_meta(cursor, "key_check", self._key_check_value())
        if counts["entries_left_unsigned"]:
            logger.warning(
                "%s: %d entries have no signature and the file had no whole-file encryption, so they cannot "
                "be told apart from tampered entries; reads refuse them until adopt_unsigned_entries() "
                "accepts them",
                self.db_path,
                counts["entries_left_unsigned"],
            )
        if self.db_path != ":memory:":
            self.scrub()  # drop the replaced digests and envelopes from free pages and the write-ahead log
        return counts

    def integrity_status(self) -> Dict[str, int]:
        """Counts of stored entries that reads refuse, found without decrypting anything (for a vault
        opened with its passphrase): ``unsigned`` (no signature), ``legacy_signature`` (a format 1
        signature) and ``unbound`` (sealed before format 2)."""
        rows = self._conn.execute("SELECT tenant_sig, is_encrypted, encrypted_envelope_json FROM entities").fetchall()

        def unbound(r: Any) -> bool:
            try:
                return json.loads(r["encrypted_envelope_json"] or "{}").get("binding") != ENTRY_BINDING
            except ValueError:
                return True

        return {
            "integrity_format": self._integrity_format,
            "entries": len(rows),
            "unsigned": sum(1 for r in rows if not r["tenant_sig"]),
            "legacy_signature": sum(
                1 for r in rows if r["tenant_sig"] and not str(r["tenant_sig"]).startswith(ENTRY_SIGNATURE_PREFIX)
            ),
            "unbound": sum(1 for r in rows if r["is_encrypted"] == 1 and unbound(r)),
        }

    def adopt_unsigned_entries(self, scope: Optional[str] = None, author_id: Optional[str] = None) -> int:
        """Sign, and bind to their entries, stored entries that carry no signature, after a person has
        checked them. Returns how many were adopted; each is journaled as an ``adopt`` event.

        Needed only for a vault upgraded from Kibisis 0.1.0a5 or earlier that ran without SQLCipher and
        holds entries written before signatures existed, or plaintext entries written while it had no
        passphrase. Kibisis cannot tell such an entry from one whose signature was removed or forged, so
        reads refuse it until it is adopted. Entries whose format 1 signature verifies under no key are
        damaged or tampered and are never adopted. ``scope`` limits adoption to one scope (``None`` or
        ``"*"``: every scope).
        """
        if not self._keyed:
            raise EncryptionRequiredError("adopt_unsigned_entries needs a vault opened with its passphrase.")
        keyless_key = hashlib.sha256(f"kibisis-tenant-sig:{self.db_path}".encode("utf-8")).digest()
        sql = (
            "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig "
            "FROM entities WHERE (tenant_sig IS NULL OR tenant_sig = '' OR tenant_sig NOT LIKE 'v2:%')"
        )
        params: List[Any] = []
        if scope not in (None, "*"):
            sql += " AND scope = ?"
            params.append(scope)
        adopted = 0
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            for r in cursor.execute(sql, params).fetchall():
                try:
                    content = self._open_legacy(r)
                except Exception:
                    continue  # does not decrypt under this passphrase: nothing to adopt
                signature, entity_id = r["tenant_sig"], f"{r['category']}:{r['key']}"
                if signature and not any(
                    verify_tenant_payload(k, r["scope"], entity_id, content, signature)
                    for k in (keyless_key, self._legacy_signing_key)
                ):
                    continue
                self._write_sealed(cursor, r, content, encrypt=r["is_encrypted"] == 1)
                self._record_audit_event(
                    cursor=cursor,
                    action="adopt",
                    category=r["category"],
                    key=r["key"],
                    scope=r["scope"],
                    value_sha256=self._digests(content)[0],
                    author_id=author_id,
                    metadata={"reason": "unsigned entry accepted by a person"},
                )
                adopted += 1
        return adopted

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
    ) -> MemoryEntity:
        """Write path behind :meth:`put`, which journals the tombstone refusals this raises."""
        if trust_ceiling is not None and trust_ceiling != EpistemicState.CANDIDATE.value:
            raise ValueError("trust_ceiling supports only 'candidate'")
        now = time.time()
        meta = dict(metadata or {})
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
            ep_state = EpistemicState(epistemic_state) if epistemic_state else EpistemicState.VERIFIED

        if trust_ceiling is not None and ep_state in (EpistemicState.VERIFIED, EpistemicState.DISPUTED):
            # Default recall returns verified and disputed entries; a capped write is neither.
            meta["trust_capped_from"] = ep_state.value
            ep_state = EpistemicState.CANDIDATE

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

        with self._conn:
            cursor = self._conn.cursor()
            self._fence(cursor, fencing_token, resource, holder_id)
            if trust_ceiling is not None:
                # A capped write cannot replace an entry a person verified or reviewed.
                cursor.execute(
                    "SELECT epistemic_state, metadata_json FROM entities WHERE category = ? AND key = ? AND scope = ?",
                    (category, key, scope),
                )
                existing = cursor.fetchone()
                if existing is not None and _is_reviewed(existing):
                    raise ReviewedEntryError(
                        f"'{category}:{key}' [scope={scope}] is verified or reviewed by a person; a capped write "
                        "cannot replace it. Write a new key with supersedes_key to propose a replacement."
                    )

            # Invalidate older entity if superseding is declared
            if supersedes_key:
                target_cat = supersedes_category or category
                cursor.execute(
                    "SELECT id, metadata_json, epistemic_state FROM entities WHERE category = ? AND key = ? AND scope = ? AND archived = 0",
                    (target_cat, supersedes_key, scope),
                )
                target_row = cursor.fetchone()
                if target_row is not None and trust_ceiling is not None and _is_reviewed(target_row):
                    # A capped write cannot retire a reviewed entry. Record the proposal instead;
                    # review_entity applies it when a person approves this entry.
                    meta.pop("supersedes", None)
                    meta["proposed_supersedes"] = {"category": target_cat, "key": supersedes_key}
                    meta_str = json.dumps(meta, sort_keys=True)
                    supersedes_ref = None
                    target_row = None
                if target_row is not None:
                    target_meta = json.loads(target_row["metadata_json"] or "{}")
                    target_meta["superseded_by"] = f"{category}:{key}"
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
                "SELECT id, version, created_at, supersedes, superseded_by FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            row = cursor.fetchone()

            if row is None:
                action = "put"
                cursor.execute(
                    """
                    INSERT INTO entities (
                        category, key, content, metadata_json, version, archived,
                        created_at, updated_at, is_encrypted, encrypted_envelope_json,
                        scope, epistemic_state, valid_from, valid_until, tenant_sig,
                        supersedes, superseded_by
                    )
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        category, key, stored_content, meta_str, now, now,
                        is_encrypted, envelope_json, scope, ep_state.value, valid_from, valid_until, tenant_sig,
                        supersedes_ref
                    ),
                )
                entity_id = cursor.lastrowid
                version = 1
                created_at = now
                existing_superseded_by = None
            else:
                action = "update"
                entity_id = row["id"]
                version = row["version"] + 1
                created_at = row["created_at"]
                existing_superseded_by = row["superseded_by"]
                cursor.execute(
                    """
                    UPDATE entities
                    SET content = ?, metadata_json = ?, version = ?, archived = 0, updated_at = ?,
                        is_encrypted = ?, encrypted_envelope_json = ?, epistemic_state = ?,
                        valid_from = ?, valid_until = ?, tenant_sig = ?,
                        supersedes = COALESCE(?, supersedes)
                    WHERE id = ?
                    """,
                    (
                        stored_content, meta_str, version, now, is_encrypted, envelope_json,
                        ep_state.value, valid_from, valid_until, tenant_sig, supersedes_ref, entity_id
                    ),
                )

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

        return MemoryEntity(
            id=entity_id,
            category=category,
            key=key,
            content=content,
            metadata=meta,
            version=version,
            archived=False,
            created_at=created_at,
            updated_at=now,
            epistemic_state=ep_state,
            valid_from=valid_from,
            valid_until=valid_until,
            scope=scope,
            tenant_sig=tenant_sig,
            supersedes=supersedes_ref or meta.get("supersedes"),
            superseded_by=existing_superseded_by or meta.get("superseded_by"),
        )

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
    ) -> MemoryEntity:
        """Insert or update an entity. See ``__init__`` for ``fencing_token``, ``resource`` and ``holder_id``.

        ``trust_ceiling="candidate"`` caps the stored state: a write that the admission gate or the
        ``epistemic_state`` argument would store as ``verified`` or ``disputed`` is stored as
        ``candidate``, and the write cannot replace or supersede an entry a person verified or
        reviewed (it raises :class:`ReviewedEntryError`, or records the supersession as a proposal
        that :meth:`review_entity` applies on approval). Write paths that carry model output (the
        MCP server) set it, so trust comes from the path, not from the payload.

        ``author_id`` is recorded in the entity's metadata and in the audit journal. A write whose
        value a tombstone rejects raises :class:`TombstonedValueError`, and the refusal is journaled.
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
        with self._conn:
            cursor = self._conn.cursor()
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
    ) -> MemoryEntity:
        """Atomically revoke old_key and record new_key as its superseding replacement."""
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
                   supersedes, superseded_by
            FROM entities
            WHERE category = ? AND key = ? AND scope = ?
            """,
            (category, key, scope),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        content = self._open_entry(row)  # raises EntryIntegrityError for a tampered or unsigned entry
        row_keys = row.keys()
        sig = row["tenant_sig"]

        return MemoryEntity(
            id=row["id"],
            category=row["category"],
            key=row["key"],
            content=content,
            metadata=json.loads(row["metadata_json"]),
            version=row["version"],
            archived=bool(row["archived"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            epistemic_state=EpistemicState(row["epistemic_state"]) if "epistemic_state" in row_keys else EpistemicState.VERIFIED,
            valid_from=row["valid_from"] if "valid_from" in row_keys else None,
            valid_until=row["valid_until"] if "valid_until" in row_keys else None,
            scope=row["scope"] if "scope" in row_keys else "default",
            tenant_sig=sig,
            supersedes=row["supersedes"] if "supersedes" in row_keys else None,
            superseded_by=row["superseded_by"] if "superseded_by" in row_keys else None,
        )

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
        with self._conn:
            cursor = self._conn.cursor()
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
            return archived

    def purge(
        self,
        category: str,
        key: str,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> bool:
        with self._conn:
            cursor = self._conn.cursor()
            self._fence(cursor, fencing_token, resource, holder_id)
            cursor.execute(
                "DELETE FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            purged = cursor.rowcount > 0
            if purged:
                self._record_audit_event(
                    cursor=cursor,
                    action="purge",
                    category=category,
                    key=key,
                    scope=scope,
                    value_sha256="",
                    author_id=author_id,
                )
            return purged

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
        scope: Optional[str] = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
        active_only: bool = True,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        authorized_lineage_roots: Optional[List[str]] = None,
    ) -> List[SearchResult]:
        if not query.strip():
            return []

        clean_terms = [t for t in query.replace('"', '""').split() if t]
        if not clean_terms:
            return []
        fts_query = " ".join(f'"{t}"*' for t in clean_terms)

        results: List[SearchResult] = []
        cursor = self._conn.cursor()

        # Normalize scope: None or empty string defaults to "default"
        target_scope = "default" if scope is None or scope == "" else scope

        # Build dynamic SQL WHERE conditions for scope, epistemic status, and validity bounds
        where_clauses = ["entities_fts MATCH ?", "e.archived = 0"]
        params: List[Any] = [fts_query]
        if target_scope != "*":
            where_clauses.append("e.scope = ?")
            params.append(target_scope)

        if category:
            where_clauses.append("e.category = ?")
            params.append(category)

        if epistemic_state:
            where_clauses.append("e.epistemic_state = ?")
            params.append(epistemic_state)
        elif not include_unverified:
            # Epistemic polarity: unverified candidate/revoked memories withheld from active recall unless explicitly requested
            where_clauses.append("e.epistemic_state IN ('verified', 'disputed')")

        if as_of_valid_time is not None:
            # Bi-temporal point-in-time filter: valid_from <= T and (valid_until IS NULL or valid_until > T)
            where_clauses.append("(e.valid_from IS NULL OR e.valid_from <= ?)")
            where_clauses.append("(e.valid_until IS NULL OR e.valid_until > ?)")
            params.extend([as_of_valid_time, as_of_valid_time])
        elif active_only:
            now_t = time.time()
            where_clauses.append("(e.valid_from IS NULL OR e.valid_from <= ?)")
            where_clauses.append("(e.valid_until IS NULL OR e.valid_until > ?)")
            params.extend([now_t, now_t])

        where_sql = " AND ".join(where_clauses)
        params.append(limit)

        try:
            sql = f"""
                SELECT e.id, e.category, e.key, e.content, e.metadata_json, e.version, e.archived,
                       e.created_at, e.updated_at, e.is_encrypted, e.encrypted_envelope_json,
                       e.scope, e.epistemic_state, e.valid_from, e.valid_until, e.tenant_sig,
                       e.supersedes, e.superseded_by,
                       rank, snippet(entities_fts, 2, '<b>', '</b>', '...', 16) AS snip
                FROM entities_fts
                JOIN entities e ON e.id = entities_fts.rowid
                WHERE {where_sql}
                ORDER BY rank
                LIMIT ?
            """
            cursor.execute(sql, params)
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            # Fallback for environments where FTS query syntax or schema differs
            pattern = f"%{query}%"
            fb_clauses = ["(content LIKE ? OR key LIKE ?)", "archived = 0"]
            fb_params: List[Any] = [pattern, pattern]
            if target_scope != "*":
                fb_clauses.append("scope = ?")
                fb_params.append(target_scope)
            if category:
                fb_clauses.append("category = ?")
                fb_params.append(category)
            if epistemic_state:
                fb_clauses.append("epistemic_state = ?")
                fb_params.append(epistemic_state)
            elif not include_unverified:
                fb_clauses.append("epistemic_state IN ('verified', 'disputed')")
            if as_of_valid_time is not None:
                fb_clauses.append("(valid_from IS NULL OR valid_from <= ?)")
                fb_clauses.append("(valid_until IS NULL OR valid_until > ?)")
                fb_params.extend([as_of_valid_time, as_of_valid_time])
            elif active_only:
                now_t = time.time()
                fb_clauses.append("(valid_from IS NULL OR valid_from <= ?)")
                fb_clauses.append("(valid_until IS NULL OR valid_until > ?)")
                fb_params.extend([now_t, now_t])
            fb_sql = " AND ".join(fb_clauses)
            fb_params.append(limit)
            cursor.execute(
                f"""
                SELECT id, category, key, content, metadata_json, version, archived,
                       created_at, updated_at, is_encrypted, encrypted_envelope_json,
                       scope, epistemic_state, valid_from, valid_until, tenant_sig,
                       supersedes, superseded_by,
                       0.0 as rank, '' as snip
                FROM entities
                WHERE {fb_sql}
                LIMIT ?
                """,
                fb_params,
            )
            rows = cursor.fetchall()

        matched_ids = set()
        for r in rows:
            matched_ids.add(r["id"])
            content = self._readable_content(r)
            if content is None:
                continue  # failed its integrity check: tampered, damaged, or moved from another entry
            sig = r["tenant_sig"]

            entity = MemoryEntity(
                id=r["id"],
                category=r["category"],
                key=r["key"],
                content=content,
                metadata=json.loads(r["metadata_json"]),
                version=r["version"],
                archived=bool(r["archived"]),
                created_at=r["created_at"],
                updated_at=r["updated_at"],
                epistemic_state=EpistemicState(r["epistemic_state"]) if "epistemic_state" in r.keys() else EpistemicState.VERIFIED,
                valid_from=r["valid_from"] if "valid_from" in r.keys() else None,
                valid_until=r["valid_until"] if "valid_until" in r.keys() else None,
                scope=r["scope"] if "scope" in r.keys() else "default",
                tenant_sig=sig,
                supersedes=r["supersedes"] if "supersedes" in r.keys() else None,
                superseded_by=r["superseded_by"] if "superseded_by" in r.keys() else None,
            )
            results.append(SearchResult(entity=entity, rank_score=float(r["rank"]), snippet=str(r["snip"])))

        # If encrypted and user searched for content terms that weren't indexed in plaintext FTS,
        # scan active entities within scope if we have crypto provider and haven't hit limit:
        if self.crypto_provider is not None and len(results) < limit:
            query_lower = query.lower().strip()
            terms = [t.lower() for t in query.split() if len(t) >= 2]
            all_entities = self.list_entities(
                category=category,
                include_archived=False,
                scope=target_scope,
                epistemic_state=epistemic_state,
                as_of_valid_time=as_of_valid_time,
                include_unverified=include_unverified,
                active_only=active_only,
            )
            for ent in all_entities:
                if ent.id in matched_ids:
                    continue
                ent_text = f"{ent.category} {ent.key} {ent.content}".lower()
                if query_lower in ent_text or (terms and all(t in ent_text for t in terms)):
                    results.append(SearchResult(entity=ent, rank_score=-0.5, snippet=f"...{query}..."))
                    matched_ids.add(ent.id)
                    if len(results) >= limit:
                        break

        # Hard post-retrieval governance gating (MemLeak arXiv:2610.04195 & Lineage AMU arXiv:2610.07258)
        filtered_results: List[SearchResult] = []
        for res in results:
            meta = res.entity.metadata or {}
            # 1. Hard tenant boundary check
            if tenant_id and meta.get("tenant_id") and meta.get("tenant_id") != tenant_id:
                continue
            # 2. Hard principal/user boundary check if specified
            if principal_id and meta.get("principal_id") and meta.get("principal_id") != principal_id:
                continue
            # 3. Derivation-gated lineage check (AMU)
            if authorized_lineage_roots is not None:
                ent_lineage = meta.get("derived_from", [])
                if any(root not in authorized_lineage_roots for root in ent_lineage):
                    continue
            filtered_results.append(res)

        return filtered_results

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
            "supersedes, superseded_by FROM entities WHERE 1=1"
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
            sig = r["tenant_sig"]

            items.append(
                MemoryEntity(
                    id=r["id"],
                    category=r["category"],
                    key=r["key"],
                    content=content,
                    metadata=json.loads(r["metadata_json"]),
                    version=r["version"],
                    archived=bool(r["archived"]),
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                    epistemic_state=EpistemicState(r["epistemic_state"]) if "epistemic_state" in r.keys() else EpistemicState.VERIFIED,
                    valid_from=r["valid_from"] if "valid_from" in r.keys() else None,
                    valid_until=r["valid_until"] if "valid_until" in r.keys() else None,
                    scope=r["scope"] if "scope" in r.keys() else "default",
                    tenant_sig=sig,
                    supersedes=r["supersedes"] if "supersedes" in r.keys() else None,
                    superseded_by=r["superseded_by"] if "superseded_by" in r.keys() else None,
                )
            )
        return items

    @staticmethod
    def _find_tombstone(cursor: Any, scope: str, val_hash: str, can_hash: str) -> Optional[Any]:
        """Return the first tombstone in ``scope`` (or a ``'*'`` tombstone) that rejects this value.

        Category and key play no part: a tombstone stops a value, not a key, so a rejected value
        cannot come back under a new key or category. Scopes stay separate, so one tenant's
        rejection neither blocks nor reveals another tenant's writes.
        """
        cursor.execute(
            """
            SELECT category, key, reason, author_id FROM rejected_value_tombstones
            WHERE (scope = ? OR scope = '*')
              AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
            LIMIT 1
            """,
            (scope, val_hash, can_hash),
        )
        return cursor.fetchone()

    def _purge_value_copies(
        self,
        cursor: Any,
        scope: str,
        val_hash: str,
        can_hash: str,
        author_id: Optional[str],
        tombstoned: str,
    ) -> int:
        """Delete every stored copy of a tombstoned value in ``scope`` (every scope for ``'*'``).

        Copies under other categories or keys, live or archived, would otherwise keep a rejected
        value retrievable. Each deletion is journaled in the caller's transaction.
        """
        if scope == "*":
            cursor.execute("SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities")
        else:
            cursor.execute(
                "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities WHERE scope = ?",
                (scope,),
            )
        purged = 0
        for row in cursor.fetchall():
            try:
                content = self._open_entry(row)
            except PermissionError:
                continue  # an entry that cannot be opened cannot be compared, and is never returned
            exact, canonical = self._digests(content)
            if exact != val_hash and not (can_hash and canonical == can_hash):
                continue
            cursor.execute("DELETE FROM entities WHERE id = ?", (row["id"],))
            self._record_audit_event(
                cursor=cursor,
                action="purge",
                category=row["category"],
                key=row["key"],
                scope=row["scope"],
                value_sha256=exact,
                author_id=author_id,
                metadata={"reason": "copy of tombstoned value", "tombstone": tombstoned},
            )
            purged += 1
        return purged

    def tombstone(
        self,
        category: str,
        key: str,
        reason: str = "revocation",
        author_id: Optional[str] = None,
        content: Optional[str] = None,
        scope: str = "default",
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> str:
        """Tombstone a value by its exact and canonical SHA-256 digests within ``scope``.

        Purges the entity at ``category:key`` and every other copy of the value in the scope
        (all scopes when ``scope`` is ``'*'``). Later writes of the value, or of a look-alike that
        canonicalizes to it, are refused under any category or key in the scope. Returns the value's
        SHA-256 hex digest; a vault with a passphrase stores it keyed (see :meth:`stored_digest`).
        """
        now = time.time()
        with self._conn:
            cursor = self._conn.cursor()
            self._fence(cursor, fencing_token, resource, holder_id)
            if content is None:
                cursor.execute(
                    "SELECT category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities "
                    "WHERE category = ? AND key = ? AND scope = ?",
                    (category, key, scope),
                )
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(f"Entity not found: {category}:{key} [scope={scope}]")
                content = self._open_entry(row)

            assert content is not None
            plain_exact, plain_canonical = value_digests(content)
            val_hash, can_hash = self._stored_digests(plain_exact, plain_canonical)

            cursor.execute(
                """
                INSERT OR REPLACE INTO rejected_value_tombstones (
                    category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                    sealed_digests
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    category, key, val_hash, can_hash, reason, author_id, now, scope,
                    self._seal_digests(scope, category, key, plain_exact, plain_canonical),
                ),
            )
            # Physical purge of the entity (the FTS index follows through triggers)
            cursor.execute("DELETE FROM entities WHERE category = ? AND key = ? AND scope = ?", (category, key, scope))

            # Record hash-chained mutation audit event
            self._record_audit_event(
                cursor=cursor,
                action="tombstone",
                category=category,
                key=key,
                scope=scope,
                value_sha256=val_hash,
                author_id=author_id,
                metadata={"reason": reason, "canonical_sha256": can_hash},
            )
            self._purge_value_copies(cursor, scope, val_hash, can_hash, author_id, f"{category}:{key}")
            return plain_exact

    def is_tombstoned(
        self,
        category: str,
        key: str,
        content: str,
        scope: str = "default",
    ) -> bool:
        """Check whether ``content`` is rejected in ``scope`` (exact or canonical digest).

        ``category`` and ``key`` are accepted for compatibility but do not narrow the check: a
        tombstoned value is rejected under every category and key in its scope.
        """
        val_hash, can_hash = self._digests(content)
        return self._find_tombstone(self._conn.cursor(), scope, val_hash, can_hash) is not None

    def list_tombstones(
        self,
        category: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tombstone records containing only digests, reason, author, scope, and timestamp (never plaintext)."""
        cursor = self._conn.cursor()
        query_sql = "SELECT id, category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope FROM rejected_value_tombstones WHERE 1=1"
        params: List[Any] = []
        if category:
            query_sql += " AND category = ?"
            params.append(category)
        if scope:
            query_sql += " AND (scope = ? OR scope = '*')"
            params.append(scope)
        query_sql += " ORDER BY id"
        cursor.execute(query_sql, params)
        return [dict(r) for r in cursor.fetchall()]

    def admit_candidate(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
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
    ) -> MemoryEntity:
        """Stage an unverified memory candidate into the vault awaiting verification/human review."""
        return self.put(
            category=category,
            key=key,
            content=content,
            metadata=metadata,
            epistemic_state=EpistemicState.CANDIDATE.value,
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
        )

    def review_entity(
        self,
        category: str,
        key: str,
        verdict: str,
        scope: str = "default",
        reviewer_id: Optional[str] = None,
        notes: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> MemoryEntity:
        """Human review gate: update epistemic state based on review decision (verified, disputed, revoked)."""
        valid_verdicts = {EpistemicState.VERIFIED.value, EpistemicState.DISPUTED.value, EpistemicState.REVOKED.value}
        if verdict not in valid_verdicts:
            raise ValueError(f"Verdict must be one of {valid_verdicts}, got '{verdict}'")

        entity = self.get(category=category, key=key, scope=scope)
        if entity is None:
            raise KeyError(f"Entity not found for review: {category}:{key} [scope={scope}]")

        meta = dict(entity.metadata)
        reviews = meta.get("human_reviews", [])
        reviews.append({
            "timestamp": time.time(),
            "reviewer_id": reviewer_id,
            "verdict": verdict,
            "notes": notes or "",
            "previous_state": entity.epistemic_state.value,
        })
        meta["human_reviews"] = reviews

        if verdict == EpistemicState.REVOKED.value:
            # Revocation initiates tombstone recording and purges plaintext
            self.tombstone(
                category=category,
                key=key,
                reason=f"Human review rejected: {notes or 'revoked'}",
                author_id=reviewer_id,
                scope=scope,
                fencing_token=fencing_token,
                resource=resource,
                holder_id=holder_id,
            )
            entity.archived = True
            entity.epistemic_state = EpistemicState.REVOKED
            entity.metadata = meta
            return entity

        # Update entity with new epistemic status and review metadata. Approving an entry that proposed
        # to supersede a reviewed entry applies the supersession now, under the reviewer's authority.
        proposal = meta.pop("proposed_supersedes", None) if verdict == EpistemicState.VERIFIED.value else None
        if proposal:
            meta["supersession_approved_by"] = reviewer_id
        return self.put(
            category=category,
            key=key,
            content=entity.content,
            metadata=meta,
            epistemic_state=verdict,
            valid_from=entity.valid_from,
            valid_until=entity.valid_until,
            scope=scope,
            author_id=reviewer_id,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            supersedes_key=proposal["key"] if proposal else None,
            supersedes_category=proposal["category"] if proposal else None,
        )

    def scrub(self) -> None:
        """Remove deleted or replaced content from the search index, the write-ahead log and free pages.

        FTS5 'delete' leaves old terms in index segments until the index is rebuilt, and the
        write-ahead log and free pages keep old bytes until a checkpoint and VACUUM. Run after a
        delete (the MCP server's forget does) or after migrating plaintext.
        """
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('rebuild')")
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('optimize')")
        self._conn.commit()
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._restrict_permissions()

    def list_audit_events(
        self,
        scope: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Fetch chronological audit records from the tamper-evident hash chain."""
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT sequence, timestamp, action, category, key, scope, value_sha256, "
            "prev_hash, event_hash, author_id, metadata_json FROM audit_journal WHERE 1=1"
        )
        params: List[Any] = []
        if scope:
            query_sql += " AND scope = ?"
            params.append(scope)
        if category:
            query_sql += " AND category = ?"
            params.append(category)
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
                )
            )
        return events

    def verify_audit_chain(self, scope: Optional[str] = None) -> bool:
        """Verify the cryptographic integrity of the append-only mutation journal hash chain."""
        # Always verify the entire hash chain (or records up to limit), because prev_hash links consecutive global events
        events = self.list_audit_events(scope=None, limit=1_000_000)
        if not events:
            return True

        expected_prev = "0" * 64
        for ev in events:
            if ev.prev_hash != expected_prev:
                return False
            payload = (
                f"{ev.sequence}:{ev.timestamp:.6f}:{ev.action}:{ev.category}:{ev.key}:{ev.scope}:{ev.value_sha256}:{ev.prev_hash}:{ev.author_id or ''}"
            )
            recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if recomputed != ev.event_hash:
                return False
            expected_prev = ev.event_hash
        return True

    def set_persona_slot(
        self,
        content: str,
        scope: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> MemoryEntity:
        """Store or update the dedicated user persona / preference slot."""
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

    def export_snapshot(
        self,
        path: Optional[Union[str, Path]] = None,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Export a deterministic, portable snapshot of entities, tombstones, and audit events.

        Computes a SHA-256 integrity manifest over the exported payload.
        If path is provided, writes the serialized JSON atomically to disk.
        """
        cursor = self._conn.cursor()

        if scope and scope != "*":
            cursor.execute(
                """
                SELECT category, key, content, metadata_json, version, archived,
                       created_at, updated_at, is_encrypted, encrypted_envelope_json,
                       scope, epistemic_state, valid_from, valid_until, tenant_sig
                FROM entities
                WHERE scope = ?
                ORDER BY scope, category, key
                """,
                (scope,),
            )
        else:
            cursor.execute(
                """
                SELECT category, key, content, metadata_json, version, archived,
                       created_at, updated_at, is_encrypted, encrypted_envelope_json,
                       scope, epistemic_state, valid_from, valid_until, tenant_sig
                FROM entities
                ORDER BY scope, category, key
                """
            )

        raw_entities = cursor.fetchall()
        entities_data = []
        unreadable = 0
        for r in raw_entities:
            try:
                content = self._open_entry(r)
            except EntryIntegrityError:
                unreadable += 1  # failed its integrity check; never exported
                continue
            entities_data.append({
                "category": r["category"],
                "key": r["key"],
                "content": content,
                "metadata": json.loads(r["metadata_json"]),
                "version": r["version"],
                "archived": bool(r["archived"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "scope": r["scope"],
                "epistemic_state": r["epistemic_state"],
                "valid_from": r["valid_from"],
                "valid_until": r["valid_until"],
            })

        cursor.execute(
            """
            SELECT category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                   sealed_digests
            FROM rejected_value_tombstones
            ORDER BY category, key, scope
            """
        )
        tombstones_data = [
            {
                "category": r["category"],
                "key": r["key"],
                "value_sha256": r["value_sha256"],
                "canonical_sha256": r["canonical_sha256"],
                "reason": r["reason"],
                "author_id": r["author_id"],
                "created_at": r["created_at"],
                "scope": r["scope"],
                "sealed_digests": r["sealed_digests"],
            }
            for r in cursor.fetchall()
        ]

        audit_events = self.list_audit_events(limit=1_000_000)
        events_data = [ev.model_dump() for ev in audit_events]

        snapshot: Dict[str, Any] = {
            "format_version": "1.1",
            "exported_at": time.time(),
            "scope": scope or "*",
            # Tombstone and journal digests: plain SHA-256 in a vault without a passphrase, otherwise keyed
            # to this vault (digest_key_id). A tombstone's sealed_digests let a vault with the same
            # passphrase re-key it on import.
            "digest_scheme": "hmac-sha256" if self._digest_key is not None else "sha256",
            "digest_key_id": self._digest_key_id(),
            "unreadable_entity_count": unreadable,
            "entity_count": len(entities_data),
            "tombstone_count": len(tombstones_data),
            "audit_event_count": len(events_data),
            "entities": entities_data,
            "tombstones": tombstones_data,
            "audit_events": events_data,
        }

        canonical_bytes = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        snapshot["manifest_sha256"] = manifest_sha256

        if path is not None:
            out_p = Path(path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            tmp_p = out_p.with_suffix(f".tmp.{os.getpid()}")
            with open(tmp_p, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, sort_keys=True)
            tmp_p.replace(out_p)

        return snapshot

    def import_snapshot(
        self,
        snapshot_or_path: Union[str, Path, Dict[str, Any]],
        *,
        clear_existing: bool = False,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> int:
        """Import a snapshot into the vault.

        Validates manifest hash integrity. Tombstones are imported first and existing tombstones
        are never removed, so restoring a snapshot taken before a deletion cannot bring the
        deleted value back: entities whose value is tombstoned in their scope are refused and not
        counted. ``clear_existing`` purges current entities (journaled) but keeps tombstones and
        the audit journal. Archived entities are restored archived.

        Returns the number of restored entities.
        """
        if isinstance(snapshot_or_path, (str, Path)):
            with open(snapshot_or_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        elif isinstance(snapshot_or_path, dict):
            data = snapshot_or_path
        else:
            raise TypeError("Expected snapshot dict or path")

        manifest_sha = data.get("manifest_sha256")
        if manifest_sha:
            check_data = {k: v for k, v in data.items() if k != "manifest_sha256"}
            canonical_bytes = json.dumps(check_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            recomputed = hashlib.sha256(canonical_bytes).hexdigest()
            if recomputed != manifest_sha:
                raise ValueError(f"Snapshot integrity violation: manifest mismatch {recomputed} != {manifest_sha}")

        imported_count = 0
        foreign_tombstones = 0
        scheme = data.get("digest_scheme", "sha256")
        same_key = (
            scheme == "hmac-sha256" and self._digest_key is not None and data.get("digest_key_id") == self._digest_key_id()
        )
        with self._conn:
            cursor = self._conn.cursor()
            self._fence(cursor, fencing_token, resource, holder_id)
            for ts in data.get("tombstones", []):
                t_scope, t_category, t_key = ts.get("scope", "default"), ts["category"], ts["key"]
                exact, canonical = ts["value_sha256"], ts.get("canonical_sha256", "")
                sealed = ts.get("sealed_digests")
                if not same_key:
                    plain: Optional[Tuple[str, str]] = None
                    if scheme == "sha256":
                        plain = (exact, canonical)
                    elif sealed and self._keyed:
                        plain = self._unseal_digests(t_scope, t_category, t_key, sealed)
                    if plain is None:
                        foreign_tombstones += 1  # from a vault with another passphrase: it cannot match here
                        continue
                    exact, canonical = self._stored_digests(*plain)
                    sealed = self._seal_digests(t_scope, t_category, t_key, *plain)
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO rejected_value_tombstones (
                        category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                        sealed_digests
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        t_category,
                        t_key,
                        exact,
                        canonical,
                        ts.get("reason", "imported"),
                        ts.get("author_id"),
                        ts.get("created_at", time.time()),
                        t_scope,
                        sealed,
                    ),
                )
            if clear_existing:
                cursor.execute("SELECT category, key, scope FROM entities")
                for row in cursor.fetchall():
                    self._record_audit_event(
                        cursor=cursor,
                        action="purge",
                        category=row["category"],
                        key=row["key"],
                        scope=row["scope"],
                        value_sha256="",
                        metadata={"reason": "import_snapshot clear_existing"},
                    )
                cursor.execute("DELETE FROM entities")
                # entities_fts is an external-content index kept in step by triggers; rebuild it
                # from the (now empty) content table rather than deleting index rows directly.
                cursor.execute("INSERT INTO entities_fts(entities_fts) VALUES('rebuild')")

        if foreign_tombstones:
            logger.warning(
                "import_snapshot: %d tombstones come from a vault with another passphrase and cannot apply here",
                foreign_tombstones,
            )
            self.record_refusal(
                path="import_snapshot",
                reason="tombstones from a vault with another passphrase",
                scope="*",
                detail={"tombstones": foreign_tombstones},
            )

        for ent_data in data.get("entities", []):
            scope = ent_data.get("scope", "default")
            val_hash, can_hash = self._digests(ent_data["content"])
            if self._find_tombstone(self._conn.cursor(), scope, val_hash, can_hash) is not None:
                self.record_refusal(
                    path="import_snapshot",
                    reason="tombstoned value",
                    scope=scope,
                    category=ent_data.get("category", ""),
                    key=ent_data.get("key", ""),
                    detail={"value_digest_prefix": val_hash[:12]},
                )
                continue
            self.put(
                category=ent_data["category"],
                key=ent_data["key"],
                content=ent_data["content"],
                metadata=ent_data.get("metadata"),
                epistemic_state=ent_data.get("epistemic_state", "verified"),
                valid_from=ent_data.get("valid_from"),
                valid_until=ent_data.get("valid_until"),
                scope=scope,
                fencing_token=fencing_token,
                resource=resource,
                holder_id=holder_id,
            )
            if ent_data.get("archived"):
                self.archive(
                    category=ent_data["category"],
                    key=ent_data["key"],
                    scope=scope,
                    fencing_token=fencing_token,
                    resource=resource,
                    holder_id=holder_id,
                )
            imported_count += 1

        return imported_count

    def evaluate_epistemic_abstention(
        self,
        negative_probes: List[str],
        scope: str = "default",
    ) -> Dict[str, Any]:
        """Evaluate vault abstention on negative out-of-scope probes.

        Ensures the vault does not return fabricated or false positive recall results
        when probed with out-of-scope or non-existent topics.
        """
        total = len(negative_probes)
        abstained = 0
        false_positives = []

        for probe in negative_probes:
            res = self.search(probe, scope=scope)
            if len(res) == 0:
                abstained += 1
            else:
                false_positives.append({
                    "probe": probe,
                    "matched_keys": [r.entity.key for r in res],
                })

        abstention_rate = (abstained / total) if total > 0 else 1.0
        return {
            "total_probes": total,
            "abstained_count": abstained,
            "false_positive_count": len(false_positives),
            "abstention_rate": abstention_rate,
            "false_positives": false_positives,
            "perfect_abstention": (abstained == total),
        }

    def close(self) -> None:
        self._conn.close()
