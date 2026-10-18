"""SQLite and FTS5 memory vault implementation for Kibisis with authenticated envelope encryption and hardened tombstones."""

from __future__ import annotations

import hashlib
import json
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
from typing import Any, Dict, List, Optional, Sequence, Union
from .crypto import AESGCMCryptoEnvelopeProvider, sign_tenant_payload, verify_tenant_payload
from .keys import MIN_PASSPHRASE_LENGTH, resolve_passphrase
from .models import AuditEvent, EncryptedEnvelope, EpistemicState, MemoryEntity, SearchResult
from .protocols import CryptoEnvelopeProvider, EncryptionRequiredError, MemoryVault


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
    ) -> None:
        """Open a vault. Entry content is encrypted by default.

        The passphrase comes from the argument, then KIBISIS_PASSPHRASE_FILE, then KIBISIS_PASSPHRASE.
        With no passphrase the vault refuses to open (EncryptionRequiredError) unless ``allow_plaintext=True``.
        An in-memory vault never touches disk, so it may run without a passphrase.
        """
        self.db_path = str(db_path)
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

        # Master key for post-retrieval HMAC tenant ownership checks (MemLeak defense)
        sig_seed = passphrase if passphrase else self.db_path
        self._signing_key = hashlib.sha256(f"kibisis-tenant-sig:{sig_seed}".encode("utf-8")).digest()

        # Check for unencrypted database migration if passphrase is provided
        if on_disk and passphrase and os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0:
            with open(self.db_path, "rb") as f:
                hdr = f.read(16)
            if hdr.startswith(b"SQLite format 3"):
                # Migrate existing plaintext SQLite database to encrypted SQLCipher database
                self._migrate_file_to_sqlcipher(self.db_path, passphrase)

        self._conn = sqlcipher3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlcipher3.Row
        if passphrase:
            escaped_pass = passphrase.replace("'", "''")
            self._conn.execute("PRAGMA cipher_memory_security = ON;")
            self._conn.execute(f"PRAGMA key = '{escaped_pass}';")
            # Verify the key immediately by accessing sqlite_master
            try:
                self._conn.execute("SELECT count(*) FROM sqlite_master;").fetchall()
            except Exception as e:
                self._conn.close()
                raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase") from e
            self._conn.execute("PRAGMA secure_delete = ON;")
        self._configure_db()
        self._init_schema()
        if passphrase and crypto_provider is None:
            self.crypto_provider = AESGCMCryptoEnvelopeProvider(salt=self._vault_salt())
        if on_disk:
            self._restrict_permissions()

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
        rows = self._conn.execute("SELECT id, category, key, scope, content FROM entities WHERE is_encrypted = 0").fetchall()
        with self._conn:
            for r in rows:
                env = self.crypto_provider.encrypt(r["content"].encode("utf-8"), self.passphrase)
                new_sig = sign_tenant_payload(self._signing_key, r["scope"], f"{r['category']}:{r['key']}", r["content"])
                self._conn.execute(
                    "UPDATE entities SET content = '', is_encrypted = 1, encrypted_envelope_json = ?, tenant_sig = ? WHERE id = ?",
                    (env.model_dump_json(), new_sig, r["id"]),
                )
        # FTS5 'delete' leaves old terms in index segments until rebuilt; WAL and free pages keep old bytes too.
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('rebuild')")
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('optimize')")
        self._conn.commit()
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._restrict_permissions()
        return {"migrated": len(rows), "remaining_plaintext": self.encryption_status()["plaintext"]}

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

            # Covering B-Tree index for bitemporal point-in-time and interval queries
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_entities_bitemporal
                ON entities (scope, category, epistemic_state, valid_from, valid_until)
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

    def _decrypt_content(self, envelope_json: Optional[str]) -> str:
        if not envelope_json:
            return ""
        if self.crypto_provider is None or not self.passphrase:
            raise PermissionError("Entity is encrypted, but vault has no crypto provider or passphrase configured.")
        envelope = EncryptedEnvelope.model_validate_json(envelope_json)
        decrypted_bytes = self.crypto_provider.decrypt(envelope, self.passphrase)
        return decrypted_bytes.decode("utf-8")

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
    ) -> MemoryEntity:
        now = time.time()
        meta = dict(metadata or {})
        if tenant_id:
            meta["tenant_id"] = tenant_id
        if principal_id:
            meta["principal_id"] = principal_id
        if derived_from:
            meta["derived_from"] = derived_from
        meta_str = json.dumps(meta, sort_keys=True)
        val_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Validate epistemic_state enum string
        ep_state = EpistemicState(epistemic_state) if epistemic_state else EpistemicState.VERIFIED

        with self._conn:
            cursor = self._conn.cursor()
            # Skip canonicalization when the vault has no tombstones. Asked of the database on every
            # write: a flag cached at open misses tombstones that other processes add later.
            cursor.execute("SELECT EXISTS (SELECT 1 FROM rejected_value_tombstones)")
            if cursor.fetchone()[0]:
                can_text = canonicalize_text(content)
                can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest() if can_text else ""
                cursor.execute(
                    """
                    SELECT reason, author_id FROM rejected_value_tombstones
                    WHERE category = ? AND (key = ? OR key = '*') AND (scope = ? OR scope = '*')
                      AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
                    """,
                    (category, key, scope, val_hash, can_hash),
                )
                tomb = cursor.fetchone()
                if tomb is not None:
                    raise ValueError(
                        f"Write rejected by tombstone: entity '{category}:{key}' [scope={scope}] matches rejected tombstone "
                        f"(digest: {val_hash[:12]}..., reason: {tomb['reason']})"
                    )

            is_encrypted = 0
            stored_content = content
            envelope_json: Optional[str] = None

            if self.crypto_provider is not None:
                if not self.passphrase:
                    raise ValueError("Crypto provider configured but no passphrase supplied to SQLiteMemoryVault.")
                envelope = self.crypto_provider.encrypt(content.encode("utf-8"), self.passphrase)
                envelope_json = envelope.model_dump_json()
                is_encrypted = 1
                # Plaintext is zeroed out to prevent leaking into entities or FTS index
                stored_content = ""

            # Cryptographic tenant signature for MemLeak isolation
            tenant_sig = sign_tenant_payload(self._signing_key, scope, f"{category}:{key}", content)

            cursor.execute(
                "SELECT id, version, created_at FROM entities WHERE category = ? AND key = ? AND scope = ?",
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
                        scope, epistemic_state, valid_from, valid_until, tenant_sig
                    )
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        category, key, stored_content, meta_str, now, now,
                        is_encrypted, envelope_json, scope, ep_state.value, valid_from, valid_until, tenant_sig
                    ),
                )
                entity_id = cursor.lastrowid
                version = 1
                created_at = now
            else:
                action = "update"
                entity_id = row["id"]
                version = row["version"] + 1
                created_at = row["created_at"]
                cursor.execute(
                    """
                    UPDATE entities
                    SET content = ?, metadata_json = ?, version = ?, archived = 0, updated_at = ?,
                        is_encrypted = ?, encrypted_envelope_json = ?, epistemic_state = ?,
                        valid_from = ?, valid_until = ?, tenant_sig = ?
                    WHERE id = ?
                    """,
                    (
                        stored_content, meta_str, version, now, is_encrypted, envelope_json,
                        ep_state.value, valid_from, valid_until, tenant_sig, entity_id
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
        )

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
        )

    def put_batch(
        self,
        items: Sequence[Union[Dict[str, Any], MemoryEntity]],
    ) -> List[MemoryEntity]:
        """Insert or update multiple entities in a single database transaction."""
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
                    )
                elif isinstance(item, dict):
                    res = self.put(**item)
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
                   is_encrypted, encrypted_envelope_json, scope, epistemic_state, valid_from, valid_until, tenant_sig
            FROM entities
            WHERE category = ? AND key = ? AND scope = ?
            """,
            (category, key, scope),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        if row["is_encrypted"] == 1:
            content = self._decrypt_content(row["encrypted_envelope_json"])
        else:
            content = row["content"]

        row_keys = row.keys()
        sig = row["tenant_sig"] if "tenant_sig" in row_keys else None
        if sig:
            if not verify_tenant_payload(self._signing_key, row["scope"], f"{row['category']}:{row['key']}", content, sig):
                raise PermissionError(f"MemLeak validation failure: invalid tenant signature for key '{key}' in scope '{scope}'.")

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
        )

    def archive(
        self,
        category: str,
        key: str,
        scope: str = "default",
        author_id: Optional[str] = None,
    ) -> bool:
        now = time.time()
        with self._conn:
            cursor = self._conn.cursor()
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
    ) -> bool:
        with self._conn:
            cursor = self._conn.cursor()
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

        where_sql = " AND ".join(where_clauses)
        params.append(limit)

        try:
            sql = f"""
                SELECT e.id, e.category, e.key, e.content, e.metadata_json, e.version, e.archived,
                       e.created_at, e.updated_at, e.is_encrypted, e.encrypted_envelope_json,
                       e.scope, e.epistemic_state, e.valid_from, e.valid_until, e.tenant_sig,
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
            fb_sql = " AND ".join(fb_clauses)
            fb_params.append(limit)
            cursor.execute(
                f"""
                SELECT id, category, key, content, metadata_json, version, archived,
                       created_at, updated_at, is_encrypted, encrypted_envelope_json,
                       scope, epistemic_state, valid_from, valid_until, tenant_sig,
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
            if r["is_encrypted"] == 1:
                try:
                    content = self._decrypt_content(r["encrypted_envelope_json"])
                except Exception:
                    content = "[ENCRYPTED]"
            else:
                content = r["content"]

            sig = r["tenant_sig"] if "tenant_sig" in r.keys() else None
            if sig and content != "[ENCRYPTED]":
                if not verify_tenant_payload(self._signing_key, r["scope"], f"{r['category']}:{r['key']}", content, sig):
                    # Cross-tenant corruption or tamper detected; skip tainted entity
                    continue

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
    ) -> List[MemoryEntity]:
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT id, category, key, content, metadata_json, version, archived, "
            "created_at, updated_at, is_encrypted, encrypted_envelope_json, "
            "scope, epistemic_state, valid_from, valid_until, tenant_sig FROM entities WHERE 1=1"
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

        query_sql += " ORDER BY category, key"
        cursor.execute(query_sql, params)

        items = []
        for r in cursor.fetchall():
            if r["is_encrypted"] == 1:
                try:
                    content = self._decrypt_content(r["encrypted_envelope_json"])
                except Exception:
                    content = "[ENCRYPTED]"
            else:
                content = r["content"]

            sig = r["tenant_sig"] if "tenant_sig" in r.keys() else None
            if sig and content != "[ENCRYPTED]":
                if not verify_tenant_payload(self._signing_key, r["scope"], f"{r['category']}:{r['key']}", content, sig):
                    # Cross-tenant corruption or tamper detected; skip tainted entity
                    continue

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
                )
            )
        return items

    def tombstone(
        self,
        category: str,
        key: str,
        reason: str = "revocation",
        author_id: Optional[str] = None,
        content: Optional[str] = None,
        scope: str = "default",
    ) -> str:
        """Tombstone entity value by SHA-256 and canonical digests within scope, then purge from live tables."""
        now = time.time()
        with self._conn:
            cursor = self._conn.cursor()
            if content is None:
                cursor.execute(
                    "SELECT content, is_encrypted, encrypted_envelope_json FROM entities WHERE category = ? AND key = ? AND scope = ?",
                    (category, key, scope),
                )
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(f"Entity not found: {category}:{key} [scope={scope}]")
                if row["is_encrypted"] == 1:
                    content = self._decrypt_content(row["encrypted_envelope_json"])
                else:
                    content = row["content"]

            assert content is not None
            val_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            can_text = canonicalize_text(content)
            can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest() if can_text else ""

            cursor.execute(
                """
                INSERT OR REPLACE INTO rejected_value_tombstones (
                    category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (category, key, val_hash, can_hash, reason, author_id, now, scope),
            )
            # Physical purge of entity and FTS index within scope
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
            return val_hash

    def is_tombstoned(
        self,
        category: str,
        key: str,
        content: str,
        scope: str = "default",
    ) -> bool:
        """Check if a specific content string is tombstoned under the given category, key, and scope (exact or canonical)."""
        val_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        can_text = canonicalize_text(content)
        can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest() if can_text else ""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT 1 FROM rejected_value_tombstones
            WHERE category = ? AND (key = ? OR key = '*') AND (scope = ? OR scope = '*')
              AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
            """,
            (category, key, scope, val_hash, can_hash),
        )
        return cursor.fetchone() is not None

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
        )

    def review_entity(
        self,
        category: str,
        key: str,
        verdict: str,
        scope: str = "default",
        reviewer_id: Optional[str] = None,
        notes: Optional[str] = None,
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
            )
            entity.archived = True
            entity.epistemic_state = EpistemicState.REVOKED
            entity.metadata = meta
            return entity

        # Update entity with new epistemic status and review metadata
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
        )

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
        if not entity.tenant_sig:
            return True
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
        for r in raw_entities:
            if r["is_encrypted"] == 1:
                content = self._decrypt_content(r["encrypted_envelope_json"])
            else:
                content = r["content"]
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
            SELECT category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope
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
            }
            for r in cursor.fetchall()
        ]

        audit_events = self.list_audit_events(limit=1_000_000)
        events_data = [ev.model_dump() for ev in audit_events]

        snapshot: Dict[str, Any] = {
            "format_version": "1.0",
            "exported_at": time.time(),
            "scope": scope or "*",
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
    ) -> int:
        """Import a snapshot into the vault.

        Validates manifest hash integrity.
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
        with self._conn:
            cursor = self._conn.cursor()
            if clear_existing:
                cursor.execute("DELETE FROM entities")
                cursor.execute("DELETE FROM entities_fts")
                cursor.execute("DELETE FROM rejected_value_tombstones")
                cursor.execute("DELETE FROM audit_log")

            for ent_data in data.get("entities", []):
                self.put(
                    category=ent_data["category"],
                    key=ent_data["key"],
                    content=ent_data["content"],
                    metadata=ent_data.get("metadata"),
                    epistemic_state=ent_data.get("epistemic_state", "verified"),
                    valid_from=ent_data.get("valid_from"),
                    valid_until=ent_data.get("valid_until"),
                    scope=ent_data.get("scope", "default"),
                )
                imported_count += 1

            for ts in data.get("tombstones", []):
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO rejected_value_tombstones (
                        category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts["category"],
                        ts["key"],
                        ts["value_sha256"],
                        ts.get("canonical_sha256", ""),
                        ts.get("reason", "imported"),
                        ts.get("author_id"),
                        ts.get("created_at", time.time()),
                        ts.get("scope", "default"),
                    ),
                )

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
