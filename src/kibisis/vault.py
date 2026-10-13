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
from typing import Any, Dict, List, Optional
from .crypto import AESGCMCryptoEnvelopeProvider
from .keys import MIN_PASSPHRASE_LENGTH, resolve_passphrase
from .models import AuditEvent, EncryptedEnvelope, EpistemicState, MemoryEntity, SearchResult
from .protocols import CryptoEnvelopeProvider, EncryptionRequiredError, MemoryVault


def canonicalize_text(text: str) -> str:
    """Normalize text for evasion-resistant tombstone matching.

    Transforms text by:
    1. Unicode NFKC normalization (replaces lookalikes, fullwidth chars, etc.)
    2. Case folding (.lower())
    3. Stripping all unicode punctuation and symbols
    4. Collapsing all whitespace runs into single spaces and trimming
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text).lower()
    chars = [(" " if unicodedata.category(ch).startswith(("P", "S")) else ch) for ch in normalized]
    return " ".join("".join(chars).split())


class SQLiteMemoryVault(MemoryVault):
    """Local SQLite memory vault featuring FTS5 full-text search, WAL mode, entity versioning,
    AES-256-GCM envelope encryption, and evasion-resistant negative memory tombstones."""

    def __init__(
        self,
        db_path: str = ":memory:",
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
        self.db_path = db_path
        on_disk = db_path != ":memory:"
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

        # Check for unencrypted database migration if passphrase is provided
        if on_disk and passphrase and os.path.exists(db_path) and os.path.getsize(db_path) > 0:
            with open(db_path, "rb") as f:
                hdr = f.read(16)
            if hdr.startswith(b"SQLite format 3"):
                # Migrate existing plaintext SQLite database to encrypted SQLCipher database
                self._migrate_file_to_sqlcipher(db_path, passphrase)

        self._conn = sqlcipher3.connect(db_path, timeout=30.0, check_same_thread=False)
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
        # Fast cache for whether tombstones exist in the database
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) AS cnt FROM rejected_value_tombstones")
        self._has_tombstones = (cursor.fetchone()["cnt"] > 0)
        cursor.execute("SELECT sequence, event_hash FROM audit_journal ORDER BY sequence DESC LIMIT 1")
        last_audit = cursor.fetchone()
        if last_audit:
            self._last_audit_seq = last_audit["sequence"]
            self._last_audit_hash = last_audit["event_hash"]
        else:
            self._last_audit_seq = 0
            self._last_audit_hash = "0" * 64
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
        rows = self._conn.execute("SELECT id, content FROM entities WHERE is_encrypted = 0").fetchall()
        with self._conn:
            for r in rows:
                env = self.crypto_provider.encrypt(r["content"].encode("utf-8"), self.passphrase)
                self._conn.execute(
                    "UPDATE entities SET content = '', is_encrypted = 1, encrypted_envelope_json = ? WHERE id = ?",
                    (env.model_dump_json(), r["id"]),
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

        # Use cached sequence & hash if available to avoid index scan on hot write path
        if hasattr(self, "_last_audit_seq") and hasattr(self, "_last_audit_hash") and self._last_audit_seq > 0:
            seq = self._last_audit_seq + 1
            prev_hash = self._last_audit_hash
        else:
            cursor.execute("SELECT sequence, event_hash FROM audit_journal ORDER BY sequence DESC LIMIT 1")
            last_row = cursor.fetchone()
            if last_row is None:
                prev_hash = "0" * 64
                seq = 1
            else:
                prev_hash = last_row["event_hash"]
                seq = last_row["sequence"] + 1

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
        self._last_audit_seq = seq
        self._last_audit_hash = event_hash
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
    ) -> MemoryEntity:
        now = time.time()
        meta = metadata or {}
        meta_str = json.dumps(meta, sort_keys=True)
        val_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Validate epistemic_state enum string
        ep_state = EpistemicState(epistemic_state) if epistemic_state else EpistemicState.VERIFIED

        with self._conn:
            cursor = self._conn.cursor()
            # Fast check: skip tombstone lookups and text canonicalization if no tombstones exist in the vault
            if getattr(self, "_has_tombstones", True):
                can_text = canonicalize_text(content)
                can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest()
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
                        scope, epistemic_state, valid_from, valid_until
                    )
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        category, key, stored_content, meta_str, now, now,
                        is_encrypted, envelope_json, scope, ep_state.value, valid_from, valid_until
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
                        valid_from = ?, valid_until = ?
                    WHERE id = ?
                    """,
                    (
                        stored_content, meta_str, version, now, is_encrypted, envelope_json,
                        ep_state.value, valid_from, valid_until, entity_id
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
        )

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
                   is_encrypted, encrypted_envelope_json, scope, epistemic_state, valid_from, valid_until
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
            epistemic_state=EpistemicState(row["epistemic_state"]) if "epistemic_state" in row.keys() else EpistemicState.VERIFIED,
            valid_from=row["valid_from"] if "valid_from" in row.keys() else None,
            valid_until=row["valid_until"] if "valid_until" in row.keys() else None,
            scope=row["scope"] if "scope" in row.keys() else "default",
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
        scope: str = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
    ) -> List[SearchResult]:
        if not query.strip():
            return []

        clean_terms = [t for t in query.replace('"', '""').split() if t]
        if not clean_terms:
            return []
        fts_query = " ".join(f'"{t}"*' for t in clean_terms)

        results: List[SearchResult] = []
        cursor = self._conn.cursor()

        # Build dynamic SQL WHERE conditions for scope, epistemic status, and validity bounds
        where_clauses = ["entities_fts MATCH ?", "e.archived = 0", "e.scope = ?"]
        params: List[Any] = [fts_query, scope]

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
                       e.scope, e.epistemic_state, e.valid_from, e.valid_until,
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
            fb_clauses = ["(content LIKE ? OR key LIKE ?)", "archived = 0", "scope = ?"]
            fb_params: List[Any] = [pattern, pattern, scope]
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
                       scope, epistemic_state, valid_from, valid_until,
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
            )
            results.append(SearchResult(entity=entity, rank_score=float(r["rank"]), snippet=str(r["snip"])))

        # If encrypted and user searched for content terms that weren't indexed in plaintext FTS,
        # scan active entities within scope if we have crypto provider and haven't hit limit:
        if self.crypto_provider is not None and len(results) < limit:
            query_lower = query.lower()
            all_entities = self.list_entities(
                category=category,
                include_archived=False,
                scope=scope,
                epistemic_state=epistemic_state,
                as_of_valid_time=as_of_valid_time,
                include_unverified=include_unverified,
            )
            for ent in all_entities:
                if ent.id in matched_ids:
                    continue
                if query_lower in ent.content.lower():
                    results.append(SearchResult(entity=ent, rank_score=-0.5, snippet=f"...{query}..."))
                    matched_ids.add(ent.id)
                    if len(results) >= limit:
                        break

        return results

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
            "scope, epistemic_state, valid_from, valid_until FROM entities WHERE 1=1"
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
            can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest()

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
            self._has_tombstones = True
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
        can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest()
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

    def close(self) -> None:
        self._conn.close()
