"""SQLite and FTS5 memory vault implementation for Kibisis with authenticated envelope encryption and hardened tombstones."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import string
import time
import unicodedata
from typing import Any, Dict, List, Optional
from .models import EncryptedEnvelope, MemoryEntity, SearchResult
from .protocols import CryptoEnvelopeProvider, MemoryVault


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
    ) -> None:
        self.db_path = db_path
        self.crypto_provider = crypto_provider
        self.passphrase = passphrase
        self._conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._configure_db()
        self._init_schema()

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
                    UNIQUE(category, key)
                )
                """
            )

            # Migration for pre-existing tables lacking encryption/tombstone columns
            cursor = self._conn.cursor()
            cursor.execute("PRAGMA table_info(entities)")
            cols = {row["name"] for row in cursor.fetchall()}
            if "is_encrypted" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0")
            if "encrypted_envelope_json" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN encrypted_envelope_json TEXT DEFAULT NULL")

            self._conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
                    category,
                    key,
                    content,
                    content='entities',
                    content_rowid='id'
                )
                """
            )

            # Triggers to keep FTS5 synchronized with entities
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_ai AFTER INSERT ON entities BEGIN
                    INSERT INTO entities_fts(rowid, category, key, content)
                    VALUES (new.id, new.category, new.key, new.content);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_ad AFTER DELETE ON entities BEGIN
                    INSERT INTO entities_fts(entities_fts, rowid, category, key, content)
                    VALUES ('delete', old.id, old.category, old.key, old.content);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_au AFTER UPDATE ON entities BEGIN
                    INSERT INTO entities_fts(entities_fts, rowid, category, key, content)
                    VALUES ('delete', old.id, old.category, old.key, old.content);
                    INSERT INTO entities_fts(rowid, category, key, content)
                    VALUES (new.id, new.category, new.key, new.content);
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
                    UNIQUE(category, key, value_sha256)
                )
                """
            )
            cursor.execute("PRAGMA table_info(rejected_value_tombstones)")
            tomb_cols = {row["name"] for row in cursor.fetchall()}
            if "canonical_sha256" not in tomb_cols:
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN canonical_sha256 TEXT NOT NULL DEFAULT ''")

            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_lookup
                ON rejected_value_tombstones(category, key, value_sha256)
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_canonical
                ON rejected_value_tombstones(category, canonical_sha256)
                """
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
    ) -> MemoryEntity:
        now = time.time()
        meta = metadata or {}
        meta_str = json.dumps(meta, sort_keys=True)
        val_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        can_text = canonicalize_text(content)
        can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest()

        with self._conn:
            cursor = self._conn.cursor()
            # Check for exact hash OR canonicalized evasion-resistant match
            cursor.execute(
                """
                SELECT reason, author_id FROM rejected_value_tombstones
                WHERE category = ? AND (key = ? OR key = '*')
                  AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
                """,
                (category, key, val_hash, can_hash),
            )
            tomb = cursor.fetchone()
            if tomb is not None:
                raise ValueError(
                    f"Write rejected by tombstone: entity '{category}:{key}' matches rejected tombstone "
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
                "SELECT id, version, created_at FROM entities WHERE category = ? AND key = ?",
                (category, key),
            )
            row = cursor.fetchone()

            if row is None:
                cursor.execute(
                    """
                    INSERT INTO entities (
                        category, key, content, metadata_json, version, archived,
                        created_at, updated_at, is_encrypted, encrypted_envelope_json
                    )
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?)
                    """,
                    (category, key, stored_content, meta_str, now, now, is_encrypted, envelope_json),
                )
                entity_id = cursor.lastrowid
                version = 1
                created_at = now
            else:
                entity_id = row["id"]
                version = row["version"] + 1
                created_at = row["created_at"]
                cursor.execute(
                    """
                    UPDATE entities
                    SET content = ?, metadata_json = ?, version = ?, archived = 0, updated_at = ?,
                        is_encrypted = ?, encrypted_envelope_json = ?
                    WHERE id = ?
                    """,
                    (stored_content, meta_str, version, now, is_encrypted, envelope_json, entity_id),
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
        )

    def get(self, category: str, key: str) -> Optional[MemoryEntity]:
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, category, key, content, metadata_json, version, archived, created_at, updated_at,
                   is_encrypted, encrypted_envelope_json
            FROM entities
            WHERE category = ? AND key = ?
            """,
            (category, key),
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
        )

    def archive(self, category: str, key: str) -> bool:
        now = time.time()
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                UPDATE entities
                SET archived = 1, updated_at = ?
                WHERE category = ? AND key = ? AND archived = 0
                """,
                (now, category, key),
            )
            return cursor.rowcount > 0

    def purge(self, category: str, key: str) -> bool:
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                "DELETE FROM entities WHERE category = ? AND key = ?",
                (category, key),
            )
            return cursor.rowcount > 0

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
    ) -> List[SearchResult]:
        if not query.strip():
            return []

        clean_terms = [t for t in query.replace('"', '""').split() if t]
        if not clean_terms:
            return []
        fts_query = " ".join(f'"{t}"*' for t in clean_terms)

        results: List[SearchResult] = []
        cursor = self._conn.cursor()

        try:
            if category:
                cursor.execute(
                    """
                    SELECT e.id, e.category, e.key, e.content, e.metadata_json, e.version, e.archived,
                           e.created_at, e.updated_at, e.is_encrypted, e.encrypted_envelope_json,
                           rank, snippet(entities_fts, 2, '<b>', '</b>', '...', 16) AS snip
                    FROM entities_fts
                    JOIN entities e ON e.id = entities_fts.rowid
                    WHERE entities_fts MATCH ? AND e.category = ? AND e.archived = 0
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (fts_query, category, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT e.id, e.category, e.key, e.content, e.metadata_json, e.version, e.archived,
                           e.created_at, e.updated_at, e.is_encrypted, e.encrypted_envelope_json,
                           rank, snippet(entities_fts, 2, '<b>', '</b>', '...', 16) AS snip
                    FROM entities_fts
                    JOIN entities e ON e.id = entities_fts.rowid
                    WHERE entities_fts MATCH ? AND e.archived = 0
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (fts_query, limit),
                )
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            pattern = f"%{query}%"
            if category:
                cursor.execute(
                    """
                    SELECT id, category, key, content, metadata_json, version, archived,
                           created_at, updated_at, is_encrypted, encrypted_envelope_json,
                           0.0 as rank, '' as snip
                    FROM entities
                    WHERE (content LIKE ? OR key LIKE ?) AND category = ? AND archived = 0
                    LIMIT ?
                    """,
                    (pattern, pattern, category, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, category, key, content, metadata_json, version, archived,
                           created_at, updated_at, is_encrypted, encrypted_envelope_json,
                           0.0 as rank, '' as snip
                    FROM entities
                    WHERE (content LIKE ? OR key LIKE ?) AND archived = 0
                    LIMIT ?
                    """,
                    (pattern, pattern, limit),
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
            )
            results.append(SearchResult(entity=entity, rank_score=float(r["rank"]), snippet=str(r["snip"])))

        # If encrypted and user searched for content terms that weren't indexed in plaintext FTS,
        # scan active entities if we have crypto provider and haven't hit limit:
        if self.crypto_provider is not None and len(results) < limit:
            query_lower = query.lower()
            all_entities = self.list_entities(category=category, include_archived=False)
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
    ) -> List[MemoryEntity]:
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT id, category, key, content, metadata_json, version, archived, "
            "created_at, updated_at, is_encrypted, encrypted_envelope_json FROM entities WHERE 1=1"
        )
        params: List[Any] = []

        if not include_archived:
            query_sql += " AND archived = 0"
        if category:
            query_sql += " AND category = ?"
            params.append(category)

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
    ) -> str:
        """Tombstone entity value by SHA-256 and canonical digests, then purge all content from live tables."""
        now = time.time()
        with self._conn:
            cursor = self._conn.cursor()
            if content is None:
                cursor.execute(
                    "SELECT content, is_encrypted, encrypted_envelope_json FROM entities WHERE category = ? AND key = ?",
                    (category, key),
                )
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(f"Entity not found: {category}:{key}")
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
                    category, key, value_sha256, canonical_sha256, reason, author_id, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (category, key, val_hash, can_hash, reason, author_id, now),
            )
            # Physical purge of entity and FTS index (triggers handle FTS delete)
            cursor.execute("DELETE FROM entities WHERE category = ? AND key = ?", (category, key))
            return val_hash

    def is_tombstoned(self, category: str, key: str, content: str) -> bool:
        """Check if a specific content string is tombstoned under the given category and key (exact or canonical)."""
        val_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        can_text = canonicalize_text(content)
        can_hash = hashlib.sha256(can_text.encode("utf-8")).hexdigest()
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT 1 FROM rejected_value_tombstones
            WHERE category = ? AND (key = ? OR key = '*')
              AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
            """,
            (category, key, val_hash, can_hash),
        )
        return cursor.fetchone() is not None

    def list_tombstones(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """List tombstone records containing only digests, reason, author, and timestamp (never plaintext)."""
        cursor = self._conn.cursor()
        if category:
            cursor.execute(
                """
                SELECT id, category, key, value_sha256, canonical_sha256, reason, author_id, created_at
                FROM rejected_value_tombstones WHERE category = ? ORDER BY id
                """,
                (category,),
            )
        else:
            cursor.execute(
                """
                SELECT id, category, key, value_sha256, canonical_sha256, reason, author_id, created_at
                FROM rejected_value_tombstones ORDER BY id
                """
            )
        return [dict(r) for r in cursor.fetchall()]

    def close(self) -> None:
        self._conn.close()
