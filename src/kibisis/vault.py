"""SQLite and FTS5 memory vault implementation for Kibisis."""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional
from .models import MemoryEntity, SearchResult
from .protocols import MemoryVault


class SQLiteMemoryVault(MemoryVault):
    """Local SQLite memory vault featuring FTS5 full-text search, WAL mode, and entity versioning."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
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
                    UNIQUE(category, key)
                )
                """
            )

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

        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT id, version, created_at FROM entities WHERE category = ? AND key = ?",
                (category, key),
            )
            row = cursor.fetchone()

            if row is None:
                cursor.execute(
                    """
                    INSERT INTO entities (category, key, content, metadata_json, version, archived, created_at, updated_at)
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?)
                    """,
                    (category, key, content, meta_str, now, now),
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
                    SET content = ?, metadata_json = ?, version = ?, archived = 0, updated_at = ?
                    WHERE id = ?
                    """,
                    (content, meta_str, version, now, entity_id),
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
            SELECT id, category, key, content, metadata_json, version, archived, created_at, updated_at
            FROM entities
            WHERE category = ? AND key = ?
            """,
            (category, key),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return MemoryEntity(
            id=row["id"],
            category=row["category"],
            key=row["key"],
            content=row["content"],
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

        # Sanitize query for FTS5 (escape double quotes, wrap words in quotes or prefix matches)
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
                           e.created_at, e.updated_at, rank, snippet(entities_fts, 2, '<b>', '</b>', '...', 16) AS snip
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
                           e.created_at, e.updated_at, rank, snippet(entities_fts, 2, '<b>', '</b>', '...', 16) AS snip
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
            # Fallback to standard LIKE matching if FTS syntax fails
            pattern = f"%{query}%"
            if category:
                cursor.execute(
                    """
                    SELECT id, category, key, content, metadata_json, version, archived,
                           created_at, updated_at, 0.0 as rank, '' as snip
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
                           created_at, updated_at, 0.0 as rank, '' as snip
                    FROM entities
                    WHERE (content LIKE ? OR key LIKE ?) AND archived = 0
                    LIMIT ?
                    """,
                    (pattern, pattern, limit),
                )
            rows = cursor.fetchall()

        for r in rows:
            entity = MemoryEntity(
                id=r["id"],
                category=r["category"],
                key=r["key"],
                content=r["content"],
                metadata=json.loads(r["metadata_json"]),
                version=r["version"],
                archived=bool(r["archived"]),
                created_at=r["created_at"],
                updated_at=r["updated_at"],
            )
            results.append(SearchResult(entity=entity, rank_score=float(r["rank"]), snippet=str(r["snip"])))

        return results

    def list_entities(
        self,
        category: Optional[str] = None,
        include_archived: bool = False,
    ) -> List[MemoryEntity]:
        cursor = self._conn.cursor()
        query_sql = "SELECT id, category, key, content, metadata_json, version, archived, created_at, updated_at FROM entities WHERE 1=1"
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
            items.append(
                MemoryEntity(
                    id=r["id"],
                    category=r["category"],
                    key=r["key"],
                    content=r["content"],
                    metadata=json.loads(r["metadata_json"]),
                    version=r["version"],
                    archived=bool(r["archived"]),
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
            )
        return items

    def close(self) -> None:
        self._conn.close()
