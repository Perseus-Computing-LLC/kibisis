"""Removal of content from :class:`kibisis.vault.SQLiteMemoryVault`: tombstones that record a value's digests and
refuse it afterwards, the purge of a value's copies and of an entry, and the scrub that reclaims file space.

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection and keys. Every name here is
also importable from ``kibisis.vault``.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ._vault_crypto import value_digests


class TombstoneMixin:
    """Tombstones values, purges entries and their copies, and scrubs the file."""

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
        with self._write_tx() as cursor:
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
        with self._write_tx() as cursor:
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

    def scrub(self) -> None:
        """Remove deleted or replaced content from the search indexes, the write-ahead log and free pages.

        FTS5 'delete' leaves old terms in index segments until the index is rebuilt (a SQLCipher
        vault's entry index is rebuilt from its decrypted entries), and the write-ahead log and free
        pages keep old bytes until a checkpoint and VACUUM. Run after a delete (the MCP server's
        forget does) or after migrating plaintext.
        """
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('rebuild')")
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('optimize')")
        self._conn.commit()
        if self._search_index or self._term_index:
            self._rebuild_search_index()
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._restrict_permissions()
