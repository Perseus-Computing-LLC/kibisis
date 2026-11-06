"""Removal of content from :class:`kibisis.vault.SQLiteMemoryVault`: tombstones that record a value's digests and
refuse it afterwards, the purge of a value's copies and of an entry, and the scrub that reclaims file space.

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection and keys. Every name here is
also importable from ``kibisis.vault``.

Every removal (``tombstone``, ``purge``, ``archive``, ``set_persona_slot`` over an existing slot) takes an
``origin`` and runs the same check, :func:`protected_reason`: a request from outside the principal class
cannot remove what a person vouched for or what a higher class wrote.

A tombstone carries the origin class of the request that made it (``origin_class`` column, ``principal``
for rows written before the column existed). A later write of the value by a HIGHER class lifts a
lower-class tombstone (journaled as ``tombstone_lifted``); a principal-class tombstone blocks every
later write until a person lifts it (``kibisis-review lift``, :meth:`TombstoneMixin.lift_tombstone`).
"""

from __future__ import annotations

import contextlib
import json
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from ._vault_crypto import value_digests

#: How a refused forget names the class of the entry it would have deleted (K-R1 classes above a requester).
_WRITTEN_BY = {
    "principal": "written by a person or an import (principal class)",
    "agent": "written by an agent (agent class)",
}

#: Columns a removal check needs from an ``entities`` row.
_ROW_COLUMNS = (
    "id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig, "
    "epistemic_state, metadata_json, origin"
)


def protected_reason(row: Any, requester: str) -> Optional[str]:
    """Why a ``requester``-class request may not remove ``row``, or ``None`` when it may.

    A row is protected from a non-principal requester when a person verified or reviewed it, or when
    it was written by a higher origin class than the requester (K-R1). A principal requester may
    remove anything.
    """
    from ._vault_review import _class_rank, _row_origin_class
    from .vault import _is_reviewed  # vault.py imports this module

    if requester == "principal":
        return None
    if _is_reviewed(row):
        return "verified or reviewed by a person"
    stored = _row_origin_class(row)
    if _class_rank(stored) > _class_rank(requester):
        return _WRITTEN_BY.get(stored, f"written by a {stored}-class writer")
    return None


def string_leaves(value: Any) -> Iterable[str]:
    """Every string held anywhere inside a JSON-like value (dict values, list items, nested)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from string_leaves(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from string_leaves(v)


class TombstoneMixin:
    """Tombstones values, purges entries and their copies, and scrubs the file."""

    def _requester_class(self, origin: Optional[str]) -> str:
        """The K-R1 class a removal request acts with: ``principal`` when no origin is stated (the caller
        vouches, as before), else the class of ``origin``."""
        from ._vault_review import _validate_origin, origin_class_of

        _validate_origin(origin)
        return origin_class_of(origin) if origin is not None else "principal"

    def _fetch_row(self, cursor: Any, category: str, key: str, scope: str) -> Any:
        cursor.execute(
            f"SELECT {_ROW_COLUMNS} FROM entities WHERE category = ? AND key = ? AND scope = ?",
            (category, key, scope),
        )
        return cursor.fetchone()

    def _refuse_if_protected(self, row: Any, requester: str, origin: Optional[str], verb: str) -> None:
        from .vault import ReviewedEntryError  # vault.py imports this module

        why = protected_reason(row, requester)
        if why:
            raise ReviewedEntryError(
                f"'{row['category']}:{row['key']}' [scope={row['scope']}] was {why}, so a {origin} request cannot "
                f"{verb} it. A person can, by rejecting it in the review CLI."
            )

    @contextlib.contextmanager
    def _journal_protected_refusal(
        self, path: str, category: str, key: str, scope: str, author_id: Optional[str], origin: Optional[str]
    ) -> Iterator[None]:
        """Journal a ``ReviewedEntryError`` or ``PermissionError`` raised in the block as a ``refuse``
        event, after the block's transaction has rolled back, and re-raise it."""
        try:
            yield
        except PermissionError as exc:  # ReviewedEntryError is one
            self.record_refusal(
                path=path,
                reason="protected entry" if type(exc).__name__ == "ReviewedEntryError" else "scope not allowed",
                scope=scope,
                category=category,
                key=key,
                author_id=author_id,
                detail={"origin": origin or "", "error": str(exc)[:200]},
            )
            raise

    def purge(
        self,
        category: str,
        key: str,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> bool:
        """Delete the entry at ``category:key`` in ``scope`` without recording a tombstone.

        ``origin`` names who asked, as on :meth:`tombstone`: a non-principal origin cannot purge an
        entry a person verified or reviewed, or one a higher class wrote
        (:class:`~kibisis.vault.ReviewedEntryError`, nothing changed). ``None`` leaves the check to the
        caller. The deletion is journaled with the requester's origin.
        """
        requester = self._requester_class(origin)
        with self._journal_protected_refusal("purge", category, key, scope, author_id, origin), self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            row = self._fetch_row(cursor, category, key, scope)
            if row is None:
                return False
            self._refuse_if_protected(row, requester, origin, "purge")
            cursor.execute("DELETE FROM entities WHERE id = ?", (row["id"],))
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
                    metadata={"origin": origin or "", "origin_class": requester},
                )
            return purged

    def _find_tombstone(self, cursor: Any, scope: str, val_hash: str, can_hash: str) -> Optional[Any]:
        """Return the first tombstone in ``scope`` (or a ``'*'`` tombstone) that rejects this value.

        Category and key play no part: a tombstone stops a value, not a key, so a rejected value
        cannot come back under a new key or category. Scopes stay separate, so one tenant's
        rejection neither blocks nor reveals another tenant's writes. A hit must carry a valid
        ``tombstone_mac`` (:meth:`_verify_tombstone_row`); an edited row raises ``VaultIntegrityError``.
        """
        cursor.execute(
            """
            SELECT id, category, key, reason, author_id, origin_class, scope, value_sha256, canonical_sha256, tombstone_mac
            FROM rejected_value_tombstones
            WHERE (scope = ? OR scope = '*')
              AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
            ORDER BY id
            LIMIT 1
            """,
            (scope, val_hash, can_hash),
        )
        row = cursor.fetchone()
        if row is not None:
            self._verify_tombstone_row(row)
        return row

    def _tombstones_matching(self, cursor: Any, scope: str, digests: Iterable[Tuple[str, str]]) -> List[Any]:
        """Every tombstone in ``scope`` (or global) that rejects any of the ``(exact, canonical)`` digests.
        Each hit must carry a valid ``tombstone_mac`` (:meth:`_verify_tombstone_row`)."""
        found: Dict[int, Any] = {}
        for val_hash, can_hash in digests:
            cursor.execute(
                """
                SELECT id, category, key, reason, author_id, origin_class, scope, value_sha256,
                       canonical_sha256, tombstone_mac
                FROM rejected_value_tombstones
                WHERE (scope = ? OR scope = '*')
                  AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
                ORDER BY id
                """,
                (scope, val_hash, can_hash),
            )
            for row in cursor.fetchall():
                if row["id"] not in found:
                    self._verify_tombstone_row(row)
                    found[row["id"]] = row
        return [found[i] for i in sorted(found)]

    def _entry_digests(self, key: str, content: str, meta: Optional[Dict[str, Any]]) -> List[Tuple[str, str]]:
        """Digests of every place a value can sit in an entry: its content, its key, and each string
        leaf of its metadata. A tombstoned value is refused wherever it is put."""
        seen: Set[Tuple[str, str]] = set()
        out: List[Tuple[str, str]] = []
        for text in [content, key, *string_leaves(meta or {})]:
            if not text:
                continue
            pair = self._digests(text)
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
        return out

    def _value_copies(self, cursor: Any, scope: str, val_hash: str, can_hash: str) -> List[Dict[str, Any]]:
        """Every stored row in ``scope`` (every scope for ``'*'``) that holds the value, live or archived:
        as its content, as its key, or as a string anywhere in its metadata.

        Each row comes back with its id, name, state, metadata and the digest that matched. A row that
        cannot be opened cannot be compared, and is never returned by any read, so it is left out.
        """
        if scope == "*":
            cursor.execute(f"SELECT {_ROW_COLUMNS} FROM entities")
        else:
            cursor.execute(f"SELECT {_ROW_COLUMNS} FROM entities WHERE scope = ?", (scope,))
        copies: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            try:
                content = self._open_entry(row)
            except PermissionError:
                continue
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except (TypeError, ValueError):
                meta = {}
            matched: Optional[str] = None
            for exact, canonical in self._entry_digests(row["key"], content, meta):
                if exact == val_hash or (can_hash and canonical == can_hash):
                    matched = exact
                    break
            if matched is None:
                continue
            copies.append({
                "id": row["id"], "category": row["category"], "key": row["key"], "scope": row["scope"],
                "epistemic_state": row["epistemic_state"], "metadata_json": row["metadata_json"],
                "origin": row["origin"], "exact": matched,
            })
        return copies

    def _purge_value_copies(
        self,
        cursor: Any,
        scope: str,
        val_hash: str,
        can_hash: str,
        author_id: Optional[str],
        tombstoned: str,
        copies: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """Delete every stored copy of a tombstoned value in ``scope`` (every scope for ``'*'``).

        Copies under other categories or keys, live or archived, or held in a key or in metadata,
        would otherwise keep a rejected value retrievable. Each deletion is journaled in the caller's
        transaction. ``copies`` is the list :meth:`_value_copies` returned, when the caller already has it.
        """
        if copies is None:
            copies = self._value_copies(cursor, scope, val_hash, can_hash)
        purged = 0
        for row in copies:
            exact = row["exact"]
            cursor.execute("DELETE FROM entities WHERE id = ?", (row["id"],))
            if not cursor.rowcount:
                continue  # the tombstoned entry itself, already deleted by the caller
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
        origin: Optional[str] = None,
    ) -> str:
        """Tombstone a value by its exact and canonical SHA-256 digests within ``scope``.

        Purges the entity at ``category:key`` when its value is the tombstoned one, and every other
        copy of the value in the scope (all scopes when ``scope`` is ``'*'``). Later writes of the
        value, or of a look-alike that canonicalizes to it, are refused under any category or key in
        the scope. Returns the value's SHA-256 hex digest; a vault with a passphrase stores it keyed
        (see :meth:`stored_digest`).

        ``content`` names the value; without it the value is the entry's stored content (``KeyError``
        when there is no entry). With ``content`` that does not match what ``category:key`` holds, the
        entry is left alone: the tombstone and the purge of copies concern the value named, not the key.

        ``origin`` names who asked, as on :meth:`put`, and is recorded on the tombstone as its origin
        class. A request from outside the principal class (``model``, ``tool`` or ``unknown``) cannot
        delete what a person vouched for: when the entry, or any other copy of the value the tombstone
        would purge, is verified, carries a person's review, or belongs to a higher origin class than
        the request, :class:`~kibisis.vault.ReviewedEntryError` is raised and nothing changes; and it
        cannot write a global (``scope='*'``) tombstone (``PermissionError``). A person deletes such an
        entry by rejecting it (``review_entity`` with ``verdict="revoked"``). ``None`` leaves the check
        to the caller, as before, and records a principal-class tombstone: library code that relays an
        agent's request passes its origin.
        """
        requester = self._requester_class(origin)
        with self._journal_protected_refusal("tombstone", category, key, scope, author_id, origin):
            if scope == "*" and requester != "principal":
                raise PermissionError(
                    f"a {origin} request cannot tombstone a value in every scope (scope='*'); it may act in its own scope"
                )
            return self._tombstone_locked(
                category, key, reason, content, author_id, scope, fencing_token, resource, holder_id, origin, requester
            )

    def _tombstone_locked(
        self,
        category: str,
        key: str,
        reason: str,
        content: Optional[str],
        author_id: Optional[str],
        scope: str,
        fencing_token: Optional[int],
        resource: Optional[str],
        holder_id: Optional[str],
        origin: Optional[str],
        requester: str,
    ) -> str:
        """Body of :meth:`tombstone`: one write transaction from lookup to tombstone row."""
        from .vault import ReviewedEntryError  # vault.py imports this module

        now = time.time()
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            target = self._fetch_row(cursor, category, key, scope) if scope != "*" else None
            stored_content: Optional[str] = None
            if target is not None:
                stored_content = self._open_entry(target)
            if content is None:
                if target is None:
                    raise KeyError(f"Entity not found: {category}:{key} [scope={scope}]")
                content = stored_content

            assert content is not None
            plain_exact, plain_canonical = value_digests(content)
            val_hash, can_hash = self._stored_digests(plain_exact, plain_canonical)
            target_matches = False
            if target is not None and stored_content is not None:
                t_exact, t_canonical = self._digests(stored_content)
                target_matches = t_exact == val_hash or (bool(can_hash) and t_canonical == can_hash)

            # The origin check runs on the entry named, whether or not ``content`` was given, and on
            # every copy of the value the purge would reach.
            if target is not None:
                self._refuse_if_protected(target, requester, origin, "delete")
            copies = self._value_copies(cursor, scope, val_hash, can_hash)
            if requester != "principal":
                for copy in copies:
                    if target is not None and copy["id"] == target["id"]:
                        continue  # checked above
                    why = protected_reason(copy, requester)
                    if why:
                        raise ReviewedEntryError(
                            f"'{category}:{key}' [scope={scope}] holds the same value as "
                            f"'{copy['category']}:{copy['key']}' [scope={copy['scope']}], which was {why}, so a "
                            f"{origin} request cannot delete the value. A person can, by rejecting it in the "
                            "review CLI."
                        )

            cursor.execute(
                """
                INSERT OR REPLACE INTO rejected_value_tombstones (
                    category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                    sealed_digests, origin_class, tombstone_mac
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    category, key, val_hash, can_hash, reason, author_id, now, scope,
                    self._seal_digests(scope, category, key, plain_exact, plain_canonical), requester,
                    self._tombstone_mac(scope, category, key, val_hash, can_hash, requester),
                ),
            )
            # Physical purge of the entity when it holds the value (the FTS index follows through triggers).
            if target is not None and target_matches:
                cursor.execute("DELETE FROM entities WHERE id = ?", (target["id"],))

            # Record hash-chained mutation audit event
            self._record_audit_event(
                cursor=cursor,
                action="tombstone",
                category=category,
                key=key,
                scope=scope,
                value_sha256=val_hash,
                author_id=author_id,
                metadata={
                    "reason": reason, "canonical_sha256": can_hash, "origin": origin or "", "origin_class": requester,
                    "entry_deleted": bool(target is not None and target_matches),
                },
            )
            self._purge_value_copies(cursor, scope, val_hash, can_hash, author_id, f"{category}:{key}", copies=copies)
            return plain_exact

    def lift_tombstone(
        self,
        category: str,
        key: str,
        scope: str = "default",
        digest: Optional[str] = None,
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> int:
        """Remove the tombstones recorded under ``category:key`` in ``scope`` and journal each as
        ``tombstone_lifted``. ``digest`` (the stored exact digest, or a hex prefix of it) narrows the
        lift to one value. Returns how many were removed.

        This is a person's act: the review CLI's ``lift`` verb calls it after its terminal check. The
        value is admitted again afterwards; the entry itself is not restored.
        """
        sql = (
            "SELECT id, value_sha256, canonical_sha256, reason, origin_class FROM rejected_value_tombstones "
            "WHERE category = ? AND key = ? AND scope = ?"
        )
        params: List[Any] = [category, key, scope]
        if digest:
            if not all(c in "0123456789abcdefABCDEF" for c in digest):
                raise ValueError("digest must be a hex digest or a hex prefix")
            sql += " AND value_sha256 LIKE ?"
            params.append(digest.lower() + "%")
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            for row in rows:
                cursor.execute("DELETE FROM rejected_value_tombstones WHERE id = ?", (row["id"],))
                self._record_audit_event(
                    cursor=cursor,
                    action="tombstone_lifted",
                    category=category,
                    key=key,
                    scope=scope,
                    value_sha256=row["value_sha256"],
                    author_id=author_id,
                    metadata={
                        "canonical_sha256": row["canonical_sha256"], "reason": row["reason"],
                        "tombstone_class": row["origin_class"], "lifted_by": "person",
                    },
                )
            return len(rows)

    def _lift_lower_class_tombstones(
        self,
        cursor: Any,
        tombs: List[Any],
        writer_class: str,
        category: str,
        key: str,
        scope: str,
        author_id: Optional[str],
    ) -> None:
        """Remove tombstones of a lower class than ``writer_class`` on the way to a write that overrides
        them (the caller checked none of them outranks the writer); journal each as ``tombstone_lifted``."""
        for tomb in tombs:
            cursor.execute("DELETE FROM rejected_value_tombstones WHERE id = ?", (tomb["id"],))
            self._record_audit_event(
                cursor=cursor,
                action="tombstone_lifted",
                category=category,
                key=key,
                scope=scope,
                value_sha256=tomb["value_sha256"],
                author_id=author_id,
                metadata={
                    "tombstone": f"{tomb['category']}:{tomb['key']}", "tombstone_scope": tomb["scope"],
                    "tombstone_class": tomb["origin_class"], "lifted_by": f"{writer_class}-class write",
                    "reason": tomb["reason"],
                },
            )

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
        """List tombstone records containing only digests, reason, author, origin class, scope, and
        timestamp (never plaintext)."""
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT id, category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope, "
            "origin_class FROM rejected_value_tombstones WHERE 1=1"
        )
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
