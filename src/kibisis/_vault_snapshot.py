"""Snapshots of :class:`kibisis.vault.SQLiteMemoryVault`: export of entries, tombstones and journal to a JSON file,
and import of such a file into a vault, with the tombstone and integrity checks the import applies.

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection and keys and write through its
``put``. Every name here is also importable from ``kibisis.vault``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from ._vault_crypto import EntryIntegrityError

# The vault's logger: records keep the name callers filter on.
logger = logging.getLogger("kibisis.vault")


class SnapshotMixin:
    """Exports a vault to a snapshot file and imports one."""

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
            # The snapshot holds decrypted content. A plain open() inherited the umask (0644 on most
            # hosts) and undid the vault's at-rest protection; create the file owner-only, refuse a
            # pre-existing path, flush to disk, then rename so a reader sees all or nothing.
            fd = os.open(tmp_p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, indent=2, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_p, out_p)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_p)
                raise

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
        with self._write_tx() as cursor:
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
                # A restore keeps the exported review history and tenant bounds. The snapshot's
                # epistemic_state is already trusted here, so this grants nothing it did not have.
                _trusted_metadata=True,
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
