"""Snapshots of :class:`kibisis.vault.SQLiteMemoryVault`: export of entries, tombstones and journal to a JSON file,
and import of such a file into a vault, with the tombstone and integrity checks the import applies.

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection and keys and write through its
``put``. Every name here is also importable from ``kibisis.vault``.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from ._vault_crypto import EntryIntegrityError
from ._vault_review import ORIGINS as VALID_ORIGINS
from .models import EpistemicState

#: AAD of a snapshot's trust seal (see ``export_snapshot``).
_TRUST_SEAL_AAD = b"kibisis snapshot trust seal v1"

#: Metadata an attestation or a person's review produced; see ``import_snapshot``.
_TRUST_FACT_KEYS = ("attestations", "verification_pending", "human_reviews", "quorum_at_verification")

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
                       scope, epistemic_state, valid_from, valid_until, tenant_sig, origin
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
                       scope, epistemic_state, valid_from, valid_until, tenant_sig, origin
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
            except EntryIntegrityError as exc:
                self._note_integrity_failure(r, exc)  # logged, counted; raised under strict=True
                if self.strict:
                    raise
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
                # K-R1: who wrote it and from where, so a restore keeps the entry's trust class.
                "origin": r["origin"],
                "author_id": (json.loads(r["metadata_json"] or "{}") or {}).get("author_id"),
            })

        cursor.execute(
            """
            SELECT category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                   sealed_digests, origin_class
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
                "origin_class": r["origin_class"],
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
        # Trust seal: the entities' digest, sealed under the passphrase (the envelope carries its own
        # salt, so a vault with the same passphrase but another file can open it). A restore keeps
        # attestations and reviews only when it can open this seal or the digest key id is its own.
        snapshot["trust_seal"] = self._seal_trust(entities_data)

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

    @staticmethod
    def _entities_digest(entities: Any) -> str:
        return hashlib.sha256(json.dumps(entities, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def _seal_trust(self, entities: Any) -> Optional[str]:
        if not self._keyed or self.crypto_provider is None or not self.passphrase:
            return None
        envelope = self.crypto_provider.encrypt(
            self._entities_digest(entities).encode("ascii"), self.passphrase, aad=_TRUST_SEAL_AAD
        )
        return envelope.model_dump_json()

    def _trust_seal_opens(self, data: Dict[str, Any]) -> bool:
        """True when the snapshot's ``trust_seal`` opens under this vault's passphrase and names the
        digest of the entities it carries."""
        sealed = data.get("trust_seal")
        if not sealed or self.crypto_provider is None or not self.passphrase:
            return False
        try:
            from .models import EncryptedEnvelope

            envelope = EncryptedEnvelope.model_validate_json(sealed)
            # The seal was made by another vault's provider under its own salt; open it the way a
            # carried-over tombstone is opened (one envelope, iteration count capped).
            opener = getattr(self.crypto_provider, "decrypt_foreign", self.crypto_provider.decrypt)
            plain = opener(envelope, self.passphrase, aad=_TRUST_SEAL_AAD)
        except Exception:
            return False
        return hmac.compare_digest(plain.decode("ascii", "replace"), self._entities_digest(data.get("entities", [])))

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

        Trust facts travel only between vaults that share a passphrase: an entity's ``attestations``,
        ``verification_pending``, ``human_reviews`` and ``quorum_at_verification`` are kept only when
        the snapshot is this vault's or a same-passphrase vault's (its ``digest_key_id`` is this
        vault's, or its ``trust_seal`` opens under this passphrase and names the entities it carries;
        a vault without a passphrase has neither key nor seal, so its snapshots match any other
        plaintext vault) and its ``manifest_sha256`` is present and verifies. Otherwise they are dropped, the ``epistemic_state`` is re-derived from what
        survives (``verified`` and ``disputed`` become ``candidate``; ``revoked`` stays) and the
        drop is journaled. An entity's ``origin`` and ``author_id`` are restored as exported, so an
        entry a person verified, whoever wrote it (a person's own, or an agent's entry a person
        approved), stays verified with its reviews and attestations when the trust facts are kept.

        The restore is one transaction: it applies whole or, on an error, not at all. Restoring over a
        live vault without ``clear_existing`` leaves a live entry a person reviewed, or one of a
        higher class than the snapshot's, in place when the snapshot is not this vault's (journaled as
        a ``protected entry`` refusal, not counted); this vault's own snapshot restores over it.

        Returns the number of restored entities.
        """
        if isinstance(snapshot_or_path, (str, Path)):
            with open(snapshot_or_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        elif isinstance(snapshot_or_path, dict):
            data = snapshot_or_path
        else:
            raise TypeError("Expected snapshot dict or path")
        from .vault import OriginClassError, ReviewedEntryError  # vault.py imports this module

        manifest_sha = data.get("manifest_sha256")
        manifest_verified = False
        if manifest_sha:
            check_data = {k: v for k, v in data.items() if k != "manifest_sha256"}
            canonical_bytes = json.dumps(check_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            recomputed = hashlib.sha256(canonical_bytes).hexdigest()
            if recomputed != manifest_sha:
                raise ValueError(f"Snapshot integrity violation: manifest mismatch {recomputed} != {manifest_sha}")
            manifest_verified = True

        imported_count = 0
        foreign_tombstones = 0
        scheme = data.get("digest_scheme", "sha256")
        same_key = (
            scheme == "hmac-sha256" and self._digest_key is not None and data.get("digest_key_id") == self._digest_key_id()
        )
        # Attestations and reviews are facts this vault's people established. They are taken from a
        # snapshot only when it came from this vault (its digest key id: per file when keyed, absent
        # for a vault without a passphrase) and is whole (manifest present and verified).
        same_vault = data.get("digest_key_id") == self._digest_key_id() or self._trust_seal_opens(data)
        keep_trust_facts = same_vault and manifest_verified
        stripped_trust_facts = 0
        protected_rows = 0
        # One transaction for the whole restore (R2-A7): tombstones, the clearing, every entity and
        # every refusal record commit together or not at all, so an error part-way leaves the vault as
        # it was. Nested writes below join this transaction (see ``_write_tx``).
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
                        sealed_digests, origin_class, tombstone_mac
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        # A tombstone from elsewhere keeps its class when it is known; one without a
                        # class is as old as the column and was made by a vouching caller.
                        ts.get("origin_class") or "principal",
                        self._tombstone_mac(t_scope, t_category, t_key, exact, canonical, ts.get("origin_class") or "principal"),
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
                category, key = ent_data["category"], ent_data["key"]
                metadata = dict(ent_data.get("metadata") or {})
                state = ent_data.get("epistemic_state", "verified")
                origin = ent_data.get("origin") or None
                if origin is not None and origin not in VALID_ORIGINS:
                    origin = None
                val_hash, can_hash = self._digests(ent_data["content"])
                tomb = self._find_tombstone(cursor, scope, val_hash, can_hash)
                if tomb is None:
                    tombs = self._tombstones_matching(
                        cursor, scope, self._entry_digests(key, ent_data["content"], metadata)
                    )
                    tomb = tombs[0] if tombs else None
                if tomb is not None:
                    self.record_refusal(
                        path="import_snapshot",
                        reason="tombstoned value",
                        scope=scope,
                        category=category,
                        key=key,
                        detail={"value_digest_prefix": val_hash[:12]},
                    )
                    continue
                if not keep_trust_facts:
                    dropped = [k for k in _TRUST_FACT_KEYS if k in metadata]
                    for k in dropped:
                        metadata.pop(k)
                    if dropped:
                        stripped_trust_facts += 1
                        metadata["trust_facts_dropped_on_import"] = sorted(dropped)
                    if state in (EpistemicState.VERIFIED.value, EpistemicState.DISPUTED.value):
                        # Those states are the outcome of attestations or reviews, which did not survive.
                        metadata["trust_capped_from"] = state
                        state = EpistemicState.CANDIDATE.value
                try:
                    self._put_journaled(
                        category=category,
                        key=key,
                        content=ent_data["content"],
                        metadata=metadata,
                        epistemic_state=state,
                        valid_from=ent_data.get("valid_from"),
                        valid_until=ent_data.get("valid_until"),
                        scope=scope,
                        origin=origin,
                        author_id=ent_data.get("author_id"),
                        fencing_token=fencing_token,
                        resource=resource,
                        holder_id=holder_id,
                        # A restore keeps the exported review history and tenant bounds when the
                        # snapshot is this vault's (see above); then the state and trust facts are
                        # taken as this vault's people decided them, whatever the entry's origin (a
                        # person's approval of an agent's entry restores verified). Otherwise the
                        # state passed is the one the facts that survived support, and the vault
                        # caps a non-principal origin to candidate. Nothing attests on a restore.
                        _trusted_metadata=True,
                        _review_verdict=keep_trust_facts,
                        _attest=False,
                    )
                except (ReviewedEntryError, OriginClassError) as exc:
                    # The live row is a person's (reviewed, or of a higher class than the snapshot's
                    # entry) and the snapshot is not this vault's: the row stays, the rest is restored.
                    protected_rows += 1
                    self.record_refusal(
                        path="import_snapshot",
                        reason="protected entry",
                        scope=scope,
                        category=category,
                        key=key,
                        detail={"error": str(exc)[:200]},
                    )
                    continue
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

            if stripped_trust_facts:
                self.record_refusal(
                    path="import_snapshot",
                    reason="trust facts dropped: snapshot is not from this vault's key or has no verified manifest",
                    scope="*",
                    detail={
                        "entities": stripped_trust_facts,
                        "same_vault": "yes" if same_vault else "no",
                        "manifest_verified": "yes" if manifest_verified else "no",
                    },
                )
        if protected_rows:
            logger.warning("import_snapshot: %d entities were not restored over a person's live entries", protected_rows)
        return imported_count
