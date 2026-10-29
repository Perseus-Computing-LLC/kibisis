"""Entry integrity of :class:`kibisis.vault.SQLiteMemoryVault`: sealing, signing and opening entries, the keyed value
digests kept in tombstones and in the journal, the vault salt, and the upgrade to integrity format 2.

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection, keys and crypto provider. Every
name here is also importable from ``kibisis.vault``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from ._vault_audit import _event_hash
from .crypto import (
    ENTRY_BINDING,
    ENTRY_SIGNATURE_PREFIX,
    TOMBSTONE_BINDING,
    entry_aad,
    keyed_value_digest,
    sign_entry,
    sign_tenant_payload,
    tombstone_aad,
    verify_entry,
    verify_tenant_payload,
)
from .models import EncryptedEnvelope
from .protocols import EncryptionRequiredError

# The vault's logger: records keep the name callers filter on.
logger = logging.getLogger("kibisis.vault")


#: Integrity format this version writes (vault_meta 'integrity_format'). Format 2 binds sealed content
#: to its entry, signs entries with a key derived by PBKDF2, keys the value digests kept in the journal
#: and in tombstones, and refuses entries without a signature. A vault without the marker is upgraded
#: the first time it is opened with its passphrase.
INTEGRITY_FORMAT = 2


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


class EntryIntegrityError(PermissionError):
    """Raised when a stored entry fails its integrity check: it has no signature, its signature does
    not verify, or its sealed content does not belong to it. ``get`` raises it; ``search`` and
    ``list_entities`` leave such an entry out."""


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


class EntryIntegrityMixin:
    """Seals, signs, opens and checks entries; keys the value digests; upgrades the integrity format."""

    def _vault_salt(self) -> bytes:
        """One random KDF salt per vault, stored beside the data. A salt is not a secret."""
        # Locked before the read so two processes opening a new vault together agree on one salt.
        with self._write_tx() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            row = cursor.execute("SELECT value FROM vault_meta WHERE key = 'kdf_salt'").fetchone()
            if row is not None:
                return bytes(row[0])
            salt = os.urandom(16)
            cursor.execute("INSERT INTO vault_meta (key, value) VALUES ('kdf_salt', ?)", (salt,))
            return salt

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
        with self._write_tx() as cursor:
            for r in rows:
                try:
                    content = self._open_entry(r)  # never seal content that fails its signature check
                except EntryIntegrityError:
                    refused += 1
                    continue
                self._write_sealed(cursor, r, content, encrypt=True)
        self.scrub()
        return {"migrated": len(rows) - refused, "remaining_plaintext": self.encryption_status()["plaintext"]}

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
        if self._search_index or self._term_index:
            self._index_entry(cursor, r["id"], r["category"], r["key"], content, r["scope"])

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
        return self._stored_digests(*value_digests(value))

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

    def _key_check_value(self) -> str:
        return hmac.new(self._signing_key, b"kibisis key check v2", hashlib.sha256).hexdigest()

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
        with self._write_tx() as cursor:
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
                "author_id, metadata_json, format FROM audit_journal ORDER BY sequence ASC"
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
            chain_was_valid = self.verify_audit_chain()
            prev_hash = "0" * 64
            for ev in events:
                value = keyed_value_digest(digest_key, ev["value_sha256"])
                metadata = json.loads(ev["metadata_json"] or "{}")
                if _rekey_metadata(metadata, digest_key) or value != ev["value_sha256"]:
                    counts["journal_events_rekeyed"] += 1
                event_hash = _event_hash(
                    ev["sequence"], ev["timestamp"], ev["action"], ev["category"], ev["key"], ev["scope"],
                    value, prev_hash, ev["author_id"], metadata, fmt=ev["format"],
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
        with self._write_tx() as cursor:
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
