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

from ._vault_audit import JOURNAL_FORMAT, _event_hash
from .crypto import (
    ENTRY_BINDING,
    ENTRY_SIGNATURE_PREFIX,
    TOMBSTONE_BINDING,
    VAULT_META_BOUND_KEYS,
    VAULT_META_BOUND_KEYS_V1,
    entry_aad,
    keyed_value_digest,
    sign_entry,
    sign_tenant_payload,
    tombstone_aad,
    tombstone_mac,
    vault_meta_mac,
    verify_entry,
    verify_tenant_payload,
    verify_tombstone_mac,
)
from .models import EncryptedEnvelope
from .protocols import EncryptionRequiredError

# The vault's logger: records keep the name callers filter on.
logger = logging.getLogger("kibisis.vault")


#: Integrity format this version writes (vault_meta 'integrity_format'). Format 2 binds sealed content
#: to its entry, signs entries with a key derived by PBKDF2, keys the value digests kept in the journal
#: and in tombstones, and refuses entries without a signature. Format 3 signs every tombstone row
#: (``tombstone_mac``), pins the journal's format floor and anchoring, and binds the ``vault_meta``
#: values that decide how the vault is checked under one MAC (``meta_mac``). A vault below the current
#: format is upgraded the first time it is opened with its passphrase, after the passphrase has been
#: checked and the journal has verified.
INTEGRITY_FORMAT = 3


class EntryIntegrityError(PermissionError):
    """Raised when a stored entry fails its integrity check: it has no signature, its signature does
    not verify, or its sealed content does not belong to it. ``get`` raises it; ``search`` and
    ``list_entities`` leave such an entry out (logged at WARNING, counted in ``integrity_failures``,
    raised instead under ``strict=True``)."""


class VaultIntegrityError(PermissionError):
    """Raised on open when the vault's own integrity records do not hold: the meta MAC is missing or
    wrong, a keyed vault has no key check, a tombstone row is missing or fails its MAC, or a journal that
    must verify before an upgrade does not. Nothing is written when it is raised."""


#: Default_Ignorable code points that take up space on the line: the Hangul fillers (``Lo``, NFKC
#: keeps them) render as a blank the width of a syllable, so a sentence typed with them in place of
#: its spaces reads as the sentence. They fold to a SPACE, not to nothing (R2-A5).
_BLANK_CODE_POINTS = frozenset([0x115F, 0x1160, 0x3164, 0xFFA0])

#: Code points that render as nothing but are not ``Cf``/``Cc``, plus the Default_Ignorable blocks
#: NFKC keeps: variation selectors, the combining grapheme joiner and the Mongolian free variation
#: selectors are ``Mn`` and are dropped by category below; these are the rest.
_IGNORABLE_CODE_POINTS = frozenset(
    [0x034F, 0x180B, 0x180C, 0x180D, 0x180E, 0x180F, 0x200B, 0x2060, 0x2061,
     0x2062, 0x2063, 0x2064, 0xFEFF, 0xFE00, 0xFE01, 0xFE02, 0xFE03, 0xFE04, 0xFE05, 0xFE06, 0xFE07, 0xFE08,
     0xFE09, 0xFE0A, 0xFE0B, 0xFE0C, 0xFE0D, 0xFE0E, 0xFE0F, 0x17B4, 0x17B5]
    + list(range(0xE0100, 0xE01F0))
)

#: Confusables fold for the look-alikes an agent can type without noticing: the Cyrillic and Greek
#: letters whose usual glyphs match a Latin letter, and dotless i. A small table on purpose: UTS #39's
#: full skeleton is not shipped, and paraphrase is out of scope (README, "Limits").
_CONFUSABLES = {
    # Cyrillic lower case (after casefold every letter is lower case)
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ѵ": "v", "ҽ": "e", "ԍ": "g",
    "ё": "e", "є": "e", "ү": "y", "ҳ": "x",
    # Greek lower case
    "α": "a", "ο": "o", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ϲ": "c", "ϳ": "j", "ⲟ": "o",
    # dotless i and other Latin look-alikes
    "ı": "i", "ȷ": "j", "ⅰ": "i", "ℓ": "l",
}


def canonicalize_text(text: str) -> str:
    """Normalize text for evasion-resistant tombstone matching.

    Transforms text by:
    1. Unicode NFKC normalization (fullwidth characters, compatibility ligatures, composed forms)
    2. Unicode case folding (.casefold())
    3. Dropping invisible code points: format/control (``Cf``/``Cc``), nonspacing and enclosing
       marks (``Mn``/``Me``: variation selectors, combining grapheme joiner, Mongolian FVS, combining
       accents that NFKC could not compose), and the zero-width Default_Ignorable code points NFKC
       keeps (zero-width joiners, word joiners, variation selectors). Spacing combining marks (``Mc``,
       the side vowel signs of Devanagari, Tamil and other abugidas) are kept: they distinguish words.
    4. Turning the Default_Ignorable code points that take up space (the Hangul fillers U+115F, U+1160,
       U+3164, U+FFA0) into a space, like any other blank
    5. Folding common Latin/Cyrillic/Greek homoglyphs and dotless i to their Latin letter (a small
       built-in table, not UTS #39's full skeleton)
    6. Stripping all Unicode punctuation and symbols (replacing with space separators)
    7. Collapsing all whitespace runs into single spaces and trimming

    What it does not do: recognise a paraphrase, a translation, a different word order, or a
    homoglyph outside the table. A tombstone stops a value and its spellings, not an idea. Vowel
    signs written as nonspacing marks (``Mn``, above or below the consonant) are still dropped, so
    two words that differ only in such a sign fold alike.
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    chars: List[str] = []
    for ch in normalized:
        if ch.isspace() or ord(ch) in _BLANK_CODE_POINTS:
            chars.append(" ")
            continue
        if ord(ch) in _IGNORABLE_CODE_POINTS:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc", "Mn", "Me"):
            # Drop invisible format/control characters (e.g. \u200b, \u200c, \u200d, \ufeff, \u00ad)
            # and nonspacing marks (e.g. \ufe0f, \u034f, \u180b, accents added to evade a match).
            continue
        ch = _CONFUSABLES.get(ch, ch)
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

    def _refuse_keyed_records_without_salt(self) -> None:
        """Raise :class:`VaultIntegrityError` when ``vault_meta`` holds what only a keyed vault writes
        (a key check, a meta MAC, an integrity format of 2 or more) but no ``kdf_salt``: the salt was
        removed. Without it the records cannot be checked and the file would read as a plaintext vault
        (read-only) or be given a fresh salt and fail its key check only after writing (writable)."""
        if not self._has_meta_key("integrity_format") and not self._has_meta_key("key_check") \
                and not self._has_meta_key("meta_mac"):
            return  # no vault_meta table, or none of the keyed records: never keyed
        rows = self._conn.execute(
            "SELECT key FROM vault_meta WHERE key IN ('key_check', 'meta_mac', 'integrity_format', 'kdf_salt')"
        ).fetchall()
        present = {r[0] for r in rows}
        if "kdf_salt" in present:
            return
        keyed = [k for k in ("key_check", "meta_mac") if k in present]
        if "integrity_format" in present and int(self._meta("integrity_format") or 0) >= 2:
            keyed.append("integrity_format >= 2")
        if keyed:
            raise VaultIntegrityError(
                f"{self.db_path}: vault_meta carries {', '.join(keyed)} but no kdf_salt; the vault's salt was "
                "removed. Refusing to open; restore the salt before opening."
            )

    def _vault_salt(self) -> bytes:
        """One random KDF salt per vault, stored beside the data. A salt is not a secret. A vault whose
        records say it was keyed but whose salt is gone gets no new one (:class:`VaultIntegrityError`)."""
        # Locked before the read so two processes opening a new vault together agree on one salt.
        with self._write_tx() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            row = cursor.execute("SELECT value FROM vault_meta WHERE key = 'kdf_salt'").fetchone()
            if row is not None:
                return bytes(row[0])
            self._refuse_keyed_records_without_salt()
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
        "[ENCRYPTED]" when it is sealed and this vault has no key to open it.

        A row left out is never silent: it is logged at WARNING with its category and key, counted in
        :attr:`integrity_failures`, and under ``strict=True`` the :class:`EntryIntegrityError` is raised
        instead of the row being dropped.
        """
        try:
            return self._open_entry(r)
        except EntryIntegrityError as exc:
            self._note_integrity_failure(r, exc)
            if self.strict:
                raise
            return None
        except PermissionError:
            return "[ENCRYPTED]"

    def _note_integrity_failure(self, r: Any, exc: BaseException) -> None:
        """Record a row that a read refused (see :attr:`integrity_failures`)."""
        failures = self.integrity_failures
        failures["count"] += 1
        recent = failures["recent"]
        recent.append((r["category"], r["key"]))
        del recent[:-10]
        logger.warning(
            "%s: entry '%s:%s' [scope=%s] left out of the results: %s",
            self.db_path, r["category"], r["key"], r["scope"], exc,
        )

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
        """Plain digests of a sealed tombstone (this vault's, or another's with the same passphrase), or None.

        A tombstone carried in by a snapshot was sealed under the other vault's salt: that is the one
        place an envelope's own salt is honoured (:meth:`AESGCMCryptoEnvelopeProvider.decrypt_foreign`).
        """
        if self.crypto_provider is None or not self.passphrase:
            return None
        try:
            envelope = EncryptedEnvelope.model_validate_json(sealed)
            aad = tombstone_aad(scope, category, key)
            opener = getattr(self.crypto_provider, "decrypt_foreign", None)
            if opener is None:
                plain = self.crypto_provider.decrypt(envelope, self.passphrase, aad=aad)
            else:
                plain = opener(envelope, self.passphrase, aad=aad)
            exact, canonical = json.loads(plain)
            return str(exact), str(canonical)
        except Exception:
            return None

    def _key_check_value(self) -> str:
        return hmac.new(self._signing_key, b"kibisis key check v2", hashlib.sha256).hexdigest()

    #: What a Kibisis 0.1.0a5 file never has (checked against ``tests/fixtures/vault-0.1.0a5-fallback.sqlite``,
    #: whose ``vault_meta`` holds ``kdf_salt`` alone): tables, columns and ``vault_meta`` keys that only
    #: integrity format 2 and later, or the schema upgrade of a later release, write.
    _A5_FOREIGN_TABLES: Tuple[str, ...] = ("audit_head",)
    _A5_FOREIGN_COLUMNS: Tuple[Tuple[str, str], ...] = (("audit_journal", "format"), ("rejected_value_tombstones", "tombstone_mac"))
    _A5_FOREIGN_META: Tuple[str, ...] = ("key_check", "meta_mac", "journal_format_floor", "journal_anchored", "verification_quorum")

    def _refuse_unless_genuine_a5(self, passphrase: str) -> Optional[Tuple[bytes, Tuple[bytes, bytes, bytes]]]:
        """The one discriminator between a genuine Kibisis 0.1.0a5 file and a keyed (integrity format 2+)
        file reset to look like one, run on the plain file BEFORE ``_init_schema`` adds what a later
        release's schema has. It applies to a file whose ``vault_meta`` carries ``kdf_salt`` but no
        ``key_check`` and claims integrity format below 2: that is what a5 wrote, and also what a file
        writer (r/w on the plain SQLite file, no passphrase) leaves after deleting the key check, meta
        MAC and integrity format, blanking the signatures and re-chaining the journal headless in
        format 1 (R2-B1, R3-AB2, R4-1), hoping to re-enter the format 1 migration, which authenticates
        nothing but the entries it opens and then signs whatever it finds. Only a file that is provably
        an a5 file is let into that migration; any failure is a :class:`VaultIntegrityError` that names
        every witness found, and nothing is written. Returns ``(salt, derived keys)`` when the file
        passed (so the open need not derive them again), or None when the file is not a candidate (no
        ``vault_meta``, no salt, or a key check present: the ordinary checks in ``_upgrade_integrity``
        decide those).

        Witnesses, each enough on its own, and why:

        * table ``audit_head`` exists: the signed journal head arrived after a5 (the migration would
          otherwise sign a headless chain; a headless format 1 chain has no keyed element at all);
        * column ``audit_journal.format``: the journal format label arrived with integrity format 2+;
        * column ``rejected_value_tombstones.tombstone_mac``: tombstone MACs are integrity format 3;
        * ``vault_meta`` ``key_check``, ``meta_mac``, ``journal_format_floor``, ``journal_anchored`` or
          ``verification_quorum`` (:data:`_A5_FOREIGN_META`), or ``integrity_format`` of 2 or more:
          a5's ``vault_meta`` holds the salt alone;
        * an entity row with ``is_encrypted != 1``: a5 sealed every entry of a vault with a passphrase
          (the fixture: 6 of 6), so a plaintext row in a keyed format 1 file was edited (the R3-AB2
          flip, or R4-1's flip plus a blanked envelope);
        * an entity row whose envelope is NULL, empty or does not parse: no sealed content to
          authenticate the row with (R4-1);
        * an envelope carrying the format 2 binding (``ENTRY_BINDING``): a5 never wrote it, and it is
          inside the ciphertext's authenticated data, so it cannot be removed without the key; an
          envelope whose binding string was scrubbed from the text still opens only under that
          associated data (``entry_aad``), and is counted the same way;
        * a sealed envelope that does not open under the passphrase-derived key the way a5 sealed it
          (no binding): every a5 row is its own proof of the passphrase. When no sealed row opens at
          all the passphrase is wrong (or every envelope was replaced): ``ValueError`` ("Failed to
          authenticate ..."), the same refusal as for any wrong passphrase;
        * the entity table is empty while the journal records ``put``/``update`` events that were never
          purged or tombstoned: the entries were deleted (the R3-AB2 ``DELETE FROM entities`` variant).

        What is left to a file writer is the reset that satisfies all of these: a headless journal
        with no entry event and no sealed entry, which is an empty vault (SECURITY.md). The
        ``tenant_sig`` column is not a witness: the fixture holds an a5 row without one.
        """
        from .crypto import AESGCMCryptoEnvelopeProvider, derive_vault_keys

        conn = self._conn
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        if "vault_meta" not in tables:
            return None
        meta = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM vault_meta").fetchall()}
        if meta.get("kdf_salt") is None or meta.get("key_check") is not None:
            return None
        salt = bytes(meta["kdf_salt"])
        found: List[str] = []
        try:
            stored_format = int(meta.get("integrity_format") or 0)
        except (TypeError, ValueError):
            stored_format = 0
        if stored_format >= 2:
            found.append(f"vault_meta.integrity_format = {stored_format}")
        for table in self._A5_FOREIGN_TABLES:
            if table in tables:
                found.append(f"a table {table}")
        for table, column in self._A5_FOREIGN_COLUMNS:
            if table in tables and column in {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}:
                found.append(f"a column {table}.{column}")
        for name in self._A5_FOREIGN_META:
            if meta.get(name) is not None:
                found.append(f"vault_meta.{name}")
        rows = (
            conn.execute(
                "SELECT category, key, scope, is_encrypted, encrypted_envelope_json FROM entities ORDER BY id"
            ).fetchall()
            if "entities" in tables
            else []
        )
        plaintext = bound = unparsable = 0
        openable: List[Tuple[Any, EncryptedEnvelope]] = []
        for r in rows:
            if r["is_encrypted"] != 1:
                plaintext += 1
            try:
                envelope = EncryptedEnvelope.model_validate_json(r["encrypted_envelope_json"] or "")
            except Exception:
                unparsable += int(r["is_encrypted"] == 1)  # a plaintext row is counted once, above
                continue
            if envelope.binding == ENTRY_BINDING:
                bound += 1
            else:
                openable.append((r, envelope))
        if plaintext:
            found.append(f"{plaintext} of {len(rows)} entries marked plaintext (is_encrypted != 1)")
        if unparsable:
            found.append(f"{unparsable} of {len(rows)} entries whose sealed envelope is missing or malformed")
        if bound:
            found.append(f"{bound} of {len(rows)} entries sealed with its binding (an integrity format 2 seal)")
        provider = AESGCMCryptoEnvelopeProvider(salt=salt)
        opened = 0
        closed: List[str] = []
        rebound = 0
        for r, envelope in openable:
            try:
                provider.decrypt(envelope, passphrase, aad=None)
                opened += 1
                continue
            except Exception:
                pass
            try:
                # The binding string was scrubbed from the envelope text but the ciphertext still carries the
                # format 2 associated data: the seal itself is the witness.
                provider.decrypt(envelope, passphrase, aad=entry_aad(r["scope"], r["category"], r["key"]))
                rebound += 1
            except Exception:
                closed.append(f"{r['category']}:{r['key']} [scope={r['scope']}]")
        if rebound:
            found.append(f"{rebound} of {len(rows)} entries whose seal opens only under its binding (an integrity format 2 seal)")
        if closed and not opened and not found:
            # Nothing else is wrong with the file and no sealed row opens: the passphrase is wrong (or every
            # envelope was replaced, which the right passphrase cannot tell apart); refused as a wrong passphrase.
            raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")
        if closed:
            found.append(
                f"{len(closed)} of {len(rows)} sealed entries that do not open under the passphrase, first {closed[0]}"
            )
        if not rows and "audit_journal" in tables:
            live: set = set()
            for ev in conn.execute("SELECT action, category, key, scope FROM audit_journal ORDER BY sequence ASC").fetchall():
                ident = (ev["category"], ev["key"], ev["scope"])
                if ev["action"] in ("put", "update"):
                    live.add(ident)
                elif ev["action"] in ("purge", "tombstone"):
                    live.discard(ident)
            if live:
                category, key, scope = sorted(live)[0]
                found.append(
                    f"an entity table that is empty while the journal records {len(live)} entries that were never "
                    f"purged, first '{category}:{key}' [scope={scope}]"
                )
        if found:
            raise VaultIntegrityError(
                f"{self.db_path}: the vault is keyed (kdf_salt present) but has no key check, and it is not a "
                f"0.1.0a5 file: it holds {'; '.join(found)}. Only a genuine 0.1.0a5 file is migrated; the "
                "integrity records were removed. Refusing to migrate; restore the records before opening."
            )
        return salt, derive_vault_keys(passphrase, salt)

    def _upgrade_integrity(self) -> None:
        """Check the passphrase, then bring an older vault up to INTEGRITY_FORMAT, then check the records.

        Order matters. The key check (``vault_meta.key_check``) is compared first, before any migration
        writes, so a wrong passphrase can never re-key a vault; a keyed vault without a key check is
        refused (:class:`VaultIntegrityError`): one that reports integrity format 2 or higher outright,
        and one that reports format 1 but carries a ``kdf_salt`` unless the one a5 discriminator
        (:meth:`_refuse_unless_genuine_a5`, run on the plain file before ``_init_schema``) proved it
        is a genuine 0.1.0a5 file. A vault at format 1 is
        migrated to 2 (:meth:`_migrate_integrity`; it authenticates through the entries it opens and
        refuses when its journal does not verify), then any vault below 3 is brought to 3
        (:meth:`_upgrade_to_format_3`). A vault already at format 3 must carry a meta MAC that verifies.
        Finally every tombstone row's MAC is checked and the journal's tombstone events are reconciled
        with the rows (:meth:`_check_tombstones`).
        """
        stored_format = int(self._meta("integrity_format") or 0)
        stored = self._meta("key_check")
        if stored is not None:
            if not hmac.compare_digest(str(stored), self._key_check_value()):
                raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")
        elif stored_format >= 2:
            raise VaultIntegrityError(
                f"{self.db_path}: the vault is keyed (integrity format {stored_format}) but has no key check; "
                "refusing to open"
            )
        elif self._was_keyed:
            # A salt with no key check and a format 1 claim: a 0.1.0a5 vault looks like this, and so does a
            # keyed vault whose key check, meta MAC and integrity format were all removed to re-enter the
            # format 1 migration (which would re-sign whatever the editor left). The one discriminator,
            # ``_refuse_unless_genuine_a5``, ran on the plain file before ``_init_schema`` and refused
            # anything that is not provably an a5 file; it must have run for the migration to be allowed.
            if not getattr(self, "_a5_checked", False):
                raise VaultIntegrityError(
                    f"{self.db_path}: the vault is keyed (kdf_salt present) but has no key check, and it was not "
                    "checked as a 0.1.0a5 file before the schema upgrade; refusing to migrate."
                )
        if stored_format < 2 and (stored is not None or self._meta("meta_mac") is not None):
            # Format 1 wrote neither record. A vault that carries one while claiming format 1 had its
            # integrity_format edited down; migrating it would re-sign under the editor's story.
            raise VaultIntegrityError(
                f"{self.db_path}: vault_meta.integrity_format says {stored_format} but the vault carries a key "
                "check or meta MAC, which only integrity format 2 and later write; the integrity record was "
                "edited. Refusing to migrate; restore the record before opening."
            )
        if stored_format < 2:
            self.integrity_upgrade = self._migrate_integrity()
            stored_format = int(self._meta("integrity_format") or 0)
        if stored_format < INTEGRITY_FORMAT:
            self._upgrade_to_format_3()
        else:
            self._verify_meta_mac()
        self._integrity_format = INTEGRITY_FORMAT
        self._journal_anchored = bool(int(self._meta("journal_anchored") or 0))
        self._check_tombstones()

    # --- vault_meta MAC (integrity format 3) ------------------------------------------------------------

    def _meta_mac_fields(self) -> Dict[str, Any]:
        return {name: self._meta(name) for name in VAULT_META_BOUND_KEYS}

    def _write_meta_mac(self, cursor: Any) -> None:
        """Sign the bound ``vault_meta`` values as they stand now; every change to one of them ends here.
        Nothing is written for a vault without a passphrase: it has no secret to sign with."""
        if not self._keyed:
            return
        self._set_meta(cursor, "meta_mac", vault_meta_mac(self._signing_key, self._meta_mac_fields()))

    def _verify_meta_mac(self) -> None:
        """Refuse a keyed vault whose meta MAC is missing or does not cover the stored values.

        A MAC written before ``verification_quorum`` was one of the bound values (the legacy set,
        :data:`VAULT_META_BOUND_KEYS_V1`) is accepted once, logged at WARNING, and replaced by one over
        the full set when the vault is open writable; a read-only open accepts it as it is. Such a MAC
        never covered the stored quorum, and any pre-upgrade copy of it stays valid over the legacy set,
        so no stored quorum is trusted while it holds, whatever its value (R3-AB4, R4-2): it is ignored
        (``_stored_quorum``, which logs the value) and dropped before the re-sign
        (``_drop_untrusted_stored_quorum``), so the new MAC never signs a value nobody signed. The
        person loses nothing: the next review verdict run under their ``KIBISIS_VERIFICATION_QUORUM``
        pins it again, under the full-set MAC.
        """
        stored = self._meta("meta_mac")
        if stored is None:
            raise VaultIntegrityError(f"{self.db_path}: the vault's meta MAC is missing; refusing to open")
        fields = self._meta_mac_fields()
        if hmac.compare_digest(str(stored), vault_meta_mac(self._signing_key, fields)):
            return
        if hmac.compare_digest(str(stored), vault_meta_mac(self._signing_key, fields, VAULT_META_BOUND_KEYS_V1)):
            self._meta_mac_legacy = True
            if getattr(self, "read_only", False):
                logger.warning(
                    "%s: the meta MAC predates the bound verification quorum, so the stored quorum is not covered "
                    "by it; re-signed at the next writable open",
                    self.db_path,
                )
                return
            logger.warning(
                "%s: the meta MAC predates the bound verification quorum; a stored quorum is not covered by it and "
                "is dropped, and the MAC is re-signed over the full set",
                self.db_path,
            )
            with self._write_tx() as cursor:
                self._drop_untrusted_stored_quorum(cursor)
                self._write_meta_mac(cursor)
            self._meta_mac_legacy = False  # what is stored now is what the new MAC covers
            return
        raise VaultIntegrityError(
            f"{self.db_path}: the vault's meta MAC does not cover its integrity records (integrity format, "
            "salt, key check, journal floor, term index format or verification quorum were changed); refusing to open"
        )

    def _upgrade_to_format_3(self) -> None:
        """Bring a format 2 vault (or a vault just migrated to 2) to format 3, in one transaction.

        The journal must verify first, under the rule it was written with (a journal from before
        0.1.0a10 may have no head); a journal that fails is refused, never re-signed. A journal that
        verified but has no head gets one for its last row, since from now on the head is demanded.
        Every tombstone row then gets its MAC, the journal's format floor is pinned at the lowest
        format the journal holds (3 for a journal with no legacy rows), the journal is marked anchored
        if it holds a row, and the meta MAC is written. The passphrase was checked before this runs.
        An empty vault reports nothing (``integrity_upgrade`` stays None); one with data adds
        ``tombstones_signed`` and ``journal_format_floor`` to the report.
        """
        with self._write_tx() as cursor:
            if int(self._meta("integrity_format") or 0) >= INTEGRITY_FORMAT:
                self._verify_meta_mac()
                return  # another process upgraded it first
            if not self.verify_audit_chain():
                raise VaultIntegrityError(
                    f"{self.db_path}: the audit journal does not verify ({self.last_chain_error}); refusing to "
                    "upgrade it to integrity format 3. Verify the journal and repair it before opening."
                )
            signed = 0
            for t in cursor.execute(
                "SELECT id, category, key, scope, value_sha256, canonical_sha256, origin_class FROM rejected_value_tombstones"
            ).fetchall():
                cursor.execute(
                    "UPDATE rejected_value_tombstones SET tombstone_mac = ? WHERE id = ?",
                    (self._tombstone_mac(t["scope"], t["category"], t["key"], t["value_sha256"], t["canonical_sha256"],
                                         t["origin_class"] or "principal"),
                     t["id"]),
                )
                signed += 1
            lowest = cursor.execute("SELECT MIN(format), COUNT(*) FROM audit_journal").fetchone()
            floor = int(lowest[0]) if lowest[0] is not None else JOURNAL_FORMAT
            if lowest[1] and cursor.execute("SELECT 1 FROM audit_head WHERE id = 1").fetchone() is None:
                last = cursor.execute(
                    "SELECT sequence, event_hash FROM audit_journal ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                self._write_audit_head(cursor, last["sequence"], last["event_hash"])
            self._set_meta(cursor, "journal_format_floor", floor)
            self._set_meta(cursor, "journal_anchored", 1 if lowest[1] else 0)
            self._set_meta(cursor, "integrity_format", INTEGRITY_FORMAT)
            self._set_meta(cursor, "key_check", self._key_check_value())
            self._write_meta_mac(cursor)
        if not (signed or lowest[1]):
            return
        if self.integrity_upgrade is None:
            self.integrity_upgrade = {}
        self.integrity_upgrade["tombstones_signed"] = signed
        self.integrity_upgrade["journal_format_floor"] = floor

    # --- tombstone MACs ------------------------------------------------------------------------------

    def _tombstone_mac(
        self, scope: str, category: str, key: str, value_sha256: str, canonical_sha256: str,
        origin_class: str = "principal",
    ) -> str:
        """MAC of a tombstone row under this vault's signing key (see :func:`kibisis.crypto.tombstone_mac`)."""
        return tombstone_mac(self._signing_key, scope, category, key, value_sha256, canonical_sha256 or "", origin_class)

    def _verify_tombstone_row(self, row: Any) -> None:
        """Raise :class:`VaultIntegrityError` unless ``row`` (with scope, category, key, value_sha256,
        canonical_sha256, tombstone_mac) carries a MAC under this vault's key. A vault still below
        integrity format 3 has unsigned rows; they are signed by the upgrade before any lookup runs."""
        if self._integrity_format < 3:
            return
        if not verify_tombstone_mac(
            self._signing_key, row["scope"], row["category"], row["key"], row["value_sha256"],
            row["canonical_sha256"] or "", row["tombstone_mac"], row["origin_class"] or "principal",
        ):
            raise VaultIntegrityError(
                f"{self.db_path}: tombstone '{row['category']}:{row['key']}' [scope={row['scope']}] "
                f"{'has no MAC' if not row['tombstone_mac'] else 'fails its MAC'}: the tombstone table was changed "
                "outside kibisis"
            )

    def _check_tombstones(self) -> None:
        """At open: every tombstone row must carry a valid MAC, and every ``tombstone`` event in the journal
        that no later ``tombstone_lifted`` event undid must still have its row (by category, key, value
        digest and scope) at no lower a class than the event journaled (``metadata.origin_class``). A row
        removed, edited or replaced by an older lower-class copy behind the vault's back raises
        :class:`VaultIntegrityError`. Other journal actions are not consulted.

        A ``tombstone_lifted`` event names the row it removed. Events written by earlier releases from a
        lower-class lift (``_lift_lower_class_tombstones``) named the writer's entry instead and put the
        row's ``category:key`` and scope in ``metadata.tombstone`` / ``tombstone_scope``; those are
        matched through the metadata so such vaults still open (R3-AB1): by the named ``category:key``
        when it differs from the event's own, and by the named scope whenever it differs from the
        event's (a global ``'*'`` row lifted by a write under the same ``category:key``, R4-3)."""
        from ._vault_review import ORIGIN_CLASSES, _class_rank

        rows = self._conn.execute(
            "SELECT category, key, scope, value_sha256, canonical_sha256, origin_class, tombstone_mac "
            "FROM rejected_value_tombstones"
        ).fetchall()
        for row in rows:
            self._verify_tombstone_row(row)
        present = {(r["category"], r["key"], r["value_sha256"], r["scope"]): r["origin_class"] or "principal" for r in rows}
        expected: Dict[Tuple[str, str, str, str], Tuple[int, Optional[str]]] = {}
        for ev in self._conn.execute(
            "SELECT sequence, action, category, key, scope, value_sha256, metadata_json FROM audit_journal "
            "WHERE action IN ('tombstone', 'tombstone_lifted') ORDER BY sequence ASC"
        ).fetchall():
            ident = (ev["category"], ev["key"], ev["value_sha256"], ev["scope"])
            try:
                meta = json.loads(ev["metadata_json"] or "{}")
            except ValueError:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            if ev["action"] == "tombstone":
                klass = meta.get("origin_class")
                expected[ident] = (ev["sequence"], klass if klass in ORIGIN_CLASSES else None)
                continue
            expected.pop(ident, None)
            named = meta.get("tombstone")
            named_scope = meta.get("tombstone_scope")
            row_scope = named_scope if isinstance(named_scope, str) and named_scope else ev["scope"]
            if isinstance(named, str) and ":" in named and named != f"{ev['category']}:{ev['key']}":
                for cut in (i for i, ch in enumerate(named) if ch == ":"):
                    expected.pop((named[:cut], named[cut + 1:], ev["value_sha256"], row_scope), None)
            if row_scope != ev["scope"]:
                # R4-3: a legacy lift of a row in another scope (a global '*' row) under the event's own
                # category:key names only the scope; pop that row whatever the name test said.
                expected.pop((ev["category"], ev["key"], ev["value_sha256"], row_scope), None)
        missing = [ident for ident in expected if ident not in present]
        if missing:
            category, key, _, scope = missing[0]
            raise VaultIntegrityError(
                f"{self.db_path}: {len(missing)} journaled tombstone(s) have no row, first '{category}:{key}' "
                f"[scope={scope}] (journal sequence {expected[missing[0]][0]}): the tombstone table was changed outside "
                "kibisis"
            )
        for ident, (sequence, klass) in expected.items():
            if klass is not None and _class_rank(present[ident]) < _class_rank(klass):
                category, key, _, scope = ident
                raise VaultIntegrityError(
                    f"{self.db_path}: tombstone '{category}:{key}' [scope={scope}] is of class {present[ident]} but "
                    f"the journal records it as {klass} (sequence {sequence}): an older copy of the row was put back "
                    "outside kibisis"
                )

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
            if int(self._meta("integrity_format") or 0) >= 2:
                return None  # another process upgraded it first
            rows = cursor.execute(
                "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities"
            ).fetchall()
            tombstones = cursor.execute(
                "SELECT id, category, key, scope, value_sha256, canonical_sha256, origin_class FROM rejected_value_tombstones"
            ).fetchall()
            events = cursor.execute(
                "SELECT sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, event_hash, "
                "author_id, metadata_json, format FROM audit_journal ORDER BY sequence ASC"
            ).fetchall()
            if not (rows or tombstones or events):
                self._set_meta(cursor, "integrity_format", 2)
                self._set_meta(cursor, "key_check", self._key_check_value())
                return None

            # A vault that never had a passphrase holds only plaintext entries, signed (if at all) with a key
            # anyone can compute, so its first open with a passphrase is where trust starts: adopt them.
            # Otherwise decide every entry before changing anything, and stop under a wrong passphrase: an
            # upgrade under the wrong key would re-key the tombstones and the journal beyond repair.
            was_keyed = self._was_keyed or any(r["is_encrypted"] == 1 for r in rows)
            # With a salt present the file passed ``_refuse_unless_genuine_a5`` before ``_init_schema``: every
            # row is sealed the way a5 sealed it and opens under the passphrase, and an empty table has no
            # unpurged entry event behind it. The chain check below is necessary (a journal that does not
            # verify is never re-signed) but it admits nothing on its own: a headless format 1 chain has no
            # keyed element, so the opened rows are what authenticate the file (R2-B1, R3-AB2, R4-1).
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
                new_exact = keyed_value_digest(digest_key, exact)
                new_canonical = keyed_value_digest(digest_key, canonical)
                klass = t["origin_class"] or "principal"
                cursor.execute(
                    "UPDATE rejected_value_tombstones SET value_sha256 = ?, canonical_sha256 = ?, sealed_digests = ?, "
                    "tombstone_mac = ? WHERE id = ?",
                    (
                        new_exact,
                        new_canonical,
                        self._seal_digests(t["scope"], t["category"], t["key"], exact, canonical),
                        self._tombstone_mac(t["scope"], t["category"], t["key"], new_exact, new_canonical, klass),
                        t["id"],
                    ),
                )
                counts["tombstones_rekeyed"] += 1

            old_head = events[-1]["event_hash"] if events else "0" * 64
            # The format 1 journal head was signed under the legacy key: the passphrase's for a vault that had
            # one, the path's for a vault opened without. A vault that carries a salt was keyed, so its chain
            # must verify under the passphrase's key alone: the path's key is one a file writer computes
            # (R3-AB2). Only a vault with no salt is tried under the path's key.
            chain_was_valid = False
            current_key = self._signing_key
            candidates = [self._legacy_signing_key]
            if not self._was_keyed:
                candidates.append(hashlib.sha256(f"kibisis-tenant-sig:{self.db_path}".encode("utf-8")).digest())
            try:
                for candidate in candidates:
                    self._signing_key = candidate
                    if self.verify_audit_chain():
                        chain_was_valid = True
                        break
            finally:
                self._signing_key = current_key
            if not chain_was_valid:
                raise VaultIntegrityError(
                    f"{self.db_path}: the audit journal does not verify ({self.last_chain_error}); refusing to "
                    "upgrade it to integrity format 2, which would re-sign it. Verify and repair the journal first."
                )
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
                    "integrity_format": 2,
                    "previous_head": old_head,
                    "previous_chain_valid": chain_was_valid,
                    **counts,
                },
            )
            self._set_meta(cursor, "integrity_format", 2)
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
