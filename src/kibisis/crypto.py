"""Cryptography for Kibisis: AES-256-GCM envelopes under PBKDF2-derived keys, entry signatures,
keyed value digests, and the keys behind them."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .models import EncryptedEnvelope
from .protocols import CryptoEnvelopeProvider

#: ``EncryptedEnvelope.binding`` of content sealed with :func:`entry_aad` as associated data.
ENTRY_BINDING = "entry-v2"
#: ``EncryptedEnvelope.binding`` of a tombstone's sealed digests (see :func:`tombstone_aad`).
TOMBSTONE_BINDING = "tombstone-v2"
#: Prefix of signatures made by :func:`sign_entry`. Legacy signatures are bare hex.
ENTRY_SIGNATURE_PREFIX = "v2:"
#: Appended to a vault's KDF salt so its integrity keys are derived apart from its content key.
_INTEGRITY_SALT_SUFFIX = b"/kibisis-integrity-v2"


class AESGCMCryptoEnvelopeProvider(CryptoEnvelopeProvider):
    """AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation."""

    ITERATIONS = 600_000  # new envelopes; older ones carry their own count
    #: Highest stored iteration count ``decrypt`` will run. The count is not authenticated (it is
    #: read before the tag check), so a writer with database access could otherwise set it to 10**9
    #: and stall every read. Twice the current default leaves room to raise ITERATIONS once.
    MAX_ITERATIONS = ITERATIONS * 2
    KEY_LENGTH = 32  # 256-bit key
    SALT_LENGTH = 16
    NONCE_LENGTH = 12

    def __init__(self, salt: bytes | None = None) -> None:
        """``salt``: optional fixed salt (a vault passes its own). One salt per vault means one key derivation,
        not one per entry; every message still gets a fresh random nonce."""
        if salt is not None and len(salt) < self.SALT_LENGTH:
            raise ValueError(f"salt must be at least {self.SALT_LENGTH} bytes")
        self._salt = salt
        self._cache: dict[tuple[bytes, bytes, int], bytes] = {}

    def _derive_key(self, passphrase: str, salt: bytes, iterations: int | None = None) -> bytes:
        iters = iterations or self.ITERATIONS
        ck = (hashlib.sha256(passphrase.encode("utf-8")).digest(), salt, iters)
        hit = self._cache.get(ck)
        if hit is not None:
            return hit
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=iters,
        )
        key = kdf.derive(passphrase.encode("utf-8"))
        if len(self._cache) >= 64:
            self._cache.clear()
        self._cache[ck] = key
        return key

    def stretched_key(self, passphrase: str, salt: bytes) -> bytes:
        """PBKDF2-HMAC-SHA256 of ``passphrase`` under ``salt`` at :attr:`ITERATIONS` (cached)."""
        return self._derive_key(passphrase, salt)

    def encrypt(self, plaintext: bytes, passphrase: str, aad: Optional[bytes] = None) -> EncryptedEnvelope:
        """Seal ``plaintext``. ``aad`` is authenticated but not stored: decryption needs the same bytes."""
        salt = self._salt if self._salt is not None else os.urandom(self.SALT_LENGTH)
        nonce = os.urandom(self.NONCE_LENGTH)
        key = self._derive_key(passphrase, salt)

        aesgcm = AESGCM(key)
        # In AESGCM, ciphertext has tag appended at the end (16 bytes)
        encrypted_data = aesgcm.encrypt(nonce, plaintext, associated_data=aad)

        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        return EncryptedEnvelope(
            cipher="aes-256-gcm",
            kdf="pbkdf2-sha256",
            iterations=self.ITERATIONS,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            tag_b64=base64.b64encode(tag).decode("ascii"),
        )

    def decrypt(self, envelope: EncryptedEnvelope, passphrase: str, aad: Optional[bytes] = None) -> bytes:
        """Open an envelope. Fails (``cryptography.exceptions.InvalidTag``) on a wrong passphrase, damaged
        data, or ``aad`` that differs from the bytes it was sealed with.

        A provider bound to a vault salt (``salt=`` given) derives the key from that salt at
        :attr:`ITERATIONS` only: the envelope's own ``salt_b64`` and ``iterations`` are not used, and an
        envelope that names another salt is refused (``ValueError``) before any key derivation, so a
        writer with database access cannot pick the salt or the cost a read runs under. Every envelope a
        vault has written since 0.1.0a5 carries the vault salt at this count, so stored rows still open.
        An unbound provider keeps opening envelopes under their own salt and count (capped by
        :attr:`MAX_ITERATIONS`); :meth:`decrypt_foreign` does the same for one envelope of a bound one.
        """
        if self._salt is not None:
            envelope_salt = base64.b64decode(envelope.salt_b64)
            if not hmac.compare_digest(envelope_salt, self._salt):
                raise ValueError("Envelope was not sealed under this vault's salt")
            return self._open(envelope, passphrase, self._salt, self.ITERATIONS, aad)
        return self.decrypt_foreign(envelope, passphrase, aad)

    def decrypt_foreign(self, envelope: EncryptedEnvelope, passphrase: str, aad: Optional[bytes] = None) -> bytes:
        """Open an envelope sealed under another salt (a tombstone carried over from another vault that
        shares the passphrase). The envelope's iteration count is honoured up to :attr:`MAX_ITERATIONS`."""
        if envelope.iterations > self.MAX_ITERATIONS:
            # Checked before PBKDF2 runs: the cost is paid before the tag could reject the row.
            raise ValueError(
                f"Envelope iteration count {envelope.iterations} exceeds the limit {self.MAX_ITERATIONS}"
            )
        return self._open(envelope, passphrase, base64.b64decode(envelope.salt_b64), envelope.iterations, aad)

    def _open(
        self, envelope: EncryptedEnvelope, passphrase: str, salt: bytes, iterations: int, aad: Optional[bytes]
    ) -> bytes:
        if envelope.cipher != "aes-256-gcm":
            raise ValueError(f"Unsupported cipher: {envelope.cipher}")
        nonce = base64.b64decode(envelope.nonce_b64)
        ciphertext = base64.b64decode(envelope.ciphertext_b64)
        tag = base64.b64decode(envelope.tag_b64) if envelope.tag_b64 else b""
        key = self._derive_key(passphrase, salt, iterations)
        return AESGCM(key).decrypt(nonce, ciphertext + tag, associated_data=aad)


def derive_vault_keys(passphrase: str, vault_salt: bytes) -> Tuple[bytes, bytes, bytes]:
    """Return a vault's (signing key, digest key, term key).

    All three come from one PBKDF2-HMAC-SHA256 stretch of the passphrase (600,000 iterations) under the
    vault's salt plus a fixed suffix, so they are separate from the content key, and are split with
    HKDF-Expand under distinct labels. Testing a passphrase guess against a stored signature, digest or
    term token therefore costs a full PBKDF2 run, the same as testing it against sealed content.

    The term key tags the words of the keyed term index that a vault without SQLCipher keeps on disk
    (``SQLiteMemoryVault._term_token``). It is its own key so that a token can never be mistaken for, or
    turned into, an entry signature or a value digest.
    """
    root = AESGCMCryptoEnvelopeProvider().stretched_key(passphrase, vault_salt + _INTEGRITY_SALT_SUFFIX)
    signing = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"kibisis entry signature v2").derive(root)
    digest = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"kibisis value digest v2").derive(root)
    term = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"kibisis term index v1").derive(root)
    return signing, digest, term


def derive_integrity_keys(passphrase: str, vault_salt: bytes) -> Tuple[bytes, bytes]:
    """Return a vault's (signing key, digest key): the first two keys of :func:`derive_vault_keys`."""
    signing, digest, _ = derive_vault_keys(passphrase, vault_salt)
    return signing, digest


def _encode(parts: List[Any]) -> bytes:
    """Unambiguous encoding of a list of fields (JSON), so no two field lists share bytes."""
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def entry_aad(scope: str, category: str, key: str) -> bytes:
    """Associated data that binds sealed content to its entry: moved to another entry, it fails to decrypt."""
    return _encode(["kibisis-entry-aad", 2, scope, category, key])


def tombstone_aad(scope: str, category: str, key: str) -> bytes:
    """Associated data that binds a tombstone's sealed digests to the tombstone."""
    return _encode(["kibisis-tombstone-aad", 2, scope, category, key])


def sign_entry(signing_key: bytes, scope: str, category: str, key: str, content: str) -> str:
    """HMAC-SHA256 signature over an entry's scope, category, key and content."""
    mac = hmac.new(signing_key, _encode(["kibisis-entry", 2, scope, category, key, content]), hashlib.sha256)
    return ENTRY_SIGNATURE_PREFIX + mac.hexdigest()


def verify_entry(
    signing_key: bytes, scope: str, category: str, key: str, content: str, signature: Optional[str]
) -> bool:
    """Constant-time check of a :func:`sign_entry` signature. A missing or legacy signature fails."""
    if not signature or not signature.startswith(ENTRY_SIGNATURE_PREFIX):
        return False
    return hmac.compare_digest(signature, sign_entry(signing_key, scope, category, key, content))


def keyed_value_digest(digest_key: bytes, sha256_hex: str) -> str:
    """Keyed form of a value's SHA-256 hex digest, as the journal and tombstones store it.

    Keying the digest rather than the value lets an upgrade convert digests already on disk without
    the values. An empty digest stays empty.
    """
    if not sha256_hex:
        return ""
    return hmac.new(digest_key, b"kibisis-value-digest:" + sha256_hex.encode("utf-8"), hashlib.sha256).hexdigest()


def tombstone_mac(
    signing_key: bytes, scope: str, category: str, key: str, value_sha256: str, canonical_sha256: str,
    origin_class: str = "principal",
) -> str:
    """HMAC-SHA256 over a tombstone row's identifying columns, stored in ``tombstone_mac``.

    A tombstone is what keeps a rejected value out; without this a writer with database access could
    delete or edit the row and the value would be accepted again, unnoticed. The origin class is covered
    too, so a principal tombstone cannot be relabelled as one an agent may override. Every lookup hit and
    every open verifies it. Without a passphrase the key is not secret (it is derived from the path), so the
    MAC then catches accidental damage only.
    """
    msg = _encode(["kibisis-tombstone-mac", 2, scope, category, key, value_sha256, canonical_sha256, origin_class])
    return hmac.new(signing_key, msg, hashlib.sha256).hexdigest()


def verify_tombstone_mac(
    signing_key: bytes,
    scope: str,
    category: str,
    key: str,
    value_sha256: str,
    canonical_sha256: str,
    mac: Optional[str],
    origin_class: str = "principal",
) -> bool:
    """Constant-time check of a :func:`tombstone_mac`. A missing MAC fails."""
    if not mac:
        return False
    return hmac.compare_digest(
        str(mac), tombstone_mac(signing_key, scope, category, key, value_sha256, canonical_sha256, origin_class)
    )


#: ``vault_meta`` keys bound together by :func:`vault_meta_mac`, in the order they are encoded.
#: ``verification_quorum`` joined the set after the first format 3 vaults were written; a meta MAC
#: computed without it (:data:`VAULT_META_BOUND_KEYS_V1`) is accepted once and replaced by one that
#: covers it the next time the vault is opened writable (see ``_verify_meta_mac``).
VAULT_META_BOUND_KEYS_V1 = ("integrity_format", "kdf_salt", "key_check", "journal_format_floor", "journal_anchored",
                            "term_index_format")
VAULT_META_BOUND_KEYS = VAULT_META_BOUND_KEYS_V1 + ("verification_quorum",)
#: ``vault_meta`` keys bound by the full-set MAC only while present (R5-4): ``quorum_dropped_from``
#: records a stored quorum that a legacy MAC never covered and was dropped at a writable open. A vault
#: without the record keeps the MAC it has; one with it cannot lose it without the signing key.
VAULT_META_BOUND_OPTIONAL = ("quorum_dropped_from",)


def vault_meta_mac(signing_key: bytes, fields: Dict[str, Any], keys: Tuple[str, ...] = VAULT_META_BOUND_KEYS) -> str:
    """HMAC-SHA256 over the ``vault_meta`` values that decide how a vault is checked and opened
    (:data:`VAULT_META_BOUND_KEYS`). Each is encoded as its text form, bytes as hex, a missing key as
    ``null``, so a writer with database access cannot lower the integrity format, swap the salt, drop
    the key check or the journal floor, change the term index format, or lower the verification
    quorum without the signing key. ``keys`` names the bound set (the legacy set for a MAC written
    before ``verification_quorum`` was bound). A full set (one that binds ``verification_quorum``)
    also binds each :data:`VAULT_META_BOUND_OPTIONAL` key that is present, as a tagged pair after the
    fixed part, so vaults without the record keep their MAC."""
    parts: List[Any] = ["kibisis-vault-meta-mac", 1]
    for name in keys:
        value = fields.get(name)
        if value is None:
            parts.append(None)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            parts.append(bytes(value).hex())
        else:
            parts.append(str(value))
    if "verification_quorum" in keys:
        for name in VAULT_META_BOUND_OPTIONAL:
            value = fields.get(name)
            if value is not None:
                text = bytes(value).decode("utf-8", "replace") if isinstance(value, (bytes, bytearray, memoryview)) else str(value)
                parts.append([name, text])
    return hmac.new(signing_key, _encode(parts), hashlib.sha256).hexdigest()


def sign_tenant_payload(key: bytes, tenant_id: str, entity_id: str, content: str) -> str:
    """Integrity format 1 signature. Vaults without a passphrase still use it (nothing there is secret);
    vaults with one check it only while upgrading to format 2."""
    msg = f"{tenant_id}:{entity_id}:{content}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_tenant_payload(key: bytes, tenant_id: str, entity_id: str, content: str, signature: str) -> bool:
    """Verify an integrity format 1 signature using constant-time comparison."""
    if not signature:
        return False
    expected = sign_tenant_payload(key, tenant_id, entity_id, content)
    return hmac.compare_digest(signature, expected)
