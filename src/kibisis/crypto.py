"""Cryptography for Kibisis: AES-256-GCM envelopes under PBKDF2-derived keys, entry signatures,
keyed value digests, and the keys behind them."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any, List, Optional, Tuple

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
        data, or ``aad`` that differs from the bytes it was sealed with."""
        if envelope.cipher != "aes-256-gcm":
            raise ValueError(f"Unsupported cipher: {envelope.cipher}")
        if envelope.iterations > self.MAX_ITERATIONS:
            # Checked before PBKDF2 runs: the cost is paid before the tag could reject the row.
            raise ValueError(
                f"Envelope iteration count {envelope.iterations} exceeds the limit {self.MAX_ITERATIONS}"
            )

        salt = base64.b64decode(envelope.salt_b64)
        nonce = base64.b64decode(envelope.nonce_b64)
        ciphertext = base64.b64decode(envelope.ciphertext_b64)
        tag = base64.b64decode(envelope.tag_b64) if envelope.tag_b64 else b""

        full_payload = ciphertext + tag
        key = self._derive_key(passphrase, salt, envelope.iterations)
        aesgcm = AESGCM(key)

        return aesgcm.decrypt(nonce, full_payload, associated_data=aad)


def derive_integrity_keys(passphrase: str, vault_salt: bytes) -> Tuple[bytes, bytes]:
    """Return a vault's (signing key, digest key).

    Both come from one PBKDF2-HMAC-SHA256 stretch of the passphrase (600,000 iterations) under the
    vault's salt plus a fixed suffix, so they are separate from the content key, and are split with
    HKDF-Expand. Testing a passphrase guess against a stored signature or digest therefore costs a
    full PBKDF2 run, the same as testing it against sealed content.
    """
    root = AESGCMCryptoEnvelopeProvider().stretched_key(passphrase, vault_salt + _INTEGRITY_SALT_SUFFIX)
    signing = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"kibisis entry signature v2").derive(root)
    digest = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"kibisis value digest v2").derive(root)
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
