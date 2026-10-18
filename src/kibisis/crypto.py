"""Cryptographic envelope provider for Kibisis using AES-256-GCM and PBKDF2."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .models import EncryptedEnvelope
from .protocols import CryptoEnvelopeProvider


class AESGCMCryptoEnvelopeProvider(CryptoEnvelopeProvider):
    """AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation."""

    ITERATIONS = 600_000  # new envelopes; older ones carry their own count
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

    def encrypt(self, plaintext: bytes, passphrase: str) -> EncryptedEnvelope:
        salt = self._salt if self._salt is not None else os.urandom(self.SALT_LENGTH)
        nonce = os.urandom(self.NONCE_LENGTH)
        key = self._derive_key(passphrase, salt)

        aesgcm = AESGCM(key)
        # In AESGCM, ciphertext has tag appended at the end (16 bytes)
        encrypted_data = aesgcm.encrypt(nonce, plaintext, associated_data=None)

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

    def decrypt(self, envelope: EncryptedEnvelope, passphrase: str) -> bytes:
        if envelope.cipher != "aes-256-gcm":
            raise ValueError(f"Unsupported cipher: {envelope.cipher}")

        salt = base64.b64decode(envelope.salt_b64)
        nonce = base64.b64decode(envelope.nonce_b64)
        ciphertext = base64.b64decode(envelope.ciphertext_b64)
        tag = base64.b64decode(envelope.tag_b64) if envelope.tag_b64 else b""

        full_payload = ciphertext + tag
        key = self._derive_key(passphrase, salt, envelope.iterations)
        aesgcm = AESGCM(key)

        return aesgcm.decrypt(nonce, full_payload, associated_data=None)


def sign_tenant_payload(key: bytes, tenant_id: str, entity_id: str, content: str) -> str:
    """Compute HMAC-SHA256 signature for post-retrieval tenant ownership validation (MemLeak mitigation)."""
    msg = f"{tenant_id}:{entity_id}:{content}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_tenant_payload(key: bytes, tenant_id: str, entity_id: str, content: str, signature: str) -> bool:
    """Verify HMAC-SHA256 signature using constant-time comparison."""
    if not signature:
        return False
    expected = sign_tenant_payload(key, tenant_id, entity_id, content)
    return hmac.compare_digest(signature, expected)
