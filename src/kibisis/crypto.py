"""Cryptographic envelope provider for Kibisis using AES-256-GCM and PBKDF2."""

from __future__ import annotations

import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .models import EncryptedEnvelope
from .protocols import CryptoEnvelopeProvider


class AESGCMCryptoEnvelopeProvider(CryptoEnvelopeProvider):
    """AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation."""

    ITERATIONS = 100_000
    KEY_LENGTH = 32  # 256-bit key
    SALT_LENGTH = 16
    NONCE_LENGTH = 12

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def encrypt(self, plaintext: bytes, passphrase: str) -> EncryptedEnvelope:
        salt = os.urandom(self.SALT_LENGTH)
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
        key = self._derive_key(passphrase, salt)
        aesgcm = AESGCM(key)

        return aesgcm.decrypt(nonce, full_payload, associated_data=None)
