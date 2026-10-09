"""Unit tests for Kibisis memory vault, AES-GCM envelope, and concurrency leases."""

import unittest
from kibisis import (
    AESGCMCryptoEnvelopeProvider,
    LeaseConflictError,
    MemoryEntity,
    SQLiteLeaseCoordinator,
    SQLiteMemoryVault,
)


class TestKibisisContracts(unittest.TestCase):
    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:")
        self.coordinator = SQLiteLeaseCoordinator(":memory:")
        self.crypto = AESGCMCryptoEnvelopeProvider()

    def tearDown(self):
        self.vault.close()
        self.coordinator.close()

    def test_vault_crud_and_fts_search(self):
        entity = self.vault.put(
            category="convention",
            key="code_style",
            content="Always use clean-room implementations with zero legacy reuse.",
            metadata={"priority": "high"},
        )
        self.assertEqual(entity.version, 1)
        self.assertEqual(entity.category, "convention")
        self.assertEqual(entity.key, "code_style")

        # Read back
        fetched = self.vault.get("convention", "code_style")
        self.assertIsNotNone(fetched)
        assert fetched is not None
        self.assertEqual(fetched.content, entity.content)
        self.assertEqual(fetched.metadata["priority"], "high")

        # FTS5 search
        results = self.vault.search("clean-room")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].entity.key, "code_style")

        # Update entity
        updated = self.vault.put(
            category="convention",
            key="code_style",
            content="Always use clean-room implementations with MIT License.",
        )
        self.assertEqual(updated.version, 2)

        # Archive entity
        archived = self.vault.archive("convention", "code_style")
        self.assertTrue(archived)
        # Search should omit archived by default
        self.assertEqual(len(self.vault.search("clean-room")), 0)

    def test_crypto_envelope_roundtrip(self):
        passphrase = "super-secret-perseus-key-2026"
        secret_data = b"Cognitive memory confidential payload"

        envelope = self.crypto.encrypt(secret_data, passphrase)
        self.assertEqual(envelope.cipher, "aes-256-gcm")
        self.assertEqual(envelope.kdf, "pbkdf2-sha256")
        self.assertTrue(len(envelope.ciphertext_b64) > 0)

        # Decrypt
        decrypted = self.crypto.decrypt(envelope, passphrase)
        self.assertEqual(decrypted, secret_data)

        # Bad passphrase should fail
        with self.assertRaises(Exception):
            self.crypto.decrypt(envelope, "wrong-passphrase")

    def test_concurrency_lease_protocol(self):
        resource = "agent_state_lock"
        # Holder 1 acquires lease
        lease1 = self.coordinator.acquire(resource, holder_id="worker_alpha", ttl_seconds=10.0)
        self.assertEqual(lease1.fencing_token, 1)
        self.assertEqual(lease1.holder_id, "worker_alpha")

        # Holder 2 attempts to acquire active lease -> conflict
        with self.assertRaises(LeaseConflictError):
            self.coordinator.acquire(resource, holder_id="worker_beta", ttl_seconds=10.0)

        # Holder 1 renews lease
        renewed = self.coordinator.renew(lease1, ttl_seconds=15.0)
        self.assertTrue(renewed)

        # Holder 1 releases lease
        released = self.coordinator.release(lease1)
        self.assertTrue(released)

        # Now Holder 2 can acquire lease, fencing token increments to 2
        lease2 = self.coordinator.acquire(resource, holder_id="worker_beta", ttl_seconds=10.0)
        self.assertEqual(lease2.fencing_token, 2)
        self.assertEqual(lease2.holder_id, "worker_beta")


if __name__ == "__main__":
    unittest.main()
