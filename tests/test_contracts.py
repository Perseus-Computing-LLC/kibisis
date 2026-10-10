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
            content="Always use high-assurance implementations with zero legacy reuse.",
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
        results = self.vault.search("high-assurance")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].entity.key, "code_style")

        # Update entity
        updated = self.vault.put(
            category="convention",
            key="code_style",
            content="Always use high-assurance implementations with MIT License.",
        )
        self.assertEqual(updated.version, 2)

        # Archive entity
        archived = self.vault.archive("convention", "code_style")
        self.assertTrue(archived)
        # Search should omit archived by default
        self.assertEqual(len(self.vault.search("high-assurance")), 0)

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

    def test_tombstone_and_rejection(self):
        content = "Confidential canary payload value"
        import hashlib
        expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Ingest entity
        self.vault.put("secret", "key1", content)
        self.assertIsNotNone(self.vault.get("secret", "key1"))

        # Tombstone entity
        tomb_hash = self.vault.tombstone("secret", "key1", reason="revocation_test")
        self.assertEqual(tomb_hash, expected_hash)
        self.assertTrue(self.vault.is_tombstoned("secret", "key1", content))

        # Direct get and search must be empty
        self.assertIsNone(self.vault.get("secret", "key1"))
        self.assertEqual(len(self.vault.search("canary")), 0)

        # Re-ingestion must be rejected by tombstone
        with self.assertRaises(ValueError):
            self.vault.put("secret", "key1", content)

    def test_vault_storage_encryption_zero_plaintext_leakage(self):
        """Canary test: verify AES-256-GCM envelope encryption leaves NO plaintext in SQLite or FTS5."""
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name

        try:
            passphrase = "canary-vault-passphrase-2026"
            canary_text = "PERSEUS_TOP_SECRET_PAYLOAD_CANARY_42"

            enc_vault = SQLiteMemoryVault(
                db_path,
                crypto_provider=self.crypto,
                passphrase=passphrase,
            )
            enc_vault.put(
                category="classified",
                key="target_alpha",
                content=canary_text,
                metadata={"clearance": "top-secret"},
            )

            # Read back through vault
            retrieved = enc_vault.get("classified", "target_alpha")
            self.assertIsNotNone(retrieved)
            assert retrieved is not None
            self.assertEqual(retrieved.content, canary_text)
            self.assertEqual(retrieved.metadata["clearance"], "top-secret")

            enc_vault.close()

            # Inspect raw SQLite database bytes on disk
            with open(db_path, "rb") as f:
                raw_bytes = f.read()

            # CANARY ASSERTION: Plaintext MUST NOT appear anywhere in the database file bytes!
            self.assertNotIn(
                canary_text.encode("utf-8"),
                raw_bytes,
                "CRITICAL SECURITY FAILURE: Plaintext canary detected in raw SQLite storage bytes!",
            )

            # Raw SQLite inspection: check content column and FTS5 table
            import sqlite3
            raw_conn = sqlite3.connect(db_path)
            raw_conn.row_factory = sqlite3.Row
            cursor = raw_conn.cursor()

            cursor.execute("SELECT content, is_encrypted, encrypted_envelope_json FROM entities WHERE key = 'target_alpha'")
            row = cursor.fetchone()
            self.assertEqual(row["content"], "", "Plaintext leaked in content column")
            self.assertEqual(row["is_encrypted"], 1)
            self.assertIsNotNone(row["encrypted_envelope_json"])
            self.assertNotIn(canary_text, row["encrypted_envelope_json"])

            # Verify FTS virtual table does not contain canary
            cursor.execute("SELECT * FROM entities_fts WHERE entities_fts MATCH 'PERSEUS_TOP_SECRET_PAYLOAD_CANARY_42'")
            self.assertEqual(len(cursor.fetchall()), 0)
            raw_conn.close()

            # Open with wrong passphrase -> decryption must fail
            bad_vault = SQLiteMemoryVault(
                db_path,
                crypto_provider=self.crypto,
                passphrase="wrong-passphrase",
            )
            with self.assertRaises(Exception):
                bad_vault.get("classified", "target_alpha")
            bad_vault.close()

        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_tombstone_evasion_hardening(self):
        """Verify negative memory tombstones resist casing, punctuation, and unicode lookalike evasion."""
        # Ingest baseline
        self.vault.put("rules", "safety_directive", "Do Not Target Civilians")

        # Tombstone it
        self.vault.tombstone("rules", "safety_directive", reason="critical_policy_violation")
        self.assertIsNone(self.vault.get("rules", "safety_directive"))

        # Evasion attempts that naive SHA-256 would fail to block:
        evasion_variants = [
            "do not target civilians",
            "   Do   Not    Target   Civilians  ",
            "DO NOT TARGET CIVILIANS",
            "Do Not Target Civilians!",
            "“Do Not Target Civilians”",
            "Do Not Target Civilians...",
            "Do Not Target Civilians —",  # unicode em-dash punctuation
            "Ｄｏ Ｎｏｔ Ｔａｒｇｅｔ Ｃｉｖｉｌｉａｎｓ",  # Unicode NFKC fullwidth
        ]

        for variant in evasion_variants:
            self.assertTrue(
                self.vault.is_tombstoned("rules", "safety_directive", variant),
                f"Failed to identify tombstoned variant: {variant!r}",
            )
            with self.assertRaises(ValueError, msg=f"Allowed evasion variant: {variant!r}"):
                self.vault.put("rules", "safety_directive", variant)

        # Legitimate different content should succeed
        clean = self.vault.put("rules", "safety_directive", "Authorize Defensive Intercept Only")
        self.assertIsNotNone(clean)
        self.assertEqual(clean.content, "Authorize Defensive Intercept Only")

    def test_encrypted_vault_tombstone_and_wildcard(self):
        """Verify tombstones work on encrypted entities and support category-wide wildcard scope."""
        vault = SQLiteMemoryVault(
            ":memory:",
            crypto_provider=self.crypto,
            passphrase="vault-encryption-test",
        )

        # Put encrypted entity
        vault.put("intel", "loc_alpha", "Coordinates Locked at Grid 9")
        # Tombstone it (decrypts entity, derives canonical hash, purges entity)
        vault.tombstone("intel", "loc_alpha", reason="compromised_grid")
        self.assertIsNone(vault.get("intel", "loc_alpha"))

        # Re-assertion with casing variation must be rejected
        with self.assertRaises(ValueError):
            vault.put("intel", "loc_alpha", "coordinates locked at grid 9!")

        # Cross-key wildcard tombstone
        vault.tombstone("intel", "*", reason="prohibited_doctrine", content="Execute First Strike")
        # Attempt to insert under any key in category "intel" must fail
        with self.assertRaises(ValueError):
            vault.put("intel", "node_12", "execute first strike!")
        with self.assertRaises(ValueError):
            vault.put("intel", "node_99", "Execute First Strike.")

        vault.close()


if __name__ == "__main__":
    unittest.main()
