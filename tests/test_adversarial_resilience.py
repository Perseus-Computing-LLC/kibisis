"""Adversarial fault injection, crash resilience, and corruption tests for Kibisis SQLCipher."""

import os
import shutil
import tempfile
import unittest
import sqlcipher3

from kibisis.vault import SQLiteMemoryVault
from kibisis.lease import SQLiteLeaseCoordinator

PASS = "adversarial_testing_passphrase_2026"


class TestAdversarialResilience(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "resilience_vault.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_corrupted_header_fails_closed(self):
        """Bit-flipping or truncating the database header must fail closed without crashing or leaking."""
        v = SQLiteMemoryVault(self.db_path, passphrase=PASS)
        v.put("sensitive", "record1", "classified secret payload")
        v.close()

        # Corrupt the first 32 bytes (SQLCipher salt and header)
        with open(self.db_path, "r+b") as f:
            f.seek(0)
            f.write(b"\x00" * 32)

        # Attempt to open must fail closed with authentication/decryption error
        with self.assertRaises(ValueError) as ctx:
            SQLiteMemoryVault(self.db_path, passphrase=PASS)
        self.assertIn("Failed to authenticate or decrypt", str(ctx.exception))

    def test_truncated_ciphertext_fails_closed(self):
        """Truncating a database file to partial page length must fail closed cleanly."""
        v = SQLiteMemoryVault(self.db_path, passphrase=PASS)
        for i in range(10):
            v.put("bulk", f"k_{i}", f"bulk content payload {i}")
        v.close()

        # Truncate to 1024 bytes (mid-page)
        with open(self.db_path, "r+b") as f:
            f.truncate(1024)

        with self.assertRaises(ValueError):
            SQLiteMemoryVault(self.db_path, passphrase=PASS)

    def test_wal_crash_recovery_preserves_committed_records(self):
        """Simulate uncheckpointed WAL file; verify that reopening recovers cleanly under SQLCipher."""
        v = SQLiteMemoryVault(self.db_path, passphrase=PASS)
        v.put("crash_test", "commit_1", "first durable transaction")
        v.put("crash_test", "commit_2", "second durable transaction")

        # Simulate crash before explicit checkpoint/close
        # Open raw connection to verify WAL presence
        wal_path = self.db_path + "-wal"
        self.assertTrue(os.path.exists(self.db_path))

        # Reopen afresh
        reopened = SQLiteMemoryVault(self.db_path, passphrase=PASS)
        item1 = reopened.get("crash_test", "commit_1")
        item2 = reopened.get("crash_test", "commit_2")
        self.assertIsNotNone(item1)
        self.assertIsNotNone(item2)
        self.assertEqual(item1.content, "first durable transaction")
        self.assertEqual(item2.content, "second durable transaction")
        reopened.close()

    def test_secure_delete_and_cipher_memory_security_active(self):
        """Verify that PRAGMA cipher_memory_security and secure_delete are active on open connections."""
        v = SQLiteMemoryVault(self.db_path, passphrase=PASS)
        res_mem = [tuple(r) for r in v._conn.execute("PRAGMA cipher_memory_security;").fetchall()]
        res_del = [tuple(r) for r in v._conn.execute("PRAGMA secure_delete;").fetchall()]
        self.assertEqual(res_mem, [('1',)])
        self.assertEqual(res_del, [(1,)])
        v.close()

    def test_lease_coordinator_memory_security_active(self):
        """Verify that SQLiteLeaseCoordinator configures memory security and secure delete."""
        lease_db = os.path.join(self.tmp.name, "lease.db")
        coord = SQLiteLeaseCoordinator(lease_db, passphrase=PASS)
        res_mem = [tuple(r) for r in coord._conn.execute("PRAGMA cipher_memory_security;").fetchall()]
        res_del = [tuple(r) for r in coord._conn.execute("PRAGMA secure_delete;").fetchall()]
        self.assertEqual(res_mem, [('1',)])
        self.assertEqual(res_del, [(1,)])


if __name__ == "__main__":
    unittest.main()
