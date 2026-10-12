"""Encryption-by-default contract for the Kibisis vault."""

import os
import sqlcipher3
import sqlite3
import stat
import tempfile
import unittest

from kibisis import (
    AESGCMCryptoEnvelopeProvider,
    EncryptionRequiredError,
    SQLiteMemoryVault,
    generate_keyfile,
    resolve_passphrase,
)
from kibisis.models import EncryptedEnvelope

PASS = "correct horse battery staple"
CANARY = "Zebracanary-7731-unique-token"


def _raw_bytes(db_path):
    out = b""
    for suffix in ("", "-wal"):
        p = db_path + suffix
        if os.path.exists(p):
            with open(p, "rb") as fh:
                out += fh.read()
    return out.lower()


class TestEncryptionByDefault(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "v.db")
        self._saved = {k: os.environ.pop(k, None) for k in ("KIBISIS_PASSPHRASE", "KIBISIS_PASSPHRASE_FILE")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v

    def test_on_disk_vault_refuses_to_open_without_passphrase(self):
        with self.assertRaises(EncryptionRequiredError):
            SQLiteMemoryVault(self.db)
        self.assertFalse(os.path.exists(self.db + "-wal") and os.path.getsize(self.db + "-wal") > 0)

    def test_plaintext_requires_explicit_opt_in(self):
        v = SQLiteMemoryVault(self.db, allow_plaintext=True)
        v.put("c", "k", CANARY)
        self.assertEqual(v.encryption_status(), {"encrypted": 0, "plaintext": 1})
        v.close()

    def test_in_memory_vault_needs_no_passphrase(self):
        v = SQLiteMemoryVault(":memory:")
        v.put("c", "k", "x")
        self.assertEqual(v.get("c", "k").content, "x")

    def test_passphrase_encrypts_without_naming_a_provider(self):
        v = SQLiteMemoryVault(self.db, passphrase=PASS)
        v.put("c", "k", CANARY)
        self.assertEqual(v.encryption_status(), {"encrypted": 1, "plaintext": 0})
        v.close()
        self.assertNotIn(CANARY.lower().encode(), _raw_bytes(self.db))

    def test_env_file_is_used_and_loose_permissions_are_refused(self):
        kf = os.path.join(self.dir, "key")
        generate_keyfile(kf)
        self.assertEqual(stat.S_IMODE(os.stat(kf).st_mode), 0o600)
        os.environ["KIBISIS_PASSPHRASE_FILE"] = kf
        v = SQLiteMemoryVault(self.db)
        v.put("c", "k", CANARY)
        v.close()
        self.assertEqual(SQLiteMemoryVault(self.db).get("c", "k").content, CANARY)
        os.chmod(kf, 0o644)
        with self.assertRaises(PermissionError):
            SQLiteMemoryVault(self.db)

    def test_keyfile_generation_never_overwrites(self):
        kf = os.path.join(self.dir, "key")
        generate_keyfile(kf)
        with self.assertRaises(FileExistsError):
            generate_keyfile(kf)

    def test_short_passphrase_rejected(self):
        with self.assertRaises(ValueError):
            SQLiteMemoryVault(self.db, passphrase="short")

    def test_database_files_are_owner_only(self):
        v = SQLiteMemoryVault(self.db, passphrase=PASS)
        v.put("c", "k", "x")
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode), 0o600)
        v.close()

    def test_wrong_passphrase_cannot_read(self):
        v = SQLiteMemoryVault(self.db, passphrase=PASS)
        v.put("c", "k", CANARY)
        v.close()
        with self.assertRaises(Exception):
            SQLiteMemoryVault(self.db, passphrase="another passphrase entirely")

    def test_search_finds_encrypted_content(self):
        v = SQLiteMemoryVault(self.db, passphrase=PASS)
        v.put("notes", "a", f"the {CANARY} is here")
        hits = v.search(CANARY)
        self.assertEqual([h.entity.key for h in hits], ["a"])

    def test_one_salt_per_vault_but_fresh_nonce_per_entry(self):
        v = SQLiteMemoryVault(self.db, passphrase=PASS)
        v.put("c", "k1", "same text")
        v.put("c", "k2", "same text")
        rows = [EncryptedEnvelope.model_validate_json(r[0]) for r in
                v._conn.execute("SELECT encrypted_envelope_json FROM entities")]
        self.assertEqual(rows[0].salt_b64, rows[1].salt_b64)
        self.assertNotEqual(rows[0].nonce_b64, rows[1].nonce_b64)
        self.assertNotEqual(rows[0].ciphertext_b64, rows[1].ciphertext_b64)

    def test_new_envelopes_record_600k_iterations(self):
        env = AESGCMCryptoEnvelopeProvider().encrypt(b"x", PASS)
        self.assertEqual(env.iterations, 600_000)

    def test_legacy_100k_envelope_still_decrypts(self):
        class Legacy(AESGCMCryptoEnvelopeProvider):
            ITERATIONS = 100_000
        legacy = Legacy().encrypt(b"old data", PASS)
        data = legacy.model_dump()
        data.pop("iterations")                       # envelopes written before the field existed
        reread = EncryptedEnvelope.model_validate(data)
        self.assertEqual(reread.iterations, 100_000)
        self.assertEqual(AESGCMCryptoEnvelopeProvider().decrypt(reread, PASS), b"old data")

    def test_migration_leaves_no_plaintext_anywhere_in_the_files(self):
        v = SQLiteMemoryVault(self.db, allow_plaintext=True)
        v.put("c", "k1", f"first {CANARY}")
        v.put("c", "k2", f"second {CANARY}-two")
        v.close()
        self.assertIn(CANARY.lower().encode(), _raw_bytes(self.db))     # premise: plaintext really was on disk
        enc = SQLiteMemoryVault(self.db, passphrase=PASS, allow_plaintext=True)
        result = enc.migrate_plaintext()
        self.assertEqual(result, {"migrated": 2, "remaining_plaintext": 0})
        enc.close()
        self.assertNotIn(CANARY.lower().encode(), _raw_bytes(self.db))
        self.assertEqual(SQLiteMemoryVault(self.db, passphrase=PASS).get("c", "k1").content, f"first {CANARY}")
        raw = sqlcipher3.connect(self.db)
        raw.execute(f"PRAGMA key = '{PASS}';")
        self.assertEqual(raw.execute("SELECT count(*) FROM entities_fts WHERE entities_fts MATCH ?", ('"' + CANARY + '"',)).fetchone()[0], 0)
        raw.close()

    def test_key_and_metadata_stay_plaintext_and_content_does_not(self):
        """Zero plaintext leakage: category, key, metadata and content are completely encrypted on disk."""
        v = SQLiteMemoryVault(self.db, passphrase=PASS)
        v.put("cat-visible", "key-visible", CANARY, {"tag": "meta-visible"})
        v.close()
        raw = _raw_bytes(self.db)
        self.assertNotIn(b"cat-visible", raw)
        self.assertNotIn(b"key-visible", raw)
        self.assertNotIn(b"meta-visible", raw)
        self.assertNotIn(CANARY.lower().encode(), raw)

    def test_migration_is_idempotent(self):
        v = SQLiteMemoryVault(self.db, passphrase=PASS)
        v.put("c", "k", "x")
        self.assertEqual(v.migrate_plaintext(), {"migrated": 0, "remaining_plaintext": 0})

    def test_resolve_passphrase_order(self):
        self.assertEqual(resolve_passphrase("a" * 12, env={"KIBISIS_PASSPHRASE": "b" * 12}), "a" * 12)
        self.assertEqual(resolve_passphrase(None, env={"KIBISIS_PASSPHRASE": "b" * 12}), "b" * 12)
        self.assertIsNone(resolve_passphrase(None, env={}))


if __name__ == "__main__":
    unittest.main()
