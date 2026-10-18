"""One vault file shared by several processes (each Hermes process opens its own vault).

State cached per instance at open goes stale as soon as another instance writes: the audit journal
head (every later write then fails on the journal's primary key) and whether tombstones exist (a
value tombstoned elsewhere could be written again). Two instances on one file reproduce both.
"""

import os
import tempfile
import unittest

from kibisis import SQLiteMemoryVault

# An explicit passphrase keeps these tests independent of KIBISIS_PASSPHRASE(_FILE) in the environment.
PASSPHRASE = "shared-vault-file-test-passphrase"


class TestSharedVaultFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = os.path.join(self.tmp.name, "vault.sqlite")
        self.first = SQLiteMemoryVault(path, passphrase=PASSPHRASE)
        self.second = SQLiteMemoryVault(path, passphrase=PASSPHRASE)

    def tearDown(self):
        self.first.close()
        self.second.close()
        self.tmp.cleanup()

    def test_journal_writes_interleave_across_instances(self):
        self.first.put("note", "k1", "one")
        self.second.put("note", "k2", "two")
        self.first.put("note", "k3", "three")  # reused sequence 2 when the head was cached at open
        self.second.archive("note", "k1")
        self.first.purge("note", "k2")
        events = self.first.list_audit_events(limit=10)
        self.assertEqual([e.sequence for e in events], [1, 2, 3, 4, 5])
        self.assertEqual([e.prev_hash for e in events[1:]], [e.event_hash for e in events[:-1]])
        self.assertTrue(self.first.verify_audit_chain())
        self.assertTrue(self.second.verify_audit_chain())

    def test_tombstone_added_by_another_instance_blocks_writes(self):
        self.first.put("note", "seed", "opened before any tombstone existed")
        self.second.put("note", "k", "a rejected value")
        self.second.tombstone("note", "k", reason="retracted")
        with self.assertRaises(ValueError):
            self.first.put("note", "k", "a rejected value")
        with self.assertRaises(ValueError):
            self.first.put("note", "k", "A  REJECTED value!")  # canonical match


if __name__ == "__main__":
    unittest.main()
