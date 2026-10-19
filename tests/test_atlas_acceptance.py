"""Kibisis cases named after the agent-memory-atlas acceptance tests they exercise.

Each test is named after the atlas acceptance test it covers (agent-memory-atlas, content/build.md).
Cases asserting that material must not come back carry a positive control, so an empty or broken
store cannot pass them.
"""

import json
import tempfile
import unittest
from pathlib import Path

from kibisis import KibisisMCPServer, SQLiteMemoryVault, TombstonedValueError

TEST_PHRASE = "atlas acceptance suite test phrase only"


def _stored_values(vault):
    """Every value the vault holds, in every scope, live or archived, at any trust state."""
    rows = vault._conn.execute("SELECT content, is_encrypted, encrypted_envelope_json FROM entities").fetchall()
    return [vault._decrypt_content(r["encrypted_envelope_json"]) if r["is_encrypted"] else r["content"] for r in rows]


def _row_count(vault):
    return vault._conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]


def _recall(vault, query, scope="default"):
    return [r.entity.content for r in vault.search(query, scope=scope, include_unverified=True)]


class TombstoneAcceptance(unittest.TestCase):
    REJECTED = "Deploy to production on Fridays"
    NEIGHBOUR = "Run the full test suite before every release"

    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        self.vault.put("ops", "deploy_day", self.REJECTED)
        self.vault.put("ops", "release_checks", self.NEIGHBOUR)
        self.vault.tombstone("ops", "deploy_day", reason="rejected by user", author_id="human:reviewer")

    def tearDown(self):
        self.vault.close()

    def test_tombstone_key_normalization_attack(self):
        attempts = [
            ("ops", "deploy_day", "Deploy to production on Fridays"),  # same key, same text
            ("ops", "deploy_day", "DEPLOY TO PRODUCTION ON FRIDAYS"),  # case
            ("ops", "deploy_day", "  Deploy   to production\ton Fridays  "),  # whitespace
            ("ops", "deploy_day", "Deploy to pro\u200bduction on Fri\u00addays"),  # invisible characters
            ("ops", "deploy_day", "\uff24\uff45\uff50\uff4c\uff4f\uff59 to production on Fridays"),  # fullwidth look-alikes
            ("ops", "Deploy_Day", "Deploy to production on Fridays"),  # key case
            ("ops", " deploy_day ", "Deploy to production on Fridays"),  # key whitespace
            ("ops", "deploy_day\u200b", "Deploy to production on Fridays"),  # invisible character in the key
            ("ops", "release_day", "Deploy to production on Fridays!"),  # a new key
            ("preferences", "shipping", "deploy to production on fridays."),  # a new category and key
        ]
        for category, key, content in attempts:
            with self.subTest(category=category, key=key, content=content):
                with self.assertRaises(TombstonedValueError):
                    self.vault.put(category, key, content)
                self.assertIsNone(self.vault.get(category, key))
        self.assertNotIn(self.REJECTED.casefold(), [v.casefold() for v in _stored_values(self.vault)])

        # Positive control: a paraphrase is a different value, so it is stored and recalled. This is
        # where the line sits: digest tombstones do not catch paraphrases.
        paraphrase = "Ship to prod at the end of the week"
        self.vault.put("ops", "release_day", paraphrase)
        self.assertIn(paraphrase, _recall(self.vault, "ship prod week"))
        self.assertIn(self.NEIGHBOUR, _recall(self.vault, "test suite release"))

    def test_tombstone_no_second_memory_unit(self):
        before = _row_count(self.vault)
        server = KibisisMCPServer(vault=self.vault)
        write_paths = {
            "put under a new key": lambda: self.vault.put("ops", "deploy_policy", self.REJECTED),
            "store": lambda: self.vault.store("notes", "deploy", self.REJECTED),
            "put_batch": lambda: self.vault.put_batch(
                [{"category": "ops", "key": "batched", "content": self.REJECTED.upper()}]
            ),
            "admit_candidate": lambda: self.vault.admit_candidate("ops", "candidate", self.REJECTED),
            "set_persona_slot": lambda: self.vault.set_persona_slot(self.REJECTED),
        }
        for name, write in write_paths.items():
            with self.subTest(path=name):
                with self.assertRaises(TombstonedValueError):
                    write()

        # The MCP surface reaches the same check.
        resp = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "kibisis_remember",
                    "arguments": {"category": "ops", "key": "via_mcp", "content": self.REJECTED},
                },
            }
        )
        assert resp is not None
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("tombstone", resp["result"]["content"][0]["text"])

        # Consulted, not collided or suppressed: no unit was created, and none carries the value.
        self.assertEqual(_row_count(self.vault), before)
        self.assertNotIn(self.REJECTED.casefold(), [v.casefold() for v in _stored_values(self.vault)])
        # Positive control: the rejection is absent, not the store.
        self.assertIn(self.NEIGHBOUR, _recall(self.vault, "test suite release"))

    def test_tombstone_laundering_sequence(self):
        original = "The capital of Australia is Sydney"
        superseding = "The capital of Australia is Canberra"
        neighbour = "The longest river in Australia is the Murray"
        vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        try:
            vault.put("facts", "capital", original)
            vault.put("facts", "river", neighbour)
            vault.review_entity("facts", "capital", "revoked", reviewer_id="human:reviewer", notes="wrong city")

            # Supersede the claim with a different value, then restate and corroborate the original.
            vault.put("facts", "capital", superseding)
            restatements = [
                ("facts", "capital", original, "verified"),
                ("facts", "capital_restated", original, "verified"),
                ("geography", "australia", "the capital of Australia is Sydney.", "candidate"),
            ]
            for category, key, content, state in restatements:
                with self.subTest(category=category, key=key):
                    with self.assertRaises(TombstonedValueError):
                        vault.put(category, key, content, epistemic_state=state)
            with self.assertRaises(TombstonedValueError):
                vault.admit_candidate("facts", "capital_corroborated", original)

            # The original is still inactive, and its rejection is intact.
            self.assertEqual(vault.get("facts", "capital").content, superseding)
            self.assertNotIn(original, _stored_values(vault))
            self.assertTrue(vault.is_tombstoned("any", "key", original))
            human_rejections = [t for t in vault.list_tombstones() if t["author_id"] == "human:reviewer"]
            self.assertEqual(len(human_rejections), 1)
            # Positive control: a neighbouring value that was never rejected is still recalled.
            self.assertIn(neighbour, _recall(vault, "longest river"))
        finally:
            vault.close()


class DeletionAcceptance(unittest.TestCase):
    ORIGINAL = "Alice's direct line is 555-0142"
    NEIGHBOUR = "Bob prefers email over phone calls"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Encrypted, so purging copies has to decrypt them to compare digests.
        self.vault = SQLiteMemoryVault(Path(self.tmp.name) / "vault.db", passphrase=TEST_PHRASE)
        self.vault.put("contacts", "alice", self.ORIGINAL)
        self.vault.put("crm", "alice_phone", self.ORIGINAL)  # a copy under another category and key
        self.vault.put("contacts", "alice", self.ORIGINAL, scope="team")  # a copy in a second scope
        self.vault.put("contacts", "bob", self.NEIGHBOUR)
        self.vault.put("contacts", "bob", self.NEIGHBOUR, scope="team")
        self.vault.archive("contacts", "bob", scope="team")
        self.backup = self.vault.export_snapshot()  # taken while the original is live

    def tearDown(self):
        self.vault.close()
        self.tmp.cleanup()

    def test_deletion_absent_from_shared_copies(self):
        self.vault.tombstone("contacts", "alice", reason="user asked to forget", author_id="human:reviewer")

        self.assertIsNone(self.vault.get("contacts", "alice"))
        self.assertIsNone(self.vault.get("crm", "alice_phone"))
        for clear_existing in (False, True):
            with self.subTest(clear_existing=clear_existing):
                self.vault.import_snapshot(self.backup, clear_existing=clear_existing)
                self.assertIsNone(self.vault.get("contacts", "alice"))
                self.assertIsNone(self.vault.get("crm", "alice_phone"))
                self.assertNotIn(self.ORIGINAL, _recall(self.vault, "direct line"))
                # Positive control: the backup restores everything not derived from the deletion,
                # and an archived entry comes back archived rather than live.
                self.assertEqual(self.vault.get("contacts", "bob").content, self.NEIGHBOUR)
                self.assertIn(self.NEIGHBOUR, _recall(self.vault, "prefers email"))
                self.assertTrue(self.vault.get("contacts", "bob", scope="team").archived)
        # A scoped deletion leaves the second scope's own write in place; a scope "*" deletion reaches it.
        self.assertEqual(self.vault.get("contacts", "alice", scope="team").content, self.ORIGINAL)
        self.vault.tombstone("contacts", "alice", content=self.ORIGINAL, scope="*", author_id="human:reviewer")
        self.assertIsNone(self.vault.get("contacts", "alice", scope="team"))
        self.vault.import_snapshot(self.backup)
        self.assertNotIn(self.ORIGINAL, _stored_values(self.vault))
        self.assertTrue(self.vault.verify_audit_chain())


class JournalSameTransaction(unittest.TestCase):
    """Every put, archive, tombstone and purge is journaled in the transaction that makes it."""

    def test_mutations_fail_closed_when_journal_is_unwritable(self):
        vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        try:
            vault.put("a", "k1", "first value")
            vault.put("a", "k2", "second value")
            events_before = len(vault.list_audit_events(limit=1000))

            def state():
                rows = vault._conn.execute("SELECT category, key, content, version, archived FROM entities").fetchall()
                tombs = vault._conn.execute("SELECT COUNT(*) FROM rejected_value_tombstones").fetchone()[0]
                return sorted(tuple(r) for r in rows), tombs

            before = state()
            vault._conn.execute(
                "CREATE TRIGGER journal_unwritable BEFORE INSERT ON audit_journal "
                "BEGIN SELECT RAISE(ABORT, 'journal unwritable'); END"
            )
            operations = {
                "put (insert)": lambda: vault.put("a", "k3", "third value"),
                "put (update)": lambda: vault.put("a", "k1", "first value, edited"),
                "archive": lambda: vault.archive("a", "k1"),
                "purge": lambda: vault.purge("a", "k2"),
                "tombstone": lambda: vault.tombstone("a", "k1"),
            }
            for name, operation in operations.items():
                with self.subTest(operation=name):
                    with self.assertRaises(Exception) as ctx:
                        operation()
                    self.assertIn("journal unwritable", str(ctx.exception))
                    self.assertEqual(state(), before)
            vault._conn.execute("DROP TRIGGER journal_unwritable")
            self.assertEqual(len(vault.list_audit_events(limit=1000)), events_before)

            # Writable again: each mutation lands with exactly one event of its kind.
            expected = []
            for name, operation in operations.items():
                operation()
                expected.append(name.split(" ")[0])
            actions = [e.action for e in vault.list_audit_events(limit=1000)][events_before:]
            self.assertEqual(len(actions), len(expected))
            self.assertTrue(vault.verify_audit_chain())
        finally:
            vault.close()


class AdmitOverMCP(unittest.TestCase):
    def test_admit_records_the_agent_not_a_caller_named_reviewer(self):
        vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        try:
            server = KibisisMCPServer(vault=vault)
            vault.put("facts", "x", "A candidate fact", epistemic_state="candidate")
            listed = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert listed is not None
            admit = next(t for t in listed["result"]["tools"] if t["name"] == "kibisis_admit")
            self.assertNotIn("reviewer_id", admit["inputSchema"]["properties"])
            self.assertIn("not a human review", admit["description"])

            resp = server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "kibisis_admit",
                        "arguments": {"category": "facts", "key": "x", "reviewer_id": "human:owner"},
                    },
                }
            )
            assert resp is not None
            self.assertFalse(resp["result"]["isError"], resp["result"]["content"][0]["text"])
            reviews = vault.get("facts", "x").metadata["human_reviews"]
            self.assertEqual([r["reviewer_id"] for r in reviews], ["mcp-agent"])
            self.assertEqual(json.loads(resp["result"]["content"][0]["text"])["status"], "verified")
        finally:
            vault.close()


if __name__ == "__main__":
    unittest.main()
