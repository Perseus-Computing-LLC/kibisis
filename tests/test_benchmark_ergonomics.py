"""Unit tests for benchmark ergonomics, store alias, and batch operations in Kibisis."""

import unittest
from kibisis import EpistemicState, SQLiteMemoryVault, MemoryEntity


class TestKibisisBenchmarkErgonomics(unittest.TestCase):
    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)

    def tearDown(self):
        self.vault.close()

    def test_store_alias_inserts_and_updates(self):
        entity = self.vault.store(
            category="user_preference",
            key="theme",
            content="dark_mode",
            metadata={"source": "benchmark"},
            epistemic_state="verified",
        )
        self.assertEqual(entity.category, "user_preference")
        self.assertEqual(entity.key, "theme")
        self.assertEqual(entity.content, "dark_mode")
        self.assertEqual(entity.version, 1)

        # Update via store
        updated = self.vault.store(
            category="user_preference",
            key="theme",
            content="system_default",
        )
        self.assertEqual(updated.content, "system_default")
        self.assertEqual(updated.version, 2)

    def test_put_batch_with_dicts(self):
        items = [
            {"category": "session", "key": f"turn_{i}", "content": f"Turn content {i}"}
            for i in range(10)
        ]
        entities = self.vault.put_batch(items)
        self.assertEqual(len(entities), 10)
        for i, ent in enumerate(entities):
            self.assertEqual(ent.key, f"turn_{i}")
            self.assertEqual(ent.content, f"Turn content {i}")

        # Verify all are searchable
        results = self.vault.search("content", category="session", limit=20)
        self.assertEqual(len(results), 10)

    def test_put_batch_with_entities(self):
        items = [
            MemoryEntity(
                id=i,
                category="notes",
                key=f"note_{i}",
                content=f"Important note number {i}",
                epistemic_state=EpistemicState.VERIFIED,
            )
            for i in range(5)
        ]
        entities = self.vault.put_batch(items)
        self.assertEqual(len(entities), 5)
        res = self.vault.get("notes", "note_3")
        self.assertIsNotNone(res)
        assert res is not None
        self.assertEqual(res.content, "Important note number 3")


if __name__ == "__main__":
    unittest.main()
