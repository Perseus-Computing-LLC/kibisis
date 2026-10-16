"""Tests for kibisis-vault plugin integration and prefetch/recall behavior."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from kibisis.vault import SQLiteMemoryVault


def load_plugin_module():
    plugin_path = Path("/opt/data/plugins/kibisis-vault/__init__.py")
    spec = importlib.util.spec_from_file_location("kibisis_vault_plugin", str(plugin_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load spec for {plugin_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kibisis_vault_plugin"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestKibisisVaultPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = load_plugin_module()
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db")
        self.db_path = Path(self.tmp.name)
        # Seed test database
        vault = SQLiteMemoryVault(self.db_path, allow_plaintext=True)
        vault.put(
            category="convention",
            key="clean_room_rule",
            content="All code is developed independently and licensed under the MIT License.",
            metadata={"sensitivity": "normal"},
            scope="default",
        )
        vault.put(
            category="convention",
            key="secret_convention",
            content="This is confidential and must never be recalled into prompt.",
            metadata={"sensitivity": "confidential"},
            scope="default",
        )
        vault.put(
            category="insight",
            key="cache_optimization",
            content="Use LRU caching for expensive FTS queries to bound latency.",
            metadata={"sensitivity": "normal"},
            scope="default",
        )
        vault.close()

    def tearDown(self):
        try:
            self.tmp.close()
        except Exception:
            pass

    def test_plugin_prefetch_and_epistemic_boundary(self):
        provider = self.plugin.KibisisMemoryProvider()
        provider._db_path = self.db_path
        provider.initialize("session-1")

        prefetch_out = provider.prefetch("cache latency")
        self.assertIn("## Kibisis Memory & Directives", prefetch_out)
        self.assertIn("Active Standing Constraints & Conventions:", prefetch_out)
        self.assertIn("clean_room_rule", prefetch_out)
        self.assertNotIn("secret_convention", prefetch_out)  # Confidential must be withheld
        self.assertIn("cache_optimization", prefetch_out)
        self.assertIn("Epistemic boundary:", prefetch_out)

    def test_plugin_recall_tool_default_scope(self):
        provider = self.plugin.KibisisMemoryProvider()
        provider._db_path = self.db_path
        provider.initialize("session-1")

        # Call kibisis_recall without passing 'scope'
        res_raw = provider.handle_tool_call("kibisis_recall", {"query": "caching"})
        res = json.loads(res_raw)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["items"][0]["key"], "cache_optimization")
        self.assertEqual(res["items"][0]["scope"], "default")


if __name__ == "__main__":
    unittest.main()
