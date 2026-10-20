"""Tests for the Kibisis MCP server, its settings, the key generator and the review command."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from kibisis import KibisisMCPServer, SQLiteMemoryVault
from kibisis.config import ConfigError, default_data_dir, default_db_path, open_vault, resolve_scope, validate_scope
from kibisis.keys import main as keys_main
from kibisis.review import main as review_main

SRC = str(Path(__file__).resolve().parents[1] / "src")
TEST_KEY = "mcp server test key only, not a secret"
_SAVED_ENV = {}


def setUpModule():
    # The vault and the settings read KIBISIS_* from the environment; keep a developer's own out.
    for name in [k for k in os.environ if k.startswith("KIBISIS_")]:
        _SAVED_ENV[name] = os.environ.pop(name)


def tearDownModule():
    os.environ.update(_SAVED_ENV)


def _call(server, tool, arguments, req_id=1):
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    )
    assert resp is not None
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


def _clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("KIBISIS_")}
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.update(extra)
    return env


class TestProtocol(unittest.TestCase):
    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        self.server = KibisisMCPServer(vault=self.vault, scope="default")

    def tearDown(self):
        self.vault.close()

    def test_initialize_ping_and_notifications(self):
        resp = self.server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}
        )
        assert resp is not None
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "kibisis-mcp")
        import kibisis

        self.assertEqual(resp["result"]["serverInfo"]["version"], kibisis.__version__)
        self.assertIn("tools", resp["result"]["capabilities"])
        self.assertEqual(self.server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"], {})
        self.assertIsNone(self.server.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        unknown = self.server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
        self.assertEqual(unknown["error"]["code"], -32601)

    def test_tools_list(self):
        resp = self.server.handle_request({"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
        assert resp is not None
        tools = resp["result"]["tools"]
        self.assertEqual(
            [t["name"] for t in tools],
            ["kibisis_remember", "kibisis_recall", "kibisis_forget", "kibisis_verify_ledger", "kibisis_health"],
        )
        for tool in tools:
            with self.subTest(tool=tool["name"]):
                schema = tool["inputSchema"]
                self.assertFalse(schema["additionalProperties"])
                self.assertFalse({"scope", "epistemic_state", "auto_gate", "reviewer_id"} & set(schema["properties"]))
                annotations = tool.get("annotations")
                self.assertIsInstance(annotations, dict)
                for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                    self.assertIn(hint, annotations)
                    self.assertIsInstance(annotations[hint], bool)

    def test_tool_errors_are_short_and_carry_no_traceback(self):
        is_error, text = _call(self.server, "kibisis_remember", {"key": "only-key"})
        self.assertTrue(is_error)
        self.assertIn("'content' is required", text)
        self.assertNotIn("Traceback", text)
        is_error, text = _call(self.server, "kibisis_recall", {"query": "x", "limit": "ten"})
        self.assertTrue(is_error)
        is_error, text = _call(self.server, "kibisis_nope", {})
        self.assertTrue(is_error)


class TestToolLifecycle(unittest.TestCase):
    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        self.server = KibisisMCPServer(vault=self.vault, scope="default")

    def tearDown(self):
        self.vault.close()

    def test_remember_recall_review_forget(self):
        is_error, text = _call(
            self.server,
            "kibisis_remember",
            {
                "category": "convention",
                "key": "formatting_style",
                "content": "Use deterministic snake_case identifiers for audit fields.",
                "metadata": {"source": "mcp_test"},
            },
        )
        self.assertFalse(is_error, text)
        data = json.loads(text)
        self.assertEqual((data["status"], data["key"], data["epistemic_state"]), ("stored", "formatting_style", "candidate"))
        self.assertEqual(self.vault.get("convention", "formatting_style").metadata["agent_metadata"], {"source": "mcp_test"})

        # Candidates come back labeled by default, and only reviewed entries with include_candidates=false.
        _, text = _call(self.server, "kibisis_recall", {"query": "deterministic snake_case"})
        self.assertIn('count="1"', text)
        self.assertIn('key="formatting_style"', text)
        self.assertIn('state="candidate"', text)
        self.assertIn('author="mcp-agent"', text)
        _, text = _call(self.server, "kibisis_recall", {"query": "deterministic snake_case", "include_candidates": False})
        self.assertIn('count="0"', text)

        # A person verifies it; recall then returns it as verified, with the reviewer named, even when
        # candidates are left out.
        self.vault.review_entity("convention", "formatting_style", verdict="verified", reviewer_id="human:owner")
        _, text = _call(self.server, "kibisis_recall", {"query": "deterministic snake_case", "include_candidates": False})
        self.assertIn('state="verified"', text)
        self.assertIn('reviewed_by="human:owner"', text)

        _, text = _call(self.server, "kibisis_verify_ledger", {})
        self.assertEqual(json.loads(text), {"valid": True, "chain_integrity": "OK"})
        _, text = _call(self.server, "kibisis_health", {})
        health = json.loads(text)
        self.assertEqual((health["status"], health["scope"], health["active_entities"]), ("healthy", "default", 1))

        is_error, text = _call(self.server, "kibisis_forget", {"category": "convention", "key": "formatting_style"})
        self.assertFalse(is_error, text)
        self.assertEqual(json.loads(text)["status"], "deleted")
        _, text = _call(self.server, "kibisis_recall", {"query": "deterministic snake_case", "include_candidates": True})
        self.assertIn('count="0"', text)
        _, text = _call(self.server, "kibisis_forget", {"category": "convention", "key": "formatting_style"})
        self.assertEqual(json.loads(text)["status"], "not_found")
        is_error, text = _call(
            self.server,
            "kibisis_remember",
            {"category": "convention", "key": "again", "content": "Use deterministic snake_case identifiers for audit fields."},
        )
        self.assertTrue(is_error)
        self.assertIn("tombstone", text.lower())

    def test_forget_reaches_a_superseded_entry(self):
        _call(self.server, "kibisis_remember", {"category": "c", "key": "old", "content": "first draft of the plan"})
        _call(self.server, "kibisis_remember", {"category": "c", "key": "new", "content": "second draft", "supersedes_key": "old"})
        _, text = _call(self.server, "kibisis_forget", {"category": "c", "key": "old"})
        self.assertEqual(json.loads(text)["status"], "deleted")
        self.assertNotIn("first draft of the plan", [r["content"] for r in self.vault._conn.execute("SELECT content FROM entities")])


class TestConfig(unittest.TestCase):
    def test_default_db_path_is_per_user(self):
        self.assertEqual(
            default_data_dir({"HOME": "/home/u"}, "linux"), Path("/home/u/.local/share/kibisis")
        )
        self.assertEqual(
            default_data_dir({"HOME": "/home/u", "XDG_DATA_HOME": "/data/u"}, "linux"), Path("/data/u/kibisis")
        )
        self.assertEqual(
            default_data_dir({"HOME": "/Users/u"}, "darwin"), Path("/Users/u/Library/Application Support/kibisis")
        )
        self.assertEqual(
            default_data_dir({"LOCALAPPDATA": "C:/Users/u/AppData/Local"}, "win32"), Path("C:/Users/u/AppData/Local/kibisis")
        )
        self.assertEqual(default_db_path({"HOME": "/home/u", "KIBISIS_DB_PATH": "/tmp/v.db"}, "linux"), "/tmp/v.db")
        self.assertNotIn("/opt/data", default_db_path({"HOME": "/home/u"}, "linux"))

    def test_scope_validation(self):
        self.assertEqual(resolve_scope({}), "default")
        self.assertEqual(resolve_scope({"KIBISIS_SCOPE": "team-a"}), "team-a")
        for bad in ("*", "", " ", "a b", "x" * 200, "a*"):
            with self.subTest(scope=bad):
                with self.assertRaises(ConfigError):
                    validate_scope(bad)

    def test_open_vault_requires_a_key_unless_plaintext_is_chosen(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "sub" / "vault.db")
            with self.assertRaises(ConfigError):
                open_vault(db, env={})
            self.assertFalse(Path(db).exists())
            vault = open_vault(db, env={"KIBISIS_ALLOW_PLAINTEXT": "1"})
            vault.close()
            keyed = open_vault(str(Path(tmp) / "k.db"), env={"KIBISIS_PASSPHRASE": TEST_KEY})
            try:
                self.assertTrue(keyed.passphrase)
            finally:
                keyed.close()

    def test_key_generator_creates_a_private_file_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "keys" / "kibisis.key")
            self.assertEqual(keys_main([path]), 0)
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            first = Path(path).read_text()
            self.assertEqual(keys_main([path]), 1)
            self.assertEqual(Path(path).read_text(), first)


class TestStdioProcess(unittest.TestCase):
    def test_refuses_to_start_without_a_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "vault.db"
            proc = subprocess.run(
                [sys.executable, "-m", "kibisis.mcp_server"],
                input="",
                capture_output=True,
                text=True,
                env=_clean_env(KIBISIS_DB_PATH=str(db)),
                timeout=120,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("No key", proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertFalse(db.exists())

    def test_serves_json_rpc_with_a_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "kibisis_remember", "arguments": {"key": "k", "content": "stdio round trip"}}},
                "not json",
            ]
            proc = subprocess.run(
                [sys.executable, "-m", "kibisis.mcp_server"],
                input="\n".join(m if isinstance(m, str) else json.dumps(m) for m in messages) + "\n",
                capture_output=True,
                text=True,
                env=_clean_env(KIBISIS_DB_PATH=str(Path(tmp) / "vault.db"), KIBISIS_PASSPHRASE=TEST_KEY, KIBISIS_SCOPE="team-a"),
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            replies = [json.loads(line) for line in proc.stdout.splitlines()]
            self.assertEqual([r.get("id") for r in replies], [1, 2, None])
            self.assertEqual(json.loads(replies[1]["result"]["content"][0]["text"])["scope"], "team-a")
            self.assertEqual(replies[2]["error"]["code"], -32700)


class TestReviewCommand(unittest.TestCase):
    def test_list_approve_and_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"KIBISIS_DB_PATH": str(Path(tmp) / "vault.db"), "KIBISIS_PASSPHRASE": TEST_KEY, "KIBISIS_SCOPE": "default"}
            saved = {k: os.environ.get(k) for k in env}
            os.environ.update(env)
            try:
                vault = open_vault()
                server = KibisisMCPServer(vault=vault, scope="default")
                _call(server, "kibisis_remember", {"category": "c", "key": "keep", "content": "Ship on Tuesdays"})
                _call(server, "kibisis_remember", {"category": "c", "key": "drop", "content": "Ship without tests"})
                vault.close()

                self.assertEqual(review_main(["approve", "c", "keep", "--reviewer", "human:owner"]), 0)
                self.assertEqual(review_main(["reject", "c", "drop", "--reviewer", "human:owner"]), 0)
                self.assertEqual(review_main(["approve", "c", "missing"]), 1)

                vault = open_vault()
                try:
                    kept = vault.get("c", "keep")
                    self.assertEqual(kept.epistemic_state.value, "verified")
                    self.assertEqual(kept.metadata["author_id"], "mcp-agent")
                    self.assertEqual(kept.metadata["human_reviews"][-1]["reviewer_id"], "human:owner")
                    self.assertIsNone(vault.get("c", "drop"))
                    with self.assertRaises(Exception):
                        vault.put("c", "drop-again", "Ship without tests")
                finally:
                    vault.close()
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
