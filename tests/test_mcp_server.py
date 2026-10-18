"""Unit tests for Kibisis MCP (Model Context Protocol) JSON-RPC server."""

import json
import unittest
from kibisis import SQLiteMemoryVault, KibisisMCPServer


class TestKibisisMCPServer(unittest.TestCase):
    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        self.server = KibisisMCPServer(vault=self.vault)

    def tearDown(self):
        self.vault.close()

    def test_initialize_and_ping(self):
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        resp = self.server.handle_request(init_req)
        self.assertIsNotNone(resp)
        assert resp is not None
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "kibisis-mcp")
        self.assertIn("tools", resp["result"]["capabilities"])

        # Test ping
        ping_resp = self.server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        self.assertIsNotNone(ping_resp)
        assert ping_resp is not None
        self.assertEqual(ping_resp["id"], 2)
        self.assertEqual(ping_resp["result"], {})

        # Test notification (no response)
        notif_resp = self.server.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(notif_resp)

    def test_tools_list(self):
        req = {"jsonrpc": "2.0", "id": 10, "method": "tools/list"}
        resp = self.server.handle_request(req)
        self.assertIsNotNone(resp)
        assert resp is not None
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("kibisis_remember", tool_names)
        self.assertIn("kibisis_recall", tool_names)
        self.assertIn("kibisis_health", tool_names)
        self.assertIn("kibisis_verify_ledger", tool_names)
        self.assertIn("kibisis_forget", tool_names)
        self.assertIn("kibisis_admit", tool_names)

    def test_tools_call_lifecycle(self):
        # 1. kibisis_remember
        rem_req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "kibisis_remember",
                "arguments": {
                    "category": "convention",
                    "key": "formatting_style",
                    "content": "Use deterministic snake_case identifiers for audit fields.",
                    "epistemic_state": "verified",
                    "metadata": {"source": "mcp_test"},
                },
            },
        }
        rem_resp = self.server.handle_request(rem_req)
        self.assertIsNotNone(rem_resp)
        assert rem_resp is not None
        self.assertFalse(rem_resp["result"]["isError"])
        data = json.loads(rem_resp["result"]["content"][0]["text"])
        self.assertEqual(data["status"], "stored")
        self.assertEqual(data["key"], "formatting_style")

        # 2. kibisis_recall
        rec_req = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "kibisis_recall",
                "arguments": {"query": "deterministic snake_case"},
            },
        }
        rec_resp = self.server.handle_request(rec_req)
        self.assertIsNotNone(rec_resp)
        assert rec_resp is not None
        self.assertFalse(rec_resp["result"]["isError"])
        recalled = json.loads(rec_resp["result"]["content"][0]["text"])
        self.assertEqual(len(recalled), 1)
        self.assertEqual(recalled[0]["key"], "formatting_style")

        # 3. kibisis_verify_ledger
        ver_req = {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {"name": "kibisis_verify_ledger", "arguments": {}},
        }
        ver_resp = self.server.handle_request(ver_req)
        self.assertIsNotNone(ver_resp)
        assert ver_resp is not None
        ver_data = json.loads(ver_resp["result"]["content"][0]["text"])
        self.assertTrue(ver_data["valid"])
        self.assertEqual(ver_data["chain_integrity"], "OK")

        # 4. kibisis_health
        health_req = {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "kibisis_health", "arguments": {}},
        }
        health_resp = self.server.handle_request(health_req)
        self.assertIsNotNone(health_resp)
        assert health_resp is not None
        health_data = json.loads(health_resp["result"]["content"][0]["text"])
        self.assertEqual(health_data["status"], "healthy")
        self.assertEqual(health_data["active_entities"], 1)

        # 5. kibisis_forget
        forget_req = {
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "kibisis_forget",
                "arguments": {"category": "convention", "key": "formatting_style"},
            },
        }
        forget_resp = self.server.handle_request(forget_req)
        self.assertIsNotNone(forget_resp)
        assert forget_resp is not None
        forget_data = json.loads(forget_resp["result"]["content"][0]["text"])
        self.assertEqual(forget_data["status"], "archived")

        # Post-forget recall returns 0
        rec_resp2 = self.server.handle_request(rec_req)
        assert rec_resp2 is not None
        recalled2 = json.loads(rec_resp2["result"]["content"][0]["text"])
        self.assertEqual(len(recalled2), 0)


if __name__ == "__main__":
    unittest.main()
