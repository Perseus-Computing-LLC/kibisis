"""Tests for the shared-vault Streamable HTTP transport (kibisis.mcp_http) and its two CLI commands."""

import http.client
import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from kibisis import SQLiteMemoryVault
from kibisis.__main__ import main as cli_main
from kibisis.mcp_http import (
    HTTPConfig,
    SharedVaultHTTPServer,
    SharedVaultService,
    load_members,
    new_token,
    token_digest,
)

_SAVED_ENV = {}


def setUpModule():
    for name in [k for k in os.environ if k.startswith("KIBISIS_")]:
        _SAVED_ENV[name] = os.environ.pop(name)
    os.environ.setdefault("ARGUS_LEDGER_PATH", "")


def tearDownModule():
    os.environ.update(_SAVED_ENV)


class SharedServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tokens = {"thomas": new_token(), "mark": new_token()}
        members = {token_digest(t): n for n, t in cls.tokens.items()}
        cls.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        config = HTTPConfig(members=members, scope="team", allowed_origins=("https://ok.example",),
                            max_body_bytes=4096)
        cls.httpd = SharedVaultHTTPServer(("127.0.0.1", 0), SharedVaultService(cls.vault, config))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.vault.close()

    def request(self, method, path, body=None, member=None, token=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        if member:
            token = self.tokens[member]
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, resp.getheader("Content-Type"), (json.loads(raw) if raw else None), resp

    def rpc(self, member, method, params=None, req_id=1):
        return self.request("POST", "/mcp", {"jsonrpc": "2.0", "id": req_id, "method": method,
                                             "params": params or {}}, member=member)

    def call(self, member, tool, arguments):
        status, _, body, _ = self.rpc(member, "tools/call", {"name": tool, "arguments": arguments})
        self.assertEqual(status, 200)
        return body["result"]["isError"], body["result"]["content"][0]["text"]

    def test_health_needs_no_token_and_leaks_nothing(self):
        status, ctype, body, _ = self.request("GET", "/health")
        self.assertEqual((status, ctype), (200, "application/json"))
        self.assertEqual(body["scope"], "team")
        self.assertEqual(body["members"], 2)
        self.assertNotIn("thomas", json.dumps(body))

    def test_post_without_or_with_wrong_token_is_401(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        for token in (None, "nope", self.tokens["mark"] + "x"):
            status, _, _, resp = self.request("POST", "/mcp", msg, token=token)
            self.assertEqual(status, 401)
            self.assertIn("Bearer", resp.getheader("WWW-Authenticate"))
        status, _, _, _ = self.request("POST", "/mcp", msg, headers={"Authorization": "Basic " + self.tokens["mark"]})
        self.assertEqual(status, 401)

    def test_initialize_and_tools_list(self):
        status, ctype, body, _ = self.rpc("mark", "initialize", {"protocolVersion": "2025-06-18",
                                                                  "capabilities": {}, "clientInfo": {"name": "t"}})
        self.assertEqual((status, ctype), (200, "application/json"))
        self.assertEqual(body["result"]["serverInfo"]["name"], "kibisis-mcp")
        status, _, body, _ = self.rpc("mark", "tools/list")
        names = {t["name"] for t in body["result"]["tools"]}
        self.assertEqual(names, {"kibisis_remember", "kibisis_recall", "kibisis_forget",
                                 "kibisis_verify_ledger", "kibisis_health"})

    def test_notification_gets_202_and_no_body(self):
        status, _, body, _ = self.request("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"},
                                          member="thomas")
        self.assertEqual((status, body), (202, None))

    def test_batch(self):
        batch = [{"jsonrpc": "2.0", "id": 7, "method": "ping"},
                 {"jsonrpc": "2.0", "method": "notifications/initialized"},
                 {"jsonrpc": "2.0", "id": 8, "method": "tools/list"}]
        status, _, body, _ = self.request("POST", "/mcp", batch, member="thomas")
        self.assertEqual(status, 200)
        self.assertEqual([r["id"] for r in body], [7, 8])
        status, _, _, _ = self.request("POST", "/mcp", [], member="thomas")
        self.assertEqual(status, 400)

    def test_writes_are_attributed_to_the_member_and_shared(self):
        err, text = self.call("mark", "kibisis_remember",
                              {"category": "decision", "key": "launch_window_q1",
                               "content": "Launch window agreed for the first quarter.",
                               "metadata": {"author_id": "thomas"}})
        self.assertFalse(err, text)
        self.assertEqual(json.loads(text)["author"], "mcp-agent:mark")
        entity = self.vault.get("decision", "launch_window_q1", scope="team")
        self.assertEqual(entity.metadata["author_id"], "mcp-agent:mark")
        # The other member's agent sees it, labelled with who wrote it.
        err, text = self.call("thomas", "kibisis_recall", {"query": "launch window quarter"})
        self.assertFalse(err, text)
        self.assertIn("launch_window_q1", text)
        self.assertIn('author="mcp-agent:mark"', text)

    def test_scope_is_fixed_by_the_server(self):
        err, text = self.call("mark", "kibisis_remember",
                              {"category": "x", "key": "k", "content": "c", "scope": "default"})
        self.assertTrue(err)

    def test_get_head_delete_on_mcp_are_405(self):
        for method in ("GET", "HEAD", "DELETE"):
            status, _, _, resp = self.request(method, "/mcp", member="mark")
            self.assertEqual(status, 405, method)
            self.assertEqual(resp.getheader("Allow"), "POST")

    def test_unknown_path_is_404(self):
        self.assertEqual(self.request("POST", "/other", {"x": 1}, member="mark")[0], 404)
        self.assertEqual(self.request("GET", "/other")[0], 404)

    def test_origin_guard(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        self.assertEqual(self.request("POST", "/mcp", msg, member="mark",
                                      headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request("POST", "/mcp", msg, member="mark",
                                      headers={"Origin": "https://ok.example"})[0], 200)

    def test_bad_bodies(self):
        self.assertEqual(self.request("POST", "/mcp", b"{not json", member="mark")[0], 400)
        self.assertEqual(self.request("POST", "/mcp", b"x" * 5000, member="mark")[0], 413)
        status, _, body, _ = self.request("POST", "/mcp", {"id": 1, "method": "ping"}, member="mark")
        self.assertEqual((status, body["error"]["code"]), (200, -32600))


class MembersFileTest(unittest.TestCase):
    def write(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data))
        self.addCleanup(os.unlink, path)
        return path

    def test_valid(self):
        d = token_digest("a")
        self.assertEqual(load_members(self.write({"members": {"mark": d}})), {d: "mark"})

    def test_rejects(self):
        d = token_digest("a")
        for bad in ({}, {"members": {}}, {"members": {"Mark": d}}, {"members": {"mark": "plain-token"}},
                    {"members": {"mark": d, "tom": d}}, {"members": {"mark": d.upper()}}):
            with self.assertRaises(ValueError, msg=bad):
                load_members(self.write(bad))


class CLITest(unittest.TestCase):
    def test_token_command_prints_a_token_and_its_digest(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli_main(["mcp-http-token", "mark"]), 0)
        lines = out.getvalue().splitlines()
        token = lines[0].rsplit(" ", 1)[1]
        self.assertEqual(lines[1], f'members.json entry: "mark": "{token_digest(token)}"')
        self.assertEqual(cli_main(["mcp-http-token", "Bad Name"]), 2)

    def test_serve_refuses_a_bad_members_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "members.json"
            path.write_text('{"members": {"mark": "token-not-digest"}}')
            self.assertEqual(cli_main(["mcp-http-serve", "--members", str(path), "--db", str(Path(tmp) / "v.db")]), 2)


if __name__ == "__main__":
    unittest.main()
