"""Smoke tests for the Kibisis AML Add/Search HTTP adapter."""
from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

from kibisis.aml_adapter import KibisisAMLHandler
from kibisis.vault import SQLiteMemoryVault

TEST_API_KEY = "kibisis-aml-smoke-test-token-7788"


class TestAMLAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Open in-memory vault for testing
        cls.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        
        class BoundHandler(KibisisAMLHandler):
            pass

        BoundHandler.vault = cls.vault
        BoundHandler.api_key = TEST_API_KEY

        # Bind to localhost port 0 (OS picks available ephemeral port)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), BoundHandler)
        cls.host, cls.port = cls.server.server_address
        cls.base_url = f"http://{cls.host}:{cls.port}"

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.vault.close()

    def _request(self, method: str, path: str, data: dict = None, headers: dict = None):
        url = f"{self.base_url}{path}"
        req_headers = {"User-Agent": "AML-Smoke-Runner"}
        if headers:
            req_headers.update(headers)
        
        body_bytes = None
        if data is not None:
            body_bytes = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                body = json.loads(resp.read().decode("utf-8"))
                return status, body
        except urllib.error.HTTPError as err:
            body = None
            try:
                body = json.loads(err.read().decode("utf-8"))
            except Exception:
                pass
            return err.code, body

    def test_01_health_check_unauthenticated(self):
        """AML health checks require an unauthenticated GET returning 2xx."""
        status, body = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertEqual(body.get("service"), "kibisis-aml-adapter")

        status, body = self._request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")

    def test_02_auth_rejection(self):
        """Requests without the required Token header must return 401."""
        add_payload = {
            "request_id": "eval:test:0",
            "messages": [{"role": "user", "content": "hello"}],
            "user_id": "user_1",
            "session_id": "s1"
        }
        status, body = self._request("POST", "/v1/memories/add", data=add_payload)
        self.assertEqual(status, 401)

        # Wrong token
        status, body = self._request(
            "POST",
            "/v1/memories/add",
            data=add_payload,
            headers={"Authorization": "Token wrong-token"}
        )
        self.assertEqual(status, 401)

    def test_03_add_memory_token_auth(self):
        """Add request using 'Authorization: Token <key>'."""
        add_payload = {
            "request_id": "eval:locomo:chunk:1",
            "messages": [
                {
                    "role": "user",
                    "timestamp": 1704067200000,
                    "content": "Alice lives in Zurich and drives an electric car."
                },
                {
                    "role": "assistant",
                    "timestamp": 1704067205000,
                    "content": "Understood, I will remember that Alice is based in Zurich."
                }
            ],
            "user_id": "eval:locomo:user_alice",
            "session_id": "eval:session:001"
        }
        status, body = self._request(
            "POST",
            "/v1/memories/add",
            data=add_payload,
            headers={"Authorization": f"Token {TEST_API_KEY}"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("request_id"), "eval:locomo:chunk:1")
        self.assertEqual(body.get("user_id"), "eval:locomo:user_alice")
        self.assertEqual(body.get("session_id"), "eval:session:001")

    def test_04_add_multimodal_content_parts(self):
        """Multimodal track places ordered text and image parts in content."""
        add_payload = {
            "request_id": "eval:mm:chunk:1",
            "messages": [
                {
                    "role": "user",
                    "timestamp": 1704067300000,
                    "content": [
                        {"type": "text", "text": "Bob has a red bicycle in Tokyo."},
                        {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,dGVzdA=="}}
                    ]
                }
            ],
            "user_id": "eval:locomo:user_bob",
            "session_id": "eval:session:002"
        }
        status, body = self._request(
            "POST",
            "/v1/memories/add",
            data=add_payload,
            headers={"Authorization": f"Token {TEST_API_KEY}"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("success"))

    def test_05_search_retrieval_and_ranking(self):
        """Search retrieves relevant facts in ranked order."""
        search_payload = {
            "query": "Where does Alice live?",
            "options": ["A. Zurich", "B. Berlin", "C. Paris", "D. Tokyo"],
            "user_id": "eval:locomo:user_alice",
            "top_k": 10
        }
        status, body = self._request(
            "POST",
            "/v1/memories/search",
            data=search_payload,
            headers={"Authorization": f"Token {TEST_API_KEY}"}
        )
        self.assertEqual(status, 200)
        self.assertIn("data", body)
        data = body["data"]
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)

        first = data[0]
        self.assertIn("Zurich", first["content"])
        self.assertIn("id", first)
        self.assertIn("score", first)
        self.assertIn("created_at", first)
        self.assertGreater(first["score"], 0)

    def test_06_scope_isolation(self):
        """Searching under user_bob must not return user_alice's memories."""
        search_payload = {
            "query": "Where does Alice live?",
            "user_id": "eval:locomo:user_bob",
            "top_k": 10
        }
        status, body = self._request(
            "POST",
            "/v1/memories/search",
            data=search_payload,
            headers={"Authorization": f"Token {TEST_API_KEY}"}
        )
        self.assertEqual(status, 200)
        self.assertIn("data", body)
        # user_bob has no mention of Zurich or Alice
        for item in body["data"]:
            self.assertNotIn("Zurich", item["content"])

    def test_07_empty_search_returns_empty_array(self):
        """Non-matching queries return empty array [] rather than omitting field."""
        search_payload = {
            "query": "Unrelated quantum astrophysical telemetry",
            "user_id": "eval:locomo:user_alice",
            "top_k": 10
        }
        status, body = self._request(
            "POST",
            "/v1/memories/search",
            data=search_payload,
            headers={"Authorization": f"Token {TEST_API_KEY}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body.get("data"), [])

    def test_08_alternative_auth_headers(self):
        """Supports 'Bearer <key>' and 'X-Api-Key: <key>' as specified by AML."""
        search_payload = {
            "query": "Tokyo bicycle",
            "user_id": "eval:locomo:user_bob",
            "top_k": 5
        }
        # Bearer
        status, body = self._request(
            "POST",
            "/v1/memories/search",
            data=search_payload,
            headers={"Authorization": f"Bearer {TEST_API_KEY}"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(body["data"]), 1)

        # X-Api-Key
        status, body = self._request(
            "POST",
            "/v1/memories/search",
            data=search_payload,
            headers={"X-Api-Key": TEST_API_KEY}
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(body["data"]), 1)


if __name__ == "__main__":
    unittest.main()
