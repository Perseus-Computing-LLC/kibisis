"""AML (Agent Memory Leaderboard) HTTP Adapter for Kibisis.

Implements the official AML Add and Search API specification:
- GET  / or /health or /v1/health -> 200 OK (unauthenticated health probe)
- POST /v1/memories/add or /add   -> Ingest episodic memories
- POST /v1/memories/search or /search -> Retrieve relevant memories within user scope
Supports Token, Bearer, and X-Api-Key authentication.
"""
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import re
import sys
from http import HTTPStatus
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional

from .vault import SQLiteMemoryVault
from .models import EpistemicState

logger = logging.getLogger("kibisis.aml_adapter")

# Precompiled regex for basic token extraction
_STRIP_PUNCT = re.compile(r"^[^\w]+|[^\w]+$")


def _format_created_at(ts: Optional[float]) -> str:
    if ts is None:
        dt = datetime.datetime.now(datetime.timezone.utc)
    else:
        # Check if ts is in milliseconds (> 10^11)
        if ts > 1e11:
            ts = ts / 1000.0
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return dt.isoformat()


def _extract_text_content(content: Any) -> str:
    """Extract plain text from string or multimodal ContentPart array."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                if part.get("type") == "text" and "text" in part:
                    parts.append(str(part["text"]))
                elif part.get("type") == "image_url":
                    parts.append("[IMAGE]")
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join(parts)
    if isinstance(content, dict):
        return json.dumps(content, ensure_ascii=False)
    return str(content or "")


class KibisisAMLHandler(BaseHTTPRequestHandler):
    vault: SQLiteMemoryVault
    api_key: Optional[str] = None

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _check_auth(self) -> bool:
        if not self.api_key:
            return True
        auth_header = self.headers.get("Authorization", "")
        # Accepts 'Token <key>' or 'Bearer <key>'
        if auth_header.startswith("Token "):
            token = auth_header[6:].strip()
            if token == self.api_key:
                return True
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token == self.api_key:
                return True
        # Accepts 'X-Api-Key: <key>'
        x_api_key = self.headers.get("X-Api-Key", "").strip()
        if x_api_key and x_api_key == self.api_key:
            return True
        return False

    def do_GET(self) -> None:
        # AML health checks use unauthenticated GET on root or health endpoints
        path = self.path.split("?")[0].rstrip("/")
        if path in ("", "/health", "/v1/health", "/v1/memories/health"):
            self._send_json(HTTPStatus.OK, {
                "status": "ok",
                "service": "kibisis-aml-adapter",
                "version": "v0.1.0-alpha.14"
            })
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        
        # Verify Authentication
        if not self._check_auth():
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized", "detail": "Invalid or missing API key"})
            return

        # Read JSON body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Empty body"})
            return
        try:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            body = json.loads(raw_body)
        except Exception as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Malformed JSON: {exc}"})
            return

        if path in ("/v1/memories/add", "/add"):
            self._handle_add(body)
        elif path in ("/v1/memories/search", "/search"):
            self._handle_search(body)
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {path}"})

    def _handle_add(self, body: Dict[str, Any]) -> None:
        """Handle Add API Request."""
        request_id = body.get("request_id")
        user_id = body.get("user_id")
        session_id = body.get("session_id")
        messages = body.get("messages", [])

        if not request_id or not user_id:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {
                "error": "Missing required fields: request_id and user_id are required"
            })
            return

        if not isinstance(messages, list):
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "messages must be a list"})
            return

        # Store incoming messages
        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "user")
            raw_content = msg.get("content", "")
            text = _extract_text_content(raw_content).strip()
            if not text:
                continue

            ts = msg.get("timestamp")
            valid_from = (ts / 1000.0) if (ts is not None and ts > 1e11) else ts
            
            # Key identifies session, sequence, and request ID
            key = f"{session_id or 's'}:{idx}:{request_id[-16:]}"
            category = f"chat_{role}"
            
            try:
                self.vault.put(
                    category=category,
                    key=key,
                    content=text,
                    scope=str(user_id),
                    valid_from=valid_from,
                    epistemic_state=EpistemicState.VERIFIED.value,
                    origin="user" if role == "user" else "external"
                )
            except Exception as exc:
                logger.warning("Failed to store entity %s: %s", key, exc)

        # Successful response conforming to AML contract
        self._send_json(HTTPStatus.OK, {
            "success": True,
            "request_id": request_id,
            "user_id": user_id,
            "session_id": session_id or ""
        })

    def _handle_search(self, body: Dict[str, Any]) -> None:
        """Handle Search API Request."""
        raw_query = body.get("query")
        user_id = body.get("user_id")
        top_k = body.get("top_k", 100)
        options = body.get("options")

        if raw_query is None or user_id is None:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {
                "error": "query and user_id are required"
            })
            return

        query_text = _extract_text_content(raw_query).strip()
        scope = str(user_id)
        limit = max(1, int(top_k))

        # Query Kibisis using match='any' for natural language questions
        try:
            results = self.vault.search(
                query=query_text,
                scope=scope,
                limit=limit,
                match="any",
                include_unverified=True
            )
        except Exception as exc:
            logger.error("Search failed: %s", exc)
            results = []

        data = []
        for r in results:
            # BM25 rank_score in SQLite FTS5 is negative (lower = better).
            # Convert so higher values indicate greater relevance.
            raw_score = r.rank_score if r.rank_score is not None else 0.0
            relevance_score = round(max(0.001, -float(raw_score)), 4)
            data.append({
                "id": str(r.entity.key),
                "content": str(r.entity.content),
                "score": relevance_score,
                "created_at": _format_created_at(r.entity.valid_from or r.entity.created_at)
            })

        self._send_json(HTTPStatus.OK, {"data": data})

    def log_message(self, format: str, *args: Any) -> None:
        # Minimal quiet logging
        logger.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)


def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    db_path: str = ":memory:",
    api_key: Optional[str] = None
) -> None:
    vault = SQLiteMemoryVault(db_path, allow_plaintext=True)
    
    class BoundHandler(KibisisAMLHandler):
        pass
    
    BoundHandler.vault = vault
    BoundHandler.api_key = api_key

    server = ThreadingHTTPServer((host, port), BoundHandler)
    print(f"Kibisis AML Adapter listening on http://{host}:{port}")
    print(f"Database: {db_path}")
    print(f"Auth token: {'[CONFIGURED]' if api_key else '[NONE]'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        vault.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Kibisis AML Adapter Service")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("--db", default=os.environ.get("KIBISIS_AML_DB", "/tmp/kibisis_aml.db"), help="Vault SQLite path")
    parser.add_argument("--key", default=os.environ.get("KIBISIS_AML_KEY"), help="Memory system key for token authentication")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, db_path=args.db, api_key=args.key)


if __name__ == "__main__":
    main()
