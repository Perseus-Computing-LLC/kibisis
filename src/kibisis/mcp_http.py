"""Streamable HTTP transport for the Kibisis MCP server: one vault that several people's agents share.

    python -m kibisis mcp-http-serve --members /run/secrets/members.json --host 0.0.0.0 --port 8080

The tools, scope rules and trust rules are the stdio server's (:mod:`kibisis.mcp_server`); this module adds
only what a shared, networked vault needs:

- **Members.** Each member holds a bearer token. The server holds only SHA-256 digests, in a JSON file
  ``{"members": {"<name>": "<hex sha256 of the token>"}}``. A request without a matching token gets 401.
  ``python -m kibisis mcp-http-token NAME`` prints a new token and its digest line.
- **Attribution.** Each member's calls run as author ``mcp-agent:<name>``, so the audit journal and every
  recalled entry name the member whose agent wrote it. A model cannot choose the author.
- **One writer at a time.** Calls are serialized on one lock over one vault connection.
- **Transport.** ``POST /mcp`` takes one JSON-RPC message or a batch and answers with ``application/json``
  (202 with no body when every message is a notification). There is no server-to-client stream, so
  ``GET``/``HEAD``/``DELETE /mcp`` answer 405. Sessions are not used: every request stands alone.
- **Browsers.** A request carrying an ``Origin`` header is refused unless that origin is listed with
  ``--allow-origin`` (DNS-rebinding guard; agent clients send no Origin).
- ``GET /health`` needs no token and reports the version and whether the vault is encrypted.

Logs carry method, route, status, milliseconds and member name; never bodies, tokens or vault text.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import socketserver
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

from .mcp_server import MCP_AUTHOR, KibisisMCPServer, _server_version
from .vault import SQLiteMemoryVault

LOG = logging.getLogger("kibisis.mcp_http")

MCP_PATH = "/mcp"
HEALTH_PATHS = ("/", "/health")
_MEMBER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def token_digest(token: str) -> str:
    """Hex SHA-256 of a member token, as stored in the members file."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    """A new member token: 43 URL-safe characters (256 bits)."""
    return secrets.token_urlsafe(32)


def load_members(path: str) -> Dict[str, str]:
    """Read ``{"members": {name: digest}}``; return ``{digest: name}``. Raise ValueError on any bad entry."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    members = data.get("members") if isinstance(data, dict) else None
    if not isinstance(members, dict) or not members:
        raise ValueError(f"{path}: expected {{\"members\": {{name: sha256}}}} with at least one member")
    by_digest: Dict[str, str] = {}
    for name, digest in members.items():
        if not isinstance(name, str) or not _MEMBER_RE.match(name):
            raise ValueError(f"{path}: member name {name!r} must be 1-64 of a-z 0-9 . _ - (lowercase)")
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            raise ValueError(f"{path}: member {name!r} needs a lowercase hex SHA-256 digest, not a token")
        if digest in by_digest:
            raise ValueError(f"{path}: members {by_digest[digest]!r} and {name!r} share a token")
        by_digest[digest] = name
    return by_digest


@dataclass
class HTTPConfig:
    members: Dict[str, str]  # digest -> member name
    scope: str
    allowed_origins: Tuple[str, ...] = ()
    max_body_bytes: int = 1 << 20
    socket_timeout: float = 30.0


class SharedVaultService:
    """One vault, one scope, one MCP server per member (each with its own author), one lock."""

    def __init__(self, vault: SQLiteMemoryVault, config: HTTPConfig):
        self.vault = vault
        self.config = config
        self.lock = threading.Lock()
        self.servers = {
            name: KibisisMCPServer(vault=vault, scope=config.scope, author=f"{MCP_AUTHOR}:{name}")
            for name in sorted(set(config.members.values()))
        }

    def member_for(self, token: Optional[str]) -> Optional[str]:
        if not token:
            return None
        digest = token_digest(token)
        found = None
        for known, name in self.config.members.items():  # compare every digest; no early exit
            if hmac.compare_digest(known, digest):
                found = name
        return found

    def handle(self, member: str, message: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
        server = self.servers[member]
        with self.lock:
            try:
                return server.handle_request(message)
            except Exception:  # pragma: no cover - the stdio server's last-resort answer, logged without content
                LOG.exception("internal error in %s", message.get("method"))
                return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32603, "message": "Internal error"}}

    def health(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "server": "kibisis-mcp-http",
            "version": _server_version(),
            "scope": self.config.scope,
            "members": len(self.servers),
            "encrypted_at_rest": bool(self.vault.encrypted_at_rest),
        }


class SharedVaultHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], service: SharedVaultService):
        self.service = service
        super().__init__(address, SharedVaultHandler)

    def server_bind(self) -> None:
        # Skip HTTPServer's reverse DNS lookup of the bind host (it can stall startup); nothing reads server_name.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class SharedVaultHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "kibisis-mcp-http"
    sys_version = ""
    timeout = 30.0

    @property
    def service(self) -> SharedVaultService:
        return cast(SharedVaultHTTPServer, self.server).service

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.service.config.socket_timeout)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        pass  # one line per request from _send, without query strings, headers or bodies

    def _route(self) -> str:
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def _send(self, status: int, payload: Any = None, headers: Optional[Dict[str, str]] = None,
              member: str = "-") -> None:
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)
        ms = (time.monotonic() - getattr(self, "_t0", time.monotonic())) * 1000
        LOG.info("%s %s %d %.0fms member=%s", self.command, self._route()[:64], status, ms, member)

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        return origin is None or origin in self.service.config.allowed_origins

    def _token(self) -> Optional[str]:
        scheme, _, credential = (self.headers.get("Authorization") or "").strip().partition(" ")
        return credential.strip() or None if scheme.lower() == "bearer" else None

    def _no_stream(self) -> None:
        self._t0 = time.monotonic()
        route = self._route()
        if route in HEALTH_PATHS and self.command in ("GET", "HEAD"):
            self._send(200, self.service.health())
        elif route == MCP_PATH:
            self._send(405, {"error": "this server answers POST only (no server-to-client stream)"},
                       {"Allow": "POST"})
        else:
            self._send(404, {"error": "not found"})

    do_GET = do_HEAD = do_DELETE = _no_stream  # noqa: N815 - stdlib naming

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self._t0 = time.monotonic()
        if self._route() != MCP_PATH:
            self._drain()
            return self._send(404, {"error": "not found"})
        if not self._origin_ok():
            self._drain()
            return self._send(403, {"error": "origin not allowed"})
        member = self.service.member_for(self._token())
        if member is None:
            self._drain()
            return self._send(401, {"error": "missing or unknown bearer token"},
                              {"WWW-Authenticate": 'Bearer realm="kibisis"'})
        try:
            length = int(self.headers.get("Content-Length") or "-1")
        except ValueError:
            length = -1
        if length < 0:
            self.close_connection = True
            return self._send(411, {"error": "Content-Length required"}, member=member)
        if length > self.service.config.max_body_bytes:
            self.close_connection = True
            return self._send(413, {"error": "body too large"}, member=member)
        raw = self.rfile.read(length)
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            return self._send(400, {"jsonrpc": "2.0", "id": None,
                                    "error": {"code": -32700, "message": f"Parse error: {exc.__class__.__name__}"}},
                              member=member)
        if isinstance(message, list):
            if not message:
                return self._send(400, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32600, "message": "Invalid request"}}, member=member)
            replies: List[Dict[str, Any]] = [r for r in (self.service.handle(member, m) for m in message) if r]
            return self._send(200, replies, member=member) if replies else self._send(202, member=member)
        reply = self.service.handle(member, message)
        return self._send(200, reply, member=member) if reply is not None else self._send(202, member=member)

    def _drain(self) -> None:
        """Read (and drop) a refused request's body, up to the cap, so the connection stays in step."""
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if 0 < length <= self.service.config.max_body_bytes:
            self.rfile.read(length)
        elif length:
            self.close_connection = True


def run_server(vault: SQLiteMemoryVault, config: HTTPConfig, host: str = "127.0.0.1", port: int = 8080) -> None:
    service = SharedVaultService(vault, config)
    httpd = SharedVaultHTTPServer((host, port), service)
    LOG.info("kibisis-mcp-http %s serving scope %r for %d member(s) on %s:%d", _server_version(), config.scope,
             len(service.servers), host, port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
