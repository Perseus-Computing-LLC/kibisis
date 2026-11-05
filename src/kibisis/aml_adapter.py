"""Agent Memory Leaderboard (AML) Add/Search adapter for Kibisis.

Serves the AML Textual-track HTTP contract (https://agentmemoryleaderboard.ai/api-guide)::

    GET  /   /health   /v1/health             200, no authentication
    POST /v1/memories/add     (alias /add)    store messages for one user_id
    POST /v1/memories/search  (alias /search) ranked memories for one user_id

Method, which is what a leaderboard entry for this adapter measures:

* Storage. One Kibisis vault per ``user_id`` (SQLCipher-encrypted unless run with
  ``--plaintext``), one entry per message, content stored exactly as received. The message
  timestamp and role are kept as entry metadata.
* Add. A request is written in one transaction together with a marker keyed on its
  ``request_id``, so it is all-or-nothing and a retried request (same id, same payload, per the
  contract) is acknowledged without being written twice. ``success`` is returned after commit,
  when the messages are durable and searchable.
* Search. One Kibisis BM25 query (``match="any"``) over the user's messages; the query is the
  question plus any answer options. Hits are grouped by the Add request (conversation chunk) they
  came from and each hit brings the message before it as context. Every group becomes one memory:
  its lines in conversation order under the message timestamp, ``...`` where lines are skipped.
  Groups are returned best hit first, at most ``top_k`` of them; the platform's Answer step keeps
  the token-counted prefix that fits its context budget.

No model calls, no summarisation, no rewriting of stored text.

Concurrency: a vault is used by one request at a time (``SQLiteMemoryVault`` shares one SQLite
connection), different users run in parallel, and requests beyond ``max_inflight`` get 429 with
``Retry-After``. Evaluation data is never logged; vaults idle for ``retention_days`` are deleted.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
import signal
import socketserver
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, cast

from .vault import SQLiteMemoryVault

LOG = logging.getLogger("kibisis.aml")

ADAPTER_REVISION = "aml-1"
MESSAGE_CATEGORY = "aml_message"
REQUEST_CATEGORY = "aml_request"
SCOPE = "aml"
VAULT_SUFFIX = ".kib"
DEFAULT_TOP_K = 100
MAX_TOP_K = 1000
GAP = "..."


class ContractError(Exception):
    """A request the contract says to refuse, with the status to refuse it with."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def key_digest(key: str) -> str:
    """Hex SHA-256 of a Memory System Key; the server stores and compares only this."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass
class AMLConfig:
    data_dir: str
    key_sha256: str
    passphrase: Optional[str] = None  # None: plaintext vaults
    candidates: int = 200
    context_before: int = 1
    max_open_vaults: int = 64
    max_inflight: int = 32
    max_body_bytes: int = 64 * 1024 * 1024
    retention_days: float = 28.0
    retry_after_s: int = 2

    def __post_init__(self) -> None:
        digest = (self.key_sha256 or "").strip().lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("key_sha256 must be the 64-character hex SHA-256 of the Memory System Key")
        self.key_sha256 = digest
        if self.candidates < 1 or self.context_before < 0 or self.max_inflight < 1 or self.max_open_vaults < 1:
            raise ValueError("candidates, max_inflight and max_open_vaults must be >= 1; context_before >= 0")


# --------------------------------------------------------------------------- value helpers


def _digest(value: str, n: int = 32) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:n]


def _required_str(body: Dict[str, Any], name: str) -> str:
    value = body.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(422, f"{name} must be a non-empty string")
    return value


def _text_of(content: Any, where: str) -> str:
    """Text of a Textual-track content field: a string, or text ContentParts in order."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for n, part in enumerate(content):
            kind = part.get("type") if isinstance(part, dict) else None
            if kind == "text" and isinstance(part.get("text"), str):
                parts.append(part["text"])
            elif kind == "image_url":
                raise ContractError(422, f"{where}[{n}]: image parts are not supported (Textual track adapter)")
            else:
                raise ContractError(422, f"{where}[{n}]: unsupported content part")
        return "\n".join(parts)
    raise ContractError(422, f"{where} must be a string or an array of text parts")


def _timestamp_ms(value: Any, where: str) -> Optional[int]:
    """Milliseconds since the epoch from the contract's ms integer (seconds and ISO 8601 also accepted)."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ContractError(422, f"{where} must be a number of milliseconds")
    if isinstance(value, (int, float)):
        ms = float(value)
        if abs(ms) < 1e11:  # a value this small is seconds, not milliseconds
            ms *= 1000.0
        return int(ms)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            moment = _dt.datetime.fromisoformat(text)
        except ValueError:
            raise ContractError(422, f"{where} is not a timestamp") from None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=_dt.timezone.utc)
        return int(moment.timestamp() * 1000)
    raise ContractError(422, f"{where} must be a number of milliseconds")


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("kibisis")
    except Exception:  # pragma: no cover - source checkout without metadata
        return "unknown"


def _utc(ms: int) -> _dt.datetime:
    return _dt.datetime.fromtimestamp(ms / 1000.0, tz=_dt.timezone.utc)


def _iso(ms: Optional[int]) -> Optional[str]:
    return None if ms is None else _utc(ms).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp(ms: int) -> str:
    return _utc(ms).strftime("%Y-%m-%d (%a) %H:%M UTC")


# --------------------------------------------------------------------------- vault pool


class _Slot:
    __slots__ = ("path", "lock", "vault", "refs")

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.vault: Optional[SQLiteMemoryVault] = None
        self.refs = 0


class VaultPool:
    """Open per-user vaults, least recently used first out; one request at a time per vault."""

    def __init__(self, data_dir: str, passphrase: Optional[str], max_open: int):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.passphrase = passphrase
        self.max_open = max_open
        self._slots: OrderedDict[str, _Slot] = OrderedDict()
        self._lock = threading.Lock()

    def path_for(self, user_id: str) -> Path:
        return self.data_dir / f"{_digest(user_id)}{VAULT_SUFFIX}"

    def _open(self, path: Path) -> SQLiteMemoryVault:
        if self.passphrase is None:
            return SQLiteMemoryVault(str(path), allow_plaintext=True, auto_gate=False)
        return SQLiteMemoryVault(str(path), passphrase=self.passphrase, auto_gate=False)

    @staticmethod
    def _close(slot: _Slot) -> None:
        with slot.lock:
            if slot.vault is not None:
                try:
                    slot.vault.close()
                finally:
                    slot.vault = None

    def _evict_locked(self) -> List[_Slot]:
        excess = len(self._slots) - self.max_open
        evicted: List[_Slot] = []
        for name, slot in list(self._slots.items()):
            if excess <= 0:
                break
            if slot.refs == 0:  # nobody holds or waits on it, and nobody can reach it once removed
                del self._slots[name]
                evicted.append(slot)
                excess -= 1
        return evicted

    @contextmanager
    def use(self, user_id: str, create: bool) -> Iterator[Optional[SQLiteMemoryVault]]:
        """Yield the user's vault under its lock; None when it does not exist and create is False."""
        path = self.path_for(user_id)
        with self._lock:
            slot = self._slots.get(path.name)
            if slot is None and (create or path.exists()):
                slot = self._slots[path.name] = _Slot(path)
            if slot is not None:
                self._slots.move_to_end(path.name)
                slot.refs += 1
            evicted = self._evict_locked()
        for old in evicted:
            self._close(old)
        if slot is None:
            yield None
            return
        try:
            with slot.lock:
                if slot.vault is None:
                    slot.vault = self._open(slot.path)
                yield slot.vault
        finally:
            with self._lock:
                slot.refs -= 1

    def open_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._slots.values() if s.vault is not None)

    def purge_idle(self, max_idle_s: float, now: Optional[float] = None) -> int:
        """Delete vaults with no write for max_idle_s seconds; returns how many were deleted."""
        now = time.time() if now is None else now
        removed = 0
        for path in sorted(self.data_dir.glob(f"*{VAULT_SUFFIX}")):
            files = [Path(f"{path}{suffix}") for suffix in ("", "-wal", "-shm")]
            try:
                last_write = max(f.stat().st_mtime for f in files if f.exists())
            except ValueError:
                continue
            if now - last_write < max_idle_s:
                continue
            with self._lock:  # no request can open this vault while the lock is held
                slot = self._slots.get(path.name)
                if slot is not None:
                    if slot.refs:
                        continue
                    del self._slots[path.name]
                    self._close(slot)
                for f in files:
                    try:
                        f.unlink()
                    except FileNotFoundError:
                        pass
            removed += 1
        return removed

    def close_all(self) -> None:
        with self._lock:
            slots = list(self._slots.values())
            self._slots.clear()
        for slot in slots:
            self._close(slot)


# --------------------------------------------------------------------------- Add / Search


class AMLService:
    """The contract's two operations over a VaultPool; transport-free so tests can call it directly."""

    def __init__(self, config: AMLConfig):
        self.config = config
        self.pool = VaultPool(config.data_dir, config.passphrase, config.max_open_vaults)

    def add(self, body: Dict[str, Any]) -> Dict[str, Any]:
        request_id = _required_str(body, "request_id")
        user_id = _required_str(body, "user_id")
        session_id = _required_str(body, "session_id")
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ContractError(422, "messages must be a non-empty array")
        rows: List[Tuple[int, str, str, Optional[int]]] = []
        for n, message in enumerate(messages):
            if not isinstance(message, dict):
                raise ContractError(422, f"messages[{n}] must be an object")
            text = _text_of(message.get("content"), f"messages[{n}].content")
            role = message.get("role", "user")
            if not isinstance(role, str):
                raise ContractError(422, f"messages[{n}].role must be a string")
            rows.append((n, role.strip() or "user", text, _timestamp_ms(message.get("timestamp"), f"messages[{n}].timestamp")))

        rid = _digest(request_id, 24)
        items: List[Dict[str, Any]] = [
            dict(category=MESSAGE_CATEGORY, key=f"{rid}:{n:05d}", content=text, scope=SCOPE,
                 epistemic_state="candidate", origin="import", metadata={"r": rid, "i": n, "t": ts, "role": role})
            for n, role, text, ts in rows if text.strip()
        ]
        items.append(dict(category=REQUEST_CATEGORY, key=rid, content=f"aml request {rid}", scope=SCOPE,
                          epistemic_state="candidate", origin="import", metadata={"messages": len(rows)}))
        with self.pool.use(user_id, create=True) as vault:
            assert vault is not None  # create=True always yields a vault
            if vault.get(REQUEST_CATEGORY, rid, scope=SCOPE) is None:  # a retry of a committed request is a no-op
                with vault._write_tx():  # one transaction: the request lands whole or not at all
                    vault.put_batch(items)
        return {"success": True, "request_id": request_id, "user_id": user_id, "session_id": session_id}

    def search(self, body: Dict[str, Any]) -> Dict[str, Any]:
        user_id = _required_str(body, "user_id")
        query = _text_of(body.get("query"), "query").strip()
        if not query:
            raise ContractError(422, "query must be non-empty")
        options = body.get("options")
        if options is None:
            options = []
        if not isinstance(options, list):
            raise ContractError(422, "options must be an array")
        top_k = body.get("top_k", DEFAULT_TOP_K)
        if top_k is None:
            top_k = DEFAULT_TOP_K
        if isinstance(top_k, str) and top_k.strip().isdigit():
            top_k = int(top_k.strip())
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= MAX_TOP_K:
            raise ContractError(422, f"top_k must be an integer from 1 to {MAX_TOP_K}")
        text = " ".join([query] + [_text_of(o, "options[]") for o in options])

        groups: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        with self.pool.use(user_id, create=False) as vault:
            if vault is None:
                return {"data": []}
            hits = vault.search(text, category=MESSAGE_CATEGORY, scope=SCOPE, limit=max(self.config.candidates, top_k),
                                match="any", include_unverified=True)
            for hit in hits:  # Kibisis returns best first; rank_score is BM25, lower is better
                meta = hit.entity.metadata or {}
                rid, n = meta.get("r"), meta.get("i")
                if not isinstance(rid, str) or not isinstance(n, int):
                    continue
                group = groups.get(rid)
                if group is None:
                    if len(groups) >= top_k:
                        continue
                    group = groups[rid] = {"anchor": hit.entity, "score": -float(hit.rank_score), "lines": {}}
                group["lines"][n] = hit.entity
            for rid, group in groups.items():
                lines = group["lines"]
                for n in sorted(lines):
                    for m in range(max(0, n - self.config.context_before), n):
                        if m not in lines:
                            entity = vault.get(MESSAGE_CATEGORY, f"{rid}:{m:05d}", scope=SCOPE)
                            if entity is not None:
                                lines[m] = entity

        data: List[Dict[str, Any]] = []
        last_score: Optional[float] = None
        for group in groups.values():
            score = group["score"] if last_score is None else min(group["score"], last_score)
            last_score = score  # never rises down the list: higher score, earlier rank
            anchor = group["anchor"]
            item: Dict[str, Any] = {"id": f"kib_{anchor.key}", "content": _render(group["lines"]), "score": round(score, 6)}
            created = _iso((anchor.metadata or {}).get("t"))
            if created:
                item["created_at"] = created
            data.append(item)
        return {"data": data}


def _render(lines: Dict[int, Any]) -> str:
    out: List[str] = []
    previous_n, previous_stamp = None, None
    for n in sorted(lines):
        entity = lines[n]
        meta = entity.metadata or {}
        if previous_n is not None and n != previous_n + 1:
            out.append(GAP)
        ts = meta.get("t")
        stamp = _stamp(ts) if isinstance(ts, int) else None
        if stamp and stamp != previous_stamp:
            out.append(f"[{stamp}]")
            previous_stamp = stamp
        out.append(f"{meta.get('role') or 'user'}: {entity.content}")
        previous_n = n
    return "\n".join(out)


# --------------------------------------------------------------------------- HTTP


class AMLServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, address: Tuple[str, int], config: AMLConfig):
        self.config = config
        self.service = AMLService(config)
        self.inflight = threading.BoundedSemaphore(config.max_inflight)
        super().__init__(address, AMLHandler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind sets server_name from socket.getfqdn(host), a reverse DNS lookup that can stall
        # startup for half a minute (seen on macOS runners). Nothing here reads server_name, so skip the lookup.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class AMLHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "kibisis-aml"
    sys_version = ""

    ROUTES: Dict[str, str] = {
        "/v1/memories/add": "add",
        "/add": "add",
        "/v1/memories/search": "search",
        "/search": "search",
    }
    HEALTH = ("/", "/health", "/v1/health")

    @property
    def aml(self) -> AMLServer:
        return cast(AMLServer, self.server)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        pass  # one line per request is written by _finish, without paths' query strings or bodies

    def _path(self) -> str:
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def _send(self, status: int, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> int:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        return status

    def _health(self) -> int:
        if self._path() not in self.HEALTH:
            return self._send(404, {"error": "not found"})
        return self._send(200, {"status": "ok", "service": "kibisis-aml", "adapter": ADAPTER_REVISION,
                                "version": _package_version(), "commit": os.environ.get("KIBISIS_AML_COMMIT") or None})

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._health()

    def do_HEAD(self) -> None:  # noqa: N802
        self._health()

    def _presented_key(self) -> Optional[str]:
        auth = (self.headers.get("Authorization") or "").strip()
        scheme, _, credential = auth.partition(" ")
        if scheme.lower() in ("token", "bearer") and credential.strip():
            return credential.strip()
        key = (self.headers.get("X-Api-Key") or "").strip()
        return key or None

    def _authorized(self) -> bool:
        key = self._presented_key()
        return key is not None and hmac.compare_digest(key_digest(key), self.aml.config.key_sha256)

    def _read_body(self) -> bytes:
        limit = self.aml.config.max_body_bytes
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = bytearray()
            while True:
                size_line = self.rfile.readline(65537)
                try:
                    size = int(size_line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    self.close_connection = True
                    raise ContractError(400, "malformed chunked body") from None
                if size == 0:
                    while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                        pass
                    return bytes(out)
                if len(out) + size > limit:
                    self.close_connection = True
                    raise ContractError(413, f"body exceeds {limit} bytes")
                out += self.rfile.read(size)
                self.rfile.readline()
        length = self.headers.get("Content-Length")
        if length is None:
            self.close_connection = True
            raise ContractError(411, "Content-Length required")
        try:
            size = int(length)
        except ValueError:
            self.close_connection = True
            raise ContractError(400, "bad Content-Length") from None
        if size < 0 or size > limit:
            self.close_connection = True
            self._body_unread = size > 0
            raise ContractError(413, f"body exceeds {limit} bytes")
        return self.rfile.read(size)

    #: After refusing a request before reading its body (413, 429), the handler reads and drops the
    #: declared body for at most this long, then closes. Closing a socket that still has unread data
    #: makes the kernel reset the connection, and a client still sending its body then gets the reset
    #: instead of the reply (macOS does this even for a body just over the limit).
    DRAIN_SECONDS = 2.0

    def _drain_body(self) -> None:
        """Read and drop the request's declared body, for at most :attr:`DRAIN_SECONDS`.

        Runs after the reply has gone out and before the connection closes. A chunked body is not
        drained: its length is not known up front.
        """
        try:
            remaining = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        deadline = time.monotonic() + self.DRAIN_SECONDS
        try:
            while remaining > 0:
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                self.connection.settimeout(left)
                chunk = self.rfile.read1(min(remaining, 65536))
                if not chunk:
                    return
                remaining -= len(chunk)
        except OSError:  # a timeout or a reset: the connection closes either way
            return

    def do_POST(self) -> None:  # noqa: N802
        started = time.perf_counter()
        op = self.ROUTES.get(self._path())
        status = 500
        self._body_unread = False
        try:
            if op is None:
                self.close_connection = True
                status = self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                self.close_connection = True
                status = self._send(401, {"error": "invalid or missing credentials"})
                return
            if not self.aml.inflight.acquire(blocking=False):
                self.close_connection = True
                retry = str(self.aml.config.retry_after_s)
                status = self._send(429, {"error": "busy, retry later"}, {"Retry-After": retry})
                self._drain_body()  # so the client reads the 429 and its Retry-After, not a reset
                return
            try:
                raw = self._read_body()
                try:
                    body = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise ContractError(400, "body is not valid UTF-8 JSON") from None
                if not isinstance(body, dict):
                    raise ContractError(422, "body must be a JSON object")
                result = getattr(self.aml.service, op)(body)
                status = self._send(200, result)
            finally:
                self.aml.inflight.release()
        except ContractError as exc:
            status = self._send(exc.status, {"error": exc.message})
            if self._body_unread:
                self._drain_body()
        except Exception as exc:  # never echo evaluation content; the type is enough to find the bug
            LOG.error("%s failed: %s", op, type(exc).__name__)
            self.close_connection = True
            status = self._send(500, {"error": "internal error"})
        finally:
            LOG.info("%s %s %d %.1fms", self.command, op or "-", status, (time.perf_counter() - started) * 1000)


def run_server(config: AMLConfig, host: str = "127.0.0.1", port: int = 8080,
               ready: Optional[Callable[[AMLServer], None]] = None) -> None:
    """Serve until SIGTERM/SIGINT; deletes vaults idle past config.retention_days once an hour."""
    server = AMLServer((host, port), config)
    stop = threading.Event()

    def _shutdown(signum: int, frame: Any) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

    def _retention() -> None:
        while not stop.wait(3600 if config.retention_days > 0 else 86400):
            if config.retention_days > 0:
                removed = server.service.pool.purge_idle(config.retention_days * 86400)
                if removed:
                    LOG.info("retention: deleted %d vaults idle > %.0f days", removed, config.retention_days)

    if config.retention_days > 0:
        removed = server.service.pool.purge_idle(config.retention_days * 86400)
        if removed:
            LOG.info("retention: deleted %d vaults idle > %.0f days", removed, config.retention_days)
    threading.Thread(target=_retention, name="aml-retention", daemon=True).start()
    LOG.info("kibisis-aml %s listening on %s:%d (encrypted=%s, candidates=%d, max_inflight=%d)", ADAPTER_REVISION,
             host, server.server_address[1], config.passphrase is not None, config.candidates, config.max_inflight)
    if ready is not None:
        ready(server)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        server.server_close()
        server.service.pool.close_all()
