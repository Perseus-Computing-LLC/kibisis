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
  contract) is acknowledged without being written twice; the same id with a different payload is
  refused with 409. ``success`` is returned after commit, when the messages are durable and
  searchable. Timestamps must convert to a date (see :data:`MS_FLOOR`); otherwise 422.
* Search. One Kibisis BM25 query (``match="any"``) over the user's messages; the query is the
  question plus any answer options. Hits are grouped by the Add request (conversation chunk) they
  came from and each hit brings the message before it as context. Every group becomes one memory:
  its lines in conversation order under the message timestamp, ``...`` where lines are skipped.
  Groups are returned best hit first, at most ``top_k`` of them; the platform's Answer step keeps
  the token-counted prefix that fits its context budget.

No model calls, no summarisation, no rewriting of stored text.

Concurrency: a vault is used by one request at a time (``SQLiteMemoryVault`` shares one SQLite
connection), different users run in parallel, and requests beyond ``max_inflight`` get 429 with
``Retry-After``. ``max_inflight`` bounds request processing (body read plus Add/Search), not
connections: those are bounded by ``max_connections`` (503 beyond it) and ``socket_timeout``, after
which an idle or stalled connection is closed. Evaluation data is never logged; vaults not used
(no Add or Search) for ``retention_days`` are deleted, and only files that are vaults are.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import logging
import math
import os
import re
import signal
import socket
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
_VAULT_NAME = re.compile(r"[0-9a-f]{32}\.kib")
_SQLITE_HEADER = b"SQLite format 3\x00"
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
    #: Seconds a connection may sit idle (between requests, or mid-body) before the server closes it.
    socket_timeout: float = 30.0
    #: Connections (handler threads) accepted at once; beyond this a connection gets 503 and is closed.
    max_connections: int = 256

    def __post_init__(self) -> None:
        digest = (self.key_sha256 or "").strip().lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("key_sha256 must be the 64-character hex SHA-256 of the Memory System Key")
        self.key_sha256 = digest
        if self.candidates < 1 or self.context_before < 0 or self.max_inflight < 1 or self.max_open_vaults < 1:
            raise ValueError("candidates, max_inflight and max_open_vaults must be >= 1; context_before >= 0")
        if not (self.socket_timeout > 0) or self.max_connections < 1:
            raise ValueError("socket_timeout must be > 0 seconds and max_connections >= 1")


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


#: Numeric timestamps at or above this are milliseconds (1973-03-03T09:46:40Z). Numbers in
#: [:data:`SECONDS_FLOOR`, :data:`SECONDS_CEILING`) are read as seconds (2001-09-09 .. 2096-10-02);
#: this is the only other form, and nothing in it can also be a millisecond value the adapter
#: accepts. Anything else (below 1e9, in [4e9, 1e11), negative, non-finite, past year 9999) is
#: refused with 422: the contract's unit is milliseconds, and such a value cannot be told apart
#: from a unit mistake.
MS_FLOOR = 100_000_000_000
SECONDS_FLOOR = 1_000_000_000
SECONDS_CEILING = 4_000_000_000
#: 9999-12-31T23:59:59.999Z, the last instant ``datetime`` can render.
MS_CEILING = 253_402_300_799_999


def _timestamp_ms(value: Any, where: str) -> Optional[int]:
    """Milliseconds since the epoch from the contract's ms integer (seconds and ISO 8601 also accepted).

    Only values that convert to a ``datetime`` are accepted, so a stored timestamp can always be
    rendered by Search. See :data:`MS_FLOOR` for the ms-vs-seconds rule.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ContractError(422, f"{where} must be a number of milliseconds")
    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number):
            raise ContractError(422, f"{where} must be a finite number of milliseconds")
        if number >= MS_FLOOR:
            ms = int(number)
        elif SECONDS_FLOOR <= number < SECONDS_CEILING:
            ms = int(number * 1000.0)
        else:
            raise ContractError(422, f"{where}: send epoch milliseconds (>= {MS_FLOOR}), epoch seconds in "
                                     f"[{SECONDS_FLOOR}, {SECONDS_CEILING}) or ISO 8601; {number:g} is neither")
        if ms > MS_CEILING:
            raise ContractError(422, f"{where} is past the year 9999")
        return ms
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            moment = _dt.datetime.fromisoformat(text)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=_dt.timezone.utc)
            ms = int(moment.timestamp() * 1000)
        except (ValueError, OverflowError, OSError):
            raise ContractError(422, f"{where} is not a timestamp") from None
        if not 0 <= ms <= MS_CEILING:
            raise ContractError(422, f"{where} is outside 1970..9999")
        return ms
    raise ContractError(422, f"{where} must be a number of milliseconds")


def _encodable(value: str, where: str) -> str:
    """``value`` if it is valid Unicode; 422 for a lone surrogate (valid JSON, not storable as UTF-8)."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ContractError(422, f"{where} contains a lone surrogate (not valid Unicode)") from None
    return value


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON number {name}")


def _parse_float(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):  # 1e400 overflows to inf
        raise ValueError(f"non-finite JSON number {text}")
    return number


def parse_json_body(raw: bytes) -> Any:
    """Decode a request body: strict UTF-8, standard JSON only (no NaN/Infinity, no overflowing
    floats), and no lone surrogates anywhere in it. Raises :class:`ContractError` 400 otherwise."""
    try:
        body = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, parse_float=_parse_float)
    except (UnicodeDecodeError, ValueError):  # JSONDecodeError is a ValueError
        raise ContractError(400, "body is not valid UTF-8 JSON") from None
    if _has_lone_surrogate(body):
        raise ContractError(400, "body contains a lone surrogate (not valid Unicode)")
    return body


def _has_lone_surrogate(value: Any) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("kibisis")
    except Exception:  # pragma: no cover - source checkout without metadata
        return "unknown"


def _utc(ms: int) -> _dt.datetime:
    return _dt.datetime.fromtimestamp(ms / 1000.0, tz=_dt.timezone.utc)


def _iso(ms: Any) -> Optional[str]:
    """ISO 8601 of a stored timestamp, or None when the row holds nothing renderable (Search never 500s on a row)."""
    if isinstance(ms, bool) or not isinstance(ms, (int, float)):
        return None
    try:
        return _utc(int(ms)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        LOG.warning("stored timestamp could not be rendered; omitted")
        return None


def _stamp(ms: Any) -> Optional[str]:
    if isinstance(ms, bool) or not isinstance(ms, (int, float)):
        return None
    try:
        return _utc(int(ms)).strftime("%Y-%m-%d (%a) %H:%M UTC")
    except (ValueError, OverflowError, OSError):
        return None


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

    def touch(self, user_id: str) -> None:
        """Mark the user's vault as used now, so retention counts reads as activity (mtime of the file)."""
        try:
            os.utime(self.path_for(user_id), None)
        except OSError:
            pass

    @staticmethod
    def is_vault_file(path: Path, encrypted: bool) -> bool:
        """True for a regular file this pool could have created: ``<32 hex>.kib``, not a symlink, with a
        SQLite header (plaintext pools) or a page-sized body with no SQLite header (SQLCipher pools, whose
        first page is encrypted). Anything else in the data directory is never retention's to delete."""
        if not _VAULT_NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            return False
        size = path.stat().st_size
        if size < 512 or size % 512:
            return False
        with path.open("rb") as f:
            header = f.read(16)
        if header.startswith(_SQLITE_HEADER):
            return not encrypted
        return encrypted

    def purge_idle(self, max_idle_s: float, now: Optional[float] = None) -> int:
        """Delete vaults not used (no Add or Search) for max_idle_s seconds; returns how many were deleted.

        Only files :meth:`is_vault_file` accepts are candidates. The pool lock is held from the mtime
        check to the unlink, so a request cannot open or write the vault in between; a vault whose slot
        is in use is skipped. A failure on one file is logged and the sweep goes on.
        """
        now = time.time() if now is None else now
        removed = 0
        for path in sorted(self.data_dir.glob(f"*{VAULT_SUFFIX}")):
            try:
                if not self.is_vault_file(path, self.passphrase is not None):
                    continue
                files = [Path(f"{path}{suffix}") for suffix in ("", "-wal", "-shm")]
                with self._lock:  # no request can open this vault while the lock is held
                    last_used = max(f.stat().st_mtime for f in files if f.exists())
                    if now - last_used < max_idle_s:
                        continue
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
            except (OSError, ValueError) as exc:  # ValueError: the files vanished under the lock
                LOG.warning("retention: skipped %s: %s", path.name, type(exc).__name__)
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
        request_id = _encodable(_required_str(body, "request_id"), "request_id")
        user_id = _encodable(_required_str(body, "user_id"), "user_id")
        session_id = _encodable(_required_str(body, "session_id"), "session_id")
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ContractError(422, "messages must be a non-empty array")
        rows: List[Tuple[int, str, str, Optional[int]]] = []
        for n, message in enumerate(messages):
            if not isinstance(message, dict):
                raise ContractError(422, f"messages[{n}] must be an object")
            text = _encodable(_text_of(message.get("content"), f"messages[{n}].content"), f"messages[{n}].content")
            role = message.get("role", "user")
            if not isinstance(role, str):
                raise ContractError(422, f"messages[{n}].role must be a string")
            role = _encodable(role.strip(), f"messages[{n}].role") or "user"
            rows.append((n, role, text, _timestamp_ms(message.get("timestamp"), f"messages[{n}].timestamp")))

        rid = _digest(request_id, 24)
        # The marker remembers what the request said, so a reused request_id with other content is
        # refused (409) instead of being acknowledged and dropped; an identical retry stays a no-op.
        payload_digest = _digest(json.dumps([session_id, rows], ensure_ascii=False, separators=(",", ":")), 64)
        items: List[Dict[str, Any]] = [
            dict(category=MESSAGE_CATEGORY, key=f"{rid}:{n:05d}", content=text, scope=SCOPE,
                 epistemic_state="candidate", origin="import", metadata={"r": rid, "i": n, "t": ts, "role": role})
            for n, role, text, ts in rows if text.strip()
        ]
        items.append(dict(category=REQUEST_CATEGORY, key=rid, content=f"aml request {rid}", scope=SCOPE,
                          epistemic_state="candidate", origin="import",
                          metadata={"messages": len(rows), "payload": payload_digest}))
        with self.pool.use(user_id, create=True) as vault:
            assert vault is not None  # create=True always yields a vault
            marker = vault.get(REQUEST_CATEGORY, rid, scope=SCOPE)
            if marker is None:
                with vault._write_tx():  # one transaction: the request lands whole or not at all
                    vault.put_batch(items)
            else:  # a retry of a committed request is a no-op; a different payload under the same id is not
                stored = (marker.metadata or {}).get("payload")
                if isinstance(stored, str) and not hmac.compare_digest(stored, payload_digest):
                    raise ContractError(409, "request_id was already used with a different payload")
        return {"success": True, "request_id": request_id, "user_id": user_id, "session_id": session_id}

    def search(self, body: Dict[str, Any]) -> Dict[str, Any]:
        user_id = _encodable(_required_str(body, "user_id"), "user_id")
        query = _encodable(_text_of(body.get("query"), "query"), "query").strip()
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
            self.pool.touch(user_id)  # a Search counts as activity for retention
            hits = vault.search(text, category=MESSAGE_CATEGORY, scope=SCOPE, limit=max(self.config.candidates, top_k),
                                match="any", include_unverified=True)
            for hit in hits:  # Kibisis returns best first; rank_score is BM25, lower is better
                meta = hit.entity.metadata or {}
                rid, n = meta.get("r"), meta.get("i")
                if not isinstance(rid, str) or isinstance(n, bool) or not isinstance(n, int) or n < 0:
                    LOG.warning("search: skipped a stored row with unusable metadata")
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
        #: One permit per accepted connection, held for the connection's whole life (``max_inflight``
        #: bounds request processing only). Over the cap a connection gets 503 and is closed at once.
        self.connections = threading.BoundedSemaphore(config.max_connections)
        super().__init__(address, AMLHandler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind sets server_name from socket.getfqdn(host), a reverse DNS lookup that can stall
        # startup for half a minute (seen on macOS runners). Nothing here reads server_name, so skip the lookup.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.connections.acquire(blocking=False):
            try:
                request.settimeout(1.0)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: "
                                + str(self.config.retry_after_s).encode() + b"\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            LOG.warning("connection refused: %d connections open (max_connections)", self.config.max_connections)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


class AMLHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "kibisis-aml"
    sys_version = ""
    #: Socket timeout applied by :meth:`setup` (StreamRequestHandler); the class default is replaced by
    #: ``AMLConfig.socket_timeout`` per connection. A connection that sends nothing, or stalls mid-body,
    #: is closed after this long and its thread ends.
    timeout = 30.0

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

    def setup(self) -> None:
        super().setup()  # applies the class timeout; the configured one replaces it
        config = getattr(self.server, "config", None)
        if config is not None:
            self.connection.settimeout(config.socket_timeout)

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

    #: Chunk-size line: hex digits, optional ``;extensions``. ``int(x, 16)`` alone would accept ``-1``,
    #: ``0x10`` and ``+5``; a negative size turned the cap check false and the read into ``read(-1)``.
    _CHUNK_SIZE = re.compile(rb"^[0-9A-Fa-f]{1,16}$")
    _MAX_TRAILERS = 64

    def _read_body(self) -> bytes:
        limit = self.aml.config.max_body_bytes
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = bytearray()
            while True:
                size_line = self.rfile.readline(65537)
                field = size_line.split(b";", 1)[0].strip()
                if not self._CHUNK_SIZE.match(field):
                    self.close_connection = True
                    raise ContractError(400, "malformed chunked body")
                size = int(field, 16)  # never negative: the pattern allows digits only
                if size == 0:
                    for _ in range(self._MAX_TRAILERS):
                        if self.rfile.readline(65537) in (b"\r\n", b"\n", b""):
                            return bytes(out)
                    self.close_connection = True
                    raise ContractError(400, "malformed chunked body")
                if len(out) + size > limit:  # checked before every chunk, so the total never passes the cap
                    self.close_connection = True
                    raise ContractError(413, f"body exceeds {limit} bytes")
                chunk = self.rfile.read(size)
                if len(chunk) != size or self.rfile.readline(3) not in (b"\r\n", b"\n"):
                    self.close_connection = True
                    raise ContractError(400, "malformed chunked body")
                out += chunk
        length = self.headers.get("Content-Length")
        if length is None:
            self.close_connection = True
            raise ContractError(411, "Content-Length required")
        if not re.fullmatch(r"[0-9]{1,18}", length.strip()):
            self.close_connection = True
            raise ContractError(400, "bad Content-Length")
        size = int(length.strip())
        if size > limit:
            self.close_connection = True
            self._body_unread = size > 0
            raise ContractError(413, f"body exceeds {limit} bytes")
        raw = self.rfile.read(size)
        if len(raw) != size:  # the client closed early
            self.close_connection = True
            raise ContractError(400, "body shorter than Content-Length")
        return raw

    #: After refusing a request before reading its body (401, 404, 413, 429), the handler reads and drops
    #: the declared body for at most this long, then closes. Closing a socket that still has unread data
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
            # The credential is checked first, so an unauthenticated client learns nothing about which
            # paths exist. Both refusals leave the body unread: drain it so the reply, not a reset, arrives.
            if not self._authorized():
                self.close_connection = True
                status = self._send(401, {"error": "invalid or missing credentials"})
                self._drain_body()
                return
            if op is None:
                self.close_connection = True
                status = self._send(404, {"error": "not found"})
                self._drain_body()
                return
            if not self.aml.inflight.acquire(blocking=False):
                self.close_connection = True
                retry = str(self.aml.config.retry_after_s)
                status = self._send(429, {"error": "busy, retry later"}, {"Retry-After": retry})
                self._drain_body()  # so the client reads the 429 and its Retry-After, not a reset
                return
            try:
                raw = self._read_body()
                body = parse_json_body(raw)
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
        except (socket.timeout, TimeoutError):  # the client stalled mid-request: give the thread back
            self.close_connection = True
            status = 408
            try:
                self._send(408, {"error": "request timed out"})
            except OSError:
                pass
        except Exception as exc:  # never echo evaluation content; the type is enough to find the bug
            LOG.error("%s failed: %s", op, type(exc).__name__)
            self.close_connection = True
            status = self._send(500, {"error": "internal error"})
        finally:
            LOG.info("%s %s %d %.1fms", self.command, op or "-", status, (time.perf_counter() - started) * 1000)


def _encrypted_at_rest(config: AMLConfig) -> bool:
    """Whether the vaults this server writes are SQLCipher files: a passphrase is set and sqlcipher3 loads.
    (A vault object reports the same as ``_sqlcipher_active`` once open; none is open at startup.)"""
    if config.passphrase is None:
        return False
    try:
        from .vault import _sqlcipher_available

        return bool(_sqlcipher_available())
    except Exception:  # pragma: no cover - older vault module
        return True


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

    def _purge() -> None:
        try:
            removed = server.service.pool.purge_idle(config.retention_days * 86400)
        except Exception as exc:  # the sweep must outlive any one surprise; per-file errors are logged inside
            LOG.error("retention sweep failed: %s", type(exc).__name__)
            return
        if removed:
            LOG.info("retention: deleted %d vaults unused > %.0f days", removed, config.retention_days)

    def _retention() -> None:
        while not stop.wait(3600 if config.retention_days > 0 else 86400):
            if config.retention_days > 0:
                _purge()

    if config.retention_days > 0:
        _purge()
    threading.Thread(target=_retention, name="aml-retention", daemon=True).start()
    encrypted = _encrypted_at_rest(config)
    if config.passphrase is not None and not encrypted:
        LOG.warning("sqlcipher3 is not available: vault files are not encrypted as a whole; entry content is sealed, "
                    "but roles, timestamps and request markers are stored in the clear")
    LOG.info("kibisis-aml %s listening on %s:%d (encrypted_at_rest=%s, candidates=%d, max_inflight=%d, "
             "max_connections=%d, socket_timeout=%.0fs)", ADAPTER_REVISION, host, server.server_address[1], encrypted,
             config.candidates, config.max_inflight, config.max_connections, config.socket_timeout)
    if ready is not None:
        ready(server)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        server.server_close()
        server.service.pool.close_all()
