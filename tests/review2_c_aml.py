"""Second-pass review (R2) of the area C fixes: AML adapter.

Not collected by default (no ``test_`` prefix); run by explicit path. Convention: ``test_control_*`` asserts
the correct behaviour (failing = bug), ``test_attack_*`` demonstrates a defect (passing = bug). Servers bind
127.0.0.1 on an ephemeral port and are shut down in a finally block; parser-level cases use BytesIO readers.
"""

from __future__ import annotations

import io
import json
import os
import socket
import sqlite3
import threading
import time
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from kibisis.aml_adapter import (
    MS_CEILING,
    AMLConfig,
    AMLHandler,
    AMLService,
    ContractError,
    key_digest,
    parse_json_body,
    run_server,
)

KEY = "review2-c-throwaway-key-0123456789"
PASSPHRASE = "review2-c-passphrase-not-secret"
T0 = 1_704_067_200_000  # 2024-01-01T00:00:00Z
AUTH = f"Authorization: Token {KEY}\r\n"


def _config(tmp_path: Path, **kw) -> AMLConfig:
    kw.setdefault("passphrase", PASSPHRASE)
    return AMLConfig(data_dir=str(tmp_path / "vaults"), key_sha256=key_digest(KEY), **kw)


@pytest.fixture
def svc(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    service = AMLService(_config(tmp_path))
    try:
        yield service
    finally:
        service.pool.close_all()


def _serve(config: AMLConfig):
    started = threading.Event()
    holder = {}

    def ready(server):
        holder["server"] = server
        started.set()

    thread = threading.Thread(target=run_server, args=(config,),
                              kwargs={"host": "127.0.0.1", "port": 0, "ready": ready}, daemon=True)
    thread.start()
    assert started.wait(10)
    return holder["server"], thread


@pytest.fixture
def http_server(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    config = _config(tmp_path, max_inflight=4, retention_days=0, socket_timeout=2.0, max_connections=4,
                     max_body_bytes=4096)
    server, thread = _serve(config)
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(10)


def _raw(server, data: bytes, read_timeout: float = 3.0) -> bytes:
    """Send bytes on a fresh connection and return everything the server sends until it closes (or the
    read times out, in which case ``<TIMEOUT>`` is appended)."""
    s = socket.create_connection(("127.0.0.1", server.server_address[1]))
    s.settimeout(read_timeout)
    out = b""
    try:
        s.sendall(data)
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        out += b"<TIMEOUT>"
    finally:
        s.close()
    return out


def _post(path: str, payload: dict, auth: bool = True, extra: str = "") -> bytes:
    body = json.dumps(payload).encode()
    head = (f"POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{AUTH if auth else ''}{extra}"
            f"Content-Length: {len(body)}\r\n\r\n")
    return head.encode() + body


def _statuses(out: bytes) -> list:
    return [int(m) for m in __import__("re").findall(rb"HTTP/1\.1 (\d{3})", out)]


def _add(rid="r1", user="u", text="hello", ts=T0, **over):
    body = {"request_id": rid, "user_id": user, "session_id": "s",
            "messages": [{"role": "user", "timestamp": ts, "content": text}]}
    body.update(over)
    return body


# ---------------------------------------------------------------- C-1 / C-7 / C-8: input-driven 500s


def test_attack_integer_timestamp_too_large_for_float_is_500(svc):
    """A JSON integer with more digits than a float can hold (``10**400``: 401 digits, under the 4300-digit
    JSON limit) reaches ``float(value)`` in ``_timestamp_ms`` and raises OverflowError, which do_POST turns
    into a 500. The same class as C-1 (an input-driven 500), one layer deeper. Passing = bug."""
    with pytest.raises(OverflowError):
        svc.add(_add(ts=10**400))


def test_attack_integer_timestamp_too_large_for_float_is_500_over_http(http_server):
    out = _raw(http_server, _post("/add", _add(ts=10**400)))
    assert _statuses(out) == [500] and b"internal error" in out


def test_attack_top_k_digit_string_over_4300_digits_is_500(svc):
    """``top_k`` as a digit string is accepted and converted with ``int()``; a string of more than 4300
    digits trips CPython's int-conversion limit (ValueError, not ContractError) -> 500. Passing = bug."""
    svc.add(_add())
    with pytest.raises(ValueError, match="Exceeds the limit"):
        svc.search({"user_id": "u", "query": "hello", "top_k": "9" * 5000})


def test_attack_deeply_nested_json_is_500():
    """``json.loads`` raises RecursionError (an Exception, not a ValueError) on deep nesting; parse_json_body
    only catches ValueError, so do_POST answers 500 for a ~200 KB body well under the 64 MiB cap."""
    with pytest.raises(RecursionError):
        parse_json_body(b"[" * 100_000 + b"]" * 100_000)


def test_control_ordinary_bad_inputs_are_4xx(svc):
    svc.add(_add())
    for bad in [{"top_k": "0"}, {"top_k": 10**4000}, {"top_k": -1}, {"top_k": 5.0}, {"options": "x"},
                {"query": ""}, {"query": None}, {"options": [[1]]}]:
        with pytest.raises(ContractError) as exc:
            svc.search({"user_id": "u", "query": "hello", **bad})
        assert exc.value.status == 422
    for ts in [MS_CEILING + 1, -T0, 0, 99_999_999_999, True, [1], {}, "9999-12-31T23:59:59-01:00", "0001-01-01"]:
        with pytest.raises(ContractError) as exc:
            svc.add(_add(rid=f"t{ts!r}", ts=ts))
        assert exc.value.status == 422
    assert svc.add(_add(rid="ceil", ts=MS_CEILING))["success"]
    for raw in [b"", b'{"a":1e400}', b'{"a":NaN}', b'{"\\ud800":1}', b"\xff", b'{"a":' + b"1" * 5000 + b"}"]:
        with pytest.raises(ContractError) as exc:
            parse_json_body(raw)
        assert exc.value.status == 400


# ---------------------------------------------------------------- C-2 / C-3: request shapes


def _handler(tmp_path, limit, stream, **headers):
    handler = AMLHandler.__new__(AMLHandler)
    handler.server = SimpleNamespace(config=AMLConfig(data_dir=str(tmp_path), key_sha256=key_digest(KEY),
                                                      max_body_bytes=limit))
    handler.close_connection = False
    message = Message()
    for name, value in headers.items():
        message[name.replace("_", "-")] = value
    handler.headers = message
    handler.rfile = stream
    return handler


def test_control_chunked_edge_shapes(tmp_path):
    """Chunk size exactly at the cap passes; one over is 413 before the read; whitespace around the hex is
    tolerated; chunk extensions and trailers are skipped; a missing CRLF after the data is 400."""
    assert _handler(tmp_path, 8, io.BytesIO(b"8\r\nABCDEFGH\r\n0\r\n\r\n"), Transfer_Encoding="chunked")._read_body() == b"ABCDEFGH"
    with pytest.raises(ContractError) as exc:
        _handler(tmp_path, 8, io.BytesIO(b"9\r\nABCDEFGHI\r\n0\r\n\r\n"), Transfer_Encoding="chunked")._read_body()
    assert exc.value.status == 413
    assert _handler(tmp_path, 64, io.BytesIO(b"  4  \r\nABCD\r\n0\r\n\r\n"), Transfer_Encoding="chunked")._read_body() == b"ABCD"
    assert _handler(tmp_path, 64, io.BytesIO(b"4;a=b\r\nABCD\r\n0\r\nT: v\r\n\r\n"), Transfer_Encoding="chunked")._read_body() == b"ABCD"
    for bad in [b"4\r\nABCDXX\r\n0\r\n\r\n", b"FFFFFFFFFFFFFFFFF\r\n", b"4\r\nAB"]:
        with pytest.raises(ContractError) as exc:
            _handler(tmp_path, 64, io.BytesIO(bad), Transfer_Encoding="chunked")._read_body()
        assert exc.value.status in (400, 413)
    # Transfer-Encoding wins over Content-Length (RFC 9112 6.3), identity falls back to Content-Length
    h = _handler(tmp_path, 64, io.BytesIO(b"4\r\nABCD\r\n0\r\n\r\n"), Transfer_Encoding="chunked", Content_Length="1")
    assert h._read_body() == b"ABCD"
    h = _handler(tmp_path, 64, io.BytesIO(b"ABCD"), Transfer_Encoding="identity", Content_Length="4")
    assert h._read_body() == b"ABCD"


def test_control_keep_alive_survives_422_and_400(http_server):
    """A refusal after the body was fully read leaves the connection usable (pipelined second request)."""
    good = _post("/search", {"user_id": "u", "query": "hi"})
    for first in (b"{}", b"{{"):
        head = f"POST /search HTTP/1.1\r\nHost: x\r\n{AUTH}Content-Length: 2\r\n\r\n".encode()
        out = _raw(http_server, head + first + good, read_timeout=1.5)
        assert _statuses(out)[:2] in ([422, 200], [400, 200]), out


def test_control_duplicate_and_conflicting_length_headers_do_not_500(http_server):
    body = json.dumps({"user_id": "u", "query": "hi"}).encode()
    dup = (f"POST /search HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{AUTH}Content-Length: {len(body)}\r\nContent-Length: 1\r\n\r\n").encode() + body
    assert _statuses(_raw(http_server, dup))[0] in (200, 400)
    both = (f"POST /search HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{AUTH}Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n").encode() \
        + b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
    assert _statuses(_raw(http_server, both)) == [200]
    nolen = (f"POST /search HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{AUTH}Transfer-Encoding: gzip\r\n\r\n").encode() + body
    assert _statuses(_raw(http_server, nolen)) == [411]


def test_attack_expect_100_continue_is_honoured_before_the_credential_check(http_server):
    """http.server answers ``Expect: 100-continue`` in parse_request, before do_POST runs, so an
    unauthenticated client is invited to send its body (then 401 + a 2 s drain). L8 said "an
    unauthenticated client learns nothing"; it learns the server accepts bodies. Low. Passing = bug."""
    head = b"POST /search HTTP/1.1\r\nHost: x\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n"
    out = _raw(http_server, head, read_timeout=3.5)
    assert _statuses(out)[:2] == [100, 401], out


def test_control_unauthenticated_requests_are_401_and_other_methods_do_not_route(http_server):
    for path in ("/add", "/search", "/nope", "/v1/memories/add"):
        out = _raw(http_server, _post(path, {}, auth=False))
        assert _statuses(out) == [401] and b"Connection: close" in out
    out = _raw(http_server, b"PUT /add HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    assert _statuses(out) == [501]
    out = _raw(http_server, b"GET /v1/memories/add HTTP/1.1\r\nHost: x\r\n\r\n")
    assert _statuses(out) == [404]


# ---------------------------------------------------------------- C-9 request_id


def test_control_request_id_reuse_rules(svc):
    assert svc.add(_add(rid="x", ts=T0))["success"]
    assert svc.add(_add(rid="x", ts=T0 // 1000))["success"]  # same instant in seconds: identical payload
    for diff in [dict(text="other"), dict(ts=T0 + 1), dict(session_id="s2"), dict(messages=[{"content": "hello", "role": "assistant"}])]:
        with pytest.raises(ContractError) as exc:
            svc.add(_add(rid="x", **diff))
        assert exc.value.status == 409
    assert svc.add(_add(rid="x", user="someone-else", text="other"))["success"]  # per-user scope
    for rid in ["", 5, None, "  "]:
        with pytest.raises(ContractError) as exc:
            svc.add(_add(rid=rid))
        assert exc.value.status == 422
    assert svc.add(_add(rid="y" * 20000))["request_id"] == "y" * 20000


# ---------------------------------------------------------------- S-1 connection accounting


def test_control_connection_permits_are_returned_after_500_and_idle_close(http_server):
    cap = http_server.config.max_connections
    for _ in range(cap + 1):
        assert _statuses(_raw(http_server, _post("/add", _add(ts=10**400)))) == [500]
    idle = [socket.create_connection(("127.0.0.1", http_server.server_address[1])) for _ in range(cap)]
    try:
        time.sleep(0.2)
        extra = socket.create_connection(("127.0.0.1", http_server.server_address[1]))
        extra.settimeout(2)
        assert extra.recv(200).startswith(b"HTTP/1.1 503")
        extra.close()
    finally:
        for s in idle:
            s.close()
    time.sleep(0.3)
    assert http_server.connections._value == cap
    assert _statuses(_raw(http_server, _post("/search", {"user_id": "u", "query": "x"}))) == [200]


# ---------------------------------------------------------------- C-4 / S-2 / S-4 retention


def _age(path: Path, seconds: float) -> None:
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        if p.exists():
            old = time.time() - seconds
            os.utime(p, (old, old))


def test_control_retention_edge_cases(svc):
    svc.add(_add(user="old"))
    svc.add(_add(user="future"))
    svc.pool.close_all()
    old, future = svc.pool.path_for("old"), svc.pool.path_for("future")
    _age(old, 40 * 86400)
    ahead = time.time() + 3600
    os.utime(future, (ahead, ahead))
    link = svc.pool.data_dir / ("f" * 32 + ".kib")
    link.symlink_to(old)
    unreadable = svc.pool.data_dir / ("e" * 32 + ".kib")
    unreadable.write_bytes(b"SQLite format 3\x00" + b"\0" * 4080)
    _age(unreadable, 40 * 86400)
    unreadable.chmod(0)
    try:
        removed = svc.pool.purge_idle(28 * 86400)
    finally:
        unreadable.chmod(0o600)
    assert removed == 1 and not old.exists() and future.exists() and link.is_symlink() and unreadable.exists()
    # a vault whose slot is held (a request creating it right now) is skipped even if its file looks idle
    with svc.pool.use("held", create=True):
        _age(svc.pool.path_for("held"), 40 * 86400)
        assert svc.pool.purge_idle(28 * 86400) == 0
    assert svc.pool.path_for("held").exists()


def test_attack_retention_never_deletes_in_the_no_sqlcipher_fallback(tmp_path, monkeypatch):
    """With a passphrase but no sqlcipher3 (the mode S-4's startup warning describes, reachable with
    KIBISIS_ALLOW_PLAINTEXT=1), vault files are plain SQLite, but ``is_vault_file`` is called with
    ``encrypted=self.passphrase is not None`` and so rejects every file: retention silently deletes
    nothing and ``--retention-days`` is a dead letter. Passing = bug."""
    import kibisis.vault as kv

    monkeypatch.setattr(kv, "sqlcipher3", sqlite3)  # what a host without the driver sees
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    assert not kv._sqlcipher_available()
    service = AMLService(_config(tmp_path, retention_days=1))
    try:
        assert service.add(_add())["success"]
        path = service.pool.path_for("u")
        service.pool.close_all()
        assert path.read_bytes().startswith(b"SQLite format 3")
        _age(path, 10 * 86400)
        assert service.pool.purge_idle(86400) == 0 and path.exists()
    finally:
        service.pool.close_all()


def test_attack_no_sqlcipher_without_opt_in_makes_every_request_500(tmp_path, monkeypatch):
    """Same host, without KIBISIS_ALLOW_PLAINTEXT: the vault constructor refuses (area B), so every Add
    is an EncryptionRequiredError -> 500, while the startup warning says the server runs with sealed
    content and plain metadata. The warning text overstates; the server is down, not degraded."""
    import kibisis.vault as kv
    from kibisis.protocols import EncryptionRequiredError

    monkeypatch.setattr(kv, "sqlcipher3", sqlite3)
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT", raising=False)
    service = AMLService(_config(tmp_path))
    try:
        with pytest.raises(EncryptionRequiredError):
            service.add(_add())
    finally:
        service.pool.close_all()


# ---------------------------------------------------------------- regressions: ordinary flows


def test_control_add_search_health_round_trip(http_server):
    out = _raw(http_server, _post("/v1/memories/add", _add(text="the capital of France is Paris")))
    assert _statuses(out) == [200]
    out = _raw(http_server, _post("/v1/memories/search", {"user_id": "u", "query": "capital of France", "top_k": 3}))
    assert _statuses(out) == [200]
    data = json.loads(out.split(b"\r\n\r\n", 1)[1])["data"]
    assert data and "Paris" in data[0]["content"] and data[0]["created_at"] == "2024-01-01T00:00:00Z"
    out = _raw(http_server, b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert _statuses(out) == [200] and b'"status":"ok"' in out
