"""Review C (alpha.16): AML adapter regression tests.

Each test that used to demonstrate a defect ("passing = bug") now asserts the fixed behaviour; the
positive controls are kept. Servers bind 127.0.0.1 on an ephemeral port in-process and are shut down in
the fixture's finally block. Only ordinary http.client requests, plus one deliberately stalled socket.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import re
import socket
import threading
import time
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from kibisis.aml_adapter import (
    MS_FLOOR,
    SECONDS_CEILING,
    SECONDS_FLOOR,
    AMLConfig,
    AMLHandler,
    AMLService,
    ContractError,
    VaultPool,
    key_digest,
    run_server,
)

KEY = "review-c-throwaway-key-0123456789"
PASSPHRASE = "review-c-passphrase-not-secret"
T0 = 1_704_067_200_000  # 2024-01-01T00:00:00Z
AUTH = {"Authorization": f"Token {KEY}"}


def _config(tmp_path: Path, **kw) -> AMLConfig:
    kw.setdefault("passphrase", PASSPHRASE)
    return AMLConfig(data_dir=str(tmp_path / "vaults"), key_sha256=key_digest(KEY), **kw)


@pytest.fixture
def svc(tmp_path):
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

    thread = threading.Thread(target=run_server, args=(config,), kwargs={"host": "127.0.0.1", "port": 0, "ready": ready},
                              daemon=True)
    thread.start()
    assert started.wait(10)
    return holder["server"], thread


@pytest.fixture
def http_server(tmp_path):
    config = _config(tmp_path, max_inflight=4, retention_days=0)
    config.max_body_bytes = 4096
    server, thread = _serve(config)
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(10)


@pytest.fixture
def quick_timeout_server(tmp_path):
    """A server whose connections time out after 1 s, for the stalled-connection tests."""
    config = _config(tmp_path, max_inflight=4, retention_days=0, socket_timeout=1.0, max_connections=8)
    server, thread = _serve(config)
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(10)


def _call(server, method, path, body=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    try:
        payload = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict(resp.getheaders()), (json.loads(data) if data else {})
    finally:
        conn.close()


def _add_body(rid, user, text, ts=T0):
    return {"request_id": rid, "user_id": user, "session_id": "s",
            "messages": [{"role": "user", "timestamp": ts, "content": text}]}


# ---------------------------------------------------------------- C-1 timestamps are validated at Add


def test_out_of_range_timestamp_is_422_at_add_and_never_poisons_search(http_server):
    """C-1: a timestamp that cannot become a datetime is refused with 422 naming the field, so no stored
    row can make a later Search 500. The same message with a sane timestamp is stored and found."""
    status, _, body = _call(http_server, "POST", "/v1/memories/add", _add_body("r-big", "u-big", "the parrot is green", ts=10**17), AUTH)
    assert status == 422 and "messages[0].timestamp" in body["error"]
    status, _, body = _call(http_server, "POST", "/v1/memories/search", {"query": "parrot", "user_id": "u-big"}, AUTH)
    assert status == 200 and body["data"] == []
    status, _, _ = _call(http_server, "POST", "/v1/memories/add", _add_body("r-ok", "u-ok", "the parrot is green"), AUTH)
    assert status == 200
    status, _, body = _call(http_server, "POST", "/v1/memories/search", {"query": "parrot", "user_id": "u-ok"}, AUTH)
    assert status == 200 and len(body["data"]) == 1 and body["data"][0]["created_at"] == "2024-01-01T00:00:00Z"


def test_search_skips_a_stored_row_it_cannot_render(svc):
    """C-1 (defence in depth): a row written by an older adapter with an unrenderable timestamp is returned
    with no date rather than a 500, and a row with unusable metadata is skipped; the user's other rows are
    still returned."""
    svc.add(_add_body("r-good", "u", "kites in the sky"))
    with svc.pool.use("u", create=True) as vault:
        vault.put("aml_message", "deadbeef:00000", "kites on the ground", scope="aml", epistemic_state="candidate",
                  origin="import", metadata={"r": "deadbeef", "i": 0, "t": 10**17, "role": "user"})
        vault.put("aml_message", "nometa:00000", "kites in a box", scope="aml", epistemic_state="candidate",
                  origin="import", metadata={"r": 7, "i": "zero"})
    out = svc.search({"query": "kites", "user_id": "u"})["data"]
    texts = "\n".join(hit["content"] for hit in out)
    assert "kites in the sky" in texts and "kites on the ground" in texts and "kites in a box" not in texts
    assert all(hit.get("created_at", "2024-").startswith("2024-") for hit in out)


# ---------------------------------------------------------------- C-7 / C-8 / C-10 JSON numbers and strings


def test_json_infinity_nan_or_overflow_is_400_not_500(http_server):
    """C-7: the non-standard literals Infinity/NaN and an overflowing float are refused when the body is
    parsed (400), not after a crash in the service (500 + closed connection)."""
    for literal in ("Infinity", "NaN", "-Infinity", "1e400"):
        raw = ('{"request_id":"r-%s","user_id":"u-inf","session_id":"s",'
               '"messages":[{"role":"user","timestamp":%s,"content":"hello world"}]}' % (literal, literal)).encode()
        status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=raw, headers=AUTH)
        assert status == 400 and body == {"error": "body is not valid UTF-8 JSON"}, literal
    status, _, body = _call(http_server, "POST", "/v1/memories/add", _add_body("r-str", "u-inf", "hello", ts="yesterday"), AUTH)
    assert status == 422 and "timestamp" in body["error"]


@pytest.mark.parametrize("value", [5_000_000_000, 99_999_999_999, 999_999_999, 10_000_000_000, 50_000_000_000, -T0, 0, True])
def test_ambiguous_numeric_timestamps_are_422(svc, value):
    """C-10: the ms-vs-seconds rule is bounded. Values that are neither a millisecond count >= MS_FLOOR nor a
    second count in [SECONDS_FLOOR, SECONDS_CEILING) are refused instead of being silently rescaled."""
    with pytest.raises(ContractError) as exc:
        svc.add(_add_body("r", "u", "kite flying", ts=value))
    assert exc.value.status == 422 and "messages[0].timestamp" in exc.value.message


def test_timestamp_forms_that_are_accepted(svc):
    """Positive control for C-10: milliseconds, seconds in the documented window and ISO 8601 all land on
    the same instant; the bounds are the documented constants."""
    assert (MS_FLOOR, SECONDS_FLOOR, SECONDS_CEILING) == (10**11, 10**9, 4 * 10**9)
    for n, ts in enumerate((T0, T0 // 1000, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00+00:00", "2024-01-01")):
        svc.add(_add_body(f"r{n}", "u", f"kite number {n}", ts=ts))
    hits = svc.search({"query": "kite", "user_id": "u"})["data"]
    assert len(hits) == 5 and {hit["created_at"] for hit in hits} == {"2024-01-01T00:00:00Z"}


def test_a_lone_surrogate_in_the_body_is_400(http_server):
    """C-8: '\\udc80' is valid JSON text but not valid Unicode; it is refused at parse time, before any
    write transaction, instead of failing inside SQLite with a 500."""
    raw = ('{"request_id":"r-sur","user_id":"u-sur","session_id":"s",'
           '"messages":[{"role":"user","content":"bad \\udc80 text"}]}').encode()
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=raw, headers=AUTH)
    assert status == 400 and "surrogate" in body["error"]
    raw = ('{"request_id":"r-sur","user_id":"u-\\ud800","session_id":"s",'
           '"messages":[{"role":"user","content":"ok"}]}').encode()
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=raw, headers=AUTH)
    assert status == 400 and "surrogate" in body["error"]
    # Properly paired surrogates (an astral character) are ordinary text (positive control).
    raw = ('{"request_id":"r-pair","user_id":"u-sur","session_id":"s",'
           '"messages":[{"role":"user","content":"a kite \\ud83e\\ude81 flies"}]}').encode()
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=raw, headers=AUTH)
    assert status == 200


# ---------------------------------------------------------------- C-9 idempotency


def test_reused_request_id_with_a_different_payload_is_409(svc):
    """C-9: the marker stores a digest of the payload; a second Add under the same request_id with other
    messages is refused with a stable 409 body, so the caller knows its data was not written."""
    assert svc.add(_add_body("dup", "u", "first payload about ducks"))["success"] is True
    with pytest.raises(ContractError) as exc:
        svc.add(_add_body("dup", "u", "second payload about geese"))
    assert exc.value.status == 409 and exc.value.message == "request_id was already used with a different payload"
    with pytest.raises(ContractError) as exc2:
        svc.add(_add_body("dup", "u", "second payload about geese"))
    assert exc2.value.message == exc.value.message
    assert len(svc.search({"query": "ducks", "user_id": "u"})["data"]) == 1
    assert svc.search({"query": "geese", "user_id": "u"})["data"] == []


def test_identical_retry_is_idempotent(svc):
    """Positive control for C-9: the same request_id with the same payload is acknowledged and stored once."""
    for _ in range(3):
        assert svc.add(_add_body("same", "u", "a memory about ducks"))["success"] is True
    assert len(svc.search({"query": "ducks", "user_id": "u"})["data"]) == 1


def test_request_ids_are_scoped_per_user(svc):
    """failing = bug (positive control). The marker lives in the user's own vault, so the same request_id
    from another user_id is a fresh request, and the first user's stored data is not returned."""
    svc.add(_add_body("same", "alice", "alice keeps bees"))
    out = svc.add(_add_body("same", "bob", "bob keeps goats"))
    assert out["user_id"] == "bob"
    assert len(svc.search({"query": "goats", "user_id": "bob"})["data"]) == 1
    assert svc.search({"query": "bees", "user_id": "bob"})["data"] == []


# ---------------------------------------------------------------- C-4 / S-2 retention


def _age(path: Path, seconds: float) -> None:
    past = time.time() - seconds
    for suffix in ("", "-wal", "-shm"):
        f = Path(f"{path}{suffix}")
        if f.exists():
            os.utime(f, (past, past))


def test_retention_deletes_only_idle_vault_files(svc):
    """C-4: a decoy that is not a vault, a directory named *.kib and a symlink are never deleted; a
    directory does not raise out of purge_idle; the live vault survives and the idle real vault goes."""
    svc.add(_add_body("r", "live-user", "fresh memory about kites"))
    svc.add(_add_body("r", "idle-user", "old memory about kites"))
    idle = svc.pool.path_for("idle-user")
    svc.pool.close_all()
    _age(idle, 40 * 86400)
    data_dir = Path(svc.config.data_dir)
    decoy = data_dir / "notes.kib"
    decoy.write_text("operator notes, not a vault")
    _age(decoy, 40 * 86400)
    hexname = data_dir / ("0" * 32 + ".kib")
    hexname.write_bytes(b"not a database" * 100)
    _age(hexname, 40 * 86400)
    stray = data_dir / "stray.kib"
    stray.mkdir()
    _age(stray, 40 * 86400)
    link = data_dir / ("f" * 32 + ".kib")
    link.symlink_to(decoy)
    assert svc.pool.purge_idle(28 * 86400) == 1
    assert not idle.exists() and decoy.exists() and hexname.exists() and stray.is_dir() and link.is_symlink()
    assert svc.search({"query": "kites", "user_id": "live-user"})["data"]  # the live vault survived


def test_retention_skips_a_vault_whose_slot_is_in_use(svc):
    """S-2: the mtime check and the unlink happen under the pool lock, and a vault with a user inside its
    slot is skipped even if its file looks idle."""
    svc.add(_add_body("r", "busy", "memory about kites"))
    path = svc.pool.path_for("busy")
    with svc.pool.use("busy", create=False):
        _age(path, 40 * 86400)
        assert svc.pool.purge_idle(28 * 86400) == 0
        assert path.exists()
    svc.pool.close_all()  # closing checkpoints the WAL and touches the file
    _age(path, 40 * 86400)
    assert svc.pool.purge_idle(28 * 86400) == 1
    assert not path.exists()


def test_retention_counts_reads_as_activity(svc):
    """C-4: a Search touches the vault's mtime, so a user whose vault is only read is not purged."""
    svc.add(_add_body("r", "reader", "memory about kites"))
    path = svc.pool.path_for("reader")
    svc.pool.close_all()
    _age(path, 40 * 86400)
    assert svc.search({"query": "kites", "user_id": "reader"})["data"]  # a read, just now
    svc.pool.close_all()
    assert svc.pool.purge_idle(28 * 86400) == 0
    assert path.exists()


def test_is_vault_file_follows_the_pool_mode(tmp_path):
    """C-4: in a SQLCipher pool a plain-SQLite header is not a vault of this pool, and vice versa."""
    hexname = tmp_path / ("a" * 32 + ".kib")
    hexname.write_bytes(b"SQLite format 3\x00" + b"\x00" * (4096 - 16))
    assert VaultPool.is_vault_file(hexname, encrypted=False)
    assert not VaultPool.is_vault_file(hexname, encrypted=True)
    hexname.write_bytes(os.urandom(4096))
    assert VaultPool.is_vault_file(hexname, encrypted=True)
    assert not VaultPool.is_vault_file(hexname, encrypted=False)
    hexname.write_bytes(os.urandom(100))  # not page-sized
    assert not VaultPool.is_vault_file(hexname, encrypted=True)


# ---------------------------------------------------------------- C-2 body handling


def _handler(tmp_path, limit, stream, **headers):
    handler = AMLHandler.__new__(AMLHandler)
    handler.server = SimpleNamespace(config=AMLConfig(data_dir=str(tmp_path), key_sha256=key_digest(KEY), max_body_bytes=limit))
    handler.close_connection = False
    message = Message()
    for name, value in headers.items():
        message[name.replace("_", "-")] = value
    handler.headers = message
    handler.rfile = stream
    return handler


@pytest.mark.parametrize("size_line", [b"-1", b"+5", b"0x10", b"", b"1" * 17, b"g"])
def test_chunked_body_with_an_invalid_chunk_size_is_400_and_reads_nothing_past_it(tmp_path, size_line):
    """C-2: the chunk-size line must be 1..16 hex digits; '-1' used to pass int(.., 16), defeat the cap and
    turn into rfile.read(-1). Now it is 400 with the connection marked for close and no body bytes consumed."""
    limit = 16
    body = b"X" * (4 * limit)

    class Recording(io.BytesIO):
        sizes: list = []

        def read(self, n=-1):
            self.sizes.append(n)
            return super().read(n)

    Recording.sizes = []
    stream = Recording(size_line + b"\r\n" + body + b"\r\n0\r\n\r\n")
    handler = _handler(tmp_path, limit, stream, Transfer_Encoding="chunked")
    with pytest.raises(ContractError) as exc:
        handler._read_body()
    assert exc.value.status == 400 and handler.close_connection is True
    assert -1 not in Recording.sizes
    assert stream.tell() <= len(size_line) + 2


def test_chunked_body_is_capped_before_every_chunk(tmp_path):
    """C-2: the running total plus the next chunk size is checked against max_body_bytes before the chunk is
    read, so a chunked body never exceeds the cap; a well-formed one under the cap is assembled."""
    stream = io.BytesIO(b"8\r\nABCDEFGH\r\n9\r\nIJKLMNOPQ\r\n0\r\n\r\n")
    handler = _handler(tmp_path, 16, stream, Transfer_Encoding="chunked")
    with pytest.raises(ContractError) as exc:
        handler._read_body()
    assert exc.value.status == 413 and stream.tell() == len(b"8\r\nABCDEFGH\r\n9\r\n")
    stream = io.BytesIO(b"8;ext=1\r\nABCDEFGH\r\n4\r\nIJKL\r\n0\r\nTrailer: x\r\n\r\n")
    assert _handler(tmp_path, 16, stream, Transfer_Encoding="chunked")._read_body() == b"ABCDEFGHIJKL"
    stream = io.BytesIO(b"8\r\nABC")  # the client went away mid-chunk
    with pytest.raises(ContractError) as exc:
        _handler(tmp_path, 16, stream, Transfer_Encoding="chunked")._read_body()
    assert exc.value.status == 400


def test_content_length_must_be_digits(tmp_path):
    """C-2: a signed or non-numeric Content-Length is 400; a plain one over the cap is 413."""
    for value in ("-5", "+5", "0x10", "abc", "1" * 19):
        with pytest.raises(ContractError) as exc:
            _handler(tmp_path, 16, io.BytesIO(b""), Content_Length=value)._read_body()
        assert exc.value.status == 400, value
    with pytest.raises(ContractError) as exc:
        _handler(tmp_path, 16, io.BytesIO(b"x" * 17), Content_Length="17")._read_body()
    assert exc.value.status == 413
    assert _handler(tmp_path, 16, io.BytesIO(b"x" * 16), Content_Length="16")._read_body() == b"x" * 16


def test_a_body_one_byte_over_the_cap_is_413(http_server):
    """failing = bug (positive control). Content-Length one over max_body_bytes -> 413, under -> 200."""
    cap = http_server.config.max_body_bytes
    base = _add_body("r-cap", "u-cap", "")
    pad = cap - len(json.dumps(base).encode())
    exact = dict(base); exact["messages"][0]["content"] = "x" * pad
    assert len(json.dumps(exact).encode()) == cap
    status, _, _ = _call(http_server, "POST", "/v1/memories/add", exact, AUTH)
    assert status == 200
    over = json.dumps(exact).encode() + b" "
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=over, headers=AUTH)
    assert status == 413 and "exceeds" in body["error"]


# ---------------------------------------------------------------- user_id -> path (positive control)


@pytest.mark.parametrize("user_id", ["../../etc/passwd", "/abs/path", "a\u0000b", "x" * 5000, "vault.kib-wal", ".", "..", " ~ "],
                         ids=["dotdot", "absolute", "nul", "5000-chars", "sidecar-like", "dot", "dotdot-only", "tilde"])
def test_user_id_to_vault_path_stays_inside_the_data_dir(svc, user_id):
    """failing = bug (positive control). path_for is data_dir / sha256(user_id)[:32] + '.kib', so
    traversal, absolute, NUL, long and sidecar-like names all map to a 32-hex-digit file in the data dir."""
    path = svc.pool.path_for(user_id)
    assert path.parent == Path(svc.config.data_dir)
    assert re.fullmatch(r"[0-9a-f]{32}\.kib", path.name)
    assert svc.add(_add_body("r", user_id, "hello world"))["success"] is True
    assert path.exists()
    assert {p.name for p in path.parent.iterdir()} <= {path.name, path.name + "-wal", path.name + "-shm"}


# ---------------------------------------------------------------- C-3 / C-12 error responses


def test_a_large_body_refused_with_401_or_404_reaches_the_client(http_server):
    """C-3: 401 and 404 are sent before the body is read; the handler now drains the declared body (as 413
    and 429 already did) so the client reads the reply instead of a connection reset. One ordinary 8 MiB
    request; auth runs before the body cap, so the fixture's small cap is irrelevant."""
    big = json.dumps(_add_body("r-big", "u-big", "x" * (8 * 1024 * 1024))).encode()
    status, headers, body = _call(http_server, "POST", "/v1/memories/add", raw=big, headers={"Authorization": "Token wrong-key"})
    assert status == 401 and body == {"error": "invalid or missing credentials"} and headers.get("Connection") == "close"
    status, headers, body = _call(http_server, "POST", "/v1/nope", raw=big, headers=AUTH)
    assert status == 404 and body == {"error": "not found"} and headers.get("Connection") == "close"
    small = json.dumps(_add_body("r", "u", "x")).encode()
    assert _call(http_server, "POST", "/v1/memories/add", raw=small, headers={"Authorization": "Token wrong-key"})[0] == 401
    assert _call(http_server, "POST", "/v1/nope", raw=small, headers=AUTH)[0] == 404


def test_error_bodies_carry_no_traceback_or_path_and_auth_is_checked_before_routing(http_server):
    """Positive control for the leak checks; C-12/L8: without a credential every POST path is 401, so route
    existence is not visible to an unauthenticated client."""
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=b"{not json", headers=AUTH)
    assert status == 400 and body == {"error": "body is not valid UTF-8 JSON"}
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=b"[1, 2]", headers=AUTH)
    assert status == 422 and body == {"error": "body must be a JSON object"}
    for text in (json.dumps(body),):
        assert "Traceback" not in text and "/" not in text.replace("UTF-8", "")
    status, _, body = _call(http_server, "POST", "/v1/nope", {"a": 1})  # no credentials
    assert status == 401 and body == {"error": "invalid or missing credentials"}
    status, _, body = _call(http_server, "POST", "/v1/memories/add", {"a": 1})  # no credentials, real route
    assert status == 401 and body == {"error": "invalid or missing credentials"}
    status, _, body = _call(http_server, "POST", "/v1/nope", {"a": 1}, AUTH)  # with credentials: 404
    assert status == 404


def test_bearer_scheme_is_case_insensitive_and_x_api_key_works(http_server):
    """failing = bug (positive control for header parsing)."""
    for headers in ({"Authorization": f"bearer {KEY}"}, {"Authorization": f"TOKEN   {KEY}  "}, {"X-Api-Key": KEY}):
        status, _, _ = _call(http_server, "POST", "/v1/memories/search", {"query": "q", "user_id": "u"}, headers)
        assert status == 200, headers
    for headers in ({"Authorization": f"Basic {KEY}"}, {"Authorization": "Bearer"}, {"X-Api-Key": KEY[:-1]}):
        status, _, _ = _call(http_server, "POST", "/v1/memories/search", {"query": "q", "user_id": "u"}, headers)
        assert status == 401, headers


# ---------------------------------------------------------------- S-1 stalled connections


def _handler_threads() -> set:
    return {t.name for t in threading.enumerate() if t.name.startswith("Thread-")}


def test_a_stalled_connection_is_closed_after_the_socket_timeout(quick_timeout_server):
    """S-1: a client that sends part of a request and then nothing is cut off after socket_timeout; the
    handler thread ends and the server keeps answering. Under 5 s in total with socket_timeout=1."""
    port = quick_timeout_server.server_address[1]
    before = _handler_threads()
    stalled = socket.create_connection(("127.0.0.1", port), timeout=5)
    stalled.sendall(b"POST /v1/memories/add HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n")  # headers never end
    started = time.monotonic()
    try:
        data = stalled.recv(1024)  # the server closes (or answers 408) within the timeout
    except (ConnectionResetError, socket.timeout):
        data = b""
    elapsed = time.monotonic() - started
    assert elapsed < quick_timeout_server.config.socket_timeout + 2, elapsed
    assert data == b"" or data.startswith(b"HTTP/1.1 408")
    stalled.close()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and _handler_threads() - before:
        time.sleep(0.05)
    assert _handler_threads() - before == set()
    status, _, _ = _call(quick_timeout_server, "POST", "/v1/memories/search", {"query": "q", "user_id": "u"}, AUTH)
    assert status == 200


def test_a_stalled_body_is_408_after_the_socket_timeout(quick_timeout_server):
    """S-1: headers complete, body never arrives: 408 (or a close) within socket_timeout + 2 s."""
    port = quick_timeout_server.server_address[1]
    stalled = socket.create_connection(("127.0.0.1", port), timeout=5)
    stalled.sendall(("POST /v1/memories/add HTTP/1.1\r\nHost: x\r\nAuthorization: Token %s\r\n"
                     "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{" % KEY).encode())
    started = time.monotonic()
    try:
        data = stalled.recv(1024)
    except (ConnectionResetError, socket.timeout):
        data = b""
    assert time.monotonic() - started < quick_timeout_server.config.socket_timeout + 2
    assert data == b"" or data.startswith(b"HTTP/1.1 408")
    stalled.close()


def test_connections_over_max_connections_get_503(quick_timeout_server):
    """S-1: the connection cap is separate from max_inflight; a connection past it is answered 503 with
    Connection: close and Retry-After, and closed at once."""
    port = quick_timeout_server.server_address[1]
    held = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(quick_timeout_server.config.max_connections)]
    try:
        time.sleep(0.3)  # let the server accept them all
        extra = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            data = extra.recv(4096)
        except (ConnectionResetError, socket.timeout):
            data = b""
        assert data.startswith(b"HTTP/1.1 503") and b"Retry-After" in data, data
        extra.close()
    finally:
        for s in held:
            s.close()
    time.sleep(0.3)
    status, _, _ = _call(quick_timeout_server, "POST", "/v1/memories/search", {"query": "q", "user_id": "u"}, AUTH)
    assert status == 200


def test_config_rejects_bad_connection_limits(tmp_path):
    for kw in (dict(socket_timeout=0), dict(socket_timeout=-1), dict(max_connections=0)):
        with pytest.raises(ValueError):
            _config(tmp_path, **kw)
