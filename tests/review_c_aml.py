"""Review C (alpha.16, commit 1299c28): AML adapter defects and positive controls.

Every test says in its docstring whether a PASS demonstrates a defect ("passing = bug") or asserts the
correct behaviour ("failing = bug"; these are positive controls). Servers bind 127.0.0.1 on an ephemeral
port in-process and are shut down in the fixture's finally block. Only ordinary http.client requests.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import re
import threading
import time
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from kibisis.aml_adapter import AMLConfig, AMLHandler, AMLService, ContractError, VaultPool, key_digest, run_server

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


@pytest.fixture
def http_server(tmp_path):
    started = threading.Event()
    holder = {}

    def ready(server):
        holder["server"] = server
        started.set()

    config = _config(tmp_path, max_inflight=4, retention_days=0)
    config.max_body_bytes = 4096
    thread = threading.Thread(target=run_server, args=(config,), kwargs={"host": "127.0.0.1", "port": 0, "ready": ready},
                              daemon=True)
    thread.start()
    assert started.wait(10)
    server = holder["server"]
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


# ---------------------------------------------------------------- A.1 finding: a stored timestamp breaks Search


def test_add_accepts_an_out_of_range_timestamp_then_every_search_for_that_user_is_500(http_server):
    """passing = bug. aml_adapter._timestamp_ms (l.133) bounds nothing; Add stores t=1e17 ms and returns 200.
    Search renders created_at through datetime.fromtimestamp (_iso/_stamp, l.165-174), which raises
    ValueError('year ... is out of range') -> do_POST's generic except -> 500 'internal error'. The user's
    vault is poisoned: every later Search whose hits include that group is a 500."""
    status, _, body = _call(http_server, "POST", "/v1/memories/add", _add_body("r-big", "u-big", "the parrot is green", ts=10**17), AUTH)
    assert status == 200 and body["success"] is True
    status, _, body = _call(http_server, "POST", "/v1/memories/search", {"query": "parrot", "user_id": "u-big"}, AUTH)
    assert status == 500 and body == {"error": "internal error"}
    # The same message with a sane timestamp is fine (positive control).
    status, _, _ = _call(http_server, "POST", "/v1/memories/add", _add_body("r-ok", "u-ok", "the parrot is green"), AUTH)
    assert status == 200
    status, _, body = _call(http_server, "POST", "/v1/memories/search", {"query": "parrot", "user_id": "u-ok"}, AUTH)
    assert status == 200 and len(body["data"]) == 1


def test_json_infinity_or_nan_timestamp_is_500_not_422(http_server):
    """passing = bug. Python's json.loads accepts the non-standard literals Infinity/NaN; _timestamp_ms then
    calls int(inf) (OverflowError) / int(nan) (ValueError), neither a ContractError, so the client gets 500 and
    the connection is closed instead of a 422 naming the field."""
    for literal in ("Infinity", "NaN", "1e400"):
        raw = ('{"request_id":"r-%s","user_id":"u-inf","session_id":"s",'
               '"messages":[{"role":"user","timestamp":%s,"content":"hello world"}]}' % (literal, literal)).encode()
        status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=raw, headers=AUTH)
        assert status == 500 and body == {"error": "internal error"}, literal
    # A string timestamp that is not a timestamp gets the contract's 422 (positive control).
    status, _, body = _call(http_server, "POST", "/v1/memories/add", _add_body("r-str", "u-inf", "hello", ts="yesterday"), AUTH)
    assert status == 422 and "timestamp" in body["error"]


def test_small_millisecond_timestamps_are_silently_read_as_seconds(svc):
    """passing = bug (low). _timestamp_ms l.141 treats any |value| < 1e11 as seconds, so a contract-conform
    millisecond timestamp before 1973-03-03 (e.g. 5e9 ms = 1970-02-27) is multiplied by 1000 and the memory
    is dated 2128."""
    svc.add(_add_body("r", "u", "kite flying", ts=5_000_000_000))
    (hit,) = svc.search({"query": "kite", "user_id": "u"})["data"]
    assert hit["created_at"].startswith("2128-")


def test_a_lone_surrogate_escape_in_content_is_500(http_server):
    """passing = bug. '\\udc80' is valid JSON text but not valid Unicode; json.loads accepts it, SQLite's
    UTF-8 encoding of the bound parameter raises UnicodeEncodeError inside the write transaction, and the
    client gets 500 'internal error' instead of a 4xx."""
    raw = ('{"request_id":"r-sur","user_id":"u-sur","session_id":"s",'
           '"messages":[{"role":"user","content":"bad \\udc80 text"}]}').encode()
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=raw, headers=AUTH)
    assert status == 500 and body == {"error": "internal error"}


# ---------------------------------------------------------------- A.7 idempotency


def test_reused_request_id_with_a_different_payload_is_acknowledged_and_silently_dropped(svc):
    """passing = bug (low). The idempotency marker (REQUEST_CATEGORY row keyed on the request_id digest,
    l.322-334) stores nothing about the payload, so a second Add that reuses a request_id with different
    messages returns success:true and writes nothing; the caller cannot tell its data was discarded."""
    assert svc.add(_add_body("dup", "u", "first payload about ducks"))["success"] is True
    assert svc.add(_add_body("dup", "u", "second payload about geese"))["success"] is True
    assert len(svc.search({"query": "ducks", "user_id": "u"})["data"]) == 1
    assert svc.search({"query": "geese", "user_id": "u"})["data"] == []


def test_request_ids_are_scoped_per_user(svc):
    """failing = bug (positive control). The marker lives in the user's own vault, so the same request_id
    from another user_id is a fresh request, and the first user's stored data is not returned."""
    svc.add(_add_body("same", "alice", "alice keeps bees"))
    out = svc.add(_add_body("same", "bob", "bob keeps goats"))
    assert out["user_id"] == "bob"
    assert len(svc.search({"query": "goats", "user_id": "bob"})["data"]) == 1
    assert svc.search({"query": "bees", "user_id": "bob"})["data"] == []


# ---------------------------------------------------------------- A.6 retention


def test_retention_deletes_any_kib_file_in_the_data_dir_and_dies_on_a_kib_directory(svc):
    """passing = bug. purge_idle (l.260-285) selects by glob '*.kib' + mtime, so a decoy that is not a vault
    (notes.kib) is unlinked; and a directory named *.kib raises IsADirectoryError out of purge_idle (only
    FileNotFoundError is caught, l.281-283), which would kill the 'aml-retention' thread (l.622-633) or
    abort run_server at startup (l.629-632)."""
    svc.add(_add_body("r", "live-user", "fresh memory about kites"))
    data_dir = Path(svc.config.data_dir)
    past = time.time() - 40 * 86400
    decoy = data_dir / "notes.kib"
    decoy.write_text("operator notes, not a vault")
    os.utime(decoy, (past, past))
    assert svc.pool.purge_idle(28 * 86400) == 1
    assert not decoy.exists()
    assert svc.search({"query": "kites", "user_id": "live-user"})["data"]  # the live vault survived
    stray = data_dir / "stray.kib"
    stray.mkdir()
    os.utime(stray, (past, past))
    with pytest.raises(IsADirectoryError):
        svc.pool.purge_idle(28 * 86400)


def test_retention_counts_writes_only_so_a_read_only_user_is_purged(svc):
    """passing = bug (low, documented as 'no write' in --help but as 'idle' in the module docstring l.29).
    Search does not touch the file's mtime, so a user whose vault is only searched is deleted on schedule."""
    svc.add(_add_body("r", "reader", "memory about kites"))
    path = svc.pool.path_for("reader")
    svc.pool.close_all()
    past = time.time() - 40 * 86400
    for suffix in ("", "-wal", "-shm"):
        f = Path(f"{path}{suffix}")
        if f.exists():
            os.utime(f, (past, past))
    assert svc.search({"query": "kites", "user_id": "reader"})["data"]  # a read, just now
    svc.pool.close_all()
    assert svc.pool.purge_idle(28 * 86400) == 1
    assert not path.exists()


# ---------------------------------------------------------------- A.3 body handling


def test_chunked_body_with_a_negative_chunk_size_reads_unbounded_past_the_cap(tmp_path):
    """passing = bug. _read_body (l.501-518) parses the chunk size with int(..., 16), which accepts '-1';
    the cap check 'len(out) + size > limit' is then false and rfile.read(-1) reads to EOF: on a socket that
    blocks until the client closes and buffers everything it sends, however large. Exercised in-process on a
    recording stream (no sockets): the handler asks for a negative read and consumes 4x the cap before failing."""
    limit = 16
    body = b"X" * (4 * limit)

    class Recording(io.BytesIO):
        sizes: list = []

        def read(self, n=-1):
            self.sizes.append(n)
            return super().read(n)

    handler = AMLHandler.__new__(AMLHandler)
    handler.server = SimpleNamespace(config=AMLConfig(data_dir=str(tmp_path), key_sha256=key_digest(KEY), max_body_bytes=limit))
    handler.close_connection = False
    headers = Message()
    headers["Transfer-Encoding"] = "chunked"
    handler.headers = headers
    stream = Recording(b"-1\r\n" + body + b"\r\n0\r\n\r\n")
    handler.rfile = stream
    with pytest.raises(ContractError) as exc:  # only after EOF, with everything consumed
        handler._read_body()
    assert exc.value.status == 400
    assert -1 in Recording.sizes
    assert stream.tell() > limit


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


# ---------------------------------------------------------------- A.2 user_id -> path (positive control)


@pytest.mark.parametrize("user_id", ["../../etc/passwd", "/abs/path", "a\u0000b", "x" * 5000, "vault.kib-wal", ".", "..", " ~ "],
                         ids=["dotdot", "absolute", "nul", "5000-chars", "sidecar-like", "dot", "dotdot-only", "tilde"])
def test_user_id_to_vault_path_stays_inside_the_data_dir(svc, user_id):
    """failing = bug (positive control). path_for (l.201) is data_dir / sha256(user_id)[:32] + '.kib', so
    traversal, absolute, NUL, long and sidecar-like names all map to a 32-hex-digit file in the data dir."""
    path = svc.pool.path_for(user_id)
    assert path.parent == Path(svc.config.data_dir)
    assert re.fullmatch(r"[0-9a-f]{32}\.kib", path.name)
    assert svc.add(_add_body("r", user_id, "hello world"))["success"] is True
    assert path.exists()
    assert {p.name for p in path.parent.iterdir()} <= {path.name, path.name + "-wal", path.name + "-shm"}


# ---------------------------------------------------------------- A.8 error responses


def test_a_large_body_refused_with_401_or_404_reaches_the_client_as_a_broken_pipe(http_server):
    """passing = bug. do_POST sends 401/404 before reading the body and sets close_connection (l.570-577)
    but, unlike the 413/429 paths (l.582, l.598-599; CHANGELOG alpha.15 'reads and drops the body'), does not
    drain it. With a body larger than the socket buffers the close resets the connection and the client sees
    BrokenPipe/ConnectionReset instead of the 401 — a client with a rotated key cannot tell auth from outage.
    One ordinary 8 MiB request (the default cap is 64 MiB); auth runs before the body cap, so the fixture's
    small cap is irrelevant."""
    big = json.dumps(_add_body("r-big", "u-big", "x" * (8 * 1024 * 1024))).encode()
    for path, headers in (("/v1/memories/add", {"Authorization": "Token wrong-key"}), ("/v1/nope", AUTH)):
        with pytest.raises((BrokenPipeError, ConnectionResetError)):
            _call(http_server, "POST", path, raw=big, headers=headers)
    # The same refusal with a small body is a clean 401/404 (positive control).
    small = json.dumps(_add_body("r", "u", "x")).encode()
    assert _call(http_server, "POST", "/v1/memories/add", raw=small, headers={"Authorization": "Token wrong-key"})[0] == 401
    assert _call(http_server, "POST", "/v1/nope", raw=small, headers=AUTH)[0] == 404


def test_error_bodies_carry_no_traceback_or_path_and_unknown_routes_answer_before_auth(http_server):
    """failing = bug for the leak checks (positive control); the last assertion documents that 404 is sent
    before the credential is checked (l.570-577), so route existence is visible without a key (low)."""
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=b"{not json", headers=AUTH)
    assert status == 400 and body == {"error": "body is not valid UTF-8 JSON"}
    status, _, body = _call(http_server, "POST", "/v1/memories/add", raw=b"[1, 2]", headers=AUTH)
    assert status == 422 and body == {"error": "body must be a JSON object"}
    for text in (json.dumps(body),):
        assert "Traceback" not in text and "/" not in text.replace("UTF-8", "")
    status, _, body = _call(http_server, "POST", "/v1/nope", {"a": 1})  # no credentials
    assert status == 404 and body == {"error": "not found"}
    status, _, body = _call(http_server, "POST", "/v1/memories/add", {"a": 1})  # no credentials, real route
    assert status == 401


def test_bearer_scheme_is_case_insensitive_and_x_api_key_works(http_server):
    """failing = bug (positive control for A.1 header parsing, l.487-497)."""
    for headers in ({"Authorization": f"bearer {KEY}"}, {"Authorization": f"TOKEN   {KEY}  "}, {"X-Api-Key": KEY}):
        status, _, _ = _call(http_server, "POST", "/v1/memories/search", {"query": "q", "user_id": "u"}, headers)
        assert status == 200, headers
    for headers in ({"Authorization": f"Basic {KEY}"}, {"Authorization": "Bearer"}, {"X-Api-Key": KEY[:-1]}):
        status, _, _ = _call(http_server, "POST", "/v1/memories/search", {"query": "q", "user_id": "u"}, headers)
        assert status == 401, headers
