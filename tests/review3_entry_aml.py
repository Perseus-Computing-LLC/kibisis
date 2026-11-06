"""R3 entry-point review: the AML HTTP adapter as a network client reaches it (not collected by
default; run by path). ``test_control_*`` = secure behaviour (failing = bug); ``test_attack_*`` =
defect demonstrated (passing = bug). Servers bind 127.0.0.1:0 and are shut down in ``finally``.
"""
from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from pathlib import Path

import pytest

from kibisis.aml_adapter import AMLConfig, AMLHandler, AMLService, key_digest, run_server

KEY = "review3-memory-system-key"
PASSPHRASE = "review3-aml-passphrase"
T0 = 1_704_067_200_000
AUTH = f"Authorization: Token {KEY}\r\n"


def _config(tmp_path: Path, **kw) -> AMLConfig:
    kw.setdefault("passphrase", PASSPHRASE)
    return AMLConfig(data_dir=str(tmp_path / "vaults"), key_sha256=key_digest(KEY), **kw)


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
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    config = _config(tmp_path, max_inflight=4, retention_days=0, socket_timeout=2.0, max_connections=4,
                     max_body_bytes=4096)
    server, thread = _serve(config)
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(10)


def _raw(server, data: bytes, read_timeout: float = 3.0) -> bytes:
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


def _req(method: str, path: str, payload=None, auth: bool = True, extra: str = "", body: bytes | None = None) -> bytes:
    if body is None:
        body = json.dumps(payload).encode() if payload is not None else b""
    head = (f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{AUTH if auth else ''}{extra}"
            f"Content-Length: {len(body)}\r\n\r\n")
    return head.encode() + body


def _statuses(out: bytes) -> list:
    return [int(m) for m in re.findall(rb"HTTP/1\.1 (\d{3})", out)]


def _add(rid="r1", user="u", text="hello world", ts=T0, **over):
    body = {"request_id": rid, "user_id": user, "session_id": "s",
            "messages": [{"role": "user", "timestamp": ts, "content": text}]}
    body.update(over)
    return body


# ------------------------------------------------------------------ auth before everything


@pytest.mark.parametrize("path", ["/add", "/v1/memories/add", "/search", "/nope", "/health", "/", "/add/../x"])
@pytest.mark.parametrize("extra", ["", "Expect: 100-continue\r\n"])
def test_control_unauthenticated_post_is_401_on_every_path_without_100(http_server, path, extra):
    out = _raw(http_server, _req("POST", path, _add(), auth=False, extra=extra))
    assert _statuses(out) == [401], out
    assert b"Traceback" not in out


@pytest.mark.parametrize("extra", ["", "Expect: 100-continue\r\n"])
def test_control_bad_key_is_401_and_a_known_path_with_the_key_is_404_before_the_body(http_server, extra):
    bad = "Authorization: Bearer not-the-key\r\n"
    out = _raw(http_server, _req("POST", "/add", _add(), auth=False, extra=bad + extra))
    assert _statuses(out) == [401]
    out = _raw(http_server, _req("POST", "/nope", _add(), extra=extra))
    assert _statuses(out) == [404]
    out = _raw(http_server, _req("POST", "/nope", _add(), extra=extra))
    assert 100 not in _statuses(out)


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "FOO"])
def test_control_unknown_methods_never_reach_storage_or_leak(http_server, tmp_path, method):
    out = _raw(http_server, _req(method, "/add", _add()))
    assert _statuses(out) == [501], out
    assert b"Traceback" not in out and KEY.encode() not in out and PASSPHRASE.encode() not in out
    assert not list((tmp_path / "vaults").glob("*.kib"))


def test_control_head_and_get_read_no_body_and_touch_nothing(http_server, tmp_path):
    for method in ("HEAD", "GET"):
        out = _raw(http_server, _req(method, "/add", _add(), auth=False))
        assert _statuses(out) == [404], out
        out = _raw(http_server, _req(method, "/health", auth=False))
        assert _statuses(out) == [200]
        assert b"Traceback" not in out
    assert not list((tmp_path / "vaults").glob("*.kib"))


# ------------------------------------------------------------------ names stay inside the data dir


@pytest.mark.parametrize("user", ["../../etc/passwd", "/abs/path", "..", ".", "a/b", "x\\y", "\u2028", "u" * 2000,
                                  "C:\\x", "%2e%2e%2f", "\x00"])
def test_control_user_id_cannot_choose_a_path(http_server, tmp_path, user):
    out = _raw(http_server, _req("POST", "/add", _add(user=user)))
    status = _statuses(out)
    assert status in ([200], [422]), out
    names = sorted(p.name for p in (tmp_path / "vaults").iterdir())
    assert all(re.fullmatch(r"[0-9a-f]{32}\.kib(-wal|-shm)?", n) for n in names), names
    assert not (tmp_path / "etc").exists() and not Path("/abs/path").exists()


def test_control_search_of_an_unknown_user_creates_nothing(http_server, tmp_path):
    out = _raw(http_server, _req("POST", "/search", {"user_id": "ghost", "query": "anything"}))
    assert _statuses(out) == [200] and b'"data":[]' in out
    assert not list((tmp_path / "vaults").glob("*"))


# ------------------------------------------------------------------ 4xx mapping and 500 hygiene


def test_control_r2c1_shapes_are_4xx_and_the_server_keeps_serving(http_server):
    assert _statuses(_raw(http_server, _req("POST", "/add", _add(ts=10 ** 400)))) == [422]
    assert _statuses(_raw(http_server, _req("POST", "/search", {"user_id": "u", "query": "q", "top_k": "1" * 20}))) == [422]
    assert _statuses(_raw(http_server, _req("POST", "/search", {"user_id": "u", "query": "q", "top_k": "\u00b2"}))) == [422]
    nested = b"[" * 2000 + b"]" * 2000
    assert _statuses(_raw(http_server, _req("POST", "/add", body=nested)))[0] in (400, 422)
    assert _statuses(_raw(http_server, _req("POST", "/add", _add()))) == [200]


def test_control_storage_failure_is_500_without_a_traceback_and_the_permits_come_back(http_server, caplog):
    import logging
    caplog.set_level(logging.ERROR)

    def boom(*a, **k):
        raise RuntimeError("secret detail: " + PASSPHRASE)

    original = http_server.service.add
    http_server.service.add = boom
    try:
        for _ in range(6):  # more than max_connections and max_inflight: permits must be released
            out = _raw(http_server, _req("POST", "/add", _add()))
            assert _statuses(out) == [500] and b'"internal error"' in out, out
            assert b"Traceback" not in out and PASSPHRASE.encode() not in out and b"secret" not in out
    finally:
        http_server.service.add = original
    assert PASSPHRASE not in caplog.text and "secret detail" not in caplog.text
    assert http_server.connections._value == http_server.config.max_connections
    assert http_server.inflight._value == http_server.config.max_inflight
    assert _statuses(_raw(http_server, _req("POST", "/add", _add(rid="after")))) == [200]


def test_control_validating_does_not_swallow_storage_bugs_as_4xx(http_server):
    """_validating wraps the field-reading halves only: a bug in the storage half is still a 500
    (visible to the operator), not disguised as the client's error."""
    service = http_server.service
    original = service.pool.use

    def broken(*a, **k):
        raise AttributeError("a real bug")

    service.pool.use = broken
    try:
        assert _statuses(_raw(http_server, _req("POST", "/add", _add()))) == [500]
        assert _statuses(_raw(http_server, _req("POST", "/search", {"user_id": "u", "query": "q"}))) == [500]
    finally:
        service.pool.use = original


def test_control_handler_exception_releases_the_connection_permit(http_server, monkeypatch):
    def explode(self):
        raise RuntimeError("handler bug")

    monkeypatch.setattr(AMLHandler, "do_POST", explode)
    for _ in range(http_server.config.max_connections + 2):
        _raw(http_server, _req("POST", "/add", _add()), read_timeout=1.0)
    time.sleep(0.3)
    assert http_server.connections._value == http_server.config.max_connections


# ------------------------------------------------------------------ retention boundaries


def test_control_retention_only_deletes_its_own_idle_vault_files(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    service = AMLService(_config(tmp_path, retention_days=1))
    try:
        service.add(_add(user="idle"))
        service.add(_add(user="busy", rid="r2"))
        data = Path(service.config.data_dir)
        idle = service.pool.path_for("idle")
        busy = service.pool.path_for("busy")
        # things retention must never touch
        (data / "notes.txt").write_bytes(b"x" * 1024)
        (data / ("f" * 32 + ".kib")).write_bytes(b"x" * 1000)  # right name, not page-sized: never a vault
        link = data / ("e" * 32 + ".kib")
        link.symlink_to(idle)
        old = time.time() - 10 * 86400
        for p in (idle, busy, data / "notes.txt", data / ("f" * 32 + ".kib")):
            os.utime(p, (old, old))
        for base in (idle, busy):
            for suffix in ("-wal", "-shm"):
                side = Path(str(base) + suffix)
                if side.exists():
                    os.utime(side, (old, old))
        with service.pool.use("busy", create=False):  # in use: skipped
            removed = service.pool.purge_idle(86400)
        assert removed == 1
        assert not idle.exists()
        assert busy.exists() and (data / "notes.txt").exists() and (data / ("f" * 32 + ".kib")).exists()
        assert link.is_symlink() and not link.exists()  # dangling now, but the link itself was not unlinked
        # the busy vault goes once it is idle and unreferenced
        for suffix in ("", "-wal", "-shm"):
            side = Path(str(busy) + suffix)
            if side.exists():
                os.utime(side, (old, old))
        assert service.pool.purge_idle(86400) == 1
        assert not busy.exists()
    finally:
        service.pool.close_all()


def test_control_add_rows_cannot_carry_trust(tmp_path, monkeypatch):
    """Add stores import-origin candidates; the request cannot name reserved or trust fields."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    service = AMLService(_config(tmp_path))
    try:
        body = _add(user="t", epistemic_state="verified", origin="user", metadata={"human_reviews": [1]},
                    trust_ceiling=None, attester="root")
        body["messages"][0].update({"epistemic_state": "verified", "origin": "user", "metadata": {"attestations": ["a"]}})
        assert service.add(body)["success"] is True
        with service.pool.use("t", create=False) as vault:
            rows = vault.list_entities(scope="aml", include_unverified=True) if "include_unverified" in \
                vault.list_entities.__code__.co_varnames else vault.list_entities(scope="aml")
            assert rows, "nothing stored"
            for e in rows:
                assert e.epistemic_state.value == "candidate" and e.origin == "import"
                assert "human_reviews" not in (e.metadata or {}) and "attestations" not in (e.metadata or {})
    finally:
        service.pool.close_all()
