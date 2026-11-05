"""AML Add/Search adapter: contract, idempotency, atomic writes, isolation, encryption, HTTP behaviour."""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from kibisis import aml_adapter
from kibisis.aml_adapter import AMLConfig, AMLService, ContractError, key_digest, run_server
from kibisis.vault import SQLiteMemoryVault

KEY = "test-memory-system-key-0123456789"
PASSPHRASE = "aml-test-passphrase-not-secret"
T0 = 1_704_067_200_000  # 2024-01-01T00:00:00Z


def _config(tmp_path: Path, **kw) -> AMLConfig:
    kw.setdefault("passphrase", PASSPHRASE)
    return AMLConfig(data_dir=str(tmp_path / "vaults"), key_sha256=key_digest(KEY), **kw)


def _add(svc: AMLService, request_id: str, user: str, texts, start: int = T0, roles=None):
    messages = [{"role": (roles or ["user", "assistant"])[i % len(roles or ["user", "assistant"])],
                 "timestamp": start + i * 60_000, "content": t} for i, t in enumerate(texts)]
    return svc.add({"request_id": request_id, "user_id": user, "session_id": f"s-{request_id}", "messages": messages})


def _search(svc: AMLService, user: str, query: str, top_k: int = 100, options=None):
    body = {"query": query, "user_id": user, "top_k": top_k}
    if options is not None:
        body["options"] = options
    return svc.search(body)["data"]


@pytest.fixture
def svc(tmp_path):
    service = AMLService(_config(tmp_path))
    yield service
    service.pool.close_all()


# ----------------------------------------------------------------------------- contract


def test_add_echoes_ids_and_search_returns_contract_fields(svc):
    out = _add(svc, "eval:r:locomo:conv-0:chunk-0", "eval:r:locomo:conv-0",
               ["I adopted a beagle named Biscuit last week.", "That is wonderful, how is Biscuit settling in?"])
    assert out == {"success": True, "request_id": "eval:r:locomo:conv-0:chunk-0",
                   "user_id": "eval:r:locomo:conv-0", "session_id": "s-eval:r:locomo:conv-0:chunk-0"}
    data = _search(svc, "eval:r:locomo:conv-0", "What is the name of the dog?")
    assert len(data) == 1
    item = data[0]
    assert set(item) == {"id", "content", "score", "created_at"}
    assert item["id"].startswith("kib_") and isinstance(item["score"], float) and item["score"] > 0
    assert "user: I adopted a beagle named Biscuit last week." in item["content"]
    assert "[2024-01-01 (Mon) 00:00 UTC]" in item["content"]
    assert item["created_at"].endswith("Z")


def test_search_unknown_user_returns_empty_data(svc):
    assert svc.search({"query": "anything", "user_id": "nobody", "top_k": 100}) == {"data": []}


def test_ids_are_stable_and_scores_never_rise_down_the_list(svc):
    for n in range(6):
        _add(svc, f"chunk-{n}", "u", [f"note {n}: the garden needs water" + " water" * n, f"filler {n}"])
    first = _search(svc, "u", "water the garden")
    second = _search(svc, "u", "water the garden")
    assert [d["id"] for d in first] == [d["id"] for d in second]
    scores = [d["score"] for d in first]
    assert scores == sorted(scores, reverse=True)
    assert len({d["id"] for d in first}) == len(first)


def test_top_k_caps_the_number_of_memories(svc):
    for n in range(12):
        _add(svc, f"c{n}", "u", [f"marathon training log entry {n}"])
    assert len(_search(svc, "u", "marathon training", top_k=5)) == 5
    assert len(_search(svc, "u", "marathon training", top_k=100)) == 12


def test_options_take_part_in_retrieval(svc):
    _add(svc, "c0", "u", ["We booked the cabin near Lake Tahoe for July."])
    assert _search(svc, "u", "Where is the cabin?") != []
    assert _search(svc, "u", "Which answer?", options=["A. Tahoe", "B. Denver"]) != []


@pytest.mark.parametrize("body,status", [
    ({"user_id": "u", "session_id": "s", "messages": [{"role": "user", "content": "x"}]}, 422),
    ({"request_id": "r", "session_id": "s", "messages": [{"role": "user", "content": "x"}]}, 422),
    ({"request_id": "r", "user_id": "u", "messages": [{"role": "user", "content": "x"}]}, 422),
    ({"request_id": "r", "user_id": "u", "session_id": "s", "messages": []}, 422),
    ({"request_id": "r", "user_id": "u", "session_id": "s", "messages": ["text"]}, 422),
    ({"request_id": "r", "user_id": "u", "session_id": "s", "messages": [{"role": 3, "content": "x"}]}, 422),
    ({"request_id": "r", "user_id": "u", "session_id": "s",
      "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:,"}}]}]}, 422),
    ({"request_id": "r", "user_id": "u", "session_id": "s",
      "messages": [{"role": "user", "content": "x", "timestamp": "not a time"}]}, 422),
])
def test_add_rejects_contract_violations_with_4xx(svc, body, status):
    with pytest.raises(ContractError) as err:
        svc.add(body)
    assert err.value.status == status


@pytest.mark.parametrize("body", [
    {"user_id": "u", "top_k": 10},
    {"query": "", "user_id": "u", "top_k": 10},
    {"query": "q", "top_k": 10},
    {"query": "q", "user_id": "u", "top_k": 0},
    {"query": "q", "user_id": "u", "top_k": True},
    {"query": "q", "user_id": "u", "top_k": 10, "options": "A"},
])
def test_search_rejects_contract_violations_with_422(svc, body):
    with pytest.raises(ContractError) as err:
        svc.search(body)
    assert err.value.status == 422


def test_text_content_parts_and_timestamp_forms(svc):
    svc.add({"request_id": "r1", "user_id": "u", "session_id": "s", "messages": [
        {"role": "user", "content": [{"type": "text", "text": "violin lessons"}, {"type": "text", "text": "start Monday"}],
         "timestamp": 1_704_067_200},  # seconds
        {"role": "assistant", "content": "noted the violin plan", "timestamp": "2024-01-02T10:00:00Z"},
        {"role": "user", "content": "no timestamp on this violin line"},
    ]})
    data = _search(svc, "u", "violin")
    assert len(data) == 1
    content = data[0]["content"]
    assert "user: violin lessons\nstart Monday" in content
    assert "[2024-01-01 (Mon) 00:00 UTC]" in content and "[2024-01-02 (Tue) 10:00 UTC]" in content


# ----------------------------------------------------------------------------- write semantics


def test_retried_request_is_stored_once(svc):
    for _ in range(3):
        out = _add(svc, "same-request", "u", ["the quokka photo from Rottnest"])
        assert out["success"] is True
    data = _search(svc, "u", "quokka")
    assert len(data) == 1 and data[0]["content"].count("quokka") == 1


def test_failed_request_leaves_nothing_and_retry_stores_it_whole(svc, monkeypatch):
    real_put = SQLiteMemoryVault.put
    calls = {"n": 0}

    def flaky_put(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("disk hiccup")
        return real_put(self, *args, **kwargs)

    monkeypatch.setattr(SQLiteMemoryVault, "put", flaky_put)
    texts = [f"atomic line {i} about telescopes" for i in range(5)]
    with pytest.raises(OSError):
        _add(svc, "req-atomic", "u", texts)
    monkeypatch.setattr(SQLiteMemoryVault, "put", real_put)
    assert _search(svc, "u", "telescopes") == []
    _add(svc, "req-atomic", "u", texts)
    data = _search(svc, "u", "telescopes")
    assert len(data) == 1 and all(t in data[0]["content"] for t in texts)


def test_users_are_isolated(svc):
    _add(svc, "a1", "alice", ["alice keeps her passport in the blue drawer"])
    _add(svc, "b1", "bob", ["bob prefers the window seat"])
    assert any("passport" in d["content"] for d in _search(svc, "alice", "passport blue drawer"))
    assert all("passport" not in d["content"] for d in _search(svc, "bob", "passport blue drawer"))
    assert all("window seat" not in d["content"] for d in _search(svc, "alice", "window seat"))
    assert len({p.name for p in Path(svc.config.data_dir).glob("*.kib")}) == 2


def test_hits_are_grouped_by_request_with_previous_message_as_context(svc):
    _add(svc, "c0", "u", ["We talked about the weather.", "Then I mentioned the saxophone recital.",
                          "Unrelated chatter here.", "More unrelated chatter.", "The saxophone recital is on Friday."])
    data = _search(svc, "u", "saxophone recital")
    assert len(data) == 1
    lines = data[0]["content"].splitlines()
    body = [ln for ln in lines if not ln.startswith("[")]
    assert body == ["user: We talked about the weather.", "assistant: Then I mentioned the saxophone recital.",
                    aml_adapter.GAP, "assistant: More unrelated chatter.", "user: The saxophone recital is on Friday."]


def test_vaults_are_encrypted_at_rest(svc):
    _add(svc, "c0", "u", ["plaintext canary zebra-41"])
    (path,) = Path(svc.config.data_dir).glob("*.kib")
    svc.pool.close_all()
    raw = path.read_bytes()
    assert not raw.startswith(b"SQLite format 3") and b"zebra-41" not in raw


def test_retention_purges_idle_vaults_only(svc):
    _add(svc, "old", "old-user", ["stale memory about kites"])
    _add(svc, "new", "new-user", ["fresh memory about kites"])
    old_path = svc.pool.path_for("old-user")
    past = time.time() - 40 * 86400
    for suffix in ("", "-wal", "-shm"):
        f = Path(f"{old_path}{suffix}")
        if f.exists():
            os.utime(f, (past, past))
    assert svc.pool.purge_idle(28 * 86400) == 1
    assert not old_path.exists()
    assert _search(svc, "old-user", "kites") == []
    assert _search(svc, "new-user", "kites") != []


def test_lru_eviction_keeps_data_searchable(tmp_path):
    service = AMLService(_config(tmp_path, max_open_vaults=2))
    try:
        for n in range(4):
            _add(service, f"r{n}", f"user-{n}", [f"user {n} likes origami cranes"])
        assert service.pool.open_count() <= 2
        for n in range(4):
            assert _search(service, f"user-{n}", "origami cranes") != []
    finally:
        service.pool.close_all()


def test_concurrent_adds_and_searches(svc):
    errors = []

    def worker(w):
        try:
            for j in range(15):
                _add(svc, f"w{w}-r{j}", f"user-{w % 3}", [f"worker {w} item {j} pelican report"])
                _search(svc, f"user-{w % 3}", "pelican report", top_k=10)
        except Exception as exc:  # pragma: no cover - failure detail
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    total = sum(len(_search(svc, f"user-{u}", "pelican report", top_k=1000)) for u in range(3))
    assert total == 6 * 15


# ----------------------------------------------------------------------------- HTTP


@pytest.fixture
def http_server(tmp_path):
    started = threading.Event()
    holder = {}

    def ready(server):
        holder["server"] = server
        started.set()

    config = _config(tmp_path, max_inflight=4, retention_days=0)
    config.max_body_bytes = 64 * 1024
    thread = threading.Thread(target=run_server, args=(config,), kwargs={"host": "127.0.0.1", "port": 0, "ready": ready},
                              daemon=True)
    thread.start()
    assert started.wait(10)
    server = holder["server"]
    yield server
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


AUTH = {"Authorization": f"Token {KEY}"}
ADD = {"request_id": "h1", "user_id": "hu", "session_id": "hs",
       "messages": [{"role": "user", "timestamp": T0, "content": "the hummingbird feeder is on the porch"}]}
SEARCH = {"query": "Where is the hummingbird feeder?", "user_id": "hu", "top_k": 100}


def test_health_needs_no_auth(http_server):
    for path in ("/", "/health", "/v1/health"):
        status, _, body = _call(http_server, "GET", path)
        assert status == 200 and body["status"] == "ok" and body["adapter"] == aml_adapter.ADAPTER_REVISION
    assert _call(http_server, "HEAD", "/health")[0] == 200
    assert _call(http_server, "GET", "/nope")[0] == 404


def test_auth_schemes_and_failures(http_server):
    assert _call(http_server, "POST", "/v1/memories/add", ADD)[0] == 401
    assert _call(http_server, "POST", "/v1/memories/add", ADD, {"Authorization": "Token wrong"})[0] == 401
    assert _call(http_server, "POST", "/v1/memories/add", ADD, {"Authorization": f"Basic {KEY}"})[0] == 401
    for headers in (AUTH, {"Authorization": f"Bearer {KEY}"}, {"X-Api-Key": KEY}):
        status, _, body = _call(http_server, "POST", "/v1/memories/add", ADD, headers)
        assert status == 200 and body["success"] is True and body["request_id"] == "h1"


def test_add_then_search_over_http_and_aliases(http_server):
    assert _call(http_server, "POST", "/add", ADD, AUTH)[0] == 200
    for path in ("/v1/memories/search", "/search", "/v1/memories/search/"):
        status, headers, body = _call(http_server, "POST", path, SEARCH, AUTH)
        assert status == 200 and len(body["data"]) == 1
        assert "hummingbird" in body["data"][0]["content"]
        assert headers["Content-Type"].startswith("application/json")
    assert _call(http_server, "POST", "/v1/memories/nope", SEARCH, AUTH)[0] == 404


def test_bad_bodies_get_clear_4xx(http_server):
    assert _call(http_server, "POST", "/v1/memories/add", raw=b"{not json", headers=AUTH)[0] == 400
    assert _call(http_server, "POST", "/v1/memories/add", raw=b"[1,2]", headers=AUTH)[0] == 422
    status, _, body = _call(http_server, "POST", "/v1/memories/search", {"user_id": "hu", "top_k": 5}, AUTH)
    assert status == 422 and "query" in body["error"]
    big = {"request_id": "big", "user_id": "hu", "session_id": "s",
           "messages": [{"role": "user", "content": "x" * 70_000}]}
    assert _call(http_server, "POST", "/v1/memories/add", big, AUTH)[0] == 413


def test_chunked_request_body(http_server):
    conn = http.client.HTTPConnection("127.0.0.1", http_server.server_address[1], timeout=10)
    try:
        payload = json.dumps(ADD).encode()
        conn.request("POST", "/v1/memories/add", body=iter([payload[:20], payload[20:]]),
                     headers={**AUTH, "Content-Type": "application/json"}, encode_chunked=True)
        resp = conn.getresponse()
        assert resp.status == 200 and json.loads(resp.read())["success"] is True
    finally:
        conn.close()


def test_keep_alive_serves_several_requests_on_one_connection(http_server):
    conn = http.client.HTTPConnection("127.0.0.1", http_server.server_address[1], timeout=10)
    try:
        for body, path in ((ADD, "/v1/memories/add"), (SEARCH, "/v1/memories/search"), (SEARCH, "/v1/memories/search")):
            conn.request("POST", path, body=json.dumps(body).encode(), headers={**AUTH, "Content-Type": "application/json"})
            resp = conn.getresponse()
            assert resp.status == 200
            resp.read()
    finally:
        conn.close()


def test_over_capacity_gets_429_with_retry_after(http_server):
    sem = http_server.inflight
    taken = 0
    while sem.acquire(blocking=False):
        taken += 1
    try:
        status, headers, _ = _call(http_server, "POST", "/v1/memories/search", SEARCH, AUTH)
        assert status == 429 and int(headers["Retry-After"]) >= 1
    finally:
        for _ in range(taken):
            sem.release()
    assert _call(http_server, "POST", "/v1/memories/search", SEARCH, AUTH)[0] == 200


# ----------------------------------------------------------------------------- CLI


def test_cli_help_and_missing_key(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("KIBISIS_AML_KEY", "KIBISIS_PASSPHRASE"))}
    help_run = subprocess.run([sys.executable, "-m", "kibisis", "aml-serve", "--help"], capture_output=True, text=True,
                              env=env, timeout=60)
    assert help_run.returncode == 0 and "--data-dir" in help_run.stdout
    no_key = subprocess.run([sys.executable, "-m", "kibisis", "aml-serve", "--data-dir", str(tmp_path)],
                            capture_output=True, text=True, env=env, timeout=60)
    assert no_key.returncode == 2 and "Memory System Key" in no_key.stderr
    no_pass = subprocess.run([sys.executable, "-m", "kibisis", "aml-serve", "--data-dir", str(tmp_path)],
                             capture_output=True, text=True, env={**env, "KIBISIS_AML_KEY_SHA256": key_digest(KEY)},
                             timeout=60)
    assert no_pass.returncode == 2 and "vault key" in no_pass.stderr


def test_config_rejects_a_raw_key_in_place_of_its_digest(tmp_path):
    with pytest.raises(ValueError):
        AMLConfig(data_dir=str(tmp_path), key_sha256=KEY)
