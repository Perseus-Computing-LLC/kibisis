"""The recall gate over the whole matched set, and what a recall tells its caller.

- The gate reads every match: ``n_matched`` and the withheld counts are those of the matched set, and a
  hit's verdict, coverage, z-score and rank are the same whatever ``limit`` the caller passed.
- Coverage is read from the index that found the match: a query word is covered in exactly the entries a
  search for that word finds, so words in the key or the category count, and so does whatever folding
  the index applies. Checked on every kind of vault, because each kind ranks through its own index.
- ``prefer_recent`` re-orders the hits that passed and never changes which pass.
- Withheld rows below the gate carry coverage, rank and time, and content only when asked for.
- The Argus event names the returned refs as one string; a recall writes nothing to the vault.
"""

import json
import sqlite3
import time

import pytest

import kibisis.vault as vault_module
from kibisis import KibisisMCPServer, SQLiteMemoryVault

PASS = "recall gate test passphrase (test only)"
DAY = 86400.0
KINDS = ["plain", "sqlcipher", "terms", "scan"]


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)


def _open(kind, path, monkeypatch):
    """A vault that ranks through the given index: 'plain' (FTS5 over plaintext), 'sqlcipher' (the entry
    index), 'terms' (the keyed term index of a passphrase vault without SQLCipher) or 'scan' (the same
    vault with the term index off: an in-memory index of the opened entries)."""
    if kind == "plain":
        return SQLiteMemoryVault(str(path), allow_plaintext=True, auto_gate=False, verification_quorum=1)
    if kind == "sqlcipher":
        if not vault_module._sqlcipher_available():
            pytest.skip("sqlcipher3 is not installed")
        if vault_module.sqlcipher3.sqlite_version_info < (3, 43, 0):
            pytest.skip("this SQLCipher's SQLite predates contentless-delete FTS5 tables (3.43)")
        return SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False, verification_quorum=1)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")  # without SQLCipher the file is plain on disk: opt-in
    return SQLiteMemoryVault(
        str(path), passphrase=PASS, auto_gate=False, verification_quorum=1, term_index=(kind == "terms")
    )


@pytest.fixture(params=KINDS)
def any_vault(request, tmp_path, monkeypatch):
    v = _open(request.param, tmp_path / "v.db", monkeypatch)
    assert v._search_mode() == {"plain": "plain", "sqlcipher": "index", "terms": "terms", "scan": "scan"}[request.param]
    yield v
    v.close()


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


def _put(vault, category, key, content, at=None, monkeypatch=None, **kw):
    """Write a model-origin candidate; with ``at``, as if the clock read that time."""
    if at is None:
        return vault.put(category, key, content, origin="model", author_id="agent", **kw)
    with monkeypatch.context() as m:
        m.setattr(time, "time", lambda: at)
        return vault.put(category, key, content, origin="model", author_id="agent", **kw)


def _crowd(vault, n=150):
    """``n`` entries that all match "valve"; a few match the other query words too."""
    for i in range(n):
        extra = " reactor coolant" if i % 30 == 0 else (" reactor" if i % 7 == 0 else "")
        filler = " ".join(f"w{(i * 13 + j) % 97}" for j in range(i % 9))
        _put(vault, "note", f"n{i:03d}", f"valve{extra} {filler}".strip())
    for i in range(20):
        _put(vault, "other", f"o{i:02d}", f"unrelated text number {i}")


def _hits(out):
    return {h["ref"]: h for h in out.receipt["hits"]}


def _refs(out):
    return [f"{r.entity.category}:{r.entity.key}" for r in out.results]


# --- the gate reads every match ------------------------------------------------------------------


def test_counts_and_verdicts_are_those_of_the_whole_matched_set(any_vault):
    vault = any_vault
    _crowd(vault)
    query = "reactor coolant valve"
    every = vault.search_keys(query, match="any", limit=1000)
    assert len(every) == 150  # control: the matched set is larger than any pool a small limit implies
    order = [f"{h.category}:{h.key}" for h in every]
    outs = {limit: vault.recall(query, match="any", limit=limit) for limit in (1, 5, 15, 200)}
    widest = _hits(outs[200])
    assert len(widest) == 150
    for limit, out in outs.items():
        receipt = out.receipt
        assert receipt["n_matched"] == 150, limit
        kept = sum(1 for h in widest.values() if h["kept"])
        assert receipt["n_withheld_gate"] == 150 - kept, limit
        assert receipt["n_returned"] == min(limit, kept), limit
        # The receipt names the best of the matched set; what it says of a hit does not move with limit.
        assert len(receipt["hits"]) == min(150, max(limit * 8, 64)), limit
        for ref, hit in _hits(out).items():
            assert hit == widest[ref], (limit, ref)
            assert hit["rank"] == order.index(ref) + 1
        assert _refs(out) == _refs(outs[200])[:limit]
    assert 0 < outs[200].receipt["n_returned"] < 150  # the gate passed some and withheld some


def test_tied_crowd_is_withheld_at_any_limit(any_vault):
    vault = any_vault
    for i in range(90):
        _put(vault, "note", f"n{i:02d}", "valve")  # ninety equal scores: none stands out
    for limit in (1, 10, 100):
        out = vault.recall("valve", match="any", limit=limit)
        assert out.results == [] and out.receipt["n_matched"] == 90 and out.receipt["n_withheld_gate"] == 90
        assert all(h["z_bp"] == 0 and h["reason"] == "below_gate" for h in out.receipt["hits"])
        assert len(out.withheld) == max(limit * 8, 64) if limit < 100 else 90


def test_mcp_envelope_counts_every_hit_below_the_gate(vault):
    for i in range(90):
        _put(vault, "note", f"n{i:02d}", "valve")
    server = KibisisMCPServer(vault=vault, scope="default")
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "kibisis_recall", "arguments": {"query": "valve"}}}
    )
    text = resp["result"]["content"][0]["text"]
    assert 'count="0"' in text and 'withheld="90"' in text
    assert '<withheld reason="below_gate" count="90"/>' in text


# --- coverage agrees with the index ---------------------------------------------------------------


COVERAGE_CORPUS = [
    ("ops", "backup-schedule", "runs nightly at two"),                 # "backup", "schedule" only in the key
    ("ops", "restore", "the backup is restored from tape"),            # "backup" only in the content
    ("backup", "tape-rotation", "weekly rotation of the reels"),       # "backup" only in the category
    ("ops", "cafe", "the café closes at nine"),                        # an accent the query does not carry
    ("ops", "naive", "a naive schedule"),                              # no accent, the query carries one
    ("ops", "plural", "schedules and backups are reviewed"),           # longer words that begin with the query's
    ("ops", "none", "nothing to see"),
]


@pytest.mark.parametrize("query", ["backup schedule cafe", "naïve backup rotation nightly", "tape schedule"])
def test_a_query_word_is_covered_where_a_search_for_it_matches(any_vault, query):
    vault = any_vault
    for category, key, content in COVERAGE_CORPUS:
        _put(vault, category, key, content)
    words = query.split()
    found = {w: {f"{h.category}:{h.key}" for h in vault.search_keys(w, match="any", limit=100)} for w in words}
    assert any(found.values())
    out = vault.recall(query, match="any", min_coverage_bp=0, limit=50)
    hits = _hits(out)
    assert set(hits) == set().union(*found.values())  # control: recall matched what the words match
    for ref, hit in hits.items():
        expected = int(round(10000 * sum(1 for w in words if ref in found[w]) / len(words)))
        assert hit["coverage_bp"] == expected, (ref, hit)


def test_words_in_key_and_category_pass_the_default_floor(any_vault):
    vault = any_vault
    for category, key, content in COVERAGE_CORPUS:
        _put(vault, category, key, content)
    out = vault.recall("backup schedule", match="any", z_max_bp=10**9)  # the coverage floor alone
    hits = _hits(out)
    assert hits["ops:backup-schedule"]["coverage_bp"] == 10000 and hits["ops:backup-schedule"]["kept"]
    assert hits["backup:tape-rotation"]["coverage_bp"] == 5000 and hits["backup:tape-rotation"]["kept"]
    assert "ops:none" not in hits


def test_every_match_of_an_all_words_query_is_fully_covered(any_vault):
    vault = any_vault
    for category, key, content in COVERAGE_CORPUS:
        _put(vault, category, key, content)
    out = vault.recall("backup schedule", match="all")
    assert "ops:backup-schedule" in _refs(out)
    assert out.receipt["hits"] and all(h["coverage_bp"] == 10000 for h in out.receipt["hits"])


def test_the_floor_still_withholds_a_hit_with_too_few_words(any_vault):
    vault = any_vault
    _put(vault, "ops", "backup", "The backup runs nightly at two.")
    out = vault.recall("backup retention policy owner", match="any")  # one word of four
    assert out.results == []
    assert [(w.ref, w.reason, w.coverage_bp) for w in out.withheld] == [("ops:backup", "below_gate", 2500)]


# --- prefer_recent ----------------------------------------------------------------------------------


def _two_ages(vault, monkeypatch, now):
    for i in range(12):
        _put(vault, "other", f"o{i:02d}", f"unrelated text number {i}")
    _put(vault, "state", "old", "reactor coolant valve inspection", at=now - 30 * DAY, monkeypatch=monkeypatch)
    _put(vault, "state", "new", "reactor coolant valve inspection loop", at=now - 60, monkeypatch=monkeypatch)


def test_recency_is_off_by_default_and_order_is_bm25(any_vault, monkeypatch):
    vault = any_vault
    _two_ages(vault, monkeypatch, time.time())
    searched = [(r.entity.key, r.rank_score) for r in vault.search("reactor coolant valve", match="any")]
    out = vault.recall("reactor coolant valve", match="any")
    assert [k for k, _ in searched] == ["old", "new"]  # control: the older entry has the better BM25 score
    assert [(r.entity.key, r.rank_score) for r in out.results] == searched
    assert out.receipt["recency"]["prefer_recent"] is False
    assert all("recency_bp" not in h for h in out.receipt["hits"])


def test_prefer_recent_multiplies_the_score_by_the_recency_factor(any_vault, monkeypatch):
    vault = any_vault
    _two_ages(vault, monkeypatch, time.time())
    plain = vault.recall("reactor coolant valve", match="any")
    base = {r.entity.key: r.rank_score for r in plain.results}
    out = vault.recall("reactor coolant valve", match="any", prefer_recent=True)
    assert [r.entity.key for r in out.results] == ["new", "old"]
    got = {r.entity.key: r.rank_score for r in out.results}
    assert got["new"] == pytest.approx(base["new"] * 1.5, rel=1e-3)   # written a minute ago: 1 + 0.5
    assert got["old"] == pytest.approx(base["old"] * 1.25, rel=1e-3)  # one half-life old: 1 + 0.5 / 2
    hits = _hits(out)
    assert hits["state:new"]["recency_bp"] == pytest.approx(15000, abs=5)
    assert hits["state:old"]["recency_bp"] == pytest.approx(12500, abs=5)
    assert (hits["state:old"]["rank"], hits["state:new"]["rank"]) == (1, 2)  # rank stays the BM25 position
    assert out.receipt["recency"] == {"prefer_recent": True, "boost_bp": 5000, "half_life_days": 30}
    # The re-rank comes before the cut to `limit`.
    assert [r.entity.key for r in vault.recall("reactor coolant valve", match="any", prefer_recent=True, limit=1).results] == ["new"]


def test_recency_parameters(vault, monkeypatch):
    _two_ages(vault, monkeypatch, time.time())
    query = "reactor coolant valve"
    keys = lambda **kw: [r.entity.key for r in vault.recall(query, match="any", prefer_recent=True, **kw).results]  # noqa: E731
    assert keys(recency_boost_bp=0) == ["old", "new"]  # no boost: BM25 order
    assert keys(recency_boost_bp=20000, recency_half_life_days=14) == ["new", "old"]
    out = vault.recall(query, match="any", prefer_recent=True, recency_boost_bp=20000, recency_half_life_days=15)
    assert _hits(out)["state:old"]["recency_bp"] == pytest.approx(15000, abs=5)  # 1 + 2 * 2 ** -2
    for bad in ({"recency_half_life_days": 0}, {"recency_half_life_days": -1}, {"recency_boost_bp": -1}):
        with pytest.raises(ValueError):
            vault.recall(query, match="any", **bad)


def test_prefer_recent_does_not_change_which_hits_pass(any_vault, monkeypatch):
    vault = any_vault
    now = time.time()
    for i in range(60):
        extra = " reactor coolant" if i % 10 == 0 else (" reactor" if i % 4 == 0 else "")
        filler = " ".join(f"w{(i * 13 + j) % 97}" for j in range(i % 9))
        _put(vault, "note", f"n{i:02d}", f"valve{extra} {filler}".strip(), at=now - (6 - i // 10) * 12 * DAY,
             monkeypatch=monkeypatch)
    # The newest entry is a weak match: recency must not carry it over the gate.
    _put(vault, "note", "fresh-and-weak", "valve", at=now - 30, monkeypatch=monkeypatch)
    query = "reactor coolant valve"
    off = vault.recall(query, match="any", limit=100)
    on = vault.recall(query, match="any", limit=100, prefer_recent=True, recency_boost_bp=50000, recency_half_life_days=7)
    assert sorted(_refs(on)) == sorted(_refs(off)) and _refs(on) != _refs(off)
    assert 0 < len(off.results) < off.receipt["n_matched"] == 61
    assert [(w.ref, w.reason, w.coverage_bp, w.rank) for w in on.withheld] == [
        (w.ref, w.reason, w.coverage_bp, w.rank) for w in off.withheld
    ]
    for key in ("n_matched", "n_returned", "n_withheld_gate", "n_withheld_conflict", "n_withheld_stale"):
        assert on.receipt[key] == off.receipt[key]
    strip = lambda h: {k: v for k, v in h.items() if k != "recency_bp"}  # noqa: E731
    assert [strip(h) for h in on.receipt["hits"]] == off.receipt["hits"]
    assert "note:fresh-and-weak" not in _refs(on)
    assert _hits(on)["note:fresh-and-weak"]["reason"] == "below_gate"
    scores = [r.rank_score for r in on.results]
    assert scores == sorted(scores)  # returned best first by the re-ranked score


# --- withheld rows ------------------------------------------------------------------------------------


BACKUP = "The backup runs nightly\n\tat two.   Tapes go offsite on Friday."


def test_a_row_below_the_gate_carries_coverage_rank_and_time_but_no_content(any_vault):
    vault = any_vault
    entity = _put(vault, "ops", "backup", BACKUP)
    _put(vault, "ops", "backup-owner", "the owner of the backup policy is the platform team")
    out = vault.recall("backup retention policy owner", match="any")
    assert _refs(out) == ["ops:backup-owner"]
    (row,) = out.withheld
    assert (row.ref, row.reason, row.coverage_bp, row.rank) == ("ops:backup", "below_gate", 2500, 2)
    assert row.updated_at == pytest.approx(entity.updated_at)
    assert row.digest is None and row.sources == []
    hit = _hits(out)["ops:backup"]
    assert hit["rank"] == 2 and hit["updated_at"] == pytest.approx(entity.updated_at) and "digest" not in hit
    for text in (json.dumps(out.receipt), json.dumps([w.model_dump() for w in out.withheld])):
        assert "nightly" not in text and "Tapes" not in text


def test_withheld_ranks_follow_bm25_order(any_vault):
    vault = any_vault
    _crowd(vault)
    order = [f"{h.category}:{h.key}" for h in vault.search_keys("reactor coolant valve", match="any", limit=1000)]
    out = vault.recall("reactor coolant valve", match="any", limit=5)
    below = [w for w in out.withheld if w.reason == "below_gate"]
    assert below and [w.rank for w in below] == sorted(w.rank for w in below)
    assert all(order[w.rank - 1] == w.ref for w in below)
    assert all(w.coverage_bp is not None and w.updated_at is not None and w.digest is None for w in below)


def test_digest_is_the_start_of_the_content_on_one_line_when_asked_for(any_vault):
    vault = any_vault
    _put(vault, "ops", "backup", BACKUP)
    out = vault.recall("backup retention policy owner", match="any", withheld_digest_chars=30)
    (row,) = out.withheld
    assert row.digest == "The backup runs nightly at two"
    assert _hits(out)["ops:backup"]["digest"] == row.digest
    assert vault.recall("backup retention policy owner", match="any", withheld_digest_chars=5).withheld[0].digest == "The b"
    long = vault.recall("backup retention policy owner", match="any", withheld_digest_chars=10_000).withheld[0].digest
    assert long == "The backup runs nightly at two. Tapes go offsite on Friday."
    for off in (0, -3):
        assert vault.recall("backup retention policy owner", match="any", withheld_digest_chars=off).withheld[0].digest is None


def test_a_conflict_or_a_stale_row_never_carries_content(vault, monkeypatch):
    put = lambda key, content, **kw: vault.put(  # noqa: E731
        "fact", key, content, origin="user", author_id="a", epistemic_state="verified", **kw
    )
    put("a", "the office is in austin texas")
    put("b", "the office is in dallas texas", conflicts_with=["fact:a"])
    # A model write cannot set last_verified_at: the stale entry is one the agent wrote ten days ago.
    _put(vault, "fact", "s", "the office moved to texas last year", at=time.time() - 10 * DAY, monkeypatch=monkeypatch)
    _put(vault, "fact", "g", "texas")
    out = vault.recall(
        "office texas austin dallas", match="any", withheld_digest_chars=200, ttl_seconds={"agent": 7 * DAY},
        z_max_bp=10**9,  # the coverage floor alone decides who is below the gate here
    )
    by_ref = {w.ref: w for w in out.withheld}
    assert {ref: w.reason for ref, w in by_ref.items()} == {
        "fact:a": "conflict_unresolved", "fact:b": "conflict_unresolved", "fact:s": "stale", "fact:g": "below_gate",
    }
    assert by_ref["fact:g"].digest == "texas"  # control: the digest is on, and a row below the gate has one
    for ref in ("fact:a", "fact:b", "fact:s"):
        assert by_ref[ref].digest is None
        assert "digest" not in _hits(out)[ref]
    dumped = json.dumps(out.receipt) + json.dumps([w.model_dump() for w in out.withheld])
    assert "austin" not in dumped and "dallas" not in dumped and "moved" not in dumped


def test_a_digest_is_not_given_for_an_entry_that_fails_its_integrity_check(tmp_path, monkeypatch):
    vault = _open("sqlcipher", tmp_path / "v.db", monkeypatch)
    try:
        _put(vault, "ops", "backup", BACKUP)
        _put(vault, "ops", "restore", "the backup is restored from tape")
        vault._conn.execute("UPDATE entities SET key = 'moved' WHERE key = 'backup'")  # no longer the entry sealed
        vault._conn.commit()
        out = vault.recall("backup retention policy owner", match="any", withheld_digest_chars=40)
        digests = {w.ref: w.digest for w in out.withheld}
        assert digests.get("ops:restore") == "the backup is restored from tape"  # control
        assert all(d is None for ref, d in digests.items() if ref != "ops:restore")
        assert "nightly" not in json.dumps(out.receipt)
    finally:
        vault.close()


# --- the ledger event, and no write to the vault -------------------------------------------------------


def _recall_events(ledger):
    lines = [json.loads(line) for line in ledger.read_text().splitlines()]
    return [line["payload"] for line in lines if line["event_type"] == "kibisis.memory_recall"]


def test_argus_event_names_the_returned_refs_as_one_string(vault, monkeypatch, tmp_path):
    pytest.importorskip("argus_ledger")
    ledger = tmp_path / "audit.jsonl"
    _two_ages(vault, monkeypatch, time.time())
    _put(vault, "state", "weak", "valve")
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(ledger))
    out = vault.recall("reactor coolant valve", match="any", channel="mcp")
    recent = vault.recall("reactor coolant valve", match="any", prefer_recent=True, withheld_digest_chars=50)
    vault.recall("nothing here matches", match="any")
    first, second, third = _recall_events(ledger)
    assert _refs(out) == ["state:old", "state:new"]
    assert first["returned"] == "state:old,state:new"  # in the order returned
    assert second["returned"] == "state:new,state:old" and _refs(recent) == ["state:new", "state:old"]
    assert third["returned"] == "" and third["n_returned"] == 0
    assert first["n_returned"] == 2 and first["n_withheld_gate"] == 1 and first["withheld"] == ["state:weak"]
    for payload in (first, second, third):
        for name, value in payload.items():
            if name == "withheld":  # the refs withheld, as before
                assert isinstance(value, list) and all(type(x) is str for x in value)
            else:
                assert type(value) in (int, str), (name, value)
        assert "reactor" not in json.dumps(payload) and "inspection" not in json.dumps(payload)  # no query, no content
    assert vault.recent_recalls()[-3]["returned"] == "state:old,state:new"


def test_argus_event_names_at_most_forty_returned_refs(vault, monkeypatch, tmp_path):
    pytest.importorskip("argus_ledger")
    ledger = tmp_path / "audit.jsonl"
    for i in range(45):
        _put(vault, "note", f"n{i:02d}", "reactor coolant valve " + " ".join(f"w{j}" for j in range(i)))
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(ledger))
    out = vault.recall("reactor coolant valve", match="any", limit=50, z_max_bp=10**9)
    assert len(out.results) == 45  # control: more were returned than the event names
    (payload,) = _recall_events(ledger)
    assert payload["n_returned"] == 45
    assert payload["returned"].split(",") == _refs(out)[:40]


def test_nothing_is_written_without_a_ledger_path(vault, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _two_ages(vault, monkeypatch, time.time())
    vault.recall("reactor coolant valve", match="any")
    assert list(tmp_path.iterdir()) == []
    assert vault.recent_recalls()[-1]["returned"] == "state:old,state:new"


def test_recall_with_every_option_on_writes_nothing_to_the_vault(tmp_path, monkeypatch):
    vault = _open("sqlcipher", tmp_path / "v.db", monkeypatch)
    try:
        _two_ages(vault, monkeypatch, time.time())
        _put(vault, "state", "weak", "valve")
        events = [ev.sequence for ev in vault.list_audit_events()]
        changes = vault._conn.total_changes
        out = vault.recall("reactor coolant valve", match="any", prefer_recent=True, withheld_digest_chars=40)
        assert out.results and out.withheld
        assert [ev.sequence for ev in vault.list_audit_events()] == events
        assert vault._conn.total_changes == changes
    finally:
        vault.close()


def test_the_recall_docstring_does_not_promise_a_journal_entry():
    doc = " ".join(SQLiteMemoryVault.recall.__doc__.split())
    assert "writes nothing to the vault or its journal" in doc
    assert "journaled" not in doc and "journal event" not in doc
