"""Ranked search over sealed entries (0.1.0a7).

With SQLCipher, kibisis keeps a contentless FTS5 index of entry text inside the encrypted database file.
Without SQLCipher it never writes entry terms to disk: search ranks an in-memory index of the decrypted
entries. Either way a vault with a passphrase ranks results with the same BM25 scores as a plaintext
vault holding the same entries.
"""
import json
import shutil
import sqlite3
import time
from pathlib import Path

import pytest

import kibisis.vault as vault_module
from kibisis import KibisisMCPServer, SQLiteMemoryVault

PASS = "ranked search passphrase (test only)"
FIXTURE = Path(__file__).parent / "fixtures" / "vault-0.1.0a5-fallback.sqlite"
FIXTURE_PASS = "legacy fixture passphrase (test only)"  # see tests/fixtures/make_legacy_vault.py

CORPUS = [
    ("travel", "trip_2023", "Alice moved to Paris in May 2023 after the conference."),
    ("travel", "trip_rome", "Bob likes Paris and Rome; Rome has the better coffee."),
    ("pets", "cat", "Alice adopted a cat named Paris from the shelter."),
    ("work", "standup", "The team standup moved to Tuesday at 9:30."),
    ("work", "budget", "The quarterly budget review is on Friday; finance wants the draft budget by Thursday."),
    ("work", "deploy", "Deploys to production freeze during the budget review week."),
    ("ops", "region", "Primary region is us-east-1 with failover to us-west-2."),
    ("ops", "firewall", "Strict inbound deny-all on port 22 except the bastion host."),
    ("ops", "backup", "Nightly backups run at 02:00 and are kept for 35 days."),
    ("people", "carol", "Carol prefers email over chat and works from Denver."),
    ("people", "dave", "Dave moved from Denver to Austin and now leads the platform team."),
    ("food", "lunch", "Lunch on Fridays is tacos; the team votes on Thursday."),
    ("food", "coffee", "The office coffee machine is broken; use the cafe across the street."),
    ("health", "allergy", "Alice is allergic to peanuts and shellfish."),
    ("health", "run", "Bob runs five kilometers every morning before work."),
    ("projects", "atlas", "Project Atlas migrates the billing database to Postgres by Q3."),
    ("projects", "hermes", "Project Hermes adds encrypted search to the memory vault."),
    ("projects", "zephyr", "Zephyr is paused until the budget is approved."),
    ("notes", "paris_note", "Paris Paris Paris: the word appears often in this note about Paris."),
    ("notes", "misc", "Nothing relevant here at all."),
]
ALL_QUERIES = ["paris", "alice", "budget", "moved", "alice paris", "budget review", "us-east-1", "project", "denver", "team"]
ANY_QUERIES = ["where did alice move", "when is the budget review", "what does carol prefer", "paris rome coffee"]


@pytest.fixture(autouse=True)
def _no_passphrase_from_environment(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)


def _open(kind, path, monkeypatch, passphrase=PASS):
    """A vault of the given kind: 'plain' (no passphrase), 'sqlcipher', or 'fallback' (sqlcipher3 absent)."""
    if kind == "fallback":
        monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    elif kind == "sqlcipher":
        if not vault_module._sqlcipher_available():
            pytest.skip("sqlcipher3 is not installed")
        if vault_module.sqlcipher3.sqlite_version_info < (3, 43, 0):
            pytest.skip("this SQLCipher's SQLite predates contentless-delete FTS5 tables (3.43)")
    if kind == "plain":
        return SQLiteMemoryVault(str(path), allow_plaintext=True)
    return SQLiteMemoryVault(str(path), passphrase=passphrase)


def _fill(vault, rows=CORPUS):
    for category, key, content in rows:
        vault.put(category, key, content, epistemic_state="verified")


def _ranking(vault, query, **kwargs):
    return [(r.entity.key, round(r.rank_score, 9)) for r in vault.search(query, limit=10, **kwargs)]


@pytest.mark.parametrize("kind", ["sqlcipher", "fallback"])
def test_sealed_entries_rank_like_plaintext(tmp_path, monkeypatch, kind):
    vault = _open(kind, tmp_path / "sealed.db", monkeypatch)
    plain = SQLiteMemoryVault(str(tmp_path / "plain.db"), allow_plaintext=True)
    _fill(vault)
    _fill(plain)
    assert vault._conn.execute("SELECT count(*) FROM entities WHERE is_encrypted = 1").fetchone()[0] == len(CORPUS)
    for query in ALL_QUERIES:
        expected = _ranking(plain, query)
        assert expected, query
        assert _ranking(vault, query) == expected, query
    for query in ANY_QUERIES:
        expected = _ranking(plain, query, match="any")
        assert expected, query
        assert _ranking(vault, query, match="any") == expected, query
    # Scores are BM25, not a placeholder: the note that repeats "paris" ranks first.
    top = vault.search("paris", limit=10)
    assert top[0].entity.key == "paris_note"
    assert len({r.rank_score for r in top}) > 1
    assert "<b>" in vault.search("tacos")[0].snippet
    vault.close()
    plain.close()


@pytest.mark.parametrize("kind", ["plain", "sqlcipher", "fallback"])
def test_any_mode_finds_a_question_that_all_mode_misses(tmp_path, monkeypatch, kind):
    vault = _open(kind, tmp_path / "v.db", monkeypatch)
    _fill(vault)
    assert vault.search("Where did Alice move?") == []
    results = vault.search("Where did Alice move?", match="any")
    assert results[0].entity.key == "trip_2023"
    with pytest.raises(ValueError):
        vault.search("alice", match="some")
    vault.close()


@pytest.mark.parametrize("kind", ["plain", "sqlcipher", "fallback"])
def test_queries_without_words_return_nothing(tmp_path, monkeypatch, kind):
    vault = _open(kind, tmp_path / "v.db", monkeypatch)
    _fill(vault)
    for query in ["?? --", '"', "*", "  ", "(", "-"]:
        assert vault.search(query) == [], query
        assert vault.search(query, match="any") == [], query
    vault.close()


@pytest.mark.parametrize("kind", ["plain", "sqlcipher", "fallback"])
def test_update_and_forget_leave_no_stale_hits(tmp_path, monkeypatch, kind):
    vault = _open(kind, tmp_path / "v.db", monkeypatch)
    vault.put("notes", "k1", "alpha banana", epistemic_state="verified")
    vault.put("notes", "k2", "delta echo", epistemic_state="verified")
    vault.put("notes", "k3", "foxtrot golf", epistemic_state="verified")
    assert [r.entity.key for r in vault.search("banana")] == ["k1"]
    vault.put("notes", "k1", "alpha cherry", epistemic_state="verified")
    assert vault.search("banana") == []
    assert [r.entity.key for r in vault.search("cherry")] == ["k1"]
    assert vault.purge("notes", "k1")
    assert vault.search("alpha") == []
    assert vault.search("cherry", match="any") == []
    vault.tombstone("notes", "k2", reason="test")
    assert vault.search("echo") == []
    assert [r.entity.key for r in vault.search("golf")] == ["k3"]
    if kind == "sqlcipher":
        index = vault._conn
        for term in ("banana", "cherry", "echo"):
            hits = index.execute("SELECT rowid FROM entities_search WHERE entities_search MATCH ?", (term,)).fetchall()
            assert hits == [], term
    vault.close()


def test_scrub_removes_deleted_terms_from_the_search_index(tmp_path, monkeypatch):
    vault = _open("sqlcipher", tmp_path / "v.db", monkeypatch)
    vault.put("notes", "gone", "zqxcanary alpha", epistemic_state="verified")
    vault.put("notes", "kept", "bravo charlie", epistemic_state="verified")
    vault.put("notes", "gone", "zqxcanary2 alpha", epistemic_state="verified")
    assert vault.purge("notes", "gone")

    def index_bytes():
        return b"".join(bytes(r[0] or b"") for r in vault._conn.execute("SELECT block FROM entities_search_data"))

    vault.scrub()
    assert b"zqxcanary" not in index_bytes()
    assert [r.entity.key for r in vault.search("charlie")] == ["kept"]
    docs = vault._conn.execute("SELECT count(*) FROM entities_search_docsize").fetchone()[0]
    assert docs == vault._conn.execute("SELECT count(*) FROM entities").fetchone()[0] == 1
    vault.close()


def test_fallback_never_writes_entry_terms_to_disk(tmp_path, monkeypatch):
    path = tmp_path / "fallback.db"
    vault = _open("fallback", path, monkeypatch)
    vault.put("notes", "canary", "The zqxwvcanary term lives only in sealed content.", epistemic_state="verified")
    vault.put("notes", "other", "Unrelated text about lunch.", epistemic_state="verified")
    assert [r.entity.key for r in vault.search("zqxwvcanary")] == ["canary"]
    assert [r.entity.key for r in vault.search("zqxwvcanary term", match="any")][0] == "canary"
    raw = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.name.startswith("fallback.db"))
    assert b"zqxwvcanary" not in raw
    vault.close()
    raw = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.name.startswith("fallback.db"))
    assert b"zqxwvcanary" not in raw


def test_fallback_index_follows_writes_from_another_connection(tmp_path, monkeypatch):
    path = tmp_path / "fallback.db"
    reader = _open("fallback", path, monkeypatch)
    writer = _open("fallback", path, monkeypatch)
    writer.put("notes", "a", "first kiwi note", epistemic_state="verified")
    assert [r.entity.key for r in reader.search("kiwi")] == ["a"]
    writer.put("notes", "b", "second kiwi note", epistemic_state="verified")
    writer.put("notes", "a", "first lemon note", epistemic_state="verified")
    assert [r.entity.key for r in reader.search("kiwi")] == ["b"]
    assert [r.entity.key for r in reader.search("lemon")] == ["a"]
    writer.close()
    reader.close()


@pytest.mark.parametrize("kind", ["sqlcipher", "fallback"])
def test_filters_behave_as_in_a_plaintext_vault(tmp_path, monkeypatch, kind):
    now = time.time()
    rows = [
        dict(category="f", key="v1", content="orchid alpha", epistemic_state="verified"),
        dict(category="f", key="c1", content="orchid beta", epistemic_state="candidate"),
        dict(category="f", key="d1", content="orchid gamma", epistemic_state="disputed"),
        dict(category="g", key="v2", content="orchid delta", epistemic_state="verified", scope="team"),
        dict(category="g", key="old", content="orchid epsilon", epistemic_state="verified", valid_from=now - 100, valid_until=now - 50),
        dict(category="g", key="future", content="orchid zeta", epistemic_state="verified", valid_from=now + 1000),
        dict(category="f", key="t1", content="orchid eta", epistemic_state="verified", tenant_id="acme"),
        dict(category="f", key="t2", content="orchid theta", epistemic_state="verified", tenant_id="globex"),
        dict(category="f", key="arch", content="orchid iota", epistemic_state="verified"),
    ]
    vault = _open(kind, tmp_path / "sealed.db", monkeypatch)
    plain = SQLiteMemoryVault(str(tmp_path / "plain.db"), allow_plaintext=True)
    for v in (vault, plain):
        for row in rows:
            row = dict(row)
            v.put(row.pop("category"), row.pop("key"), row.pop("content"), **row)
        v.archive("f", "arch")
    cases = [
        {},
        {"include_unverified": True},
        {"scope": "team"},
        {"scope": "*"},
        {"scope": "*", "category": "g"},
        {"epistemic_state": "candidate"},
        {"scope": "*", "as_of_valid_time": now - 75},
        {"scope": "*", "active_only": False},
        {"tenant_id": "acme"},
        {"scope": "*", "limit": 2},
        {"scope": "*", "match": "any"},
    ]
    for case in cases:
        case = dict(case)
        limit = case.pop("limit", 10)
        expected = [r.entity.key for r in plain.search("orchid", limit=limit, **case)]
        assert [r.entity.key for r in vault.search("orchid", limit=limit, **case)] == expected, case
    vault.close()
    plain.close()


def _index_doc_count(vault):
    return vault._conn.execute("SELECT count(*) FROM entities_search_docsize").fetchone()[0]


def _strip_search_index(path):
    """Take a vault back to the 0.1.0a6 schema: no entry index, as the live vault has before migrating."""
    vault = SQLiteMemoryVault(str(path), passphrase=PASS)
    for trigger in ("entities_search_ai", "entities_search_au", "entities_search_ad"):
        vault._conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    vault._conn.execute("DROP TABLE IF EXISTS entities_search")
    vault._conn.execute("DROP TABLE IF EXISTS entities_search_dirty")
    vault._conn.execute("DELETE FROM vault_meta WHERE key = 'search_index_format'")
    vault._conn.commit()
    vault.close()


def test_an_older_sqlcipher_vault_gets_its_index_on_open(tmp_path, monkeypatch):
    path = tmp_path / "v.db"
    vault = _open("sqlcipher", path, monkeypatch)
    _fill(vault)
    before = {q: _ranking(vault, q) for q in ALL_QUERIES}
    vault.close()
    _strip_search_index(path)
    vault = _open("sqlcipher", path, monkeypatch)
    assert _index_doc_count(vault) == len(CORPUS)
    assert {q: _ranking(vault, q) for q in ALL_QUERIES} == before
    vault.close()
    again = _open("sqlcipher", path, monkeypatch)  # a second open changes nothing
    assert _index_doc_count(again) == len(CORPUS)
    assert {q: _ranking(again, q) for q in ALL_QUERIES} == before
    again.close()


@pytest.mark.parametrize("kind", ["sqlcipher", "fallback"])
def test_upgrading_a_0_1_0a5_vault_indexes_its_sealed_entries(tmp_path, monkeypatch, kind):
    db = tmp_path / "legacy.sqlite"
    shutil.copyfile(FIXTURE, db)
    vault = _open(kind, db, monkeypatch, passphrase=FIXTURE_PASS)
    found = {
        "lobby": [r.entity.key for r in vault.search("lobby")],
        "email": [r.entity.key for r in vault.search("email", scope="team")],
        "standup": [r.entity.key for r in vault.search("standup", include_unverified=True)],
        "lobby opens": [r.entity.key for r in vault.search("when does the lobby open", match="any")],
    }
    assert found == {"lobby": ["public_note"], "email": ["alice"], "standup": ["draft"], "lobby opens": ["public_note"]}
    vault.close()
    again = _open(kind, db, monkeypatch, passphrase=FIXTURE_PASS)
    assert [r.entity.key for r in again.search("lobby")] == ["public_note"]
    # Reads refuse the entry that has no signature until it is adopted, and so does search.
    assert again.search("signatures existed") == []
    rows = again._conn.execute("SELECT count(*) FROM entities").fetchone()[0]
    if kind == "sqlcipher":
        assert _index_doc_count(again) == rows - 1
    assert again.adopt_unsigned_entries() == 1
    assert [r.entity.key for r in again.search("signatures existed")] == ["unsigned_legacy"]
    if kind == "sqlcipher":
        assert _index_doc_count(again) == rows
    again.close()


def test_entries_written_without_indexing_are_indexed_before_search(tmp_path, monkeypatch):
    """A process running an older kibisis writes rows without feeding the index; triggers queue them."""
    vault = _open("sqlcipher", tmp_path / "v.db", monkeypatch)
    vault.put("notes", "seen", "mango lassi", epistemic_state="verified")
    vault._index_entry = lambda *args, **kwargs: None  # as an older version writes
    vault.put("notes", "late", "mango sorbet", epistemic_state="verified")
    vault.put("notes", "seen", "papaya lassi", epistemic_state="verified")
    del vault._index_entry
    assert vault._conn.execute("SELECT count(*) FROM entities_search_dirty").fetchone()[0] == 2
    assert [r.entity.key for r in vault.search("mango")] == ["late"]
    assert [r.entity.key for r in vault.search("papaya")] == ["seen"]
    assert vault._conn.execute("SELECT count(*) FROM entities_search_dirty").fetchone()[0] == 0
    vault.close()


def _call(server, tool, arguments):
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    )
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


def test_mcp_recall_matches_any_word_by_default(tmp_path):
    vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
    server = KibisisMCPServer(vault=vault, scope="default")
    is_error, text = _call(
        server, "kibisis_remember", {"category": "work", "key": "standup", "content": "The team standup moved to Tuesday."}
    )
    assert not is_error, text
    _, text = _call(server, "kibisis_recall", {"query": "when is the standup now?"})
    assert 'count="1"' in text and 'key="standup"' in text
    _, text = _call(server, "kibisis_recall", {"query": "when is the standup now?", "match": "all"})
    assert 'count="0"' in text
    is_error, text = _call(server, "kibisis_recall", {"query": "standup", "match": "some"})
    assert is_error
    tools = json.dumps(server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    assert '"match"' in tools
    vault.close()


# Keys-only search (0.1.0a8): search_keys() finds what search() finds without opening any entry.


def _key_ranking(vault, query, **kwargs):
    return [(h.key, round(h.rank_score, 9)) for h in vault.search_keys(query, limit=10, **kwargs)]


@pytest.mark.parametrize("kind", ["plain", "sqlcipher", "fallback"])
def test_search_keys_returns_the_entries_and_scores_of_search(tmp_path, monkeypatch, kind):
    vault = _open(kind, tmp_path / "keys.db", monkeypatch)
    _fill(vault)
    for query in ALL_QUERIES:
        assert _key_ranking(vault, query) == _ranking(vault, query), query
    for query in ANY_QUERIES:
        assert _key_ranking(vault, query, match="any") == _ranking(vault, query, match="any"), query
    hit, result = vault.search_keys("budget review", limit=1)[0], vault.search("budget review", limit=1)[0]
    assert (hit.id, hit.category, hit.key, hit.scope) == (
        result.entity.id, result.entity.category, result.entity.key, result.entity.scope
    )
    assert vault.search_keys("?!", limit=10) == []
    with pytest.raises(ValueError):
        vault.search_keys("paris", match="some")
    vault.close()


@pytest.mark.parametrize("kind", ["plain", "sqlcipher", "fallback"])
def test_search_keys_opens_no_entries(tmp_path, monkeypatch, kind):
    vault = _open(kind, tmp_path / "keys.db", monkeypatch)
    _fill(vault)
    vault.search("paris")  # indexes the new entries (SQLCipher) or builds the in-memory index (fallback)
    opened = []
    open_entry = vault._open_entry

    def counting(row):
        opened.append(row["key"])
        return open_entry(row)

    monkeypatch.setattr(vault, "_open_entry", counting)
    for query in ALL_QUERIES:
        vault.search_keys(query, limit=10)
    for query in ANY_QUERIES:
        vault.search_keys(query, limit=10, match="any", tenant_id="acme", authorized_lineage_roots=[])
    assert opened == []
    assert len(vault.search("paris", limit=3)) == 3
    assert len(opened) == 3  # search() opens each entry it returns, and no others
    vault.close()


@pytest.mark.parametrize("kind", ["plain", "sqlcipher", "fallback"])
def test_search_keys_applies_the_filters_and_boundaries_of_search(tmp_path, monkeypatch, kind):
    now = time.time()
    rows = [
        dict(category="f", key="v1", content="orchid alpha", epistemic_state="verified"),
        dict(category="f", key="c1", content="orchid beta", epistemic_state="candidate"),
        dict(category="g", key="v2", content="orchid delta", epistemic_state="verified", scope="team"),
        dict(category="g", key="old", content="orchid epsilon", epistemic_state="verified", valid_from=now - 100, valid_until=now - 50),
        dict(category="f", key="t1", content="orchid eta", epistemic_state="verified", tenant_id="acme", principal_id="ann"),
        dict(category="f", key="t2", content="orchid theta", epistemic_state="verified", tenant_id="globex", principal_id="bo"),
        dict(category="f", key="l1", content="orchid kappa", epistemic_state="verified", derived_from=["root-a"]),
        dict(category="f", key="l2", content="orchid lambda", epistemic_state="verified", derived_from=["root-b"]),
        dict(category="f", key="arch", content="orchid iota", epistemic_state="verified"),
    ]
    vault = _open(kind, tmp_path / "keys.db", monkeypatch)
    for row in rows:
        row = dict(row)
        vault.put(row.pop("category"), row.pop("key"), row.pop("content"), **row)
    vault.archive("f", "arch")
    cases = [
        {},
        {"include_unverified": True},
        {"scope": "team"},
        {"scope": "*", "category": "g"},
        {"epistemic_state": "candidate"},
        {"scope": "*", "as_of_valid_time": now - 75},
        {"tenant_id": "acme"},
        {"principal_id": "bo"},
        {"authorized_lineage_roots": ["root-a"]},
        {"scope": "*", "limit": 2},
        {"scope": "*", "match": "any", "tenant_id": "globex"},
    ]
    for case in cases:
        case = dict(case)
        limit = case.pop("limit", 10)
        expected = [(r.entity.key, round(r.rank_score, 9)) for r in vault.search("orchid", limit=limit, **case)]
        got = [(h.key, round(h.rank_score, 9)) for h in vault.search_keys("orchid", limit=limit, **case)]
        assert got == expected, case
    # the boundaries do leave entries out, so the comparison above is not vacuous
    keys = {h.key for h in vault.search_keys("orchid", limit=10)}
    assert {"t1", "t2", "l1", "l2", "v1"} <= keys and not {"c1", "v2", "old", "arch"}.intersection(keys)
    assert {h.key for h in vault.search_keys("orchid", limit=10, tenant_id="acme")} == keys - {"t2"}
    assert {h.key for h in vault.search_keys("orchid", limit=10, authorized_lineage_roots=["root-a"])} == keys - {"l2"}
    vault.close()


def test_memory_security_is_on_by_default_and_can_be_left_off(tmp_path):
    """SQLCipher's cipher_memory_security is process-wide, so each setting is checked in a fresh process."""
    if not vault_module._sqlcipher_available():
        pytest.skip("sqlcipher3 is not installed")
    import subprocess
    import sys

    src = str(Path(vault_module.__file__).resolve().parents[1])
    probe = (
        "import sys; sys.path.insert(0, {src!r}); from kibisis import SQLiteMemoryVault; "
        "v = SQLiteMemoryVault({path!r}, passphrase={pw!r}{extra}); "
        "print(v._conn.execute('PRAGMA cipher_memory_security').fetchone()[0])"
    )
    untouched = (
        "import sqlcipher3; c = sqlcipher3.connect({path!r}); c.execute(\"PRAGMA key = 'x'\"); "
        "print(c.execute('PRAGMA cipher_memory_security').fetchone()[0])"
    )
    env = {k: v for k, v in __import__("os").environ.items() if not k.startswith("KIBISIS_")}
    seen = []
    for code in (
        untouched.format(path=str(tmp_path / "raw.db")),
        probe.format(src=src, path=str(tmp_path / "on.db"), pw=PASS, extra=""),
        probe.format(src=src, path=str(tmp_path / "off.db"), pw=PASS, extra=", memory_security=False"),
    ):
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True)
        seen.append(out.stdout.strip())
    sqlcipher_default, default, left_off = seen
    assert default == "1"
    assert left_off == sqlcipher_default  # kibisis leaves SQLCipher's own setting alone


def test_cache_mb_sets_the_page_cache_and_the_default_is_unchanged(tmp_path, monkeypatch):
    default = _open("plain", tmp_path / "default.db", monkeypatch)
    before = default._conn.execute("PRAGMA cache_size").fetchone()[0]
    default.close()
    for kind in ("plain", "sqlcipher"):
        path = tmp_path / f"{kind}.db"
        if kind == "plain":
            vault = SQLiteMemoryVault(str(path), allow_plaintext=True, cache_mb=64)
        else:
            if not vault_module._sqlcipher_available():
                continue
            vault = SQLiteMemoryVault(str(path), passphrase=PASS, cache_mb=64)
        assert vault._conn.execute("PRAGMA cache_size").fetchone()[0] == -64 * 1024
        _fill(vault)
        assert _key_ranking(vault, "budget")  # searches as before
        vault.close()
    assert before != -64 * 1024
    with pytest.raises(ValueError):
        SQLiteMemoryVault(str(tmp_path / "bad.db"), allow_plaintext=True, cache_mb=0)
