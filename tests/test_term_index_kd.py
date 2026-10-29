"""K-D: the keyed term index of a vault with a passphrase but without SQLCipher.

Before K-D such a vault wrote no entry words to disk and searched by opening every entry in the file
to build an index in memory, again after each write: linear in the vault. Now it keeps a term index in
the file whose tokens are HMAC-SHA256 tags, under a key derived from the passphrase, of each word with
the entry's scope, so search looks up the query's tags and opens only the entries it returns. The file
still holds no entry word in the clear. Whole words only: a query word no longer matches longer words
that start with it in this mode (the tag of "project" says nothing about the tag of "projects").
"""
import sqlite3
import statistics
import time
from pathlib import Path

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault

PASS = "term index passphrase (test only)"
OTHER_PASS = "another term index passphrase (test only)"

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
    ("travel", "trip_tokyo", "Alice flies to Tokyo in October for the robotics conference."),
    ("travel", "trip_berlin", "Bob and Carol drive to Berlin; the budget covers two nights."),
    ("pets", "dog", "Dave walks the dog named Rome twice a day around Denver."),
    ("work", "retro", "The retro moved to Wednesday; the team wants shorter meetings."),
    ("work", "hiring", "Hiring freeze until the budget review closes in Paris."),
    ("ops", "dns", "DNS for the platform lives in Route53; failover is manual."),
    ("ops", "oncall", "On-call rotates every Tuesday morning at 9:30."),
    ("ops", "patching", "Kernel patching happens on the first Friday of the month."),
    ("people", "erin", "Erin joined the platform team from Austin last May."),
    ("people", "frank", "Frank reviews every budget draft before finance sees it."),
    ("food", "dinner", "Team dinner is at the Rome cafe near the office on Thursday."),
    ("food", "snacks", "Snacks are restocked on Friday; peanuts stay out because of allergies."),
    ("health", "sleep", "Carol sleeps eight hours and runs before the standup."),
    ("health", "dentist", "Dentist appointment for Alice on the first Tuesday of October."),
    ("projects", "borealis", "Borealis moves the memory vault search to a keyed term index."),
    ("projects", "cascade", "Cascade adds failover for the billing database in us-west-2."),
    ("projects", "delta", "Delta is a draft; the team votes on its budget in May."),
    ("notes", "coffee_note", "Coffee coffee coffee: the office runs on coffee."),
    ("notes", "paris_again", "A second note about Paris, written after the conference."),
    ("notes", "denver_note", "Denver in October: the platform team meets Carol and Dave."),
    ("travel", "trip_austin", "Erin drives from Austin to Denver for the retro."),
    ("work", "release", "Release 2023.10 ships after the production freeze lifts."),
    ("ops", "bastion", "The bastion host rotates its keys every 35 days."),
    ("people", "grace", "Grace leads finance and signs every budget."),
    ("food", "tea", "Tea drinkers meet in the cafe across the street at 9:30."),
    ("health", "walk", "Bob walks five kilometers on days without a run."),
    ("projects", "echo", "Echo encrypts the search index of the memory vault."),
    ("notes", "rome_note", "Rome Rome Rome: a note that repeats Rome."),
    ("notes", "tokyo_note", "Tokyo notes from the robotics conference in October."),
    ("notes", "empty_ish", "Nothing."),
]
ALL_QUERIES = ["paris", "alice", "budget", "moved", "alice paris", "budget review", "us-east-1", "denver", "team", "9:30"]
ANY_QUERIES = ["where did alice go", "when is the budget review", "what does carol like", "paris rome coffee", "tokyo october"]


@pytest.fixture(autouse=True)
def _no_passphrase_from_environment(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)


@pytest.fixture
def no_sqlcipher(monkeypatch):
    """Run as when the sqlcipher3 driver fails to load: the vault file is plain SQLite."""
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)


def _open(path, passphrase=PASS, **kwargs):
    return SQLiteMemoryVault(str(path), passphrase=passphrase, verification_quorum=1, **kwargs)


def _fill(vault, rows=CORPUS):
    for category, key, content in rows:
        vault.put(category, key, content, epistemic_state="verified", origin="user")


def _ranking(vault, query, **kwargs):
    return [(r.entity.key, round(r.rank_score, 9)) for r in vault.search(query, limit=10, **kwargs)]


def _raw_text(path):
    """Every text value in every table of the file, lowercased, read with plain sqlite3."""
    raw = sqlite3.connect(str(path))
    try:
        tables = [r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        values = []
        for table in tables:
            for row in raw.execute(f'SELECT * FROM "{table}"'):
                values.extend(str(v).lower() for v in row if v is not None)
        return tables, values
    finally:
        raw.close()


# (a) no plaintext words reach the file, and search still finds the entry


def test_no_entry_word_is_written_to_the_file(tmp_path, no_sqlcipher):
    path = tmp_path / "v.db"
    vault = _open(path)
    vault.put("notes", "canary", "The zqxwvcanary word lives only in sealed content.", epistemic_state="verified")
    vault.put("notes", "other", "Unrelated text about lunch.", epistemic_state="verified")
    assert [r.entity.key for r in vault.search("zqxwvcanary")] == ["canary"]
    assert [r.entity.key for r in vault.search("zqxwvcanary word", match="any")][0] == "canary"
    tables, values = _raw_text(path)
    assert "entities_terms" in tables
    assert not any("zqxwvcanary" in v for v in values)
    assert not any("unrelated" in v for v in values)
    assert not any("lunch" in v for v in values)
    raw = sqlite3.connect(str(path))
    assert raw.execute("SELECT count(*) FROM entities_terms").fetchone()[0] > 0
    raw.close()
    vault.close()
    blob = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.name.startswith("v.db"))
    assert b"zqxwvcanary" not in blob and b"Unrelated" not in blob


# (b) results and ordering equal the plaintext (and so the former scanned) ranking for whole-word queries


def test_term_index_ranks_like_plaintext_for_whole_words(tmp_path, no_sqlcipher):
    vault = _open(tmp_path / "sealed.db")
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
    for query, kwargs in [("paris", {"scope": "*"}), ("budget", {"category": "work"}), ("rome", {"limit": 3})]:
        kwargs = dict(kwargs)
        limit = kwargs.pop("limit", 10)
        expected = [(r.entity.key, round(r.rank_score, 9)) for r in plain.search(query, limit=limit, **kwargs)]
        got = [(r.entity.key, round(r.rank_score, 9)) for r in vault.search(query, limit=limit, **kwargs)]
        assert got == expected, (query, kwargs)
    top = vault.search("paris", limit=10)
    assert top[0].entity.key == "paris_note"
    assert len({r.rank_score for r in top}) > 1
    assert "<b>" in vault.search("tacos")[0].snippet
    assert vault.search("?? --") == [] and vault.search("*", match="any") == []
    vault.close()
    plain.close()


def test_term_index_matches_whole_words_only(tmp_path, no_sqlcipher):
    """Documented difference from the other search paths: no prefix matches on keyed tokens."""
    vault = _open(tmp_path / "sealed.db")
    plain = SQLiteMemoryVault(str(tmp_path / "plain.db"), allow_plaintext=True)
    _fill(vault)
    _fill(plain)
    assert {r.entity.key for r in plain.search("project")} == {"atlas", "hermes", "zephyr"}  # "projects" too
    assert {r.entity.key for r in vault.search("project")} == {"atlas", "hermes"}
    assert {r.entity.key for r in vault.search("projects")} == {"atlas", "hermes", "zephyr", "borealis", "cascade", "delta", "echo"}
    assert vault.search("pari") == [] and plain.search("pari") != []
    vault.close()
    plain.close()


def test_search_keys_matches_search_and_opens_no_entries(tmp_path, no_sqlcipher, monkeypatch):
    vault = _open(tmp_path / "keys.db")
    _fill(vault)
    opened = []
    open_entry = vault._open_entry

    def counting(row):
        opened.append(row["key"])
        return open_entry(row)

    monkeypatch.setattr(vault, "_open_entry", counting)
    for query in ALL_QUERIES:
        hits = [(h.key, round(h.rank_score, 9)) for h in vault.search_keys(query, limit=10)]
        assert hits
    for query in ANY_QUERIES:
        assert vault.search_keys(query, limit=10, match="any")
    assert opened == []
    assert [(h.key, round(h.rank_score, 9)) for h in vault.search_keys("alice paris", limit=10)] == _ranking(vault, "alice paris")
    assert len(opened) == len(vault.search("alice paris", limit=10))  # search opens what it returns, nothing else
    vault.close()


# (c) sub-linear: a query hitting one entry costs about the same in a vault ten times larger


def _timed_search(vault, query, runs=7):
    """Median wall-clock time of one search, with a write between searches as a working vault has: the
    former path rebuilt its whole in-memory index after every write, so each search paid for the vault."""
    samples = []
    for i in range(runs + 1):
        vault.put("notes", f"between_{i}", f"a write between searches number {i}", epistemic_state="verified")
        start = time.perf_counter()
        hits = vault.search(query)
        elapsed = time.perf_counter() - start
        assert len(hits) == 1
        if i:  # the first search warms the page and key caches
            samples.append(elapsed)
    return statistics.median(samples)


def test_search_cost_does_not_grow_with_the_vault(tmp_path, no_sqlcipher):
    timings = {}
    for size in (200, 2000):
        vault = _open(tmp_path / f"v{size}.db")
        for i in range(size):
            vault.put("notes", f"k{i}", f"Entry number {i} about ordinary matters and the usual words.", epistemic_state="verified")
        vault.put("notes", "needle", "The zqxneedle sits in exactly one entry.", epistemic_state="verified")
        timings[size] = _timed_search(vault, "zqxneedle")
        vault.close()
    small, large = timings[200], timings[2000]
    print(f"search over 200 entries: {small * 1e3:.3f} ms; over 2000 entries: {large * 1e3:.3f} ms")
    assert large < 3 * small, timings
    assert large < 0.05, timings  # the former path took tens of milliseconds per query at this size


# (d) tokens are keyed: they differ between scopes and between vaults


def test_tokens_differ_between_scopes_and_vaults(tmp_path, no_sqlcipher):
    one = _open(tmp_path / "one.db")
    two = _open(tmp_path / "two.db")  # same passphrase, another salt
    three = _open(tmp_path / "three.db", passphrase=OTHER_PASS)
    tokens = {
        "one/default": one._term_token("default", "paris"),
        "one/team": one._term_token("team", "paris"),
        "two/default": two._term_token("default", "paris"),
        "three/default": three._term_token("default", "paris"),
    }
    assert len(set(tokens.values())) == len(tokens), tokens
    assert one._term_token("default", "paris") == one._term_token("default", "paris")
    assert all(len(t) == 16 and set(t) <= set("0123456789abcdef") for t in tokens.values())
    # the term key is its own key: neither the signing key nor the digest key
    assert one._term_key not in (one._signing_key, one._digest_key)
    for v in (one, two, three):
        v.close()
    again = _open(tmp_path / "one.db")
    assert again._term_token("default", "paris") == tokens["one/default"]
    again.close()


# (e) a vault written before the term index existed gets one on open


def _strip_term_index(path):
    vault = _open(path)
    for trigger in ("entities_search_ai", "entities_search_au", "entities_search_ad"):
        vault._conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    vault._conn.execute("DROP TABLE IF EXISTS entities_terms")
    vault._conn.execute("DROP TABLE IF EXISTS entities_terms_docs")
    vault._conn.execute("DROP TABLE IF EXISTS entities_search_dirty")
    vault._conn.execute("DELETE FROM vault_meta WHERE key = 'term_index_format'")
    vault._conn.commit()
    vault.close()


def _doc_count(vault):
    return vault._conn.execute("SELECT count(*) FROM entities_terms_docs").fetchone()[0]


def test_an_older_vault_gets_its_term_index_on_open(tmp_path, no_sqlcipher):
    path = tmp_path / "v.db"
    vault = _open(path)
    _fill(vault)
    before = {q: _ranking(vault, q) for q in ALL_QUERIES}
    vault.close()
    _strip_term_index(path)
    raw = sqlite3.connect(str(path))
    assert "entities_terms" not in [r[0] for r in raw.execute("SELECT name FROM sqlite_master")]
    raw.close()
    vault = _open(path)
    assert _doc_count(vault) == len(CORPUS)
    assert vault._meta("term_index_format") is not None
    assert {q: _ranking(vault, q) for q in ALL_QUERIES} == before
    vault.close()
    again = _open(path)  # a second open changes nothing
    assert _doc_count(again) == len(CORPUS)
    assert {q: _ranking(again, q) for q in ALL_QUERIES} == before
    again.close()


def test_rows_written_without_the_index_are_indexed_before_search(tmp_path, no_sqlcipher):
    """A process running an older kibisis writes rows without feeding the index; triggers queue them."""
    vault = _open(tmp_path / "v.db")
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


# (f) the index follows every write


def test_writes_leave_no_stale_hits(tmp_path, no_sqlcipher):
    vault = _open(tmp_path / "v.db")
    vault.put("notes", "k1", "alpha banana", epistemic_state="verified")
    vault.put("notes", "k2", "delta echo", epistemic_state="verified")
    vault.put("notes", "k3", "foxtrot golf", epistemic_state="verified")
    vault.put("notes", "k4", "hotel india", epistemic_state="verified")
    assert [r.entity.key for r in vault.search("banana")] == ["k1"]
    vault.put("notes", "k1", "alpha cherry", epistemic_state="verified")
    assert vault.search("banana") == []
    assert [r.entity.key for r in vault.search("cherry")] == [k for k in ["k1"]]
    assert vault.purge("notes", "k1")
    assert vault.search("alpha") == [] and vault.search("cherry", match="any") == []
    vault.tombstone("notes", "k2", reason="test")
    assert vault.search("echo") == []
    assert vault.archive("notes", "k4")
    assert vault.search("india") == []
    assert [r.entity.key for r in vault.search("golf")] == ["k3"]
    live = {r[0] for r in vault._conn.execute("SELECT id FROM entities")}
    indexed = {r[0] for r in vault._conn.execute("SELECT DISTINCT id FROM entities_terms")}
    assert indexed <= live and _doc_count(vault) == len(live)
    vault.scrub()
    assert [r.entity.key for r in vault.search("golf")] == ["k3"]
    assert _doc_count(vault) == len(live)
    vault.close()


def test_index_follows_writes_from_another_connection(tmp_path, no_sqlcipher):
    path = tmp_path / "shared.db"
    reader = _open(path)
    writer = _open(path)
    writer.put("notes", "a", "first kiwi note", epistemic_state="verified")
    assert [r.entity.key for r in reader.search("kiwi")] == ["a"]
    writer.put("notes", "b", "second kiwi note", epistemic_state="verified")
    writer.put("notes", "a", "first lemon note", epistemic_state="verified")
    assert [r.entity.key for r in reader.search("kiwi")] == ["b"]
    assert [r.entity.key for r in reader.search("lemon")] == ["a"]
    writer.close()
    reader.close()


def test_snapshot_import_feeds_the_index(tmp_path, no_sqlcipher):
    source = _open(tmp_path / "source.db")
    _fill(source)
    snapshot = tmp_path / "snap.json"
    source.export_snapshot(str(snapshot))
    source.close()
    target = _open(tmp_path / "target.db")
    target.put("notes", "stale", "a quokka that clear_existing removes", epistemic_state="verified")
    target.import_snapshot(str(snapshot), clear_existing=True)
    assert target.search("quokka") == []
    assert [r.entity.key for r in target.search("paris", limit=1)] == ["paris_note"]
    assert _doc_count(target) == len(CORPUS)
    target.close()


def test_sqlcipher_and_plaintext_vaults_keep_no_term_table(tmp_path, monkeypatch):
    plain = SQLiteMemoryVault(str(tmp_path / "plain.db"), allow_plaintext=True)
    plain.put("notes", "k", "orchid", epistemic_state="verified")
    assert [r.entity.key for r in plain.search("orchid")] == ["k"]
    assert not plain._term_index
    plain.close()
    tables, _ = _raw_text(tmp_path / "plain.db")
    assert "entities_terms" not in tables
    if not vault_module._sqlcipher_available():
        pytest.skip("sqlcipher3 is not installed")
    vault = _open(tmp_path / "cipher.db")
    assert vault._sqlcipher_active and not vault._term_index
    names = [r[0] for r in vault._conn.execute("SELECT name FROM sqlite_master")]
    assert "entities_terms" not in names
    vault.close()
