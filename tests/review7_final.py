"""Round-7 (final confirmation) review tests for kibisis at 28f56d1.

Not collected by default (``tests/review7_*.py`` is outside the ``test_*.py`` glob).
Run with::

    ARGUS_LEDGER_PATH=$TMPDIR/argus_r7.jsonl PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/review7_*.py

``test_control_*`` = behaviour confirmed secure; ``test_attack_*`` = defect demonstration
(a passing attack test means the defect is present).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kibisis.vault as vault_module  # noqa: E402
from kibisis import SQLiteMemoryVault  # noqa: E402
from kibisis.config import ConfigError  # noqa: E402
from kibisis.vault import VaultIntegrityError  # noqa: E402

import test_review3_ab_migration as M  # noqa: E402
import test_review5_discriminator as R5  # noqa: E402

PASS = M.PASS
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _plain_sqlite(monkeypatch):
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    for k in ("KIBISIS_PASSPHRASE", "KIBISIS_PASSPHRASE_FILE", "KIBISIS_DB_PATH",
              "KIBISIS_VERIFICATION_QUORUM", "KIBISIS_SCOPE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


class _conn:
    """Connection context that commits AND closes (sqlite3's own context manager only commits)."""

    def __init__(self, p):
        self.c = sqlite3.connect(str(p))
        self.c.row_factory = sqlite3.Row

    def __enter__(self):
        return self.c

    def __exit__(self, et, ev, tb):
        if et is None:
            self.c.commit()
        self.c.close()
        return False


def _dump(p):
    """Content hash of every table, for a 'nothing written' check that ignores header counters."""
    with _conn(p) as c:
        out = {}
        for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            rows = [[x.hex() if isinstance(x, bytes) else x for x in r] for r in c.execute(f"SELECT * FROM {t}")]
            out[t] = hashlib.sha256(json.dumps(rows, default=str).encode()).hexdigest()
        return out


def _meta(p):
    with _conn(p) as c:
        return {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM vault_meta")}


def _tables(p):
    with _conn(p) as c:
        return sorted(r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'"))


def _open(p, **kw):
    return SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, **kw)


_FORGED = {
    "author_id": "alice", "origin_class": "principal", "act_class": "act",
    "human_reviews": [1], "tenant_id": "t1", "principal_id": "p1", "slot": "s",
    "lineage_root": "x", "custom": 1, "derived_from": ["a"], "conflicts_with": ["b"],
    "attestations": ["alice", "bob"],
    "agent_metadata": {"human_reviews": [{"reviewer_id": "bob", "verdict": "verified"}]},
}


def _forge(p, keys=("k0",)):
    with _conn(p) as c:
        for key in keys:
            row = c.execute("SELECT metadata_json FROM entities WHERE key=?", (key,)).fetchone()
            m = json.loads(row[0] or "{}")
            m.update(_FORGED)
            c.execute("UPDATE entities SET metadata_json=?, origin='user' WHERE key=?", (json.dumps(m), key))


# ---------------------------------------------------------------------------
# A. Round-6 diff: _refuse_unadopted_keyless_rows gate and the init-meta set
# ---------------------------------------------------------------------------

def test_control_r7_fresh_plaintext_vault_writes_only_init_meta_and_is_adopted_silently(tmp_path):
    """A plaintext vault that never stored content writes only keys the gate treats as 'init'
    (schema_version, optionally quorum/salt/key-check), so a first keyed open is a fresh vault (R6-1b)."""
    p = tmp_path / "fresh.sqlite"
    SQLiteMemoryVault(str(p), allow_plaintext=True, auto_gate=False).close()
    assert set(_meta(p)) <= {"schema_version", "kdf_salt", "key_check", "meta_mac", "verification_quorum",
                             "integrity_format", "journal_format_floor", "journal_anchored", "term_index_format"}
    with _conn(p) as c:
        assert c.execute("SELECT count(*) FROM entities").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM audit_journal").fetchone()[0] == 0
    v = _open(p)
    try:
        assert v.keyless_adoption() is None
    finally:
        v.close()


def test_control_r7_keyless_vault_with_only_a_lease_table_row_is_not_refused(tmp_path):
    """A lease row is not vault content; the gate counts entities, tombstones, journal and non-init meta."""
    p = tmp_path / "lease.sqlite"
    SQLiteMemoryVault(str(p), allow_plaintext=True, auto_gate=False).close()
    with _conn(p) as c:
        c.execute("CREATE TABLE IF NOT EXISTS leases (resource TEXT PRIMARY KEY, holder TEXT)")
        c.execute("INSERT INTO leases VALUES ('r', 'h')")
    v = _open(p)
    try:
        assert v.keyless_adoption() is None
    finally:
        v.close()


def test_control_r7_keyless_vault_with_one_entity_is_refused_without_opt_in(tmp_path):
    p = tmp_path / "one.sqlite"
    v = SQLiteMemoryVault(str(p), allow_plaintext=True, auto_gate=False)
    v.remember("decision", "k0", "plain", origin="model", author_id="agent")
    v.close()
    with pytest.raises(VaultIntegrityError, match="adopt_keyless"):
        _open(p)
    with pytest.raises(VaultIntegrityError, match="adopt_keyless"):
        _open(p, read_only=True)


def test_control_r7_keyless_journal_with_no_entries_is_refused_even_with_opt_in(tmp_path):
    pl = R5._laundered_keyless_file(tmp_path, "j.sqlite")
    with _conn(pl) as c:
        c.execute("DELETE FROM entities")
    with pytest.raises(VaultIntegrityError):
        _open(pl)
    with pytest.raises(VaultIntegrityError, match="not adoptable"):
        _open(pl, adopt_keyless=True)


def test_control_r7_keyless_file_with_a_planted_non_init_meta_key_is_refused(tmp_path):
    p = tmp_path / "meta.sqlite"
    SQLiteMemoryVault(str(p), allow_plaintext=True, auto_gate=False).close()
    with _conn(p) as c:
        c.execute("INSERT INTO vault_meta (key, value) VALUES ('journal_anchored', '1')")
    with pytest.raises(VaultIntegrityError):
        _open(p)


# ---------------------------------------------------------------------------
# A. _demote_adopted_row vs a model-origin _put
# ---------------------------------------------------------------------------

def test_control_r7_adopted_row_is_field_for_field_a_model_candidate(tmp_path):
    pk = tmp_path / "keyed.sqlite"
    v = _open(pk)
    v.remember("decision", "k0", "FORGED", origin="model", author_id="alice", metadata=dict(_FORGED))
    v.close()
    with _conn(pk) as c:
        put_row = dict(c.execute("SELECT * FROM entities WHERE key='k0'").fetchone())

    pl = R5._laundered_keyless_file(tmp_path, "laund.sqlite")
    _forge(pl)
    _open(pl, adopt_keyless=True).close()
    with _conn(pl) as c:
        ad_row = dict(c.execute("SELECT * FROM entities WHERE key='k0'").fetchone())

    volatile = {"id", "content", "created_at", "updated_at", "value_sha256", "canonical_sha256",
                "entry_mac", "encrypted_envelope_json", "tenant_sig", "content_sha256",
                "metadata_json", "key", "category",
                # R7-1: the one differing column (put=1, adopted=0); see test_attack_r7_adopted_content_stays_plain_*
                "is_encrypted"}
    diff = {col: (put_row.get(col), ad_row.get(col))
            for col in set(put_row) | set(ad_row)
            if col not in volatile and put_row.get(col) != ad_row.get(col)}
    assert diff == {}, diff
    assert ad_row["origin"] == "model" and ad_row["epistemic_state"] == "candidate"
    pm, am = json.loads(put_row["metadata_json"]), json.loads(ad_row["metadata_json"])
    for k in ("human_reviews", "tenant_id", "principal_id", "lineage_root", "attestations"):
        assert k not in am and k not in pm, k
    assert am["origin_class"] == pm["origin_class"] == "agent"
    assert am["act_class"] == pm["act_class"] == "inform"
    assert set(am) - set(pm) <= {"adopted_from_keyless_file"}, set(am) - set(pm)
    # a nested agent_metadata.human_reviews survives on BOTH rows: it is agent-labelled data, read by nothing
    assert set(am.get("agent_metadata", {})) == set(pm.get("agent_metadata", {})) == {"author_id", "human_reviews", "slot"}


def test_control_r7_no_adopted_origin_marker_reaches_a_principal_check():
    """Adoption stores origin='model'; no comparison in src treats an 'adopted' label as an origin."""
    src = Path(__file__).resolve().parents[1] / "src" / "kibisis"
    hits = []
    for f in src.glob("*.py"):
        for i, line in enumerate(f.read_text().splitlines(), 1):
            if "adopted" in line and ("origin ==" in line or "origin_class ==" in line or "_origin_class(" in line):
                hits.append(f"{f.name}:{i}: {line.strip()}")
    assert hits == [], hits


# ---------------------------------------------------------------------------
# A. read-only + opt-in: every read path serves the demoted view, no bytes change
# ---------------------------------------------------------------------------

def test_control_r7_read_only_opt_in_serves_demoted_view_on_every_read_path(tmp_path):
    pl = R5._laundered_keyless_file(tmp_path, "ro.sqlite")
    _forge(pl, ("k0", "k1", "k2"))
    before = _dump(pl)
    v = _open(pl, adopt_keyless=True, read_only=True)
    try:
        assert v.read_only
        assert v.list_entities(scope="default") == []  # default view = verified/disputed: nothing adopted qualifies
        views = {
            "get": [v.get("decision", "k0", scope="default")],
            "list": list(v.list_entities(scope="default", include_unverified=True)),
            "recall": [h.entity for h in v.recall("FORGED", scope="default", limit=10).results],
            "search": [h.entity for h in v.search("FORGED", scope="default", limit=10)],
        }
        assert len(views["list"]) == len(views["recall"]) == len(views["search"]) == 3
        for name, ents in views.items():
            for e in ents:
                assert e is not None
                assert e.origin == "model", (name, e.key, e.origin)
                assert e.epistemic_state.value == "candidate", (name, e.key)
                md = e.metadata or {}
                assert md.get("origin_class") == "agent" and md.get("act_class") == "inform", (name, md)
                for k in ("human_reviews", "tenant_id", "principal_id", "attestations"):
                    assert k not in md, (name, k)
        snap = v.export_snapshot(scope="default")
        for ent in snap["entities"]:
            assert ent["origin"] == "model" and ent["epistemic_state"] == "candidate"
            for k in ("human_reviews", "tenant_id", "principal_id", "attestations"):
                assert k not in ent["metadata"], k
            assert ent["metadata"]["origin_class"] == "agent"
        with pytest.raises(Exception):
            v.remember("decision", "k9", "x", origin="model")
        assert v.verify_audit_chain()
        assert v.keyless_adoption()["sequence"] is None  # in memory only
    finally:
        v.close()
    assert _dump(pl) == before  # nothing written: every table byte-identical in content


def test_control_r7_adoption_drops_tenant_id_and_tenant_filtered_recall_degrades_predictably(tmp_path):
    """Writer-controlled tenant_id is dropped on adoption; a tenant-filtered recall over adopted rows
    sees every adopted row as tenant-less.  Documented limit, not a defect (the keyless file's tenant
    labels were on nobody's word), recorded so the operator knows tenant scoping does not survive."""
    p = tmp_path / "tenant.sqlite"
    v = SQLiteMemoryVault(str(p), allow_plaintext=True, auto_gate=False)
    v.remember("decision", "ka", "tenant A secret", origin="user", author_id="a", tenant_id="A")
    v.remember("decision", "kb", "tenant B secret", origin="user", author_id="b", tenant_id="B")
    plain_b = sorted(h.entity.key for h in v.recall("secret", scope="default", tenant_id="B", limit=10).results)
    v.close()
    assert plain_b == ["kb"]
    v = _open(p, adopt_keyless=True)
    try:
        after_b = sorted(h.entity.key for h in v.recall("secret", scope="default", tenant_id="B", limit=10).results)
        for k in ("ka", "kb"):
            assert (v.get("decision", k, scope="default").metadata or {}).get("tenant_id") is None
    finally:
        v.close()
    assert after_b == ["ka", "kb"]


# ---------------------------------------------------------------------------
# A. planted quorum / forged journal / legacy MAC key set
# ---------------------------------------------------------------------------

def test_control_r7_planted_low_quorum_in_keyless_file_is_refused_with_opt_in_and_writes_nothing(tmp_path):
    for ro in (False, True):
        pq = R5._laundered_keyless_file(tmp_path, f"q{int(ro)}.sqlite")
        with _conn(pq) as c:
            c.execute("INSERT INTO vault_meta (key, value) VALUES ('verification_quorum', '1')")
        with pytest.raises(ConfigError, match="pinned at 1"):
            _open(pq, adopt_keyless=True, read_only=ro)
        with pytest.raises(ConfigError if not ro else VaultIntegrityError):
            _open(pq)  # a plain open is still refused: the planted 1 never became the quorum silently


def test_control_r7_forged_keyless_journal_is_chained_on_the_files_word_and_rows_stay_candidates(tmp_path):
    pj = R5._laundered_keyless_file(tmp_path, "j.sqlite")
    with _conn(pj) as c:
        c.execute("DELETE FROM audit_journal")
        c.execute("DELETE FROM sqlite_sequence WHERE name='audit_journal'")
        c.execute(
            "INSERT INTO audit_journal (timestamp, action, category, key, scope, value_sha256, prev_hash, "
            "event_hash, author_id, metadata_json, format) VALUES (1700000000.0, 'human_review', 'decision', "
            "'k0', 'default', ?, '', '', 'alice', ?, 1)",
            (hashlib.sha256(b"x").hexdigest(), json.dumps({"verdict": "verified", "reviewer_id": "alice"})))
        M._legacy_rechain(c)
    v = _open(pj, adopt_keyless=True)
    try:
        assert v.verify_audit_chain()
        assert v.keyless_adoption()["events"] == 1
        assert v.get("decision", "k0", scope="default").epistemic_state.value == "candidate"
    finally:
        v.close()
    with _conn(pj) as c:
        rows = [(r["action"], r["author_id"], r["format"]) for r in c.execute("SELECT action, author_id, format FROM audit_journal ORDER BY sequence")]
    assert rows[0][:2] == ("human_review", "alice") and rows[0][2] == 1  # kept on the file's word, counted
    assert any(a == "migrate" for a, _, _ in rows)


def test_control_r7_legacy_mac_key_set_differs_from_the_full_set_only_by_the_quorum_keys():
    from kibisis.crypto import VAULT_META_BOUND_KEYS, VAULT_META_BOUND_KEYS_V1, VAULT_META_BOUND_OPTIONAL
    assert set(VAULT_META_BOUND_KEYS) - set(VAULT_META_BOUND_KEYS_V1) == {"verification_quorum"}
    assert set(VAULT_META_BOUND_OPTIONAL) == {"quorum_dropped_from"}
    assert set(VAULT_META_BOUND_KEYS_V1) <= set(VAULT_META_BOUND_KEYS)


# ---------------------------------------------------------------------------
# A. Foreign / partial / empty files
# ---------------------------------------------------------------------------

def _expect_refusal(p, **kw):
    with pytest.raises((VaultIntegrityError, ValueError, sqlite3.DatabaseError)):
        _open(p, **kw)


def test_control_r7_foreign_and_partial_files_never_silently_adopt(tmp_path):
    pk = tmp_path / "keyed.sqlite"
    v = _open(pk)
    v.remember("decision", "k0", "x", origin="model")
    v.close()

    pf = tmp_path / "plus_foreign.sqlite"
    shutil.copy(pk, pf)
    with _conn(pf) as c:
        c.execute("CREATE TABLE notes (x)")
    for ro in (False, True):  # a keyed vault plus a foreign table is still that keyed vault: opened, nothing adopted
        v = _open(pf, read_only=ro)
        try:
            assert v.keyless_adoption() is None and v.verify_audit_chain()
        finally:
            v.close()
    assert "notes" in _tables(pf)

    pkf = R5._laundered_keyless_file(tmp_path, "keyless_plus_foreign.sqlite")
    with _conn(pkf) as c:
        c.execute("CREATE TABLE notes (x)")
    for ro in (False, True):
        with pytest.raises(VaultIntegrityError, match="adopt_keyless"):
            _open(pkf, read_only=ro)

    ps = tmp_path / "subset.sqlite"
    shutil.copy(pk, ps)
    with _conn(ps) as c:
        c.execute("DROP TABLE audit_journal")
    with pytest.raises(sqlite3.OperationalError):
        _open(ps, read_only=True)
    v = _open(ps)  # writable: the table is recreated, the signed head with no rows is reported
    try:
        assert v.keyless_adoption() is None
        assert not v.verify_audit_chain() and "whole journal was removed" in v.last_chain_error
    finally:
        v.close()

    for name, ddl in (("meta_only", "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value BLOB)"),
                      ("lease_only", "CREATE TABLE leases (resource TEXT PRIMARY KEY, holder TEXT)"),
                      ("entities_bad", "CREATE TABLE entities (id INTEGER PRIMARY KEY)")):
        p = tmp_path / f"{name}.sqlite"
        with _conn(p) as c:
            c.execute(ddl)
        for ro in (False, True):
            _expect_refusal(p, read_only=ro)

    pg = tmp_path / "garbage.sqlite"
    pg.write_bytes(b"not sqlite" * 20)
    for ro in (False, True):
        _expect_refusal(pg, read_only=ro)


def test_control_r7_zero_byte_file_becomes_a_fresh_vault_in_rw_and_is_a_clean_error_in_ro(tmp_path):
    pe = tmp_path / "zero.sqlite"
    pe.write_bytes(b"")
    v = _open(pe)
    try:
        assert v.keyless_adoption() is None
    finally:
        v.close()
    assert "entities" in _tables(pe)
    pe2 = tmp_path / "zero2.sqlite"
    pe2.write_bytes(b"")
    with pytest.raises(FileNotFoundError):
        _open(pe2, read_only=True)


# ---------------------------------------------------------------------------
# A. CLI text
# ---------------------------------------------------------------------------

def _review_env(tmp_path, monkeypatch):
    import kibisis.review as review
    p = tmp_path / "plain.sqlite"
    v = SQLiteMemoryVault(str(p), allow_plaintext=True, auto_gate=False)
    v.remember("decision", "k0", "plain", origin="model", author_id="mcp-agent")
    v.close()
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASS)
    monkeypatch.setenv("KIBISIS_DB_PATH", str(p))
    monkeypatch.setenv("KIBISIS_SCOPE", "default")
    monkeypatch.setattr(review, "require_terminal", lambda command: None)
    monkeypatch.setattr(review, "account_identity", lambda: ("operator", "operator"))
    return review, p


def test_control_r7_review_cli_verdict_help_shows_the_flag_and_a_refused_list_names_it(tmp_path, monkeypatch, capsys):
    review, p = _review_env(tmp_path, monkeypatch)
    for sub in ("approve", "reject", "lift"):
        with pytest.raises(SystemExit):
            review.main([sub, "--help"])
        assert "--adopt-keyless" in capsys.readouterr().out
    assert review.main(["list"]) == 2
    err = capsys.readouterr().err
    assert "--adopt-keyless" in err and "no salt" in err
    with pytest.raises(VaultIntegrityError):
        _open(p)  # the refused list adopted nothing


def test_attack_r7_review_list_refusal_names_a_flag_list_does_not_accept(tmp_path, monkeypatch, capsys):
    """Minor (R7-2): `kibisis-review list` on a keyless file says "pass --adopt-keyless", but `list`
    has no such flag (only the verdicts and lift do, as SECURITY.md says), so following the message
    yields an argparse error; the library-only read_only+adopt_keyless path ("in memory only") is not
    reachable from any CLI."""
    review, _ = _review_env(tmp_path, monkeypatch)
    assert review.main(["list"]) == 2
    assert "pass --adopt-keyless" in capsys.readouterr().err
    with pytest.raises(SystemExit) as ex:
        review.main(["list", "--adopt-keyless"])
    assert ex.value.code == 2 and "unrecognized arguments: --adopt-keyless" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# A. Residual findings
# ---------------------------------------------------------------------------

def test_attack_r7_adopted_content_stays_plain_on_disk_until_migrate_plaintext(tmp_path):
    """Low (R7-1): adoption re-signs the rows but seals none (`_write_sealed(..., encrypt=is_encrypted==1)`),
    so in the no-SQLCipher mode the adopted entry text and its FTS words stay in the clear inside a vault
    that now has a passphrase, until the library-only `migrate_plaintext()` runs.  SECURITY.md's "Without
    SQLCipher" table says entry text is sealed in passphrase mode, and the adoption paragraph says rows are
    stored "exactly as a model-origin put stores an agent's write"."""
    pl = R5._laundered_keyless_file(tmp_path, "l.sqlite")
    v = _open(pl, adopt_keyless=True)
    try:
        v.remember("decision", "k_new", "sealed after adoption", origin="model")
        assert v.encryption_status() == {"encrypted": 1, "plaintext": 3}
    finally:
        v.close()
    with _conn(pl) as c:
        rows = {r["key"]: (r["is_encrypted"], r["content"]) for r in c.execute("SELECT key, is_encrypted, content FROM entities")}
        assert rows["k_new"] == (1, "")
        assert all(rows[k][0] == 0 and rows[k][1].startswith("FORGED") for k in ("k0", "k1", "k2"))
        assert c.execute("SELECT count(*) FROM entities_fts WHERE entities_fts MATCH 'forged'").fetchone()[0] == 3
    v = _open(pl)
    try:
        assert v.migrate_plaintext() == {"migrated": 3, "remaining_plaintext": 0}
    finally:
        v.close()
    with _conn(pl) as c:
        assert c.execute("SELECT count(*) FROM entities WHERE is_encrypted = 0").fetchone()[0] == 0


def test_attack_r7_planted_high_quorum_in_keyless_file_is_adopted_and_signed_silently(tmp_path):
    """Low (R7-3): a `verification_quorum` row planted in a salt-less file is read as the vault's stored
    quorum.  Above the default it is adopted and signed by the opt-in open with no notice that it came from
    an unsigned file; below the default it is refused with the generic ConfigError whose remedy is to set
    the env to the planted value.  Stricter-only in the first case (a review lock-out, not a bypass)."""
    pq = R5._laundered_keyless_file(tmp_path, "q.sqlite")
    with _conn(pq) as c:
        c.execute("INSERT INTO vault_meta (key, value) VALUES ('verification_quorum', '7')")
    v = _open(pq, adopt_keyless=True)
    try:
        assert v.verification_quorum == 7 and v.verification_quorum_stored == 7
        assert v.quorum_dropped_from is None
    finally:
        v.close()
    v = _open(pq)
    try:
        assert v.verification_quorum == 7  # survives the re-open under the signed meta MAC
    finally:
        v.close()
    pq1 = R5._laundered_keyless_file(tmp_path, "q1.sqlite")
    with _conn(pq1) as c:
        c.execute("INSERT INTO vault_meta (key, value) VALUES ('verification_quorum', '1')")
    v = _open(pq1, adopt_keyless=True, verification_quorum=1)
    try:
        assert v.verification_quorum_stored == 1
    finally:
        v.close()


# ---------------------------------------------------------------------------
# B. Fixture lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fixture", sorted(f.name for f in FIXTURES.iterdir() if f.suffix in (".db", ".sqlite")))
def test_control_r7_fixture_lifecycle(tmp_path, fixture):
    import test_fallback_integrity as F
    fpass = F.FIXTURE_PASS
    p = tmp_path / fixture
    shutil.copyfile(FIXTURES / fixture, p)
    with pytest.raises(ValueError, match="integrity upgrade"):
        SQLiteMemoryVault(str(p), passphrase=fpass, auto_gate=False, read_only=True)  # legacy: writable migration first
    v = SQLiteMemoryVault(str(p), passphrase=fpass, auto_gate=False)
    try:
        assert v.verify_audit_chain()
        n = len(list(v.list_entities(scope="*", include_unverified=True, include_archived=True)))
        first = dict(v.integrity_upgrade)
        assert first.get("entries_resealed", 0) > 0 and not first.get("entries_adopted_from_keyless_vault")
    finally:
        v.close()
    v = SQLiteMemoryVault(str(p), passphrase=fpass, auto_gate=False)
    try:
        assert v.verify_audit_chain()
        assert not any((v.integrity_upgrade or {}).values()), v.integrity_upgrade  # idempotent
        assert v.keyless_adoption() is None
    finally:
        v.close()
    after = p.read_bytes()
    v = SQLiteMemoryVault(str(p), passphrase=fpass, auto_gate=False, read_only=True)
    try:
        assert v.verify_audit_chain()
        assert len(list(v.list_entities(scope="*", include_unverified=True, include_archived=True))) == n
    finally:
        v.close()
    assert p.read_bytes() == after


def test_attack_r7_planted_low_quorum_refusal_has_already_committed_the_adoption(tmp_path):
    """Low (R7-3b): with the opt-in, the adoption transaction (salt, key check, MAC, demoted rows, chained
    journal) commits before the quorum check raises ConfigError, so a 'refused' open converted the file and
    MAC-signed the writer-planted quorum 1 as the vault's stored quorum; a later open under
    KIBISIS_VERIFICATION_QUORUM=1 (what the message suggests) needs no opt-in and runs with quorum 1."""
    pq = R5._laundered_keyless_file(tmp_path, "q.sqlite")
    with _conn(pq) as c:
        c.execute("INSERT INTO vault_meta (key, value) VALUES ('verification_quorum', '1')")
    with pytest.raises(ConfigError):
        _open(pq, adopt_keyless=True)
    assert {"kdf_salt", "key_check", "meta_mac"} <= set(_meta(pq))
    v = _open(pq, verification_quorum=1)  # no opt-in needed any more
    try:
        assert v.verification_quorum_stored == 1
        assert v.keyless_adoption()["entries"] == 3
    finally:
        v.close()


def test_attack_r7_emptied_journal_with_head_intact_is_laundered_by_the_next_write(tmp_path):
    """Medium (R7-4): a file writer empties `audit_journal` (or drops the table) and leaves the signed head.
    `verify_audit_chain()` reports "a signed head with no rows: the whole journal was removed" -- until the
    next append: `_append` continues from the last ROW (none -> sequence 1, prev 0*64), not from the signed
    head, and re-signs the head over the new one-row chain.  One routine agent write (MCP remember) later,
    verification is True and the removal has no trace.  Same for the head-removed variant pinned as 'caught'
    by test_threat_model_claims: caught only until the next write."""
    for wipe in ("DELETE FROM audit_journal", "DROP TABLE audit_journal", "DELETE FROM audit_journal; DELETE FROM audit_head"):
        pk = tmp_path / f"k{abs(hash(wipe))}.sqlite"
        v = _open(pk)
        for i in range(3):
            v.remember("decision", f"k{i}", f"fact {i}", origin="model")
        v.close()
        with _conn(pk) as c:
            c.executescript(wipe)
        v = _open(pk)
        try:
            assert v.verify_audit_chain() is False  # caught at this moment ...
            v.remember("decision", "k_agent", "a routine agent write", origin="model")
            assert v.verify_audit_chain() is True, wipe  # ... and laundered by the next append
            assert [e.sequence for e in v.list_audit_events(limit=10)] == [1]
        finally:
            v.close()
        v = _open(pk)
        try:
            assert v.verify_audit_chain() is True, wipe
        finally:
            v.close()
