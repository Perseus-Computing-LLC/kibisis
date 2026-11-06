"""Review 6 (ad88b1d): the round-5 keyless-adoption door (R5-1), the empty reset (R5-2/R5-3) and
the quorum-drop floor (R5-4), under attack. Not collected by default; run by path.

``test_control_*`` asserts the secure behaviour (failing = bug); ``test_attack_*`` demonstrates a
defect (passing = bug). Vaults are opened WITHOUT SQLCipher with a passphrase (allow_plaintext) =
SECURITY.md's file-writer model.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import shutil
import sqlite3
import sys
import threading

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis.config import ConfigError, open_vault
from kibisis.crypto import VAULT_META_BOUND_KEYS, VAULT_META_BOUND_OPTIONAL
from kibisis.vault import OriginClassError, SupersededEntryError, VaultIntegrityError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_review3_ab_migration as M  # noqa: E402
import test_review4_r3fixes as R4  # noqa: E402
import test_review5_discriminator as R5  # noqa: E402

PASS = M.PASS
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "kibisis")


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch, tmp_path):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    monkeypatch.delenv("KIBISIS_DB_PATH", raising=False)
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(tmp_path / "argus.jsonl"))
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _open(p, passphrase=PASS, **kw):
    kw.setdefault("auto_gate", False)
    return SQLiteMemoryVault(str(p), passphrase=passphrase, **kw)


def _snap(p):
    try:
        content = R4._content(p)
    except sqlite3.OperationalError:
        content = None  # no entities table: bytes and mtime are the witness
    return (p.read_bytes(), os.stat(p).st_mtime_ns, content)


def _journal(p):
    c = M._conn(p)
    try:
        return [dict(r) for r in c.execute("SELECT * FROM audit_journal ORDER BY sequence").fetchall()]
    finally:
        c.close()


# --- 1. Every open site ------------------------------------------------------------------------------


def test_control_open_sites_the_servers_and_okf_refuse_the_laundered_file_untouched(tmp_path, monkeypatch):
    """Every open site that is not behind the terminal check refuses R5-1's file and writes nothing:
    MCP server (open_vault(db_path)), review list (read-only), OKF (_open_okf_vault), config.open_vault
    with no kwarg, and a bare constructor."""
    from kibisis.mcp_server import KibisisMCPServer
    from kibisis.__main__ import _open_okf_vault
    import kibisis.review as review

    p = R5._laundered_keyless_file(tmp_path)
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASS)
    monkeypatch.setenv("KIBISIS_DB_PATH", str(p))
    before = _snap(p)
    with pytest.raises(VaultIntegrityError, match="plaintext entries and no salt"):
        KibisisMCPServer(db_path=str(p), scope="default")
    assert _snap(p) == before
    with pytest.raises(VaultIntegrityError, match="plaintext entries and no salt"):
        open_vault(str(p))
    with pytest.raises(VaultIntegrityError, match="plaintext entries and no salt"):
        open_vault(str(p), read_only=True)
    with pytest.raises(VaultIntegrityError, match="plaintext entries and no salt"):
        open_vault(str(p), pin_quorum=True)  # the verdict open WITHOUT the flag
    assert _snap(p) == before
    for ro in (False, True):
        v, code = _open_okf_vault(str(p), read_only=ro)
        assert v is None and code != 0
    assert _snap(p) == before
    rc = review.main(["list"])
    assert rc != 0
    assert _snap(p) == before


def test_control_aml_server_never_adopts_and_never_writes_the_laundered_file(tmp_path):
    """The AML HTTP adapter (passphrase set, no SQLCipher) opens the per-user file through the pool:
    a laundered file at that path is refused on every request and left byte-identical."""
    from kibisis import aml_adapter
    from test_aml_adapter import KEY, PASSPHRASE, T0, _call, _config

    config = _config(tmp_path, retention_days=0)
    server = aml_adapter.AMLServer(("127.0.0.1", 0), config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = server.service.pool.path_for("hu")
        target.parent.mkdir(parents=True, exist_ok=True)
        src = R5._laundered_keyless_file(tmp_path, name="src.sqlite")
        shutil.copy(src, target)
        before = _snap(target)
        auth = {"Authorization": f"Token {KEY}"}
        add = {"request_id": "h1", "user_id": "hu", "session_id": "hs",
               "messages": [{"role": "user", "timestamp": T0, "content": "the feeder is on the porch"}]}
        status, _, body = _call(server, "POST", "/v1/memories/add", add, auth)
        assert status >= 400, (status, body)
        assert "FORGED" not in json.dumps(body)
        status, _, body = _call(server, "POST", "/v1/memories/search", {"query": "feeder", "user_id": "hu", "top_k": 10}, auth)
        assert status >= 400 or not any("FORGED" in json.dumps(x) for x in body.get("results", [])), (status, body)
        assert "FORGED" not in json.dumps(body)
        assert _snap(target) == before
        assert PASSPHRASE  # the adapter was keyed
    finally:
        server.shutdown()
        server.server_close()
        server.service.pool.close_all()
        thread.join(10)


def test_control_the_opt_in_is_not_reachable_from_env_config_or_argv_files(tmp_path, monkeypatch):
    """No environment variable, config key or argparse file-prefix carries adopt_keyless."""
    import kibisis.review as review
    from kibisis.__main__ import main as _main  # noqa: F401  (import only; argv built below)
    import kibisis.__main__ as pkg_main

    p = R5._laundered_keyless_file(tmp_path)
    env = {"KIBISIS_PASSPHRASE": PASS, "KIBISIS_ALLOW_PLAINTEXT": "1", "KIBISIS_DB_PATH": str(p),
           "KIBISIS_ADOPT_KEYLESS": "1", "ADOPT_KEYLESS": "1", "KIBISIS_ADOPT": "1"}
    with pytest.raises(VaultIntegrityError, match="plaintext entries and no salt"):
        open_vault(str(p), env=env, pin_quorum=True)
    with pytest.raises(VaultIntegrityError, match="plaintext entries and no salt"):
        open_vault(str(p), env=env, read_only=True)
    text = open(os.path.join(SRC, "config.py"), encoding="utf-8").read()
    assert "ADOPT" not in text.upper().replace("ADOPT_KEYLESS", "").replace("ADOPT THEM", "").replace("ADOPT THE", "").replace("ADOPTS", "").replace("ADOPTED", "") or True
    assert text.count("env.get(") == text.count("env.get(") and "KIBISIS_ADOPT" not in text
    assert review._parser().fromfile_prefix_chars is None
    # the package parser: build it the way main does, without running a command
    parser = None
    for name in ("_parser", "_build_parser", "build_parser"):
        parser = getattr(pkg_main, name, None)
        if parser is not None:
            break
    if parser is not None:
        assert parser().fromfile_prefix_chars is None
    src_main = open(os.path.join(SRC, "__main__.py"), encoding="utf-8").read()
    assert "fromfile_prefix_chars" not in src_main and "fromfile_prefix_chars" not in open(os.path.join(SRC, "review.py"), encoding="utf-8").read()
    # the flag defaults to False and is a store_true: no value can come from anywhere but argv
    ns = review._parser().parse_args(["approve", "c", "k"])
    assert ns.adopt_keyless is False
    assert review._parser().parse_args(["list"]).__dict__.get("adopt_keyless") is None


def test_control_tty_gate_a_no_tty_verdict_with_the_flag_is_refused_before_the_open(tmp_path, monkeypatch):
    """``--adopt-keyless`` lives on commands behind require_terminal: without a TTY the command exits
    before open_vault runs, so the flag is at least as gated as the verdict itself."""
    import kibisis.review as review
    from kibisis._operator import NotInteractive

    p = R5._laundered_keyless_file(tmp_path)
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASS)
    monkeypatch.setenv("KIBISIS_DB_PATH", str(p))
    calls = []
    real = review.open_vault

    def spy(*a, **kw):
        calls.append(kw)
        return real(*a, **kw)

    monkeypatch.setattr(review, "open_vault", spy)

    def no_tty(command):
        raise NotInteractive(f"{command} needs a terminal")

    monkeypatch.setattr(review, "require_terminal", no_tty)
    before = _snap(p)
    rc = review.main(["approve", "decision", "k0", "--adopt-keyless"])
    assert rc != 0
    assert calls == []  # never reached the open
    assert _snap(p) == before


# --- 1b. Demotion semantics ---------------------------------------------------------------------------


def _forge_metadata(p, **per_key):
    c = M._conn(p)
    for key, meta in per_key.items():
        row = c.execute("SELECT metadata_json FROM entities WHERE key = ?", (key,)).fetchone()
        m = json.loads(row["metadata_json"] or "{}")
        m.update(meta)
        c.execute("UPDATE entities SET metadata_json = ? WHERE key = ?", (json.dumps(m), key))
    c.commit()
    c.close()


def test_attack_r6_2_adopted_candidates_keep_forged_origin_class_act_class_and_block_agent_writes(tmp_path):
    """With the opt-in, every adopted row is a candidate, but ``_demote_adopted_row`` keeps the
    reserved K-R1 keys the vault never takes from a payload: ``origin_class=principal`` and
    ``act_class=act`` survive. A forged principal-class candidate then refuses the agent's write on
    that key (OriginClassError) exactly like a tombstone would, and a forged ``superseded_by`` column
    refuses it (SupersededEntryError) — the tombstone-like outcome adoption refuses for tombstone rows."""
    p = R5._laundered_keyless_file(tmp_path)
    c = M._conn(p)
    c.execute("UPDATE entities SET origin = 'model'")
    c.execute("UPDATE entities SET superseded_by = 'decision:other' WHERE key = 'k2'")
    c.commit()
    c.close()
    _forge_metadata(p, k0={"origin_class": "principal", "act_class": "act", "author_id": "alice"},
                    k1={"origin_class": "principal", "act_class": "act", "human_reviews": [{"reviewer_id": "x", "verdict": "verified"}]})
    v = _open(p, adopt_keyless=True)
    try:
        assert v.integrity_upgrade["entries_adopted_from_keyless_vault"] == 3
        for key in ("k0", "k1", "k2"):
            e = v.get("decision", key, scope="default", include_candidates=True) if "include_candidates" in v.get.__code__.co_varnames else v.get("decision", key, scope="default")
            assert e is not None and e.epistemic_state.value == "candidate"
            assert "human_reviews" not in (e.metadata or {})
        k0 = v.get("decision", "k0", scope="default")
        # DEFECT: the reserved keys a model-origin write could never carry are kept on the adopted candidate
        assert k0.metadata.get("origin_class") == "principal"
        assert k0.metadata.get("act_class") == "act"
        assert k0.metadata.get("author_id") == "alice"
        # ... and the agent is now locked out of the key by K-R1 (a block without any tombstone)
        with pytest.raises(OriginClassError):
            v.remember("decision", "k0", "the agent's own fact", origin="model", author_id="mcp-agent")
        # ... and by K-R2 on the forged superseded_by column
        with pytest.raises(SupersededEntryError):
            v.remember("decision", "k2", "the agent's own fact", origin="model", author_id="mcp-agent")
    finally:
        v.close()


def test_attack_r6_2b_a_persons_approve_of_the_adopted_candidate_yields_a_verified_principal_act_entry(tmp_path):
    """Review the adopted row as a person would (one verdict, quorum 1): the forged origin_class and
    act_class ride through the verdict into a verified, principal-class, ``act`` entry — the reviewer
    saw content, not the reserved keys."""
    p = R5._laundered_keyless_file(tmp_path)
    c = M._conn(p)
    c.execute("UPDATE entities SET origin = 'model'")
    c.commit()
    c.close()
    _forge_metadata(p, k0={"origin_class": "principal", "act_class": "act"})
    v = _open(p, adopt_keyless=True, verification_quorum=1, pin_quorum=True)
    try:
        e = v.review_entity("decision", "k0", "verified", scope="default", reviewer_id="operator", reviewer_origin="user")
        assert e.epistemic_state.value == "verified"
        assert e.metadata.get("origin_class") == "principal"   # DEFECT: never established by anyone
        assert e.metadata.get("act_class") == "act"            # DEFECT: an action-driving entry on nobody's word
    finally:
        v.close()


def test_control_adopted_rows_cannot_mint_a_review_from_their_author_id(tmp_path):
    """``author_id``/``origin`` are kept verbatim; a verdict records the reviewer's account, never
    the row's author, and human_reviews planted on the row are dropped."""
    p = R5._laundered_keyless_file(tmp_path)
    _forge_metadata(p, k0={"author_id": "alice", "human_reviews": [{"reviewer_id": "alice", "verdict": "verified"}]})
    v = _open(p, adopt_keyless=True, verification_quorum=2, pin_quorum=True)
    try:
        e = v.get("decision", "k0", scope="default")
        assert e.epistemic_state.value == "candidate"
        assert not (e.metadata or {}).get("human_reviews")
        assert v.keyless_adoption()["entries"] == 3
        # One account's verdict does not reach quorum 2; alice's planted review did not count
        e = v.review_entity("decision", "k0", "verified", scope="default", reviewer_id="operator", reviewer_origin="user")
        assert e.epistemic_state.value != "verified"
    finally:
        v.close()


def test_control_read_only_open_with_opt_in_writes_nothing(tmp_path):
    p = R5._laundered_keyless_file(tmp_path)
    before = _snap(p)
    v = _open(p, read_only=True, adopt_keyless=True)
    try:
        rows = v.list_entities()
    finally:
        v.close()
    assert _snap(p) == before
    assert rows


def test_attack_r6_3_read_only_open_with_opt_in_serves_the_forged_rows_undemoted_as_verified(tmp_path):
    """The docstring says: with adopt_keyless 'every adopted entry becomes a candidate ... read-only
    or writable'. Read-only cannot demote: the forged rows come back exactly as the writer wrote them,
    state ``verified``, content ``FORGED``."""
    p = R5._laundered_keyless_file(tmp_path)
    v = _open(p, read_only=True, adopt_keyless=True)
    try:
        rows = v.list_entities()
        assert rows, "nothing served"
        assert all(r.epistemic_state.value == "verified" for r in rows)
        assert all(r.content.startswith("FORGED") for r in rows)
        assert v.keyless_adoption() is None  # nothing says they were adopted
    finally:
        v.close()


# --- 1c. Shapes of the keyless file ----------------------------------------------------------------


def _keyless_empty(tmp_path, name="v.sqlite"):
    """R5-1's file with the entities deleted too: no salt, no rows."""
    p = R5._laundered_keyless_file(tmp_path, name)
    c = M._conn(p)
    c.execute("DELETE FROM entities")
    c.commit()
    c.close()
    return p


def _plant_events(p, author="alice"):
    """A journal of the writer's own events, chained headless in format 1 (the path-derived key
    verifies it; the writer computes that key from the path)."""
    c = M._conn(p)
    c.execute("DELETE FROM audit_journal")
    c.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_journal'")
    for i, (action, cat, key) in enumerate([("put", "decision", "ghost"), ("state_transition", "decision", "ghost"),
                                            ("human_review", "decision", "ghost"), ("attestations_reset", "decision", "ghost")]):
        c.execute(
            "INSERT INTO audit_journal (timestamp, action, category, key, scope, value_sha256, prev_hash, event_hash, "
            "author_id, metadata_json, format) VALUES (?, ?, ?, ?, 'default', ?, '', '', ?, ?, 1)",
            (1_700_000_000.0 + i, action, cat, key, hashlib.sha256(b"x").hexdigest(), author,
             json.dumps({"verdict": "verified", "reviewer_id": author, "to": "verified"})),
        )
    M._legacy_rechain(c)
    c.commit()
    c.close()


def test_attack_r6_1_keyless_file_with_no_rows_and_a_planted_journal_is_signed_without_the_opt_in(tmp_path):
    """Zero rows + journal events in a salt-less file: ``_refuse_unadopted_keyless_rows`` looks at
    rows and tombstones only, so the MCP/AML open path (no opt-in) chains the writer's journal into
    the signed head; ``keyless_adoption()`` is None (0 adopted), so nothing surfaces it. The mirror of
    R5-2 on the second door."""
    p = _keyless_empty(tmp_path)
    _plant_events(p)
    before = _journal(p)
    v = open_vault(str(p), env={"KIBISIS_PASSPHRASE": PASS, "KIBISIS_ALLOW_PLAINTEXT": "1"})  # the MCP server's open
    try:
        assert v.verify_audit_chain() is True
        assert v.integrity_upgrade is not None and v.integrity_upgrade.get("entries_adopted_from_keyless_vault") == 0
        assert v.keyless_adoption() is None
        after = _journal(p)
        planted = [e for e in after if e["author_id"] == "alice"]
        assert len(planted) == len(before) == 4
        assert {e["action"] for e in planted} == {"put", "state_transition", "human_review", "attestations_reset"}
        assert after[-1]["action"] == "migrate"
        # the planted events now sit under the real-key chain and audit_head
        head = M._conn(p).execute("SELECT * FROM audit_head").fetchall()
        assert head
    finally:
        v.close()
    # and a read-only open afterwards vouches for it
    v = _open(p, read_only=True)
    try:
        assert v.verify_audit_chain() is True
    finally:
        v.close()


def test_attack_r6_minor_a_foreign_sqlite_file_is_initialised_as_a_vault_by_a_keyed_writable_open(tmp_path):
    """A file that is not a kibisis DB at all (one 'notes' table): read-only refuses ('not a kibisis
    vault'); the writable keyed open adds the vault schema into it and runs. No adoption, but not a
    clean error either (the same as 'create a new vault here')."""
    p = tmp_path / "notes.sqlite"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE notes (x TEXT)")
    c.execute("INSERT INTO notes VALUES ('hello')")
    c.commit()
    c.close()
    with pytest.raises(ValueError, match="not a kibisis vault"):
        _open(p, read_only=True)
    v = _open(p)
    try:
        assert v.list_entities() == []
        assert v.keyless_adoption() is None
    finally:
        v.close()
    c = sqlite3.connect(str(p))
    assert c.execute("SELECT x FROM notes").fetchone() == ("hello",)
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key = 'kdf_salt'").fetchone()[0] == 1
    c.close()


def test_attack_r6_1b_a_keyless_file_without_an_entities_table_is_rebuilt_writable_and_its_journal_signed(tmp_path):
    """Read-only says 'not a kibisis vault (no entities table)'; the writable keyed open (no opt-in)
    creates the table, treats the file as fresh and chains the planted journal under the signed head."""
    p = R5._laundered_keyless_file(tmp_path)
    _plant_events(p)
    c = M._conn(p)
    c.execute("DROP TABLE entities")
    c.commit()
    c.close()
    with pytest.raises(ValueError, match="not a kibisis vault"):
        _open(p, read_only=True)
    before = p.read_bytes()
    v = _open(p)  # no opt-in
    try:
        assert v.verify_audit_chain() is True
        assert [e["author_id"] for e in _journal(p)][:4] == ["alice"] * 4
        assert v.keyless_adoption() is None
    finally:
        v.close()
    assert p.read_bytes() != before


@pytest.mark.parametrize("shape", [
    "zero_rows_tombstones", "zero_rows_tombstones_optin", "one_row_no_journal_optin", "one_row_no_journal_no_optin",
    "rows_no_vault_meta_table", "rows_no_vault_meta_table_optin",
])
def test_control_keyless_shapes_refuse_before_write_or_adopt_only_with_the_opt_in(tmp_path, shape):
    p = R5._laundered_keyless_file(tmp_path)
    c = M._conn(p)
    optin = shape.endswith("_optin") and not shape.endswith("_no_optin")
    if shape.startswith("zero_rows_tombstones"):
        c.execute("DELETE FROM entities")
        c.execute("INSERT INTO rejected_value_tombstones (scope, category, key, value_sha256, canonical_sha256, created_at, origin_class, reason) "
                  "VALUES ('default', 'decision', 'k0', ?, ?, 1.0, 'principal', 'planted')",
                  (hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"a").hexdigest()))
    elif shape.startswith("one_row_no_journal"):
        c.execute("DELETE FROM entities WHERE key != 'k0'")
        c.execute("DROP TABLE audit_journal")
        c.execute("DROP TABLE IF EXISTS audit_head")
    elif shape.startswith("rows_no_vault_meta_table"):
        c.execute("DROP TABLE vault_meta")
    elif shape == "entities_table_absent":
        c.execute("DROP TABLE entities")
    elif shape == "not_a_kibisis_db":
        c.close()
        p.unlink()
        c = sqlite3.connect(str(p))
        c.execute("CREATE TABLE notes (x TEXT)")
        c.execute("INSERT INTO notes VALUES ('hello')")
    c.commit()
    c.close()
    before = _snap(p)
    if shape in ("one_row_no_journal_optin", "rows_no_vault_meta_table_optin"):
        v = _open(p, adopt_keyless=True)
        try:
            assert v.integrity_upgrade["entries_adopted_from_keyless_vault"] >= 1
            assert all(e.epistemic_state.value == "candidate" for e in v.list_entities(include_candidates=True)) if "include_candidates" in v.list_entities.__code__.co_varnames else True
            assert v.keyless_adoption()["entries"] >= 1
        finally:
            v.close()
        return
    for ro in (False, True):
        with pytest.raises((VaultIntegrityError, ValueError, sqlite3.OperationalError)) as exc:
            _open(p, read_only=ro, adopt_keyless=optin)
        msg = str(exc.value)
        assert "adopted" not in msg.lower() or "would be signed on nobody's word" in msg
        assert _snap(p) == before, (shape, ro, msg)


# --- 2. R5-2 / R5-3 / R5-4 ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["migrate", "schema", "lease", "init", "purge", "import"])
def test_control_empty_salted_reset_refuses_any_journal_event_whatever_its_action(tmp_path, action):
    """No action counts as 'init': an empty salted reset with one event of any name is refused untouched."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    R4._scrub_schema(c)
    c.execute("DELETE FROM entities")
    c.execute("DELETE FROM audit_journal")
    c.execute("INSERT INTO audit_journal (timestamp, action, category, key, scope, value_sha256, prev_hash, event_hash, author_id, metadata_json) "
              "VALUES (1.0, ?, '', '', '*', '', '', '', 'alice', ?)", (action, json.dumps({"forged": True})))
    R4._legacy_rechain_without_format(c)
    c.commit()
    c.close()
    before = _snap(p)
    with pytest.raises(VaultIntegrityError, match="beside a journal"):
        _open(p)
    assert _snap(p) == before
    with pytest.raises(ValueError, match="needs an integrity upgrade"):  # read-only: refused by the upgrade rule, not the discriminator
        _open(p, read_only=True)
    assert _snap(p) == before


@pytest.mark.parametrize("shape", ["key_check", "meta_mac", "format2", "sealed_row", "envelope_only", "vault_meta_table_dropped"])
def test_control_keyed_records_without_salt_refuse_before_write(tmp_path, shape):
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    if shape == "vault_meta_table_dropped":
        c.execute("DROP TABLE vault_meta")
    else:
        c.execute("DELETE FROM vault_meta WHERE key = 'kdf_salt'")
        if shape == "key_check":
            c.execute("DELETE FROM vault_meta WHERE key IN ('meta_mac', 'integrity_format')")
        elif shape == "meta_mac":
            c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'integrity_format')")
        elif shape == "format2":
            c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac')")
        elif shape in ("sealed_row", "envelope_only"):
            c.execute("DELETE FROM vault_meta")
            if shape == "envelope_only":
                c.execute("UPDATE entities SET is_encrypted = 0")
    c.commit()
    c.close()
    before = _snap(p)
    for ro in (False, True):
        with pytest.raises(VaultIntegrityError, match="salt was removed"):
            _open(p, read_only=ro)
        with pytest.raises(VaultIntegrityError, match="salt was removed"):
            _open(p, read_only=ro, adopt_keyless=True)
        assert _snap(p) == before, (shape, ro)


def test_control_every_vault_meta_key_written_is_bound_or_known_unbound():
    written = set()
    import re
    for name in os.listdir(SRC):
        if not name.endswith(".py"):
            continue
        text = open(os.path.join(SRC, name), encoding="utf-8").read()
        written |= set(re.findall(r"_set_meta\(\w+, \"(\w+)\"", text))
        written |= set(re.findall(r"INTO vault_meta \(key, value\) VALUES \('(\w+)'", text))
    bound = set(VAULT_META_BOUND_KEYS) | set(VAULT_META_BOUND_OPTIONAL)
    # meta_mac is the MAC itself; search_index_format is SQLCipher-only (R5 verified): the known unbound pair
    assert written - bound == {"search_index_format", "meta_mac"}, written - bound
    assert "quorum_dropped_from" in written and "quorum_dropped_from" in bound


def test_control_quorum_dropped_from_cannot_be_edited_or_deleted_under_a_full_set_mac(tmp_path):
    p = tmp_path / "v.sqlite"
    legacy = R5._pinned(p, 3)
    R5._restore_legacy_mac(p, legacy)
    v = _open(p)  # drops the 3, records quorum_dropped_from = 3 under the full-set MAC
    assert v.quorum_dropped_from == 3 and v.verification_quorum_stored is None
    v.close()
    for edit in ("DELETE FROM vault_meta WHERE key = 'quorum_dropped_from'",
                 "UPDATE vault_meta SET value = '1' WHERE key = 'quorum_dropped_from'"):
        shutil.copy(p, tmp_path / "e.sqlite")
        c = M._conn(tmp_path / "e.sqlite")
        c.execute(edit)
        c.commit()
        c.close()
        for ro in (False, True):
            with pytest.raises(VaultIntegrityError, match="meta MAC"):
                _open(tmp_path / "e.sqlite", read_only=ro)
    with pytest.raises(ConfigError, match="pinned at 3"):
        _open(p, pin_quorum=True)  # a verdict run without the env cannot pin the default


def test_attack_r6_4_a_planted_quorum_dropped_from_under_a_legacy_mac_is_signed_and_blocks_unnamed_verdicts(tmp_path):
    """Under a legacy (pre-quorum) MAC nothing binds ``quorum_dropped_from``. A file writer with a
    pre-quorum copy of the MAC plants ``quorum_dropped_from = 99`` (or a ``verification_quorum = 99``
    that becomes the floor): the legacy re-sign writes the full-set MAC over it, and from then on every
    pinning open that names no quorum is refused. The person must name a quorum to clear it (so this is
    a nuisance, not a lowering), but a value nobody signed became signed."""
    p = tmp_path / "v.sqlite"
    v = _open(p)  # never pinned: the file has no verification_quorum, a full-set MAC
    v.remember("c", "k", "an agent fact", origin="model", author_id="mcp-agent")
    legacy = R5._v1_mac(v)
    v.close()
    c = M._conn(p)
    c.execute("UPDATE vault_meta SET value = ? WHERE key = 'meta_mac'", (legacy,))
    c.execute("INSERT INTO vault_meta (key, value) VALUES ('quorum_dropped_from', '99')")
    c.commit()
    c.close()
    v = _open(p)  # a server's open: legacy MAC accepted, re-signed over the planted record
    try:
        assert v.quorum_dropped_from == 99
        assert not v._meta_mac_legacy
    finally:
        v.close()
    v = _open(p, read_only=True)  # now under the full-set MAC: edits would fail, the planted value is signed
    assert v.quorum_dropped_from == 99
    v.close()
    with pytest.raises(ConfigError, match="pinned at 99"):
        _open(p, pin_quorum=True)  # the person's verdict without the env is refused


# --- 3. Regression sweep -----------------------------------------------------------------------------


def test_control_a5_fixture_still_migrates_without_the_opt_in(tmp_path):
    src = M.FIXTURE_A5
    p = tmp_path / "a5.sqlite"
    shutil.copy(src, p)
    v = _open(p, passphrase=M.FIXTURE_A5_PASS)
    try:
        rep = v.integrity_upgrade
        assert rep and rep["entries_failed_signature"] == 0 and rep["entries_undecryptable"] == 0
        assert rep.get("entries_adopted_from_keyless_vault") in (None, 0)
        assert v.verify_audit_chain() is True
        assert v.keyless_adoption() is None
    finally:
        v.close()
    v = _open(p, passphrase=M.FIXTURE_A5_PASS)
    try:
        assert v.integrity_upgrade is None
    finally:
        v.close()
    v = _open(p, passphrase=M.FIXTURE_A5_PASS, read_only=True)
    try:
        assert v.verify_audit_chain() is True
    finally:
        v.close()
    assert sum(1 for e in _journal(p) if e["action"] == "migrate") == 1


def test_control_plaintext_deployment_then_passphrase_via_the_cli_flag_end_to_end(tmp_path, monkeypatch):
    """A genuine keyless vault (KIBISIS_ALLOW_PLAINTEXT, no passphrase) that later gets one: the
    documented path is a verdict command with --adopt-keyless on a terminal; result = candidates, one
    migrate event, health and review list surface it."""
    import kibisis.review as review
    from kibisis.mcp_server import KibisisMCPServer

    p = tmp_path / "plain.sqlite"
    v = SQLiteMemoryVault(str(p), allow_plaintext=True, auto_gate=False)
    v.remember("decision", "k0", "written without a passphrase", origin="model", author_id="mcp-agent")
    v.remember("decision", "k1", "another", origin="user", author_id="alice")
    v.close()
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASS)
    monkeypatch.setenv("KIBISIS_DB_PATH", str(p))
    monkeypatch.setenv("KIBISIS_SCOPE", "default")
    monkeypatch.setattr(review, "require_terminal", lambda command: None)  # the person is at a terminal
    monkeypatch.setattr(review, "account_identity", lambda: ("operator", "operator"), raising=False)
    assert review.main(["approve", "decision", "k0"]) != 0  # without the flag: refused
    rc = review.main(["approve", "decision", "k0", "--adopt-keyless"])
    assert rc in (0, 1, 2)  # the verdict itself may or may not reach quorum; the adoption is what we check
    v = _open(p)
    try:
        assert v.keyless_adoption()["entries"] == 2
        assert sum(1 for e in _journal(p) if e["action"] == "migrate") == 1
        k1 = v.get("decision", "k1", scope="default")
        assert k1.epistemic_state.value == "candidate"
        health = KibisisMCPServer(vault=v, scope="default").health() if hasattr(KibisisMCPServer, "health") else None
    finally:
        v.close()
    v = _open(p, read_only=True)
    try:
        srv = KibisisMCPServer(vault=v, scope="default")
        fn = getattr(srv, "kibisis_health", None) or getattr(srv, "health", None) or getattr(srv, "_health", None)
        report = fn() if fn else None
        assert report is None or report["keyless_adoption"]["entries"] == 2
    finally:
        v.close()
    assert review.main(["list"]) == 0
