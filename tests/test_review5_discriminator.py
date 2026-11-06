"""Review 5 (091c218): the a5 discriminator (R4-1 lineage), the quorum under a legacy MAC (R4-2) and the
lift reconciliation state space (R4-3), under attack; converted to a regression suite at round 5.

``test_control_*`` asserts the secure behaviour (failing = bug); ``test_fixed_r5_*`` are the four
``test_attack_*`` repros rewritten to assert the round-5 fix (R5-1..R5-4, review_notes/R5.md).
Vaults are opened WITHOUT SQLCipher with a passphrase (allow_plaintext) = SECURITY.md's
file-writer model.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis._vault_crypto import value_digests
from kibisis.config import ConfigError
from kibisis.crypto import (
    AESGCMCryptoEnvelopeProvider,
    VAULT_META_BOUND_KEYS,
    VAULT_META_BOUND_KEYS_V1,
    VAULT_META_BOUND_OPTIONAL,
    sign_tenant_payload,
    vault_meta_mac,
)
from kibisis._vault_review import _class_rank
from kibisis.vault import VaultIntegrityError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_review3_ab_migration as M  # noqa: E402  _seeded, _conn, _scrub_everything_but_entries, PASS, fixture
import test_review4_r3fixes as R4  # noqa: E402  _scrub_schema, _legacy_rechain_without_format, _content, _plant_global_agent_row

PASS = M.PASS
VALUE = "deploy on fridays"
SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "kibisis")


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch, tmp_path):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(tmp_path / "argus.jsonl"))
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _open(p, passphrase=PASS, **kw):
    kw.setdefault("auto_gate", False)
    return SQLiteMemoryVault(str(p), passphrase=passphrase, **kw)


def _file_digest(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def _a5_seal(salt: bytes, passphrase: str, scope: str, category: str, key: str, content: str):
    """A row the way 0.1.0a5 wrote it: envelope under the vault salt with no binding, a format 1
    signature under the passphrase's legacy key, an empty content column."""
    provider = AESGCMCryptoEnvelopeProvider(salt=salt)
    envelope = provider.encrypt(content.encode("utf-8"), passphrase)
    legacy_key = hashlib.sha256(f"kibisis-tenant-sig:{passphrase}".encode("utf-8")).digest()
    sig = sign_tenant_payload(legacy_key, scope, f"{category}:{key}", content)
    return envelope.model_dump_json(), sig


# =============================================================== 1. the discriminator and the salt-absent door


ADOPT_REFUSAL = "plaintext entries and no salt; a keyed vault whose records were removed looks the same"


def _laundered_keyless_file(tmp_path, name="v.sqlite"):
    """R5-1's file: a keyed vault whose WHOLE vault_meta (salt included) was deleted, every row
    flattened to plaintext with the writer's content and state, tombstones dropped, journal
    re-chained headless. Nothing in it tells it from a vault that never had a passphrase."""
    p = M._seeded(tmp_path / name)
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    c.execute("DELETE FROM vault_meta")
    c.execute("UPDATE entities SET is_encrypted = 0, encrypted_envelope_json = NULL, tenant_sig = NULL, "
              "content = 'FORGED ' || key, epistemic_state = 'verified'")
    c.commit()
    c.close()
    return p


def test_fixed_r5_1_salt_absent_reset_is_refused_without_the_opt_in_and_nothing_is_written(tmp_path):
    """R5-1 (b). The salt-absent door needs an explicit opt-in: without ``adopt_keyless=True`` the
    writable open AND the read-only open are refused, naming the count and the ambiguity, and the
    file is byte for byte as the writer left it (no salt, no schema upgrade). A keyless file with
    no rows is a fresh vault and needs no opt-in."""
    p = _laundered_keyless_file(tmp_path)
    before = R4._content(p)
    digest, mtime = _file_digest(p), os.stat(p).st_mtime_ns
    with pytest.raises(VaultIntegrityError, match=ADOPT_REFUSAL) as info:
        _open(p)
    assert "this file has 3 plaintext entries and no salt" in str(info.value)
    assert "pass adopt_keyless=True to adopt them as candidates" in str(info.value)
    assert R4._content(p) == before
    assert (_file_digest(p), os.stat(p).st_mtime_ns) == (digest, mtime)
    with pytest.raises(VaultIntegrityError, match=ADOPT_REFUSAL):
        _open(p, read_only=True)  # the forged content is not served either
    assert R4._content(p) == before
    c = M._conn(p)
    assert c.execute("SELECT count(*) FROM vault_meta").fetchone()[0] == 0
    c.close()
    # an empty keyless file (no rows, no tombstones) is a fresh vault: no opt-in needed
    empty = tmp_path / "empty.sqlite"
    SQLiteMemoryVault(str(empty), auto_gate=False, allow_plaintext=True).close()
    v = _open(empty)
    try:
        assert v.integrity_upgrade is None and v.list_entities() == []
    finally:
        v.close()


def test_fixed_r5_1_opted_in_adoption_demotes_every_row_to_candidate_and_is_surfaced(tmp_path):
    """R5-1 (a). With the opt-in, every adopted row is a ``candidate`` with its attestations and
    reviews reset, whatever state and metadata the file carried; the ``migrate`` event records
    ``entries_adopted_from_keyless_vault``; ``keyless_adoption()``, ``review list``'s notice and
    the MCP ``health`` report say so; the forged state is not ``verified`` and the value the vault
    had rejected is writable only as what it is, a candidate on nobody's word."""
    p = _laundered_keyless_file(tmp_path)
    c = M._conn(p)
    c.execute("UPDATE entities SET metadata_json = ? WHERE key = 'k0'", (json.dumps({
        "human_reviews": [{"reviewer_id": "forged", "verdict": "verified"}],
        "attestations": ["forged"], "last_verified_at": 1.0, "author_id": "alice", "note": "kept",
    }),))
    c.commit()
    c.close()
    v = _open(p, adopt_keyless=True)
    try:
        up = v.integrity_upgrade
        assert up["entries_adopted_from_keyless_vault"] == 3 and up["entries_resealed"] == 3
        assert v.list_entities() == []  # nothing verified is served
        got = {(e.key, e.content, e.epistemic_state.value) for e in v.list_entities(epistemic_state="candidate")}
        assert got == {(f"k{i}", f"FORGED k{i}", "candidate") for i in range(3)}
        k0 = v.get("decision", "k0")
        assert "human_reviews" not in k0.metadata and "attestations" not in k0.metadata
        assert "last_verified_at" not in k0.metadata and k0.metadata["note"] == "kept"
        assert k0.metadata["adopted_from_keyless_file"]["stored_state"] == "verified"
        assert v.verify_audit_chain() is True
        migrate = [e for e in v.list_audit_events(limit=50) if e.action == "migrate"]
        assert len(migrate) == 1 and migrate[0].metadata["entries_adopted_from_keyless_vault"] == 3
        report = v.keyless_adoption()
        assert report["entries"] == 3 and report["sequence"] == migrate[0].sequence
        from kibisis.review import _adoption_line
        assert "3 entries adopted from a keyless file on" in _adoption_line(v)
        assert v._meta("key_check") is not None and v._meta("meta_mac") is not None
    finally:
        v.close()
    ro = _open(p, read_only=True)  # salted now: the ordinary keyed open, no opt-in involved
    try:
        assert ro.list_entities() == [] and len(ro.list_entities(epistemic_state="candidate")) == 3
        assert ro.keyless_adoption()["entries"] == 3
    finally:
        ro.close()
    from kibisis.mcp_server import KibisisMCPServer
    server = KibisisMCPServer(vault=_open(p), scope="default")
    try:
        health = server._health()
        assert health["keyless_adoption"]["entries"] == 3
        assert "adopted from a keyless file" in health["keyless_adoption"]["note"]
    finally:
        server.vault.close()


def test_fixed_r5_1_a_keyless_file_with_tombstones_is_refused_even_with_the_opt_in(tmp_path):
    """A tombstone in a keyless file would be MAC-signed on nobody's word: refused outright, with
    nothing written; the operator lifts it in the keyless vault (no passphrase) first."""
    p = _laundered_keyless_file(tmp_path)
    c = M._conn(p)
    exact, canonical = value_digests(VALUE)
    c.execute(
        "INSERT INTO rejected_value_tombstones (category, key, value_sha256, canonical_sha256, reason, author_id, "
        "created_at, scope, sealed_digests, origin_class) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("decision", "planted", exact, canonical, "planted", "file-writer", 0.0, "default", None, "principal"),
    )
    c.commit()
    c.close()
    before = R4._content(p)
    for kw in ({}, {"adopt_keyless": True}, {"read_only": True}):
        with pytest.raises(VaultIntegrityError, match="tombstone rows; a tombstone adopted from a keyless file"):
            _open(p, **kw)
        assert R4._content(p) == before


def test_fixed_r5_1_servers_and_okf_commands_never_pass_the_opt_in():
    """The opt-in lives only on the operator commands behind the terminal check."""
    for name in ("mcp_server.py", "aml_adapter.py"):
        text = open(os.path.join(SRC, name), encoding="utf-8").read()
        assert "adopt_keyless" not in text, name
    for name in os.listdir(os.path.join(SRC, "okf")):
        if name.endswith(".py"):
            text = open(os.path.join(SRC, "okf", name), encoding="utf-8").read()
            assert "adopt_keyless" not in text, name
    main_text = open(os.path.join(SRC, "__main__.py"), encoding="utf-8").read()
    assert main_text.count("adopt_keyless=bool(args.adopt_keyless)") == 1  # admit only
    assert "_open_okf_vault" in main_text and "adopt_keyless" not in main_text.split("def _open_okf_vault")[1].split("def ")[0]


def test_control_a_genuine_never_keyed_vault_and_the_laundered_file_differ_only_by_what_the_writer_chooses(tmp_path):
    """What a vault the current code writes without a passphrase looks like: ``vault_meta`` empty, a
    head row, format 3 events, rows signed under the path key. Everything in that list is computable
    from the path, so the laundered file of R5-1 can be made identical; nothing in the file tells the
    two apart (SECURITY.md:144-146 says so for an EMPTY file; the file need not be empty)."""
    p = tmp_path / "keyless.sqlite"
    v = SQLiteMemoryVault(str(p), auto_gate=False, allow_plaintext=True)
    v.remember("decision", "k0", "fact 0", origin="user", author_id="a")
    v.close()
    c = M._conn(p)
    assert c.execute("SELECT count(*) FROM vault_meta").fetchone()[0] == 0
    assert c.execute("SELECT count(*) FROM audit_head").fetchone()[0] == 1
    assert {r[0] for r in c.execute("SELECT format FROM audit_journal")} == {3}
    assert c.execute("SELECT is_encrypted FROM entities").fetchone()[0] == 0
    c.close()
    with pytest.raises(VaultIntegrityError, match=ADOPT_REFUSAL):
        _open(p)  # the genuine keyless vault is refused the same way: the file cannot tell
    v = _open(p, adopt_keyless=True)  # first open with a passphrase: adopted, as candidates
    try:
        assert v.integrity_upgrade["entries_adopted_from_keyless_vault"] == 1
        assert v.get("decision", "k0").epistemic_state.value == "candidate"
    finally:
        v.close()


def _plant_tombstone_and_history(c, content, author="file-writer"):
    """On an a5-shaped (schema-scrubbed, headless) file: a tombstone row with plain digests, its
    journal event, and a few more non-entry events, re-chained in format 1."""
    exact, canonical = value_digests(content)
    c.execute(
        "INSERT INTO rejected_value_tombstones (category, key, value_sha256, canonical_sha256, reason, author_id, "
        "created_at, scope, sealed_digests, origin_class) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("decision", "planted", exact, canonical, "planted by the file writer", author, 0.0, "default", None, "principal"),
    )
    seq = (c.execute("SELECT coalesce(max(sequence), 0) FROM audit_journal").fetchone()[0] or 0) + 1
    for action, cat, key, val, meta in (
        ("tombstone", "decision", "planted", exact, {"reason": "planted", "origin_class": "principal", "canonical_sha256": canonical}),
        ("attestations_reset", "decision", "k0", "", {"reason": "forged history"}),
        ("state_transition", "decision", "k0", "", {"from": "candidate", "to": "verified", "reason": "forged"}),
    ):
        c.execute(
            "INSERT INTO audit_journal (sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, "
            "event_hash, author_id, metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (seq, 1700000000.0 + seq, action, cat, key, "default", val, "", "", author, json.dumps(meta, sort_keys=True)),
        )
        seq += 1
    R4._legacy_rechain_without_format(c)


def test_fixed_r5_2_the_empty_vault_reset_with_planted_tombstones_or_history_is_refused_untouched(tmp_path):
    """R5-2. "An empty vault" means empty: with no entity row, a planted tombstone row or ANY journal
    event (``tombstone``, ``attestations_reset``, ``state_transition``, ...) is a witness; the open
    is refused naming it and the file is as the writer left it. Each planted piece on its own is
    enough."""
    for variant in ("both", "tombstone_only", "history_only"):
        p = M._seeded(tmp_path / f"{variant}.sqlite")
        c = M._conn(p)
        M._scrub_everything_but_entries(c)
        R4._scrub_schema(c)
        c.execute("DELETE FROM entities")
        c.execute("DELETE FROM audit_journal")
        c.execute("DELETE FROM vault_meta WHERE key = 'term_index_format'")  # a witness since round 5
        _plant_tombstone_and_history(c, "the value the writer wants blocked")
        if variant == "tombstone_only":
            c.execute("DELETE FROM audit_journal")
        elif variant == "history_only":
            c.execute("DELETE FROM rejected_value_tombstones")
        c.commit()
        c.close()
        before = R4._content(p)
        with pytest.raises(VaultIntegrityError, match="not a 0.1.0a5 file") as info:
            _open(p)
        msg = str(info.value)
        if variant != "history_only":
            assert "empty beside 1 tombstone rows" in msg, msg
        if variant != "tombstone_only":
            assert "empty beside a journal of" in msg and "'tombstone' on 'decision:planted'" in msg, msg
        assert R4._content(p) == before, variant
        with pytest.raises((ValueError, VaultIntegrityError)):
            _open(p, read_only=True)
        assert R4._content(p) == before, variant


def _fixture_envelope():
    c = M._conn(M.FIXTURE_A5)
    row = c.execute("SELECT encrypted_envelope_json FROM entities WHERE is_encrypted = 1 LIMIT 1").fetchone()
    c.close()
    return row[0]


# Each state is the R2-B1 reset + the schema scrub (so every structural witness is gone) + one more edit,
# on a vault that was keyed. Expected: refused with nothing written. ``ValueError`` is the wrong-passphrase
# refusal (no sealed row opens and nothing else is found); ``VaultIntegrityError`` names a witness.
STATES = {
    "integrity_format_1": (["UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'",
                            "INSERT OR IGNORE INTO vault_meta VALUES ('integrity_format', '1')"], VaultIntegrityError),
    "integrity_format_0": (["INSERT OR REPLACE INTO vault_meta VALUES ('integrity_format', '0')"], VaultIntegrityError),
    "integrity_format_empty": (["INSERT OR REPLACE INTO vault_meta VALUES ('integrity_format', '')"], VaultIntegrityError),
    "integrity_format_text": (["INSERT OR REPLACE INTO vault_meta VALUES ('integrity_format', 'abc')"], VaultIntegrityError),
    "integrity_format_1_9": (["INSERT OR REPLACE INTO vault_meta VALUES ('integrity_format', '1.9')"], VaultIntegrityError),
    "is_encrypted_2": (["UPDATE entities SET is_encrypted = 2"], VaultIntegrityError),
    "is_encrypted_null_rebuilt": (["@is_encrypted_null"], VaultIntegrityError),
    "term_index_format_left": ([], VaultIntegrityError),  # left by the R2-B1 reset; a witness since round 5 (a5 never wrote it)
    # term_index_format is a witness since round 5 (a5 never wrote it); the writer deletes it so the
    # wrong-passphrase ambiguity these three states record is what is tested
    "envelope_valid_a5_shape_other_passphrase": (["@drop_term_index_format", "@reseal:other passphrase (test only)"], ValueError),
    "fixture_envelopes_spliced": (["@drop_term_index_format", "@fixture_envelopes"], ValueError),
    "attacker_salt_rows_resealed_under_attacker_passphrase": (["@drop_term_index_format", "@attacker_salt"], ValueError),
    "one_row_real_bound_others_attacker_sealed": (["@reseal_all_but_k0:other passphrase (test only)"], VaultIntegrityError),
}


def _apply(c, p, steps):
    for step in steps:
        if step == "@is_encrypted_null":
            # rebuild the table with a nullable is_encrypted column (the file writer's table rebuild)
            sql = c.execute("SELECT sql FROM sqlite_master WHERE name = 'entities'").fetchone()[0]
            assert "is_encrypted INTEGER NOT NULL DEFAULT 0" in sql
            cols = [r[1] for r in c.execute("PRAGMA table_info(entities)")]
            c.execute("PRAGMA foreign_keys = OFF")
            c.executescript(
                "DROP TRIGGER IF EXISTS entities_ai; DROP TRIGGER IF EXISTS entities_au; DROP TRIGGER IF EXISTS entities_ad; "
                "DROP TRIGGER IF EXISTS entities_search_ai; DROP TRIGGER IF EXISTS entities_search_au; "
                "DROP TRIGGER IF EXISTS entities_search_ad; "
                "ALTER TABLE entities RENAME TO e2; "
                + sql.replace("is_encrypted INTEGER NOT NULL DEFAULT 0", "is_encrypted INTEGER") + "; "
                + "INSERT INTO entities (" + ", ".join(cols) + ") SELECT "
                + ", ".join("NULL" if col == "is_encrypted" else col for col in cols) + " FROM e2; DROP TABLE e2;"
            )
        elif step.startswith("@reseal:") or step.startswith("@reseal_all_but_k0:"):
            other = step.split(":", 1)[1]
            salt = bytes(c.execute("SELECT value FROM vault_meta WHERE key = 'kdf_salt'").fetchone()[0])
            where = "" if step.startswith("@reseal:") else " WHERE key != 'k0'"
            for r in c.execute(f"SELECT id, scope, category, key FROM entities{where}").fetchall():
                env, sig = _a5_seal(salt, other, r["scope"], r["category"], r["key"], f"attacker text for {r['key']}")
                c.execute("UPDATE entities SET encrypted_envelope_json = ?, tenant_sig = ?, is_encrypted = 1 WHERE id = ?",
                          (env, sig, r["id"]))
        elif step == "@drop_term_index_format":
            c.execute("DELETE FROM vault_meta WHERE key = 'term_index_format'")
        elif step == "@fixture_envelopes":
            c.execute("UPDATE entities SET encrypted_envelope_json = ?", (_fixture_envelope(),))
        elif step == "@attacker_salt":
            salt = os.urandom(16)
            c.execute("INSERT OR REPLACE INTO vault_meta VALUES ('kdf_salt', ?)", (salt,))
            for r in c.execute("SELECT id, scope, category, key FROM entities").fetchall():
                env, sig = _a5_seal(salt, "attacker passphrase (test only)", r["scope"], r["category"], r["key"], "attacker text")
                c.execute("UPDATE entities SET encrypted_envelope_json = ?, tenant_sig = ?, is_encrypted = 1 WHERE id = ?",
                          (env, sig, r["id"]))
        else:
            c.execute(step)


@pytest.mark.parametrize("state", sorted(STATES))
def test_control_salt_present_states_beyond_r4s_table_are_refused_untouched(tmp_path, state):
    steps, expected = STATES[state]
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    R4._scrub_schema(c)
    _apply(c, p, steps)
    c.commit()
    c.close()
    before = R4._content(p)
    with pytest.raises(expected) as info:
        _open(p)
    assert R4._content(p) == before, state
    msg = str(info.value)
    if expected is ValueError:
        assert "Failed to authenticate" in msg
    else:
        assert "not a 0.1.0a5 file" in msg, msg
        if state == "term_index_format_left":
            assert "vault_meta.term_index_format" in msg, msg
    # the read-only open refuses the same file without writing (by design: no upgrade, no discriminator)
    with pytest.raises((ValueError, VaultIntegrityError)):
        _open(p, read_only=True)
    assert R4._content(p) == before, state


def test_control_attacker_salt_reseal_opens_only_under_the_attackers_passphrase(tmp_path):
    """The flip side of ``attacker_salt_rows_resealed...``: the file writer's own passphrase opens and
    migrates the file (it is now their vault); the operator's is refused as a WRONG PASSPHRASE, with no
    hint that the salt was replaced. Recorded as an ambiguity, not a hole (a file writer can delete the
    file; SECURITY.md)."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    R4._scrub_schema(c)
    _apply(c, p, ["@drop_term_index_format", "@attacker_salt"])
    c.commit()
    c.close()
    with pytest.raises(ValueError, match="Failed to authenticate"):
        _open(p)
    v = _open(p, passphrase="attacker passphrase (test only)")
    try:
        assert v.integrity_upgrade["entries_resealed"] == 3
    finally:
        v.close()


def test_fixed_r5_3_sealed_rows_without_any_vault_meta_are_refused_before_anything_is_written(tmp_path):
    """R5-3. With ``vault_meta`` emptied (or dropped) and the rows still sealed, a sealed row is itself
    proof the file was keyed: the open is refused naming the sealed rows and the missing salt BEFORE
    ``_init_schema`` and before any salt is issued; bytes and mtime are unchanged, and the next open
    tells the same story. The read-only open refuses the same way."""
    for drop_table in (False, True):
        p = M._seeded(tmp_path / f"v{int(drop_table)}.sqlite")
        c = M._conn(p)
        M._scrub_everything_but_entries(c)
        c.execute("DROP TABLE vault_meta" if drop_table else "DELETE FROM vault_meta")
        c.commit()
        c.close()
        before = R4._content(p)
        digest, mtime = _file_digest(p), os.stat(p).st_mtime_ns
        for _ in range(2):  # the second refusal is the same refusal
            with pytest.raises(VaultIntegrityError, match="salt was removed") as info:
                _open(p)
            assert "3 sealed entries" in str(info.value) and "no kdf_salt" in str(info.value)
            assert R4._content(p) == before
            assert (_file_digest(p), os.stat(p).st_mtime_ns) == (digest, mtime)
        with pytest.raises(VaultIntegrityError, match="salt was removed"):
            _open(p, read_only=True)
        assert R4._content(p) == before
        c = M._conn(p)
        assert c.execute("SELECT count(*) FROM sqlite_master WHERE name = 'vault_meta'").fetchone()[0] == int(not drop_table)
        if not drop_table:
            assert c.execute("SELECT count(*) FROM vault_meta").fetchone()[0] == 0
        c.close()


def test_control_read_only_open_of_a_reset_file_writes_nothing(tmp_path):
    """Read-only never runs the discriminator or the migration: a salt-present format 1 file is refused
    ("needs an integrity upgrade") and the bytes and mtime are unchanged, for the all-witness scrub and
    for the empty reset alike."""
    for empty in (False, True):
        p = M._seeded(tmp_path / f"v{int(empty)}.sqlite")
        c = M._conn(p)
        M._scrub_everything_but_entries(c)
        R4._scrub_schema(c)
        if empty:
            c.execute("DELETE FROM entities")
            c.execute("DELETE FROM audit_journal")
        c.commit()
        c.close()
        digest, mtime = _file_digest(p), os.stat(p).st_mtime_ns
        with pytest.raises(ValueError, match="needs an integrity upgrade"):
            _open(p, read_only=True)
        assert (_file_digest(p), os.stat(p).st_mtime_ns) == (digest, mtime)
        assert not os.path.exists(str(p) + "-wal") or os.path.getsize(str(p) + "-wal") == 0


def test_control_the_empty_reset_is_told_from_a_new_vault_by_its_migrate_event(tmp_path):
    """What the operator sees after the admitted (truly empty) reset: since round 5 the migration of
    a salted file with nothing in it writes a ``migrate`` event (``empty_keyed_file``), so the reset
    file is NOT byte-for-byte the shape of a vault created fresh: its journal says a keyed file was
    here. A vault created fresh has no such event."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    R4._scrub_schema(c)
    c.execute("DELETE FROM entities")
    c.execute("DELETE FROM audit_journal")
    c.execute("DELETE FROM vault_meta WHERE key = 'term_index_format'")  # a witness since round 5
    c.commit()
    c.close()
    v = _open(p)
    try:
        assert v.list_entities() == []
        assert v.integrity_upgrade is not None and v.integrity_upgrade["empty_keyed_file"] is True
        events = v.list_audit_events(limit=10)
        assert [e.action for e in events] == ["migrate"]
        assert events[0].metadata["empty_keyed_file"] is True
        assert v.verify_audit_chain() is True
        assert v.keyless_adoption() is None
    finally:
        v.close()
    v = _open(p)
    try:
        assert v.integrity_upgrade is None and [e.action for e in v.list_audit_events(limit=10)] == ["migrate"]
    finally:
        v.close()
    fresh = _open(tmp_path / "new.sqlite")
    try:
        assert fresh.integrity_upgrade is None
        assert fresh._conn.execute("SELECT count(*) FROM audit_journal").fetchone()[0] == 0
    finally:
        fresh.close()


def test_control_a5_fixture_and_an_a5_style_variant_with_one_more_entry_migrate(tmp_path):
    """The genuine fixture, and the fixture plus one entry sealed the way a5 sealed (vault salt, no
    binding, format 1 signature under the passphrase's legacy key), both migrate writable, migrate
    idempotently, re-open read-only and verify their chain; a wrong passphrase stays a wrong passphrase."""
    for variant in (False, True):
        p = tmp_path / f"a5-{int(variant)}.sqlite"
        shutil.copy(M.FIXTURE_A5, p)
        c = M._conn(p)
        if variant:
            salt = bytes(c.execute("SELECT value FROM vault_meta WHERE key = 'kdf_salt'").fetchone()[0])
            env, sig = _a5_seal(salt, M.FIXTURE_A5_PASS, "default", "ops", "extra", "one more a5 entry")
            c.execute(
                "INSERT INTO entities (category, key, content, metadata_json, created_at, updated_at, is_encrypted, "
                "encrypted_envelope_json, scope, epistemic_state, tenant_sig) "
                "VALUES ('ops', 'extra', '', '{}', 1.0, 1.0, 1, ?, 'default', 'verified', ?)",
                (env, sig),
            )
            # a5 journaled the put with a plain digest
            exact, _ = value_digests("one more a5 entry")
            last = c.execute("SELECT * FROM audit_journal ORDER BY sequence DESC LIMIT 1").fetchone()
            c.execute(
                "INSERT INTO audit_journal (sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, "
                "event_hash, author_id, metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (last["sequence"] + 1, last["timestamp"] + 1, "put", "ops", "extra", "default", exact, "", "", None, "{}"),
            )
            R4._legacy_rechain_without_format(c)
        n_rows = c.execute("SELECT count(*) FROM entities").fetchone()[0]
        c.commit()
        c.close()
        with pytest.raises(ValueError, match="Failed to authenticate"):
            _open(p, passphrase="not the fixture passphrase (test only)")
        v = _open(p, passphrase=M.FIXTURE_A5_PASS)
        try:
            up = v.integrity_upgrade
            assert up["entries_failed_signature"] == 0 and up["entries_undecryptable"] == 0
            assert up["entries_resealed"] >= 5 + int(variant)
            assert v.verify_audit_chain() is True
            assert v._conn.execute("SELECT count(*) FROM entities").fetchone()[0] == n_rows
            if variant:
                assert v.get("ops", "extra").content == "one more a5 entry"
        finally:
            v.close()
        v = _open(p, passphrase=M.FIXTURE_A5_PASS)
        try:
            assert v.integrity_upgrade is None and v.verify_audit_chain() is True
        finally:
            v.close()
        ro = _open(p, passphrase=M.FIXTURE_A5_PASS, read_only=True)
        try:
            assert ro.verify_audit_chain() is True
            assert ro._conn.execute("SELECT count(*) FROM entities").fetchone()[0] == n_rows
        finally:
            ro.close()
        with pytest.raises(ValueError, match="Failed to authenticate"):
            _open(p, passphrase="not the fixture passphrase (test only)")


# =============================================================== 2. quorum under a legacy MAC (R4-2)


def _v1_mac(v):
    return vault_meta_mac(v._signing_key, v._meta_mac_fields(), VAULT_META_BOUND_KEYS_V1)


def _pinned(p, quorum):
    v = _open(p, verification_quorum=quorum, pin_quorum=True)
    v.remember("c", "k", "an agent fact", origin="model", author_id="mcp-agent")
    legacy = _v1_mac(v)
    assert v.verification_quorum_stored == quorum
    v.close()
    return legacy


def _restore_legacy_mac(p, legacy):
    """The file writer puts back the meta MAC from a pre-quorum copy of the file (the V1-bound values
    have not changed since, so that copy still verifies over the legacy set)."""
    c = M._conn(p)
    c.execute("UPDATE vault_meta SET value = ? WHERE key = 'meta_mac'", (legacy,))
    c.commit()
    c.close()


def test_control_file_writer_cannot_make_a_full_set_mac_legacy_by_editing(tmp_path):
    """Without a pre-quorum copy there is no legacy MAC to restore: editing or deleting the stored quorum
    under a full-set MAC fails both MAC checks in both open modes."""
    p = tmp_path / "v.sqlite"
    _pinned(p, 3)
    for edit in ("UPDATE vault_meta SET value = '2' WHERE key = 'verification_quorum'",
                 "DELETE FROM vault_meta WHERE key = 'verification_quorum'"):
        shutil.copy(p, tmp_path / "e.sqlite")
        c = M._conn(tmp_path / "e.sqlite")
        c.execute(edit)
        c.commit()
        c.close()
        for ro in (False, True):
            with pytest.raises(VaultIntegrityError, match="meta MAC does not cover"):
                _open(tmp_path / "e.sqlite", read_only=ro)


def test_control_legacy_mac_on_a_pinned_3_vault_drops_the_quorum_and_the_env_repins_it(tmp_path, caplog):
    p = tmp_path / "v.sqlite"
    legacy = _pinned(p, 3)
    _restore_legacy_mac(p, legacy)
    digest = _file_digest(p)
    ro = _open(p, read_only=True)  # read-only: ignored, not re-signed, nothing written
    try:
        assert ro.verification_quorum_stored is None and ro.verification_quorum == vault_module.DEFAULT_VERIFICATION_QUORUM
        assert ro._meta("verification_quorum") == "3"
    finally:
        ro.close()
    assert _file_digest(p) == digest
    caplog.clear()
    v = _open(p)  # writable, naming no quorum: dropped, re-signed over the full set with no quorum
    try:
        assert v.verification_quorum_stored is None
        assert v._meta("verification_quorum") is None
        assert v._meta("meta_mac") == vault_meta_mac(v._signing_key, v._meta_mac_fields())
        assert v._meta_mac_legacy is False
        from kibisis.review import _quorum_line
        assert "default until a verdict pins it" in _quorum_line(v)
    finally:
        v.close()
    assert any("not covered by the meta MAC" in r.message and "3" in r.message for r in caplog.records)
    for ro in (False, True):  # every later open: full-set MAC, nothing stored
        v = _open(p, read_only=ro)
        try:
            assert v.verification_quorum_stored is None and v._meta_mac_legacy is False
        finally:
            v.close()
    v = _open(p, verification_quorum=3, pin_quorum=True)  # the operator's verdict under their env re-pins
    try:
        assert v.verification_quorum_stored == 3
    finally:
        v.close()


def test_fixed_r5_4_after_a_legacy_mac_restore_a_verdict_run_without_the_env_cannot_pin_lower(tmp_path):
    """R5-4. The drop records ``quorum_dropped_from = 3`` under the full-set MAC. A later pinning
    open that names no quorum would pin the default 2, below it: refused (ConfigError naming the 3
    and the env to set). Non-pinning opens run as before. A pinning open under the env re-pins 3
    and clears the record; a pinning open that names a LOWER quorum explicitly is allowed (the
    person said so) and clears it too. A file writer cannot remove or lower the record: both MAC
    checks fail."""
    from kibisis.config import ConfigError
    p = tmp_path / "v.sqlite"
    legacy = _pinned(p, 3)
    _restore_legacy_mac(p, legacy)
    v = _open(p)  # any writable open: the 3 is dropped, and recorded
    try:
        assert v.verification_quorum_stored is None and v.quorum_dropped_from == 3
        assert v._meta("quorum_dropped_from") == "3"
        assert v._meta("meta_mac") == vault_meta_mac(v._signing_key, v._meta_mac_fields())
        from kibisis.review import _quorum_line
        assert "a pinned 3 was dropped" in _quorum_line(v)
    finally:
        v.close()
    with pytest.raises(ConfigError, match="pinned at 3") as info:
        _open(p, pin_quorum=True)  # a verdict run without KIBISIS_VERIFICATION_QUORUM
    assert "KIBISIS_VERIFICATION_QUORUM=3" in str(info.value)
    for ro in (False, True):  # non-pinning opens: unchanged, the record stands
        v = _open(p, read_only=ro)
        try:
            assert v.verification_quorum_stored is None and v.quorum_dropped_from == 3
            assert v.verification_quorum == vault_module.DEFAULT_VERIFICATION_QUORUM
        finally:
            v.close()
    # the file writer cannot lower or remove the record
    for edit in ("UPDATE vault_meta SET value = '1' WHERE key = 'quorum_dropped_from'",
                 "DELETE FROM vault_meta WHERE key = 'quorum_dropped_from'"):
        shutil.copy(p, tmp_path / "e.sqlite")
        c = M._conn(tmp_path / "e.sqlite")
        c.execute(edit)
        c.commit()
        c.close()
        for ro in (False, True):
            with pytest.raises(VaultIntegrityError, match="meta MAC does not cover"):
                _open(tmp_path / "e.sqlite", read_only=ro)
    # the person's verdict under their env re-pins 3 and clears the record
    v = _open(p, verification_quorum=3, pin_quorum=True)
    try:
        assert v.verification_quorum_stored == 3 and v.quorum_dropped_from is None
        assert v._meta("quorum_dropped_from") is None
        assert v._meta("meta_mac") == vault_meta_mac(v._signing_key, v._meta_mac_fields())
    finally:
        v.close()
    v = _open(p)
    try:
        assert v.verification_quorum_stored == 3 and v.verification_quorum == 3
    finally:
        v.close()
    # naming a lower quorum explicitly is the person's choice: allowed, record cleared
    p2 = tmp_path / "v2.sqlite"
    _restore_legacy_mac(p2, _pinned(p2, 3))
    _open(p2).close()
    v = _open(p2, verification_quorum=2, pin_quorum=True)
    try:
        assert v.verification_quorum_stored == 2 and v.quorum_dropped_from is None
    finally:
        v.close()


def test_control_every_vault_meta_key_written_is_under_the_mac_or_known_unbound():
    """Enumerate every key the code writes to ``vault_meta`` against VAULT_META_BOUND_KEYS."""
    written = set()
    for name in os.listdir(SRC):
        if name.endswith(".py"):
            text = open(os.path.join(SRC, name), encoding="utf-8").read()
            written |= set(re.findall(r"_set_meta\(\w+,\s*\"(\w+)\"", text))
            written |= set(re.findall(r"INSERT (?:OR REPLACE )?INTO vault_meta \(key, value\) VALUES \('(\w+)'", text))
    assert "kdf_salt" in written and "verification_quorum" in written and "quorum_dropped_from" in written
    unbound = written - set(VAULT_META_BOUND_KEYS) - set(VAULT_META_BOUND_OPTIONAL) - {"meta_mac"}
    # search_index_format governs the SQLCipher-only entry search index (a file writer cannot reach it
    # without the passphrase); anything else here is a finding.
    assert unbound == {"search_index_format"}, unbound


# =============================================================== 3. lift reconciliation state space (R4-3)


def _plant_row(v, category, key, content, scope, klass):
    """A tombstone row of ``klass`` in ``scope`` ('*' included), journaled as the import does."""
    exact, canonical = value_digests(content)
    s_exact, s_canonical = v._stored_digests(exact, canonical)
    with v._write_tx() as cursor:
        cursor.execute(
            "INSERT INTO rejected_value_tombstones (category, key, value_sha256, canonical_sha256, reason, author_id, "
            "created_at, scope, sealed_digests, origin_class, tombstone_mac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (category, key, s_exact, s_canonical, "planted", "mcp-agent", 0.0, scope,
             v._seal_digests(scope, category, key, exact, canonical), klass,
             v._tombstone_mac(scope, category, key, s_exact, s_canonical, klass)),
        )
        v._record_audit_event(cursor=cursor, action="tombstone", category=category, key=key, scope=scope,
                              value_sha256=s_exact, author_id="mcp-agent",
                              metadata={"reason": "planted", "canonical_sha256": s_canonical,
                                        "path": "import_snapshot", "origin_class": klass})


def _legacy_writer(v, writer_cat, writer_key, shape):
    """Journal lifts the way earlier releases did: under the writer's identity, the row named in the
    metadata (``pre_r3``: with ``tombstone_scope``; ``pre_r3_no_scope``: a hypothetical shape without)."""
    real = v._record_audit_event

    def pre_fix(cursor, action, category, key, scope, value_sha256, author_id=None, metadata=None, **kw):
        if action == "tombstone_lifted":
            category, key, scope = writer_cat, writer_key, metadata["entry_scope"]
            drop = ("entry", "entry_scope") + (("tombstone_scope",) if shape == "pre_r3_no_scope" else ())
            metadata = {k: val for k, val in metadata.items() if k not in drop}
        return real(cursor=cursor, action=action, category=category, key=key, scope=scope,
                    value_sha256=value_sha256, author_id=author_id, metadata=metadata, **kw)

    v._record_audit_event = pre_fix


WRITERS = {"principal": "user", "agent": "model"}
ROW_CLASSES = ("external", "agent")
SPACE = [
    (row_scope, writer_scope, same_key, row_class, writer_class, shape)
    for writer_scope in ("default", "team")
    for row_scope in (writer_scope, "*")
    for same_key in (True, False)
    for row_class in ROW_CLASSES
    for writer_class in ("principal", "agent")
    for shape in ("new", "pre_r3", "pre_r3_no_scope")
    if _class_rank(row_class) < _class_rank(writer_class)
]


def _ids(t):
    row_scope, writer_scope, same_key, row_class, writer_class, shape = t
    return f"row[{row_scope}/{row_class}]-writer[{writer_scope}/{writer_class}/{'same' if same_key else 'other'}key]-{shape}"


@pytest.mark.parametrize("case", SPACE, ids=_ids)
def test_control_lift_state_space_reconciles_or_refuses_naming_the_row(tmp_path, case):
    row_scope, writer_scope, same_key, row_class, writer_class, shape = case
    p = tmp_path / "v.sqlite"
    v = _open(p)
    row_cat, row_key = ("decision", "k1") if same_key else ("other", "k9")
    _plant_row(v, row_cat, row_key, VALUE, row_scope, row_class)
    assert v.is_tombstoned("decision", "k1", VALUE, scope=writer_scope) is True
    v.close()
    _open(p).close()  # the planted row reconciles before the lift
    v = _open(p)
    if shape != "new":
        _legacy_writer(v, "decision", "k1", shape)
    v.remember("decision", "k1", VALUE, origin=WRITERS[writer_class], author_id="alice", scope=writer_scope)
    lifted = [e for e in v.list_audit_events(limit=50) if e.action == "tombstone_lifted"]
    assert len(lifted) == 1 and v.list_tombstones() == []
    assert v.verify_audit_chain() is True
    v.close()
    outcomes = []
    for ro in (False, True):
        try:
            w = _open(p, read_only=ro)
            try:
                assert w.verify_audit_chain() is True
                assert w.is_tombstoned("decision", "k1", VALUE, scope=writer_scope) is False
                outcomes.append("reconciled")
            finally:
                w.close()
        except VaultIntegrityError as exc:
            assert f"'{row_cat}:{row_key}' [scope={row_scope}]" in str(exc), str(exc)
            outcomes.append("refused")
    print("LIFT-OUTCOME", _ids(case), outcomes[0])
    assert len(set(outcomes)) == 1, outcomes  # the two open modes agree
    if shape in ("new", "pre_r3"):
        # every shape the current code or the R3/R4-era code wrote must reconcile
        assert outcomes == ["reconciled", "reconciled"], (case, outcomes)
