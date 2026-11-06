"""Review 5 (091c218): the a5 discriminator (R4-1 lineage), the quorum under a legacy MAC (R4-2) and the
lift reconciliation state space (R4-3), under attack.

``test_control_*`` asserts the secure behaviour (failing = bug); ``test_attack_*`` demonstrates a
defect (passing = bug). Vaults are opened WITHOUT SQLCipher with a passphrase (allow_plaintext) =
SECURITY.md's file-writer model. Not collected by default; run by path.
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


def test_attack_r5_1_salt_absent_reset_launders_a_keyed_vault_as_never_keyed(tmp_path):
    """R5-1. ``_refuse_unless_genuine_a5`` is only reached with ``kdf_salt`` present. A file writer who
    removes the WHOLE of vault_meta (salt included), sets every row plaintext with content of their
    choosing, drops the tombstones and re-chains the journal headless makes the file look like a vault
    that never had a passphrase; the next open with the real passphrase treats it as one: every row is
    adopted (``entries_adopted_from_keyless_vault``), sealed and signed under the real key with the
    epistemic state the writer wrote, the chain verifies, the rejected value is no longer tombstoned
    and is readmitted. Same cost as R4-1 (the sealed text is lost) with a stronger outcome (adopted and
    ``verified``, not left unsigned)."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    c.execute("DELETE FROM vault_meta")
    c.execute("UPDATE entities SET is_encrypted = 0, encrypted_envelope_json = NULL, tenant_sig = NULL, "
              "content = 'FORGED ' || key, epistemic_state = 'verified'")
    c.commit()
    c.close()
    v = _open(p)
    try:
        up = v.integrity_upgrade
        assert up["entries_adopted_from_keyless_vault"] == 3 and up["entries_resealed"] == 3
        assert up["entries_left_unsigned"] == 0 and up["entries_undecryptable"] == 0
        got = {(e.key, e.content, e.epistemic_state.value) for e in v.list_entities()}
        assert got == {(f"k{i}", f"FORGED k{i}", "verified") for i in range(3)}
        assert v.integrity_status()["unsigned"] == 0
        assert v.verify_audit_chain() is True
        assert v.is_tombstoned("decision", "any", VALUE) is False
        v.remember("decision", "bad", VALUE, origin="user", author_id="alice")  # readmitted
        assert v._meta("key_check") is not None and v._meta("meta_mac") is not None
    finally:
        v.close()
    ro = _open(p, read_only=True)
    try:
        assert {e.content for e in ro.list_entities()} >= {"FORGED k0"}
        assert ro.get("decision", "bad").content == VALUE
        assert ro.verify_audit_chain() is True
    finally:
        ro.close()


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
    v = _open(p)  # first open with a passphrase: adopted, by design
    try:
        assert v.integrity_upgrade["entries_adopted_from_keyless_vault"] == 1
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


def test_attack_r5_2_the_empty_vault_reset_signs_planted_tombstones_and_audit_history(tmp_path):
    """R5-2. The one state the discriminator admits ("an empty vault") is empty of ENTRIES only. The
    file writer plants tombstone rows with plain digests and journal events of any non-entry action
    under any author; the migration keys and MAC-signs the tombstones (``tombstones_rekeyed``) and
    re-chains the forged history into a signed head: ``verify_audit_chain()`` is True, the planted
    value is rejected in the operator's scope with a valid ``tombstone_mac``, and the forged
    ``attestations_reset`` / ``state_transition`` events read as authentic."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    R4._scrub_schema(c)
    c.execute("DELETE FROM entities")
    c.execute("DELETE FROM audit_journal")
    _plant_tombstone_and_history(c, "the value the writer wants blocked")
    c.commit()
    c.close()
    v = _open(p)
    try:
        assert v.integrity_upgrade["tombstones_rekeyed"] == 1
        assert v.verify_audit_chain() is True
        assert v.is_tombstoned("decision", "anything", "the value the writer wants blocked") is True
        tombs = v.list_tombstones()
        assert len(tombs) == 1 and tombs[0]["origin_class"] == "principal"
        actions = [e.action for e in v.list_audit_events(limit=50)]
        assert "attestations_reset" in actions and "state_transition" in actions
        with pytest.raises(vault_module.TombstonedValueError):
            v.remember("decision", "x", "the value the writer wants blocked", origin="user", author_id="alice")
    finally:
        v.close()
    ro = _open(p, read_only=True)
    try:
        assert ro.verify_audit_chain() is True and len(ro.list_tombstones()) == 1
    finally:
        ro.close()


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
    "term_index_format_left": ([], VaultIntegrityError),  # left by the R2-B1 reset; not a witness, rows still are
    "envelope_valid_a5_shape_other_passphrase": (["@reseal:other passphrase (test only)"], ValueError),
    "fixture_envelopes_spliced": (["@fixture_envelopes"], ValueError),
    "attacker_salt_rows_resealed_under_attacker_passphrase": (["@attacker_salt"], ValueError),
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
    _apply(c, p, ["@attacker_salt"])
    c.commit()
    c.close()
    with pytest.raises(ValueError, match="Failed to authenticate"):
        _open(p)
    v = _open(p, passphrase="attacker passphrase (test only)")
    try:
        assert v.integrity_upgrade["entries_resealed"] == 3
    finally:
        v.close()


def test_attack_r5_3_sealed_rows_without_any_vault_meta_get_a_fresh_salt_before_the_wrong_passphrase_refusal(tmp_path):
    """R5-3 (low). With ``vault_meta`` emptied (or dropped) and the rows still sealed, the discriminator
    is not a candidate, ``_init_schema`` runs, ``_vault_salt`` writes a FRESH salt (no keyed record is
    left to stop it), and only then does the migration fail every row and raise a wrong passphrase.
    The refusal has written: a new ``kdf_salt`` and the schema upgrade. SECURITY.md:108-110 ("no fresh
    salt is written over it") holds only while a key check, MAC or format record remains."""
    for drop_table in (False, True):
        p = M._seeded(tmp_path / f"v{int(drop_table)}.sqlite")
        c = M._conn(p)
        M._scrub_everything_but_entries(c)
        c.execute("DROP TABLE vault_meta" if drop_table else "DELETE FROM vault_meta")
        c.commit()
        c.close()
        before = R4._content(p)
        with pytest.raises(ValueError, match="Failed to authenticate"):
            _open(p)
        after = R4._content(p)
        assert after != before
        c = M._conn(p)
        assert c.execute("SELECT count(*) FROM vault_meta WHERE key = 'kdf_salt'").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM vault_meta WHERE key IN ('key_check', 'meta_mac')").fetchone()[0] == 0
        c.close()
        # the next open finds a salt and the witnesses the schema upgrade added: a different refusal
        with pytest.raises(VaultIntegrityError, match="not a 0.1.0a5 file"):
            _open(p)


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


def test_control_the_empty_reset_leaves_no_migrate_event_so_it_reads_exactly_as_a_new_vault(tmp_path):
    """What the operator sees after the admitted reset. ``_migrate_integrity`` on an empty file writes
    the format and key check and returns None WITHOUT a ``migrate`` event, so the reset file ends with
    the same journal (none), the same ``vault_meta`` key set and the same integrity records as a vault
    created fresh by this code: nothing inside the file says a vault was ever here. SECURITY.md:104-106
    describes what the operator sees; it does not say that it is byte-for-byte the shape of a new vault."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    R4._scrub_schema(c)
    c.execute("DELETE FROM entities")
    c.execute("DELETE FROM audit_journal")
    c.commit()
    c.close()
    v = _open(p)
    try:
        assert v.list_entities() == [] and v.integrity_upgrade is None
        assert v._conn.execute("SELECT count(*) FROM audit_journal").fetchone()[0] == 0
        reset_meta = {r[0] for r in v._conn.execute("SELECT key FROM vault_meta")}
        reset_head = v._conn.execute("SELECT count(*) FROM audit_head").fetchone()[0]
    finally:
        v.close()
    fresh = _open(tmp_path / "new.sqlite")
    try:
        assert fresh._conn.execute("SELECT count(*) FROM audit_journal").fetchone()[0] == 0
        assert {r[0] for r in fresh._conn.execute("SELECT key FROM vault_meta")} == reset_meta
        assert fresh._conn.execute("SELECT count(*) FROM audit_head").fetchone()[0] == reset_head
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


def test_attack_r5_4_after_a_legacy_mac_restore_a_verdict_run_without_the_env_pins_the_default(tmp_path):
    """R5-4 (low, residual of the R4-2 design). The dropped quorum is re-pinned by the NEXT pinning
    open with whatever that process runs with. A person who pinned 3 once (env set for that run) and
    later runs a verdict without the env pins the default 2, permanently and silently (the only trace
    is the WARNING at the drop, one open earlier). The end state is R4-2's: 3 became 2."""
    p = tmp_path / "v.sqlite"
    legacy = _pinned(p, 3)
    _restore_legacy_mac(p, legacy)
    _open(p).close()  # any writable open: the 3 is dropped
    v = _open(p, pin_quorum=True)  # a verdict run without KIBISIS_VERIFICATION_QUORUM
    try:
        assert v.verification_quorum == vault_module.DEFAULT_VERIFICATION_QUORUM == 2
        assert v.verification_quorum_stored == 2
    finally:
        v.close()
    v = _open(p)
    try:
        assert v.verification_quorum_stored == 2 and v.verification_quorum == 2
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
    assert "kdf_salt" in written and "verification_quorum" in written
    unbound = written - set(VAULT_META_BOUND_KEYS) - {"meta_mac"}
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
