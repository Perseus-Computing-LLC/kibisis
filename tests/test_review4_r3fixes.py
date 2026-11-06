"""Review 4: the round-3 fixes (fea119d..0db8e45) under attack — lift journaling (R3-AB1), the a5
migration discriminator (R3-AB2), the snapshot trust seal (R3-AB3), quorum pinning (R3-AB4/E1/E4),
MCP hygiene (R3-E2/E3), the legacy fixture.

Converted after the round-4 fixes: ``test_control_*`` asserts the secure behaviour (failing = bug);
``test_attack_*`` keeps the reviewer's attack and asserts the FIXED behaviour (failing = regression).
Vaults are opened WITHOUT SQLCipher with a passphrase (allow_plaintext) = SECURITY.md's file-writer
model, unless a test says otherwise.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sqlite3
import sys

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis._vault_crypto import value_digests
from kibisis.config import ConfigError, open_vault
from kibisis.crypto import VAULT_META_BOUND_KEYS, VAULT_META_BOUND_KEYS_V1, VAULT_META_BOUND_OPTIONAL, vault_meta_mac
from kibisis.mcp_server import KibisisMCPServer, TOOL_DEFINITIONS
from kibisis.vault import TombstonedValueError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_review3_ab_migration as M  # noqa: E402  _seeded, _conn, _scrub_everything_but_entries, PASS, fixture names
from test_review3_entry_cli import _env as _cli_env, _review as _cli_review, _stored_quorum  # noqa: E402

PASS = M.PASS
VALUE = "deploy on fridays"
_REAL_SQLCIPHER = vault_module.sqlcipher3
_REAL_AVAILABLE = vault_module._sqlcipher_available


def _remanifest(d):
    """A forger recomputes the plain manifest over the edited file."""
    import hashlib
    body = {k: v for k, v in d.items() if k != "manifest_sha256"}
    d["manifest_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return d


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch, tmp_path):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(tmp_path / "argus.jsonl"))
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _open(p, **kw):
    kw.setdefault("auto_gate", False)
    return SQLiteMemoryVault(str(p), passphrase=PASS, **kw)


def _events(v, action):
    return [e for e in v.list_audit_events(limit=200) if e.action == action]


def _reopens_clean(p):
    """Writable and read-only opens succeed, the chain verifies, nothing is tombstoned for VALUE."""
    for read_only in (False, True):
        v = _open(p, read_only=read_only)
        try:
            assert v.verify_audit_chain() is True
            assert v.is_tombstoned("decision", "any", VALUE) is False
        finally:
            v.close()


# ===================================================================== R3-AB1: lift journaling


@pytest.mark.parametrize("path", ["put", "remember", "mcp_remember"])
def test_control_every_lift_path_journals_the_row_and_the_next_open_reconciles(tmp_path, path):
    """A lower-class tombstone under ``c:k1`` lifted by a write of the value under another key, by
    ``put``, ``remember`` and an MCP ``kibisis_remember`` (agent-class write over a tool-class row):
    the ``tombstone_lifted`` event names the ROW; writable and read-only opens reconcile."""
    p = tmp_path / "v.sqlite"
    v = _open(p, verification_quorum=2)
    lower = "tool" if path == "mcp_remember" else "model"
    v.remember("decision", "k1", VALUE, origin=lower)
    v.tombstone("decision", "k1", reason="lower-class forget", origin=lower)
    assert v.is_tombstoned("decision", "k1", VALUE)
    if path == "put":
        v.put("note", "other", VALUE, origin="user", author_id="alice")
    elif path == "remember":
        v.remember("note", "other", VALUE, origin="user", author_id="alice")
    else:
        server = KibisisMCPServer(vault=v, scope="default")
        resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "kibisis_remember",
                                                 "arguments": {"category": "note", "key": "other", "content": VALUE}}})
        assert resp["result"]["isError"] is False, resp
    ev = _events(v, "tombstone_lifted")[-1]
    assert (ev.category, ev.key, ev.scope) == ("decision", "k1", "default")
    assert ev.metadata["entry"] == "note:other" and ev.metadata["tombstone"] == "decision:k1"
    assert v.list_tombstones(category="decision") == []
    assert v.verify_audit_chain() is True
    v.close()
    _reopens_clean(p)


def _plant_global_agent_row(v, category, key, content):
    """An agent-class tombstone in scope '*' as a snapshot import with ``origin="model"`` leaves it
    (an agent cannot write one through ``tombstone``; a file can). Journaled as the import does."""
    exact, canonical = value_digests(content)
    s_exact, s_canonical = v._stored_digests(exact, canonical)
    with v._write_tx() as cursor:
        cursor.execute(
            "INSERT INTO rejected_value_tombstones (category, key, value_sha256, canonical_sha256, reason, author_id, "
            "created_at, scope, sealed_digests, origin_class, tombstone_mac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (category, key, s_exact, s_canonical, "imported", "mcp-agent", 0.0, "*",
             v._seal_digests("*", category, key, exact, canonical), "agent",
             v._tombstone_mac("*", category, key, s_exact, s_canonical, "agent")),
        )
        v._record_audit_event(cursor=cursor, action="tombstone", category=category, key=key, scope="*",
                              value_sha256=s_exact, author_id="mcp-agent",
                              metadata={"reason": "imported", "canonical_sha256": s_canonical,
                                        "path": "import_snapshot", "origin_class": "agent"})


def test_control_one_write_lifts_the_scoped_and_the_global_row_and_both_reconcile(tmp_path):
    """Two lower-class rows for the same value, one in the writer's scope and one global ('*'): a
    person's write lifts both, each ``tombstone_lifted`` names its own row and scope, and the next
    opens reconcile."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k1", VALUE, origin="model")
    v.tombstone("decision", "k1", reason="agent forgot", origin="model")
    _plant_global_agent_row(v, "decision", "k1", VALUE)
    assert len(v.list_tombstones(category="decision")) == 2
    _open(p).close()  # the planted row reconciles with its journal before the lift
    v.remember("decision", "k1", VALUE, origin="user", author_id="alice")
    lifted = _events(v, "tombstone_lifted")[-2:]
    assert sorted(e.scope for e in lifted) == ["*", "default"]
    assert all((e.category, e.key) == ("decision", "k1") for e in lifted)
    assert v.list_tombstones(category="decision") == []
    v.close()
    _reopens_clean(p)


def test_attack_legacy_lift_event_of_a_global_row_under_the_same_key_still_wedges_the_open(tmp_path):
    """R4-3 fixed. A pre-fix ``tombstone_lifted`` event for a global ('*') row lifted by a write of the
    SAME ``category:key`` in scope ``default`` journaled the writer's scope with
    ``metadata.tombstone_scope = '*'``; the compatibility match used to run only when
    ``metadata.tombstone`` differed from the event's own name, so ``(c, k, V, '*')`` was never popped
    and the vault wedged. Now the named scope is honoured whenever it differs from the event's: both
    open modes reconcile, the chain verifies and nothing is tombstoned for the value."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k1", "something else", origin="user", author_id="alice")
    _plant_global_agent_row(v, "decision", "k1", VALUE)
    v.close()
    _open(p).close()  # reconciles before the lift
    v = _open(p)
    real = v._record_audit_event

    def pre_fix(cursor, action, category, key, scope, value_sha256, author_id=None, metadata=None, **kw):
        if action == "tombstone_lifted":  # the writer's identity, as before the fix
            category, key, scope = "decision", "k1", metadata["entry_scope"]
            metadata = {k: val for k, val in metadata.items() if k not in ("entry", "entry_scope")}
        return real(cursor=cursor, action=action, category=category, key=key, scope=scope,
                    value_sha256=value_sha256, author_id=author_id, metadata=metadata, **kw)

    v._record_audit_event = pre_fix
    v.remember("decision", "k1", VALUE, origin="user", author_id="alice")  # lifts the '*' row
    ev = _events(v, "tombstone_lifted")[-1]
    assert (ev.category, ev.key, ev.scope) == ("decision", "k1", "default")
    assert ev.metadata["tombstone"] == "decision:k1" and ev.metadata["tombstone_scope"] == "*"
    assert v.list_tombstones(category="decision") == [] and v.verify_audit_chain() is True
    v.close()
    _reopens_clean(p)


# ===================================================================== R3-AB2: the a5 discriminator


def _content(p):
    """Every table's schema and rows: what a refused open must leave as it was (the file header's WAL
    flag is not content; the connection sets it)."""
    c = M._conn(p)
    out = [tuple(r) for r in c.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name")]
    for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").fetchall():
        out.append((name, [tuple(r) for r in c.execute(f"SELECT * FROM {name}").fetchall()]))
    c.close()
    return out


def _refused_untouched(p, match="not a 0.1.0a5 file"):
    """The open is refused by the a5 discriminator and the file is byte for byte as the writer left it:
    no head, no key check, no meta MAC, no migrate event."""
    before = _content(p)
    with pytest.raises(vault_module.VaultIntegrityError, match=match) as info:
        _open(p)
    assert _content(p) == before
    c = M._conn(p)
    assert c.execute("SELECT count(*) FROM audit_head").fetchone()[0] == 0
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key IN ('key_check','meta_mac')").fetchone()[0] == 0
    assert c.execute("SELECT count(*) FROM audit_journal WHERE action = 'migrate'").fetchone()[0] == 0
    c.close()
    return str(info.value)


def test_attack_discriminator_is_defeated_by_blanking_the_envelope(tmp_path):
    """R4-1 fixed (the R2-B1 / R3-AB2 / R4-1 class). The R2-B1 reset plus ``is_encrypted = 0``,
    ``encrypted_envelope_json = NULL``, ``tenant_sig = NULL`` leaves no binding string and no
    inconsistent row; it used to migrate, sign a head, key check and meta MAC and readmit the rejected
    value. Now the one discriminator refuses it before ``_init_schema`` (naming the plaintext rows and
    the later-format schema) and nothing is written: the operator sees a refusal naming what was
    found, never a laundered vault."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    c.execute("UPDATE entities SET is_encrypted = 0, encrypted_envelope_json = NULL, tenant_sig = NULL")
    c.commit()
    c.close()
    message = _refused_untouched(p)
    assert "marked plaintext" in message and "audit_head" in message


def _drop_column(c, table, column):
    c.execute(f"ALTER TABLE {table} DROP COLUMN {column}")


def _scrub_schema(c):
    """The file writer rebuilds the schema an a5 file has: no audit_head, no journal format column, no
    tombstone_mac column (the three tables a later release's schema upgrade adds)."""
    c.execute("DROP TABLE IF EXISTS audit_head")
    _drop_column(c, "audit_journal", "format")
    _drop_column(c, "rejected_value_tombstones", "tombstone_mac")


def _legacy_rechain_without_format(c):
    """``M._legacy_rechain`` writes the ``format`` column; this one re-chains a journal that has none."""
    from kibisis.vault import _event_hash
    prev = "0" * 64
    for r in c.execute("SELECT * FROM audit_journal ORDER BY sequence").fetchall():
        h = _event_hash(r["sequence"], r["timestamp"], r["action"], r["category"], r["key"], r["scope"],
                        r["value_sha256"], prev, r["author_id"], None, fmt=1)
        c.execute("UPDATE audit_journal SET prev_hash = ?, event_hash = ? WHERE sequence = ?", (prev, h, r["sequence"]))
        prev = h


# Each scrub is applied on top of the R2-B1 reset (meta records deleted, signatures blanked, journal
# re-chained headless in format 1) of a vault that was keyed at format 3. A single-witness scrub
# removes ONE thing the discriminator looks at; the file still fails on the rest. The all-witnesses
# scrub removes everything a file writer can remove; the rows' envelopes are then the only witness
# left, and they cannot be re-sealed without the key.
SCRUBS = {
    "nothing_more": [],
    "is_encrypted_0": ["UPDATE entities SET is_encrypted = 0"],
    "envelope_null": ["UPDATE entities SET encrypted_envelope_json = NULL"],
    "envelope_empty": ["UPDATE entities SET encrypted_envelope_json = ''"],
    "envelope_garbage": ["UPDATE entities SET encrypted_envelope_json = '{\"not\": \"an envelope\"}'"],
    "binding_scrubbed": ["UPDATE entities SET encrypted_envelope_json = replace(encrypted_envelope_json, 'binding', 'bndng')"],
    "tenant_sig_null": ["UPDATE entities SET tenant_sig = NULL"],
    "tenant_sig_empty": ["UPDATE entities SET tenant_sig = ''"],
    "is_encrypted_0_envelope_null_sig_null": [
        "UPDATE entities SET is_encrypted = 0, encrypted_envelope_json = NULL, tenant_sig = NULL"],
    "rows_deleted": ["DELETE FROM entities"],
    "rows_deleted_journal_deleted": ["DELETE FROM entities", "DELETE FROM audit_journal"],
    "journal_deleted": ["DELETE FROM audit_journal"],
    "journal_put_events_deleted": ["DELETE FROM audit_journal WHERE action IN ('put', 'update')"],
    "audit_head_dropped": ["DROP TABLE audit_head"],
    "format_column_dropped": ["ALTER TABLE audit_journal DROP COLUMN format"],
    "tombstone_mac_column_dropped": ["ALTER TABLE rejected_value_tombstones DROP COLUMN tombstone_mac"],
    "schema_scrubbed": ["@schema"],
    "schema_scrubbed_rows_plaintext": [
        "@schema", "UPDATE entities SET is_encrypted = 0, encrypted_envelope_json = NULL, tenant_sig = NULL"],
    "schema_scrubbed_rows_deleted": ["@schema", "DELETE FROM entities"],
    "schema_scrubbed_rows_deleted_journal_kept_headless": ["@schema", "DELETE FROM entities", "@rechain"],
    "schema_scrubbed_rows_kept_bound": ["@schema", "UPDATE entities SET tenant_sig = NULL", "@rechain"],
    "schema_scrubbed_rows_kept_bound_binding_scrubbed": [
        "@schema", "UPDATE entities SET encrypted_envelope_json = replace(encrypted_envelope_json, 'binding', 'bndng')",
        "@rechain"],
    "everything_but_a_sealed_row": [
        "@schema", "DELETE FROM audit_journal WHERE action != 'put'", "DELETE FROM entities WHERE key != 'k0'",
        "DELETE FROM audit_journal WHERE key != 'k0'", "@rechain"],
}


@pytest.mark.parametrize("scrub", sorted(SCRUBS))
def test_attack_every_single_witness_scrub_and_the_full_scrub_are_refused(tmp_path, scrub):
    """R4-1: the class, not the variant. Whatever single witness the file writer removes on top of
    the R2-B1 reset, and whatever combination up to everything a file writer can remove, the open is
    refused and nothing is written. The one state that passes (``@schema`` + no rows + no entry event,
    the last case of ``test_control_the_only_reset_that_passes_is_an_empty_vault``) is an empty vault."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    for step in SCRUBS[scrub]:
        if step == "@schema":
            _scrub_schema(c)
        elif step == "@rechain":
            _legacy_rechain_without_format(c)
        else:
            c.execute(step)
    c.commit()
    c.close()
    before = _content(p)
    with pytest.raises(vault_module.VaultIntegrityError, match="not a 0.1.0a5 file") as info:
        _open(p)
    assert _content(p) == before, scrub
    message = str(info.value)
    c = M._conn(p)
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key IN ('key_check','meta_mac')").fetchone()[0] == 0
    if c.execute("SELECT 1 FROM sqlite_master WHERE name = 'audit_journal'").fetchone():
        assert c.execute("SELECT count(*) FROM audit_journal WHERE action = 'migrate'").fetchone()[0] == 0
    c.close()
    # The refusal names what was found: at least one of the witnesses the scrub left behind.
    assert any(w in message for w in ("audit_head", "audit_journal.format", "tombstone_mac", "marked plaintext",
                                      "missing or malformed", "sealed with its binding", "opens only under its binding",
                                      "do not open", "entity table that is empty")), message


def test_control_the_only_reset_that_passes_is_an_empty_vault(tmp_path):
    """The reset the discriminator cannot tell from an a5 file: schema scrubbed, every row, tombstone
    and journal event deleted, and no vault_meta key a5 never wrote (SECURITY.md; round 5 made
    ``term_index_format``, any tombstone and any journal event witnesses). What the operator gets is
    an empty vault whose journal holds one ``migrate`` event saying a keyed file was here, not a vault
    whose rejections were laundered; the value is not readmitted as a laundered entry because there
    is nothing left to launder."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    _scrub_schema(c)
    c.execute("DELETE FROM entities")
    c.execute("DELETE FROM audit_journal")
    c.execute("DELETE FROM vault_meta WHERE key = 'term_index_format'")
    c.commit()
    c.close()
    v = _open(p)
    try:
        assert v.list_entities() == []
        assert [e.action for e in v.list_audit_events(limit=200)] == ["migrate"]
        assert v._conn.execute("SELECT count(*) FROM entities").fetchone()[0] == 0
    finally:
        v.close()


def test_control_wrong_passphrase_on_a_genuine_a5_file_is_a_wrong_passphrase_not_tampering(tmp_path):
    """Every a5 row is sealed and opens under the passphrase; under the wrong one none opens, and that
    is reported as ``Failed to authenticate`` (the file untouched), not as a tampered file."""
    p = tmp_path / "a5.sqlite"
    shutil.copy(M.FIXTURE_A5, p)
    before = _content(p)
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase="not the passphrase", auto_gate=False)
    assert _content(p) == before


def test_control_a5_file_with_one_row_that_does_not_open_is_refused(tmp_path):
    """A genuine a5 file with ONE row whose seal was tampered with (its tag no longer verifies while
    the other rows open) is refused as tampered, naming the row: the migration never leaves an
    undecryptable row behind."""
    p = tmp_path / "a5.sqlite"
    shutil.copy(M.FIXTURE_A5, p)
    c = M._conn(p)
    env = json.loads(c.execute("SELECT encrypted_envelope_json FROM entities WHERE key = 'door_code'").fetchone()[0])
    env["tag_b64"] = env["tag_b64"][::-1]  # the ciphertext no longer authenticates
    c.execute("UPDATE entities SET encrypted_envelope_json = ? WHERE key = 'door_code'", (json.dumps(env),))
    c.commit()
    c.close()
    before = _content(p)
    with pytest.raises(vault_module.VaultIntegrityError, match="do not open under the passphrase.*ops:door_code"):
        SQLiteMemoryVault(str(p), passphrase=M.FIXTURE_A5_PASS, auto_gate=False)
    assert _content(p) == before


@pytest.mark.parametrize("witness", [
    "CREATE TABLE audit_head (id INTEGER PRIMARY KEY CHECK (id = 1), sequence INTEGER NOT NULL, event_hash TEXT NOT NULL, mac TEXT NOT NULL)",
    "ALTER TABLE audit_journal ADD COLUMN format INTEGER NOT NULL DEFAULT 2",
    "ALTER TABLE rejected_value_tombstones ADD COLUMN tombstone_mac TEXT DEFAULT NULL",
    "INSERT INTO vault_meta (key, value) VALUES ('meta_mac', 'x')",
    "INSERT INTO vault_meta (key, value) VALUES ('journal_format_floor', '3')",
    "INSERT INTO vault_meta (key, value) VALUES ('journal_anchored', '1')",
    "INSERT INTO vault_meta (key, value) VALUES ('verification_quorum', '1')",
    "INSERT INTO vault_meta (key, value) VALUES ('integrity_format', '2')",
    "UPDATE entities SET is_encrypted = 0 WHERE key = 'unsigned_legacy'",
    "UPDATE entities SET encrypted_envelope_json = NULL WHERE key = 'unsigned_legacy'",
    "DELETE FROM entities",
])
def test_control_a5_fixture_with_one_planted_witness_is_refused(tmp_path, witness):
    """Each witness on its own, planted into the genuine a5 fixture, is enough to refuse the migration
    (a5 never wrote any of them), and nothing is written."""
    p = tmp_path / "a5.sqlite"
    shutil.copy(M.FIXTURE_A5, p)
    c = M._conn(p)
    c.execute(witness)
    c.commit()
    c.close()
    before = _content(p)
    with pytest.raises(vault_module.VaultIntegrityError):
        SQLiteMemoryVault(str(p), passphrase=M.FIXTURE_A5_PASS, auto_gate=False)
    assert _content(p) == before


def test_control_tenant_sig_blank_alone_is_still_refused(tmp_path):
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    c.execute("UPDATE entities SET tenant_sig = ''")
    c.commit()
    c.close()
    before = _content(p)
    with pytest.raises(vault_module.VaultIntegrityError, match="sealed with its binding"):
        _open(p)
    assert _content(p) == before


def test_control_journal_deleted_with_entries_kept_is_refused(tmp_path):
    """Deleting the journal entirely (so 'the journal says entries existed' is false) keeps the sealed
    rows as witnesses; refused."""
    p = M._seeded(tmp_path / "v.sqlite")
    c = M._conn(p)
    M._scrub_everything_but_entries(c)
    c.execute("DELETE FROM audit_journal")
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="sealed with its binding"):
        _open(p)


# ===================================================================== R3-AB3: the trust seal


def _export_with_verified_entry(p):
    v = _open(p, verification_quorum=1)
    v.remember("decision", "d", "ship it", origin="user", author_id="alice", epistemic_state="verified")
    assert v.get("decision", "d").epistemic_state.value == "verified"
    v.remember("decision", "bad", VALUE, origin="model")
    v.tombstone("decision", "bad", reason="agent forgot", origin="model")
    snap = v.export_snapshot()
    v.close()
    return snap


def test_control_a_genuine_seal_does_not_vouch_for_spliced_entities_or_tombstones(tmp_path):
    """A seal lifted from a real own-export binds the entities AND the tombstones of that export: a
    file with the seal and the digest_key_id but an edited entity (attestations added) or an added
    principal tombstone keeps no trust facts, and the planted tombstone's class is capped at the
    importer's class when the importer names one."""
    p = tmp_path / "v.sqlite"
    snap = _export_with_verified_entry(p)
    assert snap.get("trust_seal") and snap["trust_seal"].startswith("{")
    # (a) entity spliced: a model-origin entity with attestations nobody made, under the real seal
    forged = copy.deepcopy(snap)
    forged["entities"].append({**copy.deepcopy(snap["entities"][0]), "key": "forged", "origin": "model",
                               "epistemic_state": "verified",
                               "metadata": {**snap["entities"][0].get("metadata", {}), "attestations": ["alice", "bob"],
                                            "human_reviews": [{"reviewer": "alice", "verdict": "verified"}]}})
    _remanifest(forged)
    v = _open(p)
    try:
        v.import_snapshot(forged, clear_existing=True)
        for key in ("d", "forged"):
            e = v.get("decision", key)
            assert e.epistemic_state.value == "candidate", key
            assert "attestations" not in e.metadata and "human_reviews" not in e.metadata
    finally:
        v.close()
    # (b) tombstone spliced under the real seal: entity trust facts dropped too (v2 seal covers both),
    #     and the planted class is capped at the importer's class.
    forged = copy.deepcopy(snap)
    t = copy.deepcopy(snap["tombstones"][0])
    forged["tombstones"].append({**t, "key": "planted", "origin_class": "principal", "scope": "default"})
    _remanifest(forged)
    v = _open(p)
    try:
        v.import_snapshot(forged, clear_existing=True, origin="model")
        assert v.get("decision", "d").epistemic_state.value == "candidate"
        classes = {r["key"]: r["origin_class"] for r in v.list_tombstones(category="decision")}
        assert classes.get("bad") == "agent"
        if "planted" in classes:  # its sealed digests are bound to key 'bad', so it may not unseal at all
            assert classes["planted"] == "agent"
        reasons = [e.metadata.get("reason", "") for e in _events(v, "refuse")]
        assert any("tombstone classes capped" in r for r in reasons), reasons
    finally:
        v.close()


def test_control_own_export_with_full_seal_restores_trust_and_classes(tmp_path):
    p = tmp_path / "v.sqlite"
    snap = _export_with_verified_entry(p)
    v = _open(p)
    try:
        assert v.import_snapshot(snap, clear_existing=True) == 1  # 'bad' was purged by its tombstone
        assert v.get("decision", "d").epistemic_state.value == "verified"
        assert [r["origin_class"] for r in v.list_tombstones(category="decision")] == ["agent"]
        assert v.verify_audit_chain() is True
    finally:
        v.close()
    _open(p, read_only=True).close()


def test_control_default_import_origin_is_principal_so_the_cap_only_bites_when_named(tmp_path):
    """``import_snapshot(origin=None)`` = the caller vouches for a person (as on ``put``): an unsealed
    file's principal tombstone lands at principal class. Documented; recorded because no caller in
    ``src/`` passes ``origin``, so the R3-AB3 cap protects only embedders that opt in."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    exact, canonical = value_digests(VALUE)
    v.close()
    v = _open(p)
    try:
        forged = {"digest_scheme": "sha256", "entities": [],
                  "tombstones": [{"category": "decision", "key": "x", "value_sha256": exact, "canonical_sha256": canonical,
                                  "reason": "forged", "author_id": "x", "created_at": 0.0, "scope": "default",
                                  "origin_class": "principal"}]}
        v.import_snapshot(forged)
        assert [r["origin_class"] for r in v.list_tombstones(category="decision")] == ["principal"]
        with pytest.raises(TombstonedValueError):  # a person's own write of the value is now refused
            v.remember("decision", "y", VALUE, origin="user", author_id="alice")
    finally:
        v.close()
    v = _open(p)
    try:
        v.import_snapshot({**forged, "tombstones": [{**forged["tombstones"][0], "key": "z"}]}, origin="model")
        assert sorted(r["origin_class"] for r in v.list_tombstones(category="decision")) == ["agent", "principal"]
    finally:
        v.close()


# ===================================================================== R3-AB4 / E1 / E4: the quorum


def test_attack_legacy_meta_mac_keeps_a_lowered_quorum_that_is_still_at_the_default(tmp_path, caplog):
    """R4-2 fixed. Under a V1 (pre-quorum) meta MAC no stored quorum is trusted, whatever its value: a
    person pinned 3, a file writer lowers it to 2 (the default), and the next writable open ignores
    the value (logging it at WARNING), drops it before re-signing the full-set MAC, so the MAC never
    covers a value nobody signed; two accounts do not mint ``verified``; a pinning verdict under the
    person's quorum restores 3 under the full-set MAC."""
    import logging
    p = tmp_path / "v.sqlite"
    v = _open(p, verification_quorum=3, pin_quorum=True, trust_caller_identity=True)
    v.remember("decision", "d", "ship it", origin="user", author_id="alice", epistemic_state="verified", attester="alice")
    assert v.get("decision", "d").epistemic_state.value == "candidate"  # 1 of 3
    v1_mac = vault_meta_mac(v._signing_key, v._meta_mac_fields(), VAULT_META_BOUND_KEYS_V1)
    signing_key = v._signing_key
    v.close()
    c = M._conn(p)
    c.execute("UPDATE vault_meta SET value = ? WHERE key = 'meta_mac'", (v1_mac,))  # the file as pre-R2-B4 left it
    c.execute("UPDATE vault_meta SET value = '2' WHERE key = 'verification_quorum'")  # the file writer's edit
    c.commit()
    c.close()
    with caplog.at_level(logging.WARNING, logger="kibisis"):
        v = _open(p, trust_caller_identity=True)  # the operator's process, naming no quorum
    assert any("stored verification quorum 2 is not covered by the meta MAC" in r.getMessage()
               and r.levelno == logging.WARNING for r in caplog.records), [r.getMessage() for r in caplog.records]
    try:
        assert v.verification_quorum == 2 and v.verification_quorum_stored is None  # the default, nothing stored
        v.review_entity("decision", "d", "verified", reviewer_id="bob", attester="bob")
        assert v.get("decision", "d").epistemic_state.value == "verified"  # the default quorum, 2 accounts
    finally:
        v.close()
    c = M._conn(p)
    fields = M._bound(c)
    c.close()
    assert fields.get("verification_quorum") is None  # dropped, not re-signed
    assert fields["meta_mac"] == vault_meta_mac(signing_key, {k: fields.get(k) for k in VAULT_META_BOUND_KEYS + VAULT_META_BOUND_OPTIONAL})
    v = _open(p, verification_quorum=3, pin_quorum=True, trust_caller_identity=True)  # the person re-pins
    try:
        assert v.verification_quorum == 3 and v.verification_quorum_stored == 3
    finally:
        v.close()
    v = _open(p)
    try:
        assert v.verification_quorum == 3  # under the full-set MAC
    finally:
        v.close()


def test_control_only_a_pinning_open_stores_the_quorum(tmp_path):
    p = tmp_path / "v.sqlite"
    v = _open(p, verification_quorum=5)
    v.remember("c", "k", "x", origin="model")
    assert v.verification_quorum == 5 and v.verification_quorum_stored is None
    v.close()
    c = M._conn(p)
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key='verification_quorum'").fetchone()[0] == 0
    c.close()
    for kw in ({"read_only": True, "pin_quorum": True}, {"read_only": True}, {}):
        v = _open(p, verification_quorum=7, **kw)
        try:
            assert v.verification_quorum == 7 and v.verification_quorum_stored is None
        finally:
            v.close()
    v = _open(p, verification_quorum=3, pin_quorum=True)
    assert v.verification_quorum_stored == 3
    v.close()
    with pytest.raises(ConfigError):
        _open(p, verification_quorum=2)
    with pytest.raises(ConfigError):
        _open(p, verification_quorum=2, pin_quorum=True)
    v = _open(p, read_only=True)
    try:
        assert v.verification_quorum == 3 and v.verification_quorum_stored == 3  # read-only adopts
    finally:
        v.close()


def test_control_a_pinned_one_is_adopted_only_when_named_and_the_env_mapping_counts(tmp_path, monkeypatch):
    p = tmp_path / "v.sqlite"
    _open(p, verification_quorum=1, pin_quorum=True).close()
    for kw in ({}, {"read_only": True}, {"pin_quorum": True}):
        with pytest.raises(ConfigError, match="pinned at 1"):
            _open(p, **kw)
    env = {"KIBISIS_DB_PATH": str(p), "KIBISIS_PASSPHRASE": PASS, "KIBISIS_ALLOW_PLAINTEXT": "1"}
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "1")  # the process env names 1 ...
    with pytest.raises(ConfigError, match="pinned at 1"):
        open_vault(str(p), env=env)  # ... but a scrubbed mapping that names none does not (R3-E4)
    v = open_vault(str(p), env={**env, "KIBISIS_VERIFICATION_QUORUM": "1"})
    try:
        assert v.verification_quorum == 1 and v.verification_quorum_stored == 1
        server = KibisisMCPServer(vault=v, scope="default")
        resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "kibisis_health", "arguments": {}}})
        text = resp["result"]["content"][0]["text"]
        assert "one account verifies" in text and str(p) not in text and PASS not in text
    finally:
        v.close()
    v = open_vault(str(p), env={**env, "KIBISIS_VERIFICATION_QUORUM": "2"})  # names 2: runs with 2, pins nothing
    try:
        assert v.verification_quorum == 2 and v.verification_quorum_stored == 1
    finally:
        v.close()
    v = open_vault(str(p), env={**env, "KIBISIS_VERIFICATION_QUORUM": "2"}, pin_quorum=True)
    try:
        assert v.verification_quorum_stored == 2
    finally:
        v.close()
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM")
    v = open_vault(str(p), env=env)
    try:
        assert v.verification_quorum == 2  # adopted: at the default again
    finally:
        v.close()


def test_control_pty_approve_with_quorum_one_pins_loudly_and_the_operators_next_open_refuses(tmp_path, monkeypatch):
    """The documented pty limit, re-checked after the pinning change: one pty-driven ``approve`` run
    with ``KIBISIS_VERIFICATION_QUORUM=1`` pins 1 AND verifies the entry in one go (as before). What
    is new and must hold: the run says so, and the operator's next open (naming no quorum) refuses
    rather than adopting 1 in silence."""
    monkeypatch.setattr(vault_module, "sqlcipher3", _REAL_SQLCIPHER)  # the subprocess uses the real one
    monkeypatch.setattr(vault_module, "_sqlcipher_available", _REAL_AVAILABLE)
    db = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(db), passphrase="review3-entry-passphrase", auto_gate=False)
    v.remember("c", "k", "an agent fact", origin="model", author_id="mcp-agent")
    v.close()
    env = _cli_env(tmp_path, db, KIBISIS_VERIFICATION_QUORUM="1", KIBISIS_ALLOW_PLAINTEXT="1")
    r = _cli_review(["approve", "c", "k"], env, tty=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "one account verifies" in (r.stdout + r.stderr), r.stdout + r.stderr
    assert _stored_quorum(db) == 1
    with pytest.raises(ConfigError, match="pinned at 1"):
        SQLiteMemoryVault(str(db), passphrase="review3-entry-passphrase", auto_gate=False)
    r = _cli_review(["list"], _cli_env(tmp_path, db, KIBISIS_ALLOW_PLAINTEXT="1"), tty=False, cwd=str(tmp_path))
    assert r.returncode == 2 and "pinned at 1" in r.stderr, r.stderr


# ===================================================================== R3-E2 / E3 and the MCP surface


def test_control_mcp_surface_unchanged_and_new_kwargs_unreachable(tmp_path):
    p = tmp_path / "v.sqlite"
    v = _open(p, verification_quorum=2)
    try:
        server = KibisisMCPServer(vault=v, scope="default")
        names = [t["name"] for t in server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]]
        assert names == ["kibisis_remember", "kibisis_recall", "kibisis_forget", "kibisis_verify_ledger", "kibisis_health"]
        assert all(t["inputSchema"].get("additionalProperties") is False for t in TOOL_DEFINITIONS)
        for tool, extra in (("kibisis_remember", "pin_quorum"), ("kibisis_remember", "origin"), ("kibisis_remember", "env"),
                            ("kibisis_forget", "origin"), ("kibisis_remember", "verification_quorum")):
            resp = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                          "params": {"name": tool, "arguments": {"category": "c", "key": "k", "content": "x", extra: 1}}})
            assert resp["result"]["isError"] is True and "Refused" in resp["result"]["content"][0]["text"], (tool, extra, resp)
        assert v.get("c", "k") is None
        # R3-E3
        resp = server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": ["kibisis_health"]})
        assert resp["error"]["code"] == -32602
        # R3-E2: an agent write over a person's candidate is a refusal, not an internal error
        v.remember("c", "pk", "a person's note", origin="user", author_id="alice")
        resp = server.handle_request({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                      "params": {"name": "kibisis_remember", "arguments": {"category": "c", "key": "pk", "content": "agent"}}})
        text = resp["result"]["content"][0]["text"]
        assert resp["result"]["isError"] is True and text.startswith("Refused") and "Internal error" not in text
        assert v.get("c", "pk").content == "a person's note"
    finally:
        v.close()


# ===================================================================== legacy fixtures


def test_control_a5_fixture_full_lifecycle(tmp_path):
    p = tmp_path / "a5.sqlite"
    shutil.copy(M.FIXTURE_A5, p)
    with pytest.raises(ValueError, match="integrity upgrade"):  # by design: read-only before the upgrade
        SQLiteMemoryVault(str(p), passphrase=M.FIXTURE_A5_PASS, auto_gate=False, read_only=True)
    v = SQLiteMemoryVault(str(p), passphrase=M.FIXTURE_A5_PASS, auto_gate=False)
    try:
        up = v.integrity_upgrade
        assert up and up["entries_resealed"] >= 1 and up["entries_failed_signature"] == 0
        assert up["entries_undecryptable"] == 0
        assert v.verify_audit_chain() is True
        n = len(v.list_entities())  # the default scope; the fixture spreads its 6 rows over scopes
        assert n >= 1
        rows = v._conn.execute("SELECT count(*) FROM entities").fetchone()[0]
        assert rows == 6
    finally:
        v.close()
    v = SQLiteMemoryVault(str(p), passphrase=M.FIXTURE_A5_PASS, auto_gate=False)
    try:
        assert v.integrity_upgrade is None and v.verify_audit_chain() is True
    finally:
        v.close()
    for kw in ({"read_only": True}, {"read_only": True, "pin_quorum": True}):
        v = SQLiteMemoryVault(str(p), passphrase=M.FIXTURE_A5_PASS, auto_gate=False, **kw)
        try:
            assert len(v.list_entities()) == n and v.verify_audit_chain() is True
            assert v.verification_quorum == 2 and v.verification_quorum_stored is None
        finally:
            v.close()
    env = {"KIBISIS_DB_PATH": str(p), "KIBISIS_PASSPHRASE": M.FIXTURE_A5_PASS, "KIBISIS_ALLOW_PLAINTEXT": "1"}
    v = open_vault(str(p), env=env, read_only=True)
    try:
        assert len(v.list_entities()) == n
    finally:
        v.close()
    with pytest.raises(ValueError):  # wrong passphrase still refused after the migration
        SQLiteMemoryVault(str(p), passphrase="not the passphrase", auto_gate=False)
