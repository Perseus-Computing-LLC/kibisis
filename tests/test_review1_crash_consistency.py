"""Round 1 (atomicity and crash consistency), the fixed behaviour, asserted class by class.

The pinned evidence (``review1_*.py``) proves one witness per finding; these tests pin the class each
fix closes: what a fresh open sees after a process stops between any two steps of a write path.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

import kibisis._vault_audit as vault_audit
import kibisis.keys as keys
import kibisis.vault as vault_mod
from kibisis import SQLiteMemoryVault
from kibisis.okf import export as okf_export
from kibisis.okf.export import export_bundle
from kibisis.okf.profile import parse_profile

PASS = "correct horse battery staple 1"


class _Killed(BaseException):
    """Stands in for the process dying at this point."""


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


# --- Argus mirror: appended only after the vault commits ------------------------------------------


@pytest.fixture
def mirrored(monkeypatch):
    """Records every Argus append as (event type, payload, transaction open at that moment)."""
    calls = []
    holder = {}

    def fake_write(event_type, actor, payload):
        v = holder.get("vault")
        calls.append((event_type, dict(payload), bool(v is not None and v._conn.in_transaction)))

    monkeypatch.setattr(vault_audit, "_argus_write", fake_write)
    return calls, holder


def _transitions(calls):
    return [c for c in calls if c[0] == "kibisis.state_transition"]


def test_argus_record_is_written_after_commit_never_inside_the_transaction(tmp_path, mirrored):
    calls, holder = mirrored
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False, verification_quorum=1)
    holder["vault"] = v
    try:
        v.put("facts", "k", "a claim", origin="model")
        v.review_entity("facts", "k", "verified", reviewer_id="alice")
        mirrored_now = _transitions(calls)
        assert mirrored_now, "a committed review is mirrored"
        assert all(not in_tx for _t, _p, in_tx in mirrored_now), "appended while the transaction was still open"
        assert v._argus_queue() == []
    finally:
        v.close()


def test_argus_record_of_a_rolled_back_transaction_is_dropped(tmp_path, mirrored):
    calls, holder = mirrored
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False, verification_quorum=1)
    holder["vault"] = v
    try:
        v.put("facts", "k", "a claim", origin="model")
        before = len(_transitions(calls))
        with pytest.raises(_Killed):
            with v._write_tx():
                v.review_entity("facts", "k", "verified", reviewer_id="alice")
                raise _Killed()
        assert len(_transitions(calls)) == before, "a transition that rolled back was mirrored"
        assert v._argus_queue() == []
        assert v.get("facts", "k").epistemic_state.value == "candidate"
        # The next committed write mirrors only its own transition.
        v.review_entity("facts", "k", "verified", reviewer_id="alice")
        after = _transitions(calls)[before:]
        assert [p.get("key") for _t, p, _i in after] == ["k"]
    finally:
        v.close()


# --- nested _write_tx: savepoint semantics --------------------------------------------------------


def test_refused_nested_write_rolls_back_only_its_own_effects(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    try:
        with v._write_tx():
            v.put("facts", "kept", "the outer transaction's own write", origin="model")
            with pytest.raises(RuntimeError):
                with v._write_tx() as cursor:
                    cursor.execute("UPDATE entities SET content = 'clobbered' WHERE key = 'kept'")
                    v.put("facts", "inner", "a nested write that is then refused", origin="model")
                    raise RuntimeError("refused")
            v.put("facts", "after", "the outer transaction goes on", origin="model")
        keys_now = sorted(e.key for e in v.list_entities("facts", include_unverified=True))
        assert keys_now == ["after", "kept"]
        assert v.get("facts", "kept").content == "the outer transaction's own write"
        assert v.verify_audit_chain()
        assert not [e for e in v.list_audit_events(category="facts", key="inner")]
    finally:
        v.close()


# --- keyed first open: one transaction ------------------------------------------------------------


def test_first_open_killed_after_integrity_records_leaves_a_fresh_file(tmp_path, monkeypatch):
    db = tmp_path / "v.sqlite"
    original = vault_mod.SQLiteMemoryVault._upgrade_integrity

    def upgrade_then_die(self):
        original(self)
        raise _Killed()

    monkeypatch.setattr(vault_mod.SQLiteMemoryVault, "_upgrade_integrity", upgrade_then_die)
    with pytest.raises(_Killed):
        SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    monkeypatch.undo()
    v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    try:
        v.put("facts", "k", "works after the interrupted first open", origin="model")
        assert v.get("facts", "k").content == "works after the interrupted first open"
    finally:
        v.close()


def test_open_of_a_current_vault_needs_no_initialisation_transaction(tmp_path):
    db = tmp_path / "v.sqlite"
    SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False).close()
    probe = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    try:
        assert probe._needs_keyed_initialisation() is False
    finally:
        probe.close()


# --- erasure: the scrub debt commits with the delete ----------------------------------------------


TOKEN = "plinthmarrowcadenza"


def _bytes(db):
    out = b""
    for suffix in ("", "-wal"):
        p = str(db) + suffix
        if os.path.exists(p):
            with open(p, "rb") as fh:
                out += fh.read()
    return out


def test_tombstone_records_a_scrub_debt_the_next_open_pays(tmp_path):
    db = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    v.put("notes", "pin", f"the pin is {TOKEN}", origin="model")
    v.tombstone("notes", "pin", origin="user")
    assert v.scrub_owed(), "a committed delete owes a scrub until one finishes"
    v._conn.close()  # the process stops here: no scrub ran
    v2 = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        assert not v2.scrub_owed()
        assert TOKEN.encode() not in _bytes(db)
    finally:
        v2.close()


def test_scrub_inside_a_write_transaction_is_owed_not_skipped(tmp_path):
    db = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        with v._write_tx():
            v.scrub()
        assert v.scrub_owed()
        v.scrub()
        assert not v.scrub_owed()
    finally:
        v.close()


def test_a_finished_scrub_clears_the_debt(tmp_path):
    db = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        v.put("notes", "pin", f"the pin is {TOKEN}", origin="model")
        v.tombstone("notes", "pin", origin="user")
        v.scrub()
        assert not v.scrub_owed()
        assert TOKEN.encode() not in _bytes(db)
    finally:
        v.close()


# --- durability of an acknowledged commit ---------------------------------------------------------


def test_file_vault_commits_are_fsynced(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    try:
        assert v._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert v._conn.execute("PRAGMA synchronous").fetchone()[0] >= 2
    finally:
        v.close()


# --- key file: never at its final path without its key --------------------------------------------


def test_keyfile_killed_before_install_leaves_no_file_and_no_temp(tmp_path, monkeypatch):
    path = str(tmp_path / "kibisis.key")

    def die(_fd):
        raise _Killed()

    monkeypatch.setattr(keys.os, "fsync", die)
    with pytest.raises(_Killed):
        keys.generate_keyfile(path)
    monkeypatch.undo()
    assert not os.path.exists(path)
    assert os.listdir(tmp_path) == []
    assert keys.main([path]) == 0
    assert len(keys.resolve_passphrase(env={keys.ENV_FILE: path})) >= keys.MIN_PASSPHRASE_LENGTH
    assert oct(os.stat(path).st_mode & 0o777) == oct(0o600)


def test_keyfile_temp_of_a_dead_run_is_swept(tmp_path):
    path = str(tmp_path / "kibisis.key")
    stale = tmp_path / f".kibisis.key.tmp-{_dead_pid()}-deadbeef"
    stale.write_text("a key that was never installed\n")
    assert keys.main([path]) == 0
    assert sorted(os.listdir(tmp_path)) == ["kibisis.key"]


def test_empty_keyfile_is_an_error_not_no_key(tmp_path):
    path = tmp_path / "kibisis.key"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with pytest.raises(ValueError):
        keys.resolve_passphrase(env={keys.ENV_FILE: str(path)})


# --- OKF export: leftovers of a killed run --------------------------------------------------------


PROFILE = (
    '{"schema": "kibisis.okf_export_profile/1", "audience": "owner",'
    ' "allow": {"scopes": ["default"], "categories": ["decision"]},'
    ' "named": [], "exclude": {"keys": [], "categories": []}}'
)


def _export_vault(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    v.put("decision", "alpha", "Alpha is decided.", origin="model")
    return v


def test_okf_previous_bundle_set_aside_by_a_killed_run_is_restored(tmp_path):
    v = _export_vault(tmp_path)
    parent = tmp_path / "exports"
    parent.mkdir()
    out = parent / "bundle"
    try:
        export_bundle(v, parse_profile(PROFILE), out, at="2026-11-01", bundle_gate=lambda s, f: True)
        # A run killed between the two renames of the fallback: out moved aside, the new bundle not in.
        aside = parent / f".okf-old-{_dead_pid()}-0123456789abcdef.bundle"
        os.rename(out, aside)
        stage = parent / f".okf-stage-{_dead_pid()}-xyz"
        stage.mkdir()
        (stage / "index.md").write_text("ungated\n")
        export_bundle(v, parse_profile(PROFILE), out, at="2026-11-02", bundle_gate=lambda s, f: True)
    finally:
        v.close()
    assert sorted(os.listdir(parent)) == ["bundle"]
    log = (out / "log.md").read_text()
    assert "2026-11-01" in log and "2026-11-02" in log, "the previous bundle's log was restored, then extended"


def test_okf_stage_of_a_live_export_is_left_alone(tmp_path):
    v = _export_vault(tmp_path)
    parent = tmp_path / "exports"
    parent.mkdir()
    live = parent / f".okf-stage-{os.getppid()}-live"
    live.mkdir()
    try:
        export_bundle(v, parse_profile(PROFILE), parent / "bundle", at="2026-11-01", bundle_gate=lambda s, f: True)
    finally:
        v.close()
    assert live.is_dir(), "a concurrent export's stage was removed"
    assert okf_export._leftover_owner(live.name, okf_export._STAGE_PREFIX) == os.getppid()
