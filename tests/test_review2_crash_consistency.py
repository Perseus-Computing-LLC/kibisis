"""Round-2 crash-consistency guarantees: exact-name, lock-checked leftovers; scoped scrub debt; no stranded transactions."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys

import pytest

import kibisis._vault_snapshot as snap_mod
import kibisis.keys as keys
from kibisis import SQLiteMemoryVault, _atomic
from kibisis.okf import export as okf_export
from kibisis.okf.export import export_bundle
from kibisis.okf.profile import parse_profile

PASS = "correct horse battery staple 9"
PROFILE = (
    '{"schema": "kibisis.okf_export_profile/1", "audience": "owner",'
    ' "allow": {"scopes": ["default"], "categories": ["decision"]},'
    ' "named": [], "exclude": {"keys": [], "categories": []}}'
)
HOLDER = (
    "import sqlite3, sys\n"
    "c = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
    "c.execute('BEGIN IMMEDIATE')\n"
    "print('held', flush=True)\n"
    "sys.stdin.readline()\n"
    "c.execute('ROLLBACK')\n"
)


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _locked(path, directory=False):
    """Stand in for a live writer: create ``path`` and hold its lock."""
    fd = _atomic.create_locked(str(path), directory=directory)
    assert fd is not None
    return fd


# --- leftovers: a live writer's lock is respected, whatever pid its name carries ----------------------


def test_key_temp_held_by_a_live_writer_is_not_swept(tmp_path):
    path = str(tmp_path / "kibisis.key")
    live = tmp_path / f"{keys._temp_prefix(path)}{_dead_pid()}-abcd1234"
    fd = _locked(live)
    try:
        assert keys.main([path]) == 0
        assert live.exists(), "a live writer's temp was removed because its pid looked dead"
    finally:
        os.close(fd)
    os.unlink(live)
    assert keys.main([path]) == 1
    assert sorted(os.listdir(tmp_path)) == ["kibisis.key"]


def test_key_sweep_matches_its_own_temp_names_only(tmp_path):
    path = str(tmp_path / "kibisis.key")
    other = tmp_path / f"{keys._temp_prefix(path)}{_dead_pid()}-ab.tmp-{_dead_pid()}-cd"  # another key file's
    other.write_text("not ours\n")
    assert keys.main([path]) == 0
    assert other.exists()


def test_snapshot_temp_of_a_live_export_and_of_another_output_are_left(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    try:
        v.put("notes", "n", "content", origin="model")
        out = tmp_path / "snaps" / "nightly.json"
        out.parent.mkdir()
        live = snap_mod._snapshot_temp_path(out)
        other = out.parent / f"nightly.tmp.{_dead_pid()}-{'0' * 16}.txt"  # a killed export to nightly.txt
        other.write_text("{}")
        fd = _locked(live)
        try:
            v.export_snapshot(path=str(out))
            assert live.exists(), "a live export's temp was removed"
        finally:
            os.close(fd)
        assert other.exists(), "an export to nightly.json took nightly.txt's temp for its own"
        v.export_snapshot(path=str(out))
        assert not live.exists()
    finally:
        v.close()


def test_okf_stage_held_by_a_live_export_is_left_even_as_pid_1(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    v.put("decision", "alpha", "Alpha is decided.", origin="model")
    parent = tmp_path / "exports"
    parent.mkdir()
    live = parent / f"{okf_export._STAGE_PREFIX}1-{'a' * 16}.bundle"
    fd = _locked(live, directory=True)
    try:
        export_bundle(v, parse_profile(PROFILE), parent / "bundle", at="2026-11-01", bundle_gate=lambda s, f: True)
        assert live.is_dir()
    finally:
        os.close(fd)
        v.close()


def test_okf_set_aside_bundle_of_a_live_export_is_not_restored(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    v.put("decision", "alpha", "Alpha is decided.", origin="model")
    parent = tmp_path / "exports"
    parent.mkdir()
    aside = parent / f"{okf_export._OLD_PREFIX}{_dead_pid()}-{'b' * 16}.bundle"
    fd = _locked(aside, directory=True)
    try:
        export_bundle(v, parse_profile(PROFILE), parent / "bundle", at="2026-11-01", bundle_gate=lambda s, f: True)
        assert aside.is_dir(), "a live export's set-aside bundle was taken"
    finally:
        os.close(fd)
        v.close()


# --- scrub debt and transactions ----------------------------------------------------------------------


def test_debt_recorded_by_an_earlier_release_is_paid(tmp_path):
    db = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    v.close()
    raw = sqlite3.connect(db)
    raw.execute("CREATE TABLE pending_scrub (id INTEGER PRIMARY KEY CHECK (id = 1), requested_at REAL NOT NULL)")
    raw.execute("INSERT INTO pending_scrub (id, requested_at) VALUES (1, 1.5)")
    raw.commit()
    raw.close()
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        assert not v.scrub_owed()
    finally:
        v.close()


def test_a_failed_scrub_leaves_no_transaction_open(tmp_path, monkeypatch):
    db = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    v.put("notes", "pin", "the pin is 4417", origin="model")
    v.tombstone("notes", "pin", origin="user")
    v.close()
    import kibisis.vault as vault_mod

    real_connect = vault_mod.sqlcipher3.connect
    monkeypatch.setattr(vault_mod.sqlcipher3, "connect", lambda *a, **k: real_connect(*a, **{**k, "timeout": 0.3}))
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)  # pays the debt (no contention)
    assert not v.scrub_owed()
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(db)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert holder.stdin is not None and holder.stdout is not None
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(Exception):
            v.scrub()
        assert not v._conn.in_transaction
    finally:
        holder.stdin.write("\n")
        holder.stdin.flush()
        holder.wait(timeout=30)
    v.put("notes", "after", "written after the failed scrub", origin="model")
    v.close()
    fresh = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        assert fresh.get("notes", "after") is not None
    finally:
        fresh.close()


class _CommitFailsOnce:
    def __init__(self, conn):
        self.__dict__["_conn"] = conn
        self.__dict__["failed"] = False

    def commit(self):
        if not self.failed:
            self.__dict__["failed"] = True
            raise sqlite3.OperationalError("disk I/O error")
        return self._conn.commit()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_a_failed_commit_is_rolled_back_not_carried_by_the_next_write(tmp_path):
    db = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    real = v._conn
    v._conn = _CommitFailsOnce(real)
    with pytest.raises(sqlite3.OperationalError):
        v.put("notes", "lost", "its commit failed", origin="model")
    assert not real.in_transaction
    v.put("notes", "kept", "committed", origin="model")
    v._conn = real
    v.close()
    fresh = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        assert fresh.get("notes", "kept") is not None
        assert fresh.get("notes", "lost") is None, "a write reported as failed was committed by a later one"
    finally:
        fresh.close()
