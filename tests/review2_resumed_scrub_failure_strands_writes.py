"""severity: high
finding: when the scrub that a writable open resumes (round 1) fails, e.g. another writer holds the lock past the busy timeout, the open swallows the error but leaves its connection inside the scrub's half-begun transaction; every later write is reported done, runs as a savepoint of that transaction and is discarded at close.

Round 1 added ``_resume_owed_scrub`` (_vault_tombstone.py:658-670), called at the end of every writable
open (vault.py:566-569): when a delete committed a scrub debt and the process died before its scrub, the
next open runs ``scrub()``. ``scrub()`` starts with ``self._conn.execute("INSERT INTO entities_fts(...)
VALUES ('rebuild')")`` (:690), outside ``_write_tx``: the driver issues an implicit ``BEGIN`` first. If that
INSERT fails (``database is locked`` once another process has held the write lock longer than the 30 s
busy timeout, vault.py:574; ``database or disk is full`` during the rebuild), the ``except Exception`` at
:669-670 logs "retried at the next open" and the open returns, with nobody rolling back: the connection
stays ``in_transaction``. From then on ``_write_tx`` (vault.py:920-934) sees an open transaction and runs
every write as a SAVEPOINT that it RELEASEs without committing; only the outermost block commits, and
there is none. ``put`` returns, ``get`` on the same object reads the row back, the AML adapter
acknowledges the Add, and ``close()`` throws all of it away. Meanwhile the connection keeps the write lock
once it has written, so every other process on the vault is blocked until this one closes.

The busy timeout is shortened from 30 s to 0.3 s through the vault's own ``sqlcipher3.connect`` call so the
test does not sleep; nothing else is changed. A child process holds ``BEGIN IMMEDIATE`` for the duration of
the open, as a long import or a VACUUM of a large vault in another process would.

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes); ``test_attack_*``
asserts the correct post-crash behaviour and fails today because of the defect.
"""

from __future__ import annotations

import subprocess
import sys

import kibisis.vault as vault_mod
from kibisis import SQLiteMemoryVault

HOLDER = (
    "import sqlite3, sys\n"
    "c = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
    "c.execute('BEGIN IMMEDIATE')\n"
    "print('held', flush=True)\n"
    "sys.stdin.readline()\n"
    "c.execute('ROLLBACK')\n"
)


def _vault(db):
    return SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)


def _vault_owing_a_scrub(tmp_path):
    """A vault whose forget committed and whose process died before the scrub (round 1's window)."""
    db = tmp_path / "v.sqlite"
    v = _vault(db)
    v.put("notes", "pin", "the pin is 4417", origin="model")
    v.tombstone("notes", "pin", origin="user")
    assert v.scrub_owed()
    v._conn.close()  # killed before scrub(): the debt stays on disk
    return db


def _open_with_short_busy_timeout(db, monkeypatch):
    real_connect = vault_mod.sqlcipher3.connect

    def connect(*args, **kwargs):
        kwargs["timeout"] = 0.3
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(vault_mod.sqlcipher3, "connect", connect)
    try:
        return _vault(db)
    finally:
        monkeypatch.setattr(vault_mod.sqlcipher3, "connect", real_connect)


def _write_then_reopen(v, db):
    v.put("notes", "after", "written after the open", origin="model")
    seen_by_writer = v.get("notes", "after") is not None
    v.close()
    fresh = _vault(db)
    try:
        return seen_by_writer, fresh.get("notes", "after") is not None
    finally:
        fresh.close()


def test_control_resumed_scrub_that_succeeds_leaves_writes_durable(tmp_path, monkeypatch):
    db = _vault_owing_a_scrub(tmp_path)
    v = _open_with_short_busy_timeout(db, monkeypatch)
    assert not v.scrub_owed()
    assert not v._conn.in_transaction
    seen_by_writer, durable = _write_then_reopen(v, db)
    assert seen_by_writer and durable


def test_attack_resumed_scrub_that_fails_strands_every_later_write(tmp_path, monkeypatch):
    db = _vault_owing_a_scrub(tmp_path)
    holder = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(db)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        v = _open_with_short_busy_timeout(db, monkeypatch)  # the resumed scrub fails: locked
    finally:
        holder.stdin.write("\n")
        holder.stdin.flush()
        holder.wait(timeout=30)
    assert v.scrub_owed(), "fixture: the resumed scrub did not complete; the debt is kept for the next open"
    stranded = v._conn.in_transaction
    seen_by_writer, durable = _write_then_reopen(v, db)
    assert seen_by_writer, "fixture: the write was reported done and is visible to its writer"
    assert durable, (
        f"a put after an open whose resumed scrub failed was lost at close (connection left in a "
        f"transaction by the failed scrub: {stranded})"
    )
