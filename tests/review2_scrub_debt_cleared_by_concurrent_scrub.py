"""severity: medium
finding: scrub() clears the single-row scrub debt unconditionally after its VACUUM, so an erasure another connection commits during the scrub loses its debt; if that process then dies before its own scrub, no later open ever erases the deleted text.

Round 1 made forget's scrub resumable: a tombstone that deletes content writes ``pending_scrub`` row
id=1 in its own transaction (_vault_tombstone.py:641-647), the next writable open pays it
(_resume_owed_scrub, :658-670, called from vault.py:569). But the row is one shared flag with no
generation: ``scrub()`` runs FTS rebuild + VACUUM + checkpoint (:690-698), and only then, in a separate
transaction, ``DELETE FROM pending_scrub`` (:699-701) whatever the row says and whenever it was written.
A second connection (an MCP server and an AML adapter on one vault; the CLI and a server) whose
tombstone commits after the VACUUM and before that DELETE has its debt deleted although none of its
bytes were scrubbed. If that second process is killed before running its own scrub (the window round 1
exists to cover), the deleted plaintext stays in the file for good: a fresh open finds no debt.

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes); ``test_attack_*``
asserts the correct post-crash behaviour and fails today because of the defect.
"""

from __future__ import annotations

import os

from kibisis import SQLiteMemoryVault

TOKEN = "quillfernobsidianwharf"


def _bytes(db) -> bytes:
    out = b""
    for suffix in ("", "-wal"):
        p = str(db) + suffix
        if os.path.exists(p):
            with open(p, "rb") as fh:
                out += fh.read()
    return out


def _vault(db):
    return SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)


def _setup(tmp_path):
    db = tmp_path / "v.sqlite"
    a = _vault(db)  # process A: runs a scrub (say, after its own forget)
    a.put("notes", "other", "an unrelated entry", origin="model")
    b = _vault(db)  # process B: another server on the same vault
    b.put("notes", "pin", f"the pin is {TOKEN}", origin="model")
    return db, a, b


def test_control_erasure_committed_after_a_finished_scrub_is_resumed(tmp_path):
    db, a, b = _setup(tmp_path)
    a.scrub()  # A's scrub finishes first
    b.tombstone("notes", "pin", origin="user")
    assert b.scrub_owed()
    b._conn.close()  # B is killed before its own scrub
    a.close()
    assert TOKEN.encode() in _bytes(db), "fixture: the deleted text is still in the file before any scrub"
    fresh = _vault(db)  # the next writable open pays the debt
    try:
        assert not fresh.scrub_owed()
        assert TOKEN.encode() not in _bytes(db)
    finally:
        fresh.close()


def test_attack_erasure_committed_during_a_scrub_keeps_its_debt(tmp_path):
    db, a, b = _setup(tmp_path)
    real_scrub_owed = a.scrub_owed
    fired = []

    def scrub_owed_after_b_commits():
        # Between A's VACUUM/checkpoint and A's check-and-clear of the debt, B's forget commits.
        if not fired:
            fired.append(True)
            b.tombstone("notes", "pin", origin="user")
            assert b.scrub_owed(), "B's delete recorded its scrub debt"
        return real_scrub_owed()

    a.scrub_owed = scrub_owed_after_b_commits  # instance attribute: only A's scrub sees the interleaving
    a.scrub()
    assert fired
    b._conn.close()  # B is killed before its own scrub (the window round 1's debt exists for)
    a.close()
    assert TOKEN.encode() in _bytes(db), "fixture: B's deleted text was never scrubbed"
    fresh = _vault(db)
    try:
        still_there = TOKEN.encode() in _bytes(db)
        owed = fresh.scrub_owed()
        assert not still_there, (
            f"B's committed erasure lost its scrub debt to A's scrub (debt now recorded: {owed}): a fresh "
            "open did not scrub and the deleted text is still in the file"
        )
    finally:
        fresh.close()
