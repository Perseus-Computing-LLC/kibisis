"""severity: high
finding: the Argus mirror of a state transition is appended before the vault transaction commits, so a killed or rolled-back write leaves a transition in the tamper-evident ledger that the vault never made

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes; proves the fixture
and the mirror work). ``test_attack_*`` asserts the correct post-crash behaviour (every Argus
``kibisis.state_transition`` names a transition the vault's own journal holds) and FAILS on this head.

Write path: ``_put`` (vault.py) -> supersession branch -> ``_record_state_transition``
(_vault_review.py) -> ``_argus_append`` (an fsync'd append to an external file) -> ... -> commit in
``_write_tx`` (vault.py). The Argus append is a separate durable write issued inside the SQLite
transaction, before COMMIT. A kill after it and before COMMIT (attack 1), or any later refusal in the
same transaction (attack 2: a tombstone check that runs after the supersession), rolls the vault back
but leaves the Argus record in place.
"""

from __future__ import annotations

import pytest

argus_ledger = pytest.importorskip("argus_ledger")

import kibisis._vault_review as vault_review  # noqa: E402
from kibisis import SQLiteMemoryVault, TombstonedValueError  # noqa: E402

PASS = "correct horse battery staple 1"


class _Killed(BaseException):
    """Stands in for the process dying at this point (not an Exception, so nothing catches it)."""


def _ledger_transitions(path):
    if not path.exists():
        return []
    led = argus_ledger.AppendOnlyLedger(str(path))
    return [
        (e.payload.get("category"), e.payload.get("key"), e.payload.get("from"), e.payload.get("to"))
        for e in led.iter_events()
        if e.event_type == "kibisis.state_transition"
    ]


def _journal_transitions(vault):
    return [
        (ev.category, ev.key, ev.metadata.get("from"), ev.metadata.get("to"))
        for ev in vault.list_audit_events(limit=10_000)
        if ev.action == "state_transition"
    ]


@pytest.fixture
def env(tmp_path, monkeypatch):
    ledger = tmp_path / "argus" / "audit.jsonl"
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(ledger))
    db = tmp_path / "vault.sqlite"
    v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    v.put("facts", "old", "the sky is green", origin="user")
    yield db, ledger, v
    v.close()


def test_control_committed_supersession_is_mirrored(env):
    db, ledger, v = env
    v.put("facts", "new", "the sky is blue", supersedes_key="old", origin="user")
    v.close()
    fresh = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    try:
        assert fresh.get("facts", "old").epistemic_state.value == "revoked"
        journal = _journal_transitions(fresh)
        assert ("facts", "old", "candidate", "revoked") in journal
        assert ("facts", "old", "candidate", "revoked") in _ledger_transitions(ledger)
    finally:
        fresh.close()


def test_attack_kill_after_argus_append_before_commit(env, monkeypatch):
    db, ledger, v = env
    real = vault_review._argus_append

    def append_then_die(*a, **kw):
        real(*a, **kw)  # the Argus record reaches its file ...
        raise _Killed()  # ... and the process dies before the vault's COMMIT

    monkeypatch.setattr(vault_review, "_argus_append", append_then_die)
    with pytest.raises(_Killed):
        v.put("facts", "new", "the sky is blue", supersedes_key="old", origin="user")
    monkeypatch.setattr(vault_review, "_argus_append", real)
    v.close()

    fresh = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    try:
        assert fresh.get("facts", "new") is None  # the write never committed
        assert fresh.get("facts", "old").epistemic_state.value == "candidate"
        journal = _journal_transitions(fresh)
        phantom = [t for t in _ledger_transitions(ledger) if t not in journal]
        assert phantom == [], f"Argus ledger attests transitions the vault never made: {phantom}"
    finally:
        fresh.close()


def test_attack_refused_write_leaves_phantom_revocation(env):
    db, ledger, v = env
    # A person rejects the value "the sky is blue"; then a supersession whose replacement holds it is
    # refused by the tombstone check, which runs after the supersession branch in the same transaction.
    v.tombstone("facts", "rejected", content="the sky is blue", origin="user")
    with pytest.raises(TombstonedValueError):
        v.put("facts", "new", "the sky is blue", supersedes_key="old", origin="user")
    v.close()

    fresh = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    try:
        assert fresh.get("facts", "old").epistemic_state.value == "candidate"  # nothing was revoked
        journal = _journal_transitions(fresh)
        phantom = [t for t in _ledger_transitions(ledger) if t not in journal]
        assert phantom == [], f"Argus ledger attests transitions the vault never made: {phantom}"
    finally:
        fresh.close()
