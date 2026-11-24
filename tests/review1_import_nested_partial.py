"""severity: medium
finding: import_snapshot commits the partial effects of a per-entity write it refused, because nested _write_tx opens no savepoint: an attestations_reset event is journaled for a protected entry whose attestations were left in place

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes). ``test_attack_*``
asserts the correct behaviour (an entity the import refused leaves nothing behind but the refusal
record) and FAILS on this head.

Write path: ``import_snapshot`` (_vault_snapshot.py:315) opens one transaction and calls
``_put_journaled`` per entity (_vault_snapshot.py:445). The nested ``_write_tx`` (vault.py:903-905)
just yields the outer cursor: no SAVEPOINT, no rollback on error. ``_put`` journals
``attestations_reset`` (vault.py:1709-1717) and only then raises ``ReviewedEntryError``
(vault.py:1739-1744). ``import_snapshot`` catches it (_vault_snapshot.py:469-481), records a
"protected entry" refusal and goes on, so the half-done write is committed with the rest of the restore.
"""

from __future__ import annotations

from kibisis import SQLiteMemoryVault

PASS = "correct horse battery staple 1"


def _setup(tmp_path):
    db = tmp_path / "vault.sqlite"
    v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False, verification_quorum=1)
    v.put("facts", "k", "an agent's claim", origin="model")
    v.review_entity("facts", "k", "verified", reviewer_id="alice")
    e = v.get("facts", "k")
    assert e.epistemic_state.value == "verified"
    assert e.metadata.get("attestations")
    return db, v


def _foreign_snapshot(content):
    # No manifest, no trust seal: a file from elsewhere (or handed over by an agent).
    return {
        "format_version": "1.1",
        "entities": [{
            "category": "facts", "key": "k", "content": content, "scope": "default",
            "origin": "model", "epistemic_state": "candidate", "metadata": {},
        }],
        "tombstones": [],
    }


def _events(vault, action):
    return [ev for ev in vault.list_audit_events(limit=10_000) if ev.action == action and ev.key == "k"]


def test_control_protected_entry_survives_foreign_import(tmp_path):
    db, v = _setup(tmp_path)
    before = v.get("facts", "k")
    assert v.import_snapshot(_foreign_snapshot("a different claim")) == 0
    v.close()
    fresh = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False, verification_quorum=1)
    try:
        after = fresh.get("facts", "k")
        assert after.content == "an agent's claim"
        assert after.epistemic_state.value == "verified"
        assert after.metadata.get("attestations") == before.metadata.get("attestations")
        assert fresh.verify_audit_chain()
    finally:
        fresh.close()


def test_attack_refused_entity_leaves_attestations_reset_in_journal(tmp_path):
    db, v = _setup(tmp_path)
    assert _events(v, "attestations_reset") == []
    v.import_snapshot(_foreign_snapshot("a different claim"))
    v.close()
    fresh = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False, verification_quorum=1)
    try:
        kept = fresh.get("facts", "k").metadata.get("attestations")
        assert kept, "the live entry keeps its attestations"
        resets = _events(fresh, "attestations_reset")
        assert resets == [], (
            "the journal says the attestations of facts:k were reset by a write that was refused and never "
            f"applied (attestations still {kept}): {[r.metadata for r in resets]}"
        )
    finally:
        fresh.close()
