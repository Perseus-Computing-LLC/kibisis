"""Review 2, area B: key check before migration / SQLCipher conversion (R2-B2; F9, F13, L4 second pass).

Regression tests converted from the review's repro file: ``test_attack_*`` assert the fixed behaviour.
"""

import shutil
import sqlite3
from pathlib import Path

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault

FIXTURE = Path(__file__).parent / "fixtures" / "vault-0.1.0a5-fallback.sqlite"
FIXTURE_PASS = "legacy fixture passphrase (test only)"
WRONG = "not the passphrase (test only)"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT", raising=False)


def _legacy_copy(tmp_path):
    db = tmp_path / "legacy.db"
    shutil.copyfile(FIXTURE, db)
    return db


def test_attack_legacy_a5_vault_wrong_passphrase_leaves_plain_file_untouched(tmp_path):
    """R2-B2: a 0.1.0a5 vault (kdf_salt present, no key_check, no integrity_format) opened with a WRONG
    passphrase on a host with sqlcipher3 is authenticated against the plain file (one of its sealed
    entries must open under the passphrase) before any conversion: the file is byte for byte as it was,
    no temp copy is left beside it, and the right passphrase still opens it."""
    import sqlcipher3  # noqa: F401
    assert vault_module._sqlcipher_available() is True
    db = _legacy_copy(tmp_path)
    before = db.read_bytes()
    assert before.startswith(b"SQLite format 3")
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(db), passphrase=WRONG, auto_gate=False)
    assert db.read_bytes() == before, "the plain file was changed by a failed open"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["legacy.db"], "a conversion artefact was left behind"
    v = SQLiteMemoryVault(str(db), passphrase=FIXTURE_PASS, auto_gate=False)
    try:
        assert v.encrypted_at_rest is True
        assert v.verify_audit_chain() is True, v.last_chain_error
    finally:
        v.close()


def test_conversion_is_not_adopted_when_the_upgrade_fails(tmp_path, monkeypatch):
    """R2-B2: the SQLCipher copy replaces the plain file only after it opened, authenticated and
    upgraded; a failure in the upgrade leaves the plain file untouched and removes the copy."""
    import sqlcipher3  # noqa: F401
    db = _legacy_copy(tmp_path)
    before = db.read_bytes()

    def boom(self):
        raise RuntimeError("upgrade interrupted (test)")

    monkeypatch.setattr(SQLiteMemoryVault, "_upgrade_integrity", boom)
    with pytest.raises(RuntimeError, match="upgrade interrupted"):
        SQLiteMemoryVault(str(db), passphrase=FIXTURE_PASS, auto_gate=False)
    assert db.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["legacy.db"]


def test_control_legacy_a5_vault_right_passphrase_upgrades_to_format_3(tmp_path):
    import sqlcipher3  # noqa: F401
    db = _legacy_copy(tmp_path)
    v = SQLiteMemoryVault(str(db), passphrase=FIXTURE_PASS, auto_gate=False)
    try:
        assert v.encrypted_at_rest is True
        assert v.verify_audit_chain() is True, v.last_chain_error
        assert v.integrity_upgrade and v.integrity_upgrade.get("journal_format_floor") in (1, 2)
    finally:
        v.close()
    v = SQLiteMemoryVault(str(db), passphrase=FIXTURE_PASS, auto_gate=False)  # idempotent
    try:
        assert v.integrity_upgrade is None
        assert v.verify_audit_chain() is True, v.last_chain_error
    finally:
        v.close()


# ---------------------------------------------------------------- regressions: older formats still open

def _simulate_format_2(path, *, headless=False):
    """Turn a format-3 plain file into what a 0.1.0a10-a15 (integrity format 2) vault stored: no meta
    MAC, no floor/anchoring, unsigned tombstone rows; ``headless`` = pre-a10 journal without audit_head."""
    c = sqlite3.connect(str(path))
    c.execute("UPDATE vault_meta SET value = '2' WHERE key = 'integrity_format'")
    c.execute("DELETE FROM vault_meta WHERE key IN ('meta_mac', 'journal_format_floor', 'journal_anchored')")
    c.execute("UPDATE rejected_value_tombstones SET tombstone_mac = NULL")
    if headless:  # a6-a9: integrity format 2, journal rows in format 2 (keyed digests, ':'-joined hash), no head
        from kibisis.vault import _event_hash
        c.row_factory = sqlite3.Row
        prev = "0" * 64
        for r in c.execute("SELECT * FROM audit_journal ORDER BY sequence").fetchall():
            h = _event_hash(r["sequence"], r["timestamp"], r["action"], r["category"], r["key"], r["scope"],
                            r["value_sha256"], prev, r["author_id"], None, fmt=2)
            c.execute("UPDATE audit_journal SET prev_hash=?, event_hash=?, format=2 WHERE sequence=?",
                      (prev, h, r["sequence"]))
            prev = h
        c.execute("DELETE FROM audit_head")
    c.commit(); c.close()


@pytest.mark.parametrize("headless", [False, True])
def test_control_format_2_vault_upgrades_to_3_and_keeps_tombstones(tmp_path, monkeypatch, headless):
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=WRONG, auto_gate=False)
    v.remember("decision", "k", "kept", origin="user", author_id="person")
    v.remember("decision", "gone", "rejected", origin="user", author_id="person")
    v.tombstone("decision", "gone", reason="wrong", author_id="person", scope="default")
    v.close()
    _simulate_format_2(p, headless=headless)
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase=FIXTURE_PASS, auto_gate=False)  # wrong passphrase: no upgrade
    v = SQLiteMemoryVault(str(p), passphrase=WRONG, auto_gate=False)
    try:
        assert v.integrity_upgrade == {"tombstones_signed": 1, "journal_format_floor": 2 if headless else 3}
        assert v.verify_audit_chain() is True, v.last_chain_error
        assert v.get("decision", "k").content == "kept"
        from kibisis import TombstonedValueError
        with pytest.raises(TombstonedValueError):
            v.remember("decision", "gone", "rejected", origin="user", author_id="person")
    finally:
        v.close()
    v = SQLiteMemoryVault(str(p), passphrase=WRONG, auto_gate=False)
    assert v.integrity_upgrade is None and v.verify_audit_chain() is True
    v.close()
    v = SQLiteMemoryVault(str(p), passphrase=WRONG, auto_gate=False, read_only=True)
    assert v.verify_audit_chain() is True and v.get("decision", "k").content == "kept"
    v.close()


def test_control_in_memory_vault_with_passphrase_round_trips():
    v = SQLiteMemoryVault(":memory:", passphrase=WRONG, auto_gate=False)
    v.remember("decision", "k", "kept", origin="user", author_id="person")
    v.tombstone("decision", "k", reason="wrong", author_id="person", scope="default")
    assert v.verify_audit_chain() is True, v.last_chain_error
    v.close()
