"""Review 2, area B: signed tombstone table (F4 second pass) and read-only open integrity.

Vault opened WITHOUT SQLCipher, with a passphrase (allow_plaintext). Not collected by default.
``test_control_*`` = secure behaviour (failing = bug); ``test_attack_*`` = defect demo (passing = bug).
"""

import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault, TombstonedValueError
from kibisis._vault_crypto import value_digests
from kibisis.vault import _event_hash

PASS = "review2-b tombstone passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


def _plain_snapshot_with_tombstone(value):
    exact, canonical = value_digests(value)
    return {
        "digest_scheme": "sha256",
        "entities": [],
        "tombstones": [{
            "scope": "default", "category": "decision", "key": "k", "value_sha256": exact,
            "canonical_sha256": canonical, "reason": "rejected elsewhere", "author_id": "person",
            "origin_class": "principal",
        }],
    }


def test_control_imported_tombstone_is_enforced_and_signed(tmp_path):
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        v.import_snapshot(_plain_snapshot_with_tombstone("the rejected value"))
        with pytest.raises(TombstonedValueError):
            v.remember("decision", "k", "the rejected value", origin="user", author_id="person")
    finally:
        v.close()
    c = _conn(p)
    row = c.execute("SELECT tombstone_mac FROM rejected_value_tombstones").fetchone()
    assert row and row[0]
    assert c.execute("SELECT count(*) FROM audit_journal WHERE action='tombstone'").fetchone()[0] == 0  # <- not journaled
    c.close()


def test_attack_snapshot_imported_tombstone_row_deletion_readmits_value_unnoticed(tmp_path):
    """F4 residual: import_snapshot inserts tombstone rows (with a MAC) but records no ``tombstone``
    journal event, so _check_tombstones has nothing to reconcile against. A file writer deletes the
    row; the next open succeeds, verify_audit_chain() is True, and the value is accepted. Passing = bug."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.import_snapshot(_plain_snapshot_with_tombstone("the rejected value"))
    v.close()
    c = _conn(p)
    c.execute("DELETE FROM rejected_value_tombstones")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # no VaultIntegrityError
    try:
        assert v.verify_audit_chain() is True, v.last_chain_error
        v.remember("decision", "k", "the rejected value", origin="user", author_id="person")  # readmitted
        assert v.get("decision", "k").content == "the rejected value"
    finally:
        v.close()


def test_control_native_tombstone_row_deletion_is_caught(tmp_path):
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k", "the rejected value", origin="user", author_id="person")
    v.tombstone("decision", "k", reason="wrong", author_id="person", scope="default")
    v.close()
    c = _conn(p)
    c.execute("DELETE FROM rejected_value_tombstones")
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="journaled tombstone"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_read_only_open_treats_keyed_vault_with_salt_removed_as_plaintext(tmp_path):
    """Read-only open block: when ``kdf_salt`` is gone, ``_open_read_only`` takes the 'plain file never
    opened with a passphrase' branch: no key check, no meta MAC, no tombstone reconciliation, path-derived
    signing key, floor 1. A file writer deletes the salt, deletes the tombstone row + event, re-chains the
    journal as format 1 and drops the head: the read-only open (okf-export) reports a verified journal
    and no integrity error. The writable open fails closed on the same file. Passing = bug."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k", "the rejected value", origin="user", author_id="person")
    v.tombstone("decision", "k", reason="wrong", author_id="person", scope="default")
    v.close()
    c = _conn(p)
    c.execute("DELETE FROM vault_meta WHERE key='kdf_salt'")
    c.execute("DELETE FROM rejected_value_tombstones")
    c.execute("DELETE FROM audit_journal WHERE action='tombstone'")
    prev = "0" * 64
    for r in c.execute("SELECT * FROM audit_journal ORDER BY sequence").fetchall():
        h = _event_hash(r["sequence"], r["timestamp"], r["action"], r["category"], r["key"], r["scope"],
                        r["value_sha256"], prev, r["author_id"], None, fmt=1)
        c.execute("UPDATE audit_journal SET prev_hash=?, event_hash=?, format=1 WHERE sequence=?", (prev, h, r["sequence"]))
        prev = h
    c.execute("DELETE FROM audit_head")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, read_only=True)  # no error
    try:
        assert v.verify_audit_chain() is True, v.last_chain_error
        assert v._keyed is False and v.passphrase is None
    finally:
        v.close()
    # The writable open fails closed on the same file (key check under a freshly generated salt), but note
    # that it writes that new salt into vault_meta before failing.
    with pytest.raises((vault_module.VaultIntegrityError, ValueError)):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    c = _conn(p)
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key='kdf_salt'").fetchone()[0] == 1
    c.close()
