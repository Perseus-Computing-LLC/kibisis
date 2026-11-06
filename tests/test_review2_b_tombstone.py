"""Review 2, area B: signed tombstone table (R2-B3; F4 second pass) and read-only open integrity (R2-B5).

Vault opened WITHOUT SQLCipher, with a passphrase (allow_plaintext). Regression tests converted from the
review's repro file: ``test_attack_*`` assert the fixed behaviour.
"""

import json
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
    ev = c.execute("SELECT metadata_json FROM audit_journal WHERE action='tombstone'").fetchall()
    assert len(ev) == 1  # journaled in the import's transaction
    meta = json.loads(ev[0][0])
    assert meta["path"] == "import_snapshot" and meta["origin_class"] == "principal"
    c.close()


def test_attack_snapshot_imported_tombstone_row_deletion_is_caught(tmp_path):
    """R2-B3: import_snapshot records a ``tombstone`` journal event for every row it inserts, so a row a
    file writer deletes is missed by _check_tombstones at the next open (VaultIntegrityError) instead of
    readmitting the value unnoticed."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.import_snapshot(_plain_snapshot_with_tombstone("the rejected value"))
    v.close()
    c = _conn(p)
    c.execute("DELETE FROM rejected_value_tombstones")
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="journaled tombstone"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_control_importing_the_same_tombstone_twice_journals_it_once(tmp_path):
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        v.import_snapshot(_plain_snapshot_with_tombstone("the rejected value"))
        v.import_snapshot(_plain_snapshot_with_tombstone("the rejected value"))
        assert v.verify_audit_chain() is True, v.last_chain_error
    finally:
        v.close()
    c = _conn(p)
    assert c.execute("SELECT count(*) FROM rejected_value_tombstones").fetchone()[0] == 1
    assert c.execute("SELECT count(*) FROM audit_journal WHERE action='tombstone'").fetchone()[0] == 1
    c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # reconciles
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


def test_attack_read_only_open_refuses_keyed_vault_with_salt_removed(tmp_path):
    """R2-B5: a keyed vault whose ``kdf_salt`` is gone but whose key check, meta MAC or integrity format
    remain is refused by the read-only open (VaultIntegrityError) instead of being read as a plaintext
    vault with a path-derived signing key; the writable open refuses too, and writes no fresh salt."""
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
    with pytest.raises(vault_module.VaultIntegrityError, match="no kdf_salt"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, read_only=True)
    with pytest.raises(vault_module.VaultIntegrityError, match="no kdf_salt"):
        SQLiteMemoryVault(str(p), passphrase=None, auto_gate=False, read_only=True, allow_plaintext=True)
    with pytest.raises(vault_module.VaultIntegrityError, match="no kdf_salt"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    c = _conn(p)
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key='kdf_salt'").fetchone()[0] == 0  # no new salt
    c.close()


@pytest.mark.parametrize("keep", ["key_check", "meta_mac", "integrity_format"])
def test_read_only_open_refuses_each_keyed_record_without_salt(tmp_path, keep):
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k", "value", origin="user", author_id="person")
    v.close()
    c = _conn(p)
    c.execute("DELETE FROM vault_meta WHERE key IN ('kdf_salt', 'key_check', 'meta_mac', 'integrity_format') AND key != ?",
              (keep,))
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="no kdf_salt"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, read_only=True)
    with pytest.raises(vault_module.VaultIntegrityError, match="no kdf_salt"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_control_plain_vault_never_keyed_still_opens_read_only(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT", raising=False)
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=None, auto_gate=False, allow_plaintext=True)
    v.remember("decision", "k", "value", origin="user", author_id="person")
    v.close()
    v = SQLiteMemoryVault(str(p), passphrase=None, auto_gate=False, read_only=True, allow_plaintext=True)
    try:
        assert v.get("decision", "k").content == "value"
    finally:
        v.close()
