"""Review 2, area B: journal / tombstone / meta laundering against a file writer (F2, F4, F13 second pass).

Vault opened WITHOUT SQLCipher, with a passphrase (allow_plaintext). Not collected by default.
``test_control_*`` = secure behaviour (failing = bug); ``test_attack_*`` = defect demo (passing = bug).
"""

import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis.vault import _event_hash

PASS = "review2-b journal passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _seeded(path):
    v = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    for i in range(4):
        v.remember("decision", f"k{i}", f"fact number {i}", origin="user", author_id=f"author{i}")
    v.tombstone("decision", "k3", reason="wrong", author_id="reviewer", scope="default")
    assert v.verify_audit_chain() is True
    v.close()
    return path


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


def _rows(conn):
    return conn.execute("SELECT * FROM audit_journal ORDER BY sequence").fetchall()


def _legacy_rechain(conn, fmt=1):
    prev = "0" * 64
    for r in _rows(conn):
        h = _event_hash(r["sequence"], r["timestamp"], r["action"], r["category"], r["key"], r["scope"],
                        r["value_sha256"], prev, r["author_id"], None, fmt=fmt)
        conn.execute("UPDATE audit_journal SET prev_hash = ?, event_hash = ?, format = ? WHERE sequence = ?",
                     (prev, h, fmt, r["sequence"]))
        prev = h
    conn.execute("DELETE FROM audit_head")
    conn.commit()


def test_attack_full_meta_reset_launders_tombstone_and_journal_through_remigration(tmp_path):
    """F2+F4+F13 residual. The fix refuses a format-1 claim that still carries key_check/meta_mac, and
    refuses to re-sign a chain that does not verify. A file writer removes ALL of them: integrity_format
    -> 1, key_check and meta_mac deleted (kdf_salt kept), every tenant_sig blanked, the tombstone row and
    its journal event deleted, the remaining rows re-chained as format 1 (unkeyed), head deleted.
    The next honest open with the right passphrase re-migrates 1->2->3: it re-keys digests, appends a
    'migrate' event (previous_chain_valid=True), signs a new head and meta MAC. Afterwards the
    tombstoned value is accepted again and verify_audit_chain() is True. Passing = bug."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM rejected_value_tombstones")
    c.execute("DELETE FROM audit_journal WHERE action = 'tombstone'")
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
    c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac')")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    _legacy_rechain(c)
    c.close()

    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # no VaultIntegrityError
    try:
        assert v.verify_audit_chain() is True, v.last_chain_error
        assert v.integrity_upgrade is not None and v.integrity_upgrade.get("previous_chain_valid", True)
        actions = [e.action for e in v.list_audit_events()]
        assert "tombstone" not in actions and "migrate" in actions
        v.remember("decision", "k3", "fact number 3", origin="user", author_id="victim")  # readmitted
        assert v.get("decision", "k3").content == "fact number 3"
    finally:
        v.close()
    c = _conn(p)
    assert int(c.execute("SELECT value FROM vault_meta WHERE key='integrity_format'").fetchone()[0]) == 3
    assert c.execute("SELECT count(*) FROM audit_head").fetchone()[0] == 1  # honest opener signed the forged chain
    c.close()


def test_attack_meta_reset_without_tombstone_deletion_double_keys_the_digests(tmp_path):
    """F13 residual: same reset but the tombstone row and its event are left in place. The re-migration
    re-keys both (double HMAC) consistently, so _check_tombstones reconciles, yet the lookup digest of
    the live value no longer matches: the value is readmitted without deleting anything. Passing = bug."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
    c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac')")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    _legacy_rechain(c)
    c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verify_audit_chain() is True, v.last_chain_error
        v.remember("decision", "k3", "fact number 3", origin="user", author_id="victim")  # readmitted
    finally:
        v.close()


def test_attack_same_reset_with_integrity_format_row_deleted(tmp_path):
    """Same road with the integrity_format row deleted outright (int(None or 0) == 0 < 2). Passing = bug."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac', 'integrity_format')")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    _legacy_rechain(c)
    c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verify_audit_chain() is True
    finally:
        v.close()


def test_attack_row_relabelled_format_4_is_accepted_by_python_refused_by_rust(tmp_path):
    """A row relabelled format 4 hashes like format 3 in Python (fmt >= 3 branch) but the Rust verifier
    refuses it (UnsupportedFormat). Format column is not pinned upward. Passing = bug (disagreement)."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE audit_journal SET format = 4 WHERE sequence = 2")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verify_audit_chain() is True, v.last_chain_error
    finally:
        v.close()


def test_attack_verification_quorum_in_vault_meta_is_outside_the_meta_mac(tmp_path, monkeypatch):
    """vault_meta.verification_quorum (area A's F7 fix: 'a quorum may be raised but not lowered') is not
    one of VAULT_META_BOUND_KEYS, so a file writer lowers it to 1 and the next process that names no
    quorum adopts it; the meta MAC still verifies. Passing = bug."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    stored = int(c.execute("SELECT value FROM vault_meta WHERE key='verification_quorum'").fetchone()[0])
    assert stored >= 2
    c.execute("UPDATE vault_meta SET value = '1' WHERE key='verification_quorum'")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # no VaultIntegrityError
    try:
        assert v.verification_quorum == 1
    finally:
        v.close()
