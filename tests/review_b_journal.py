"""Review B: audit-journal integrity against a local file writer (vault opened WITHOUT SQLCipher, with a
passphrase, so the signing key is secret but every table is plain SQLite).

Tests named ``test_control_*`` assert the SECURE behaviour (failing = bug).
Tests named ``test_attack_*`` DEMONSTRATE an insecure behaviour (passing = bug).
"""

import hashlib
import json
import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis.vault import _event_hash

PASS = "review-b journal passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)


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


def _verify(path):
    v = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    try:
        return v.verify_audit_chain(), [(e.sequence, e.action, e.key, e.format) for e in v.list_audit_events()]
    finally:
        v.close()


# ---------------------------------------------------------------- positive controls (secure = pass)

def test_control_delete_tail_is_caught(tmp_path):
    """Asserts secure behaviour: deleting the last journal row (head left) fails verify_audit_chain."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM audit_journal WHERE sequence = (SELECT MAX(sequence) FROM audit_journal)")
    c.commit(); c.close()
    ok, _ = _verify(p)
    assert ok is False


def test_control_delete_middle_is_caught(tmp_path):
    """Asserts secure behaviour: deleting a middle row breaks the prev_hash link."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM audit_journal WHERE sequence = 2")
    c.commit(); c.close()
    assert _verify(p)[0] is False


def test_control_edit_payload_is_caught(tmp_path):
    """Asserts secure behaviour: editing author_id of a row changes its hash."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE audit_journal SET author_id = 'mallory' WHERE sequence = 2")
    c.commit(); c.close()
    assert _verify(p)[0] is False


def test_control_delete_head_only_is_caught(tmp_path):
    """Asserts secure behaviour: format-3 rows with no audit_head fail (SECURITY.md line 53-54)."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM audit_head")
    c.commit(); c.close()
    assert _verify(p)[0] is False


def test_control_rust_verifier_rejects_non_format3_rows():
    """Asserts (via the crate's documented ChainError::UnsupportedFormat) that the Rust verifier refuses
    legacy-format rows; this test only pins that JOURNAL_FORMAT exported by the extension is 3."""
    import kibisis_native
    assert kibisis_native.JOURNAL_FORMAT == 3


# ---------------------------------------------------------------- attacks (passing = bug)

def _legacy_rechain(conn):
    """Attacker helper: rewrite every remaining row as journal format 1 (unkeyed SHA-256 of ':'-joined
    fields, metadata excluded), re-link the chain, and delete the signed head. No key needed."""
    prev = "0" * 64
    for r in _rows(conn):
        h = _event_hash(r["sequence"], r["timestamp"], r["action"], r["category"], r["key"], r["scope"],
                        r["value_sha256"], prev, r["author_id"], None, fmt=1)
        conn.execute("UPDATE audit_journal SET prev_hash = ?, event_hash = ?, format = 1 WHERE sequence = ?",
                     (prev, h, r["sequence"]))
        prev = h
    conn.execute("DELETE FROM audit_head")
    conn.commit()


def test_attack_format_downgrade_launders_middle_deletion(tmp_path):
    """DEMONSTRATES insecure behaviour (passing = bug): a file writer without the passphrase deletes a
    middle event, rewrites the remaining rows as format 1 and drops audit_head; verify_audit_chain
    returns True because (a) format<3 rows are recomputed with an unkeyed hash and (b) a journal with
    no format-3 rows needs no signed head (_vault_audit.py:234-236)."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    before = [r["action"] for r in _rows(c)]
    assert "tombstone" in before
    c.execute("DELETE FROM audit_journal WHERE action = 'tombstone'")  # erase the evidence of a rejection
    _legacy_rechain(c)
    c.close()
    ok, events = _verify(p)
    print("verify_audit_chain after downgrade+deletion:", ok, events)
    assert ok is True  # <-- bug: tampering undetected
    assert all(fmt == 1 for *_, fmt in events)
    assert not any(a == "tombstone" for _, a, _, _ in events)


def test_attack_format_downgrade_launders_payload_edit_and_reorder(tmp_path):
    """DEMONSTRATES insecure behaviour (passing = bug): author_id rewritten and two rows swapped, then
    downgraded; verify passes, and the NEXT legitimate append re-signs a head over the forged history,
    so the forgery becomes permanently 'verified'."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE audit_journal SET author_id = 'mallory' WHERE sequence = 2")
    # swap the keys of rows 1 and 3 (reorder of what happened)
    k1 = c.execute("SELECT key FROM audit_journal WHERE sequence = 1").fetchone()[0]
    k3 = c.execute("SELECT key FROM audit_journal WHERE sequence = 3").fetchone()[0]
    c.execute("UPDATE audit_journal SET key = ? WHERE sequence = 1", (k3,))
    c.execute("UPDATE audit_journal SET key = ? WHERE sequence = 3", (k1,))
    _legacy_rechain(c)
    c.close()
    ok, events = _verify(p)
    print("after edit+swap+downgrade:", ok, events)
    assert ok is True  # <-- bug

    # The legitimate owner keeps using the vault: the new head signs the forged chain.
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k9", "a later fact", origin="user")
    assert v.verify_audit_chain() is True
    head = v._conn.execute("SELECT sequence FROM audit_head").fetchone()[0]
    v.close()
    print("head re-signed at sequence", head)
    assert head == len(events) + 1


def test_attack_tombstone_row_deletion_readmits_value(tmp_path):
    """DEMONSTRATES insecure behaviour (passing = bug): SECURITY.md:56-59 lists 'Re-inserting a forgotten
    value' as CAUGHT for a local file writer, but the tombstone table is neither signed nor reconciled
    with the journal. Deleting the row lets the value back in and verify_audit_chain stays True."""
    p = _seeded(tmp_path / "v.sqlite")
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "k3b", "fact number 3", origin="user")
    v.close()
    c = _conn(p)
    n = c.execute("DELETE FROM rejected_value_tombstones").rowcount
    c.commit(); c.close()
    assert n == 1
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    ent = v.remember("decision", "k3b", "fact number 3", origin="user")  # <-- bug: accepted
    assert ent is not None
    assert v.verify_audit_chain() is True
    v.close()


def test_attack_meta_integrity_format_edit_bricks_open(tmp_path):
    """DEMONSTRATES a one-cell denial of service (passing = bug, low): setting vault_meta.integrity_format
    to 1 makes the next open run _migrate_integrity, which checks format-2 'v2:' signatures as format 1,
    counts them all as failed and raises 'Failed to authenticate' (_vault_crypto.py:354-367). The vault
    cannot be opened with the right passphrase until the cell is restored by hand."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
    c.commit(); c.close()
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_meta_integrity_format_edit_plus_blank_sigs_resigns_journal(tmp_path):
    """DEMONSTRATES insecure behaviour (passing = bug): with signatures blanked as well, the forced
    re-migration rewrites the journal (tampered beforehand: tombstone event removed), signs a fresh head,
    double-keys every tombstone digest (keyed_value_digest applied to an already-keyed value,
    _vault_crypto.py:379-380) and verify_audit_chain is True afterwards. The migrate event records
    previous_chain_valid=False but nothing surfaces it beyond a log line."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    old_tomb = c.execute("SELECT value_sha256 FROM rejected_value_tombstones").fetchone()[0]
    c.execute("DELETE FROM audit_journal WHERE action = 'tombstone'")
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    up = v.integrity_upgrade
    print("integrity_upgrade:", up)
    assert up is not None and up["journal_events_rekeyed"] >= 1
    assert v.verify_audit_chain() is True  # <-- laundered
    ev = v.list_audit_events()
    assert ev[-1].action == "migrate" and ev[-1].metadata["previous_chain_valid"] is False
    new_tomb = v._conn.execute("SELECT value_sha256 FROM rejected_value_tombstones").fetchone()[0]
    assert new_tomb != old_tomb  # digest keyed a second time
    # the tombstone no longer matches the value it was recorded for
    ent = v.remember("decision", "k3c", "fact number 3", origin="user")  # <-- accepted: tombstone defeated
    assert ent is not None
    v.close()
