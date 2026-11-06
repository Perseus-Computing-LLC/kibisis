"""Review B: audit-journal integrity against a local file writer (vault opened WITHOUT SQLCipher, with a
passphrase, so the signing key is secret but every table is plain SQLite).

Tests named ``test_control_*`` assert behaviour that was already secure. Tests named ``test_attack_*``
replay the review's attacks and assert that each is now caught (F2 journal format downgrade, F4 unsigned
tombstone table, F13/F9 meta edits and re-signing migrations).
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
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")  # the file writer's position: a plain SQLite file


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
        ok = v.verify_audit_chain()
        return ok, [(e.sequence, e.action, e.key, e.format) for e in v.list_audit_events()], v.last_chain_error
    finally:
        v.close()


# ---------------------------------------------------------------- positive controls (secure = pass)

def test_control_delete_tail_is_caught(tmp_path):
    """Asserts secure behaviour: deleting the last journal row (head left) fails verify_audit_chain."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM audit_journal WHERE sequence = (SELECT MAX(sequence) FROM audit_journal)")
    c.commit(); c.close()
    ok, _, _ = _verify(p)
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


# ---------------------------------------------------------------- the review's attacks, now caught

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


def test_attack_format_downgrade_of_middle_deletion_is_caught(tmp_path):
    """F2: a file writer deletes a middle event, rewrites the remaining rows as format 1 and drops
    audit_head. The vault's journal format floor is 3 (pinned under the meta MAC) and its journal is
    anchored, so the rewritten rows are refused and the missing head would be too."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    assert "tombstone" in [r["action"] for r in _rows(c)]
    c.execute("DELETE FROM audit_journal WHERE action = 'tombstone'")  # erase the evidence of a rejection
    _legacy_rechain(c)
    c.close()
    ok, events, error = _verify(p)
    assert ok is False
    assert "below this vault's floor 3" in error
    assert all(fmt == 1 for *_, fmt in events)
    assert not any(a == "tombstone" for _, a, _, _ in events)
    # The tombstone row itself still stands (and verifies under its own MAC): the value stays refused.
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "k3b", "fact number 3", origin="user")
    v.close()


def test_attack_format_downgrade_of_payload_edit_and_reorder_is_caught(tmp_path):
    """F2: author_id rewritten and two rows swapped, then downgraded; verification fails, and the next
    legitimate append does not launder it: the head signs the new row, but the rewritten rows still
    fail under the floor."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE audit_journal SET author_id = 'mallory' WHERE sequence = 2")
    k1 = c.execute("SELECT key FROM audit_journal WHERE sequence = 1").fetchone()[0]
    k3 = c.execute("SELECT key FROM audit_journal WHERE sequence = 3").fetchone()[0]
    c.execute("UPDATE audit_journal SET key = ? WHERE sequence = 1", (k3,))
    c.execute("UPDATE audit_journal SET key = ? WHERE sequence = 3", (k1,))
    _legacy_rechain(c)
    c.close()
    ok, events, error = _verify(p)
    assert ok is False and "floor 3" in error

    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k9", "a later fact", origin="user")
    assert v.verify_audit_chain() is False
    assert "floor 3" in v.last_chain_error
    v.close()


def test_attack_whole_journal_deletion_with_head_is_caught(tmp_path):
    """F2: removing every row and the head leaves an 'empty' journal; the vault remembers that its
    journal has held a row (journal_anchored, under the meta MAC) and demands the head."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM rejected_value_tombstones")  # or the missing tombstone evidence fails first
    c.execute("DELETE FROM audit_journal")
    c.execute("DELETE FROM audit_head")
    c.commit(); c.close()
    ok, events, error = _verify(p)
    assert ok is False and events == []
    assert "no signed head" in error


def test_attack_tombstone_row_deletion_is_caught(tmp_path):
    """F4: SECURITY.md lists 'Re-inserting a forgotten value' as caught for a local file writer. The
    tombstone table is reconciled with the journal at open: a journaled tombstone with no row refuses
    the open, so the value never gets back in."""
    p = _seeded(tmp_path / "v.sqlite")
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "k3b", "fact number 3", origin="user")
    v.close()
    c = _conn(p)
    assert c.execute("DELETE FROM rejected_value_tombstones").rowcount == 1
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="journaled tombstone"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_tombstone_row_edit_is_caught(tmp_path):
    """F4: every tombstone row carries a MAC under the signing key. Changing the digest it rejects (so
    another value is blocked, or the real one admitted) fails at open; a row whose MAC is blanked too."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE rejected_value_tombstones SET value_sha256 = ?", (hashlib.sha256(b"other").hexdigest(),))
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="fails its MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    c = _conn(p)
    c.execute("UPDATE rejected_value_tombstones SET tombstone_mac = NULL")
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="has no MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_tombstone_row_added_without_the_key_is_caught_on_hit(tmp_path):
    """F4: a row a file writer inserts (to block a value) has no valid MAC; the lookup that hits it
    raises instead of honouring it. Rows are also checked at open."""
    p = _seeded(tmp_path / "v.sqlite")
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    forged = v._value_digests("a value the writer wants blocked")[0] if hasattr(v, "_value_digests") else None
    v.close()
    c = _conn(p)
    c.execute(
        "INSERT INTO rejected_value_tombstones (category, key, value_sha256, canonical_sha256, reason, author_id, "
        "created_at, scope) VALUES ('decision', 'forged', ?, '', 'forged', 'mallory', 0, 'default')",
        (forged or hashlib.sha256(b"x").hexdigest(),),
    )
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="no MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_meta_integrity_format_edit_is_caught_not_bricking(tmp_path):
    """F13: setting vault_meta.integrity_format to 1 no longer forces a re-migration that fails as a
    wrong passphrase: the key check is compared first (it passes), then the forced migration finds the
    journal's head signed under a key it does not know and refuses, naming the integrity record."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_meta_integrity_format_edit_plus_blank_sigs_does_not_resign_journal(tmp_path):
    """F13: with signatures blanked as well and the journal tampered (tombstone event removed), the
    forced re-migration refuses rather than re-signing a chain that does not verify; nothing is written."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    before = [tuple(r) for r in _rows(c)]
    old_tomb = c.execute("SELECT value_sha256, tombstone_mac FROM rejected_value_tombstones").fetchone()
    c.execute("DELETE FROM audit_journal WHERE action = 'tombstone'")
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    c.commit(); c.close()
    with pytest.raises((vault_module.VaultIntegrityError, ValueError)):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    c = _conn(p)
    assert [tuple(r) for r in _rows(c)] == [r for r in before if r[2] != "tombstone"]  # untouched since the attack
    assert tuple(c.execute("SELECT value_sha256, tombstone_mac FROM rejected_value_tombstones").fetchone()) == tuple(old_tomb)
    assert c.execute("SELECT count(*) FROM audit_journal WHERE action = 'migrate'").fetchone()[0] == 0
    c.close()


def test_attack_meta_mac_binds_the_integrity_records(tmp_path):
    """F9/F13: integrity_format, kdf_salt, key_check, the journal floor and the term index format are
    bound under one MAC; changing or removing any of them without the key refuses the open."""
    p = _seeded(tmp_path / "v.sqlite")
    for sql in (
        "UPDATE vault_meta SET value = '2' WHERE key = 'journal_format_floor'",
        "UPDATE vault_meta SET value = '0' WHERE key = 'journal_anchored'",
        "DELETE FROM vault_meta WHERE key = 'meta_mac'",
        "DELETE FROM vault_meta WHERE key = 'key_check'",
    ):
        c = _conn(p)
        saved = c.execute("SELECT key, value FROM vault_meta").fetchall()
        c.execute(sql)
        c.commit(); c.close()
        with pytest.raises(vault_module.VaultIntegrityError):
            SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
        c = _conn(p)
        c.execute("DELETE FROM vault_meta")
        c.executemany("INSERT INTO vault_meta (key, value) VALUES (?, ?)", [tuple(r) for r in saved])
        c.commit(); c.close()
    SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False).close()  # restored: opens again


# ---------------------------------------------------------------- Python and Rust verifiers agree

def _native_rows(v):
    return [
        {
            "sequence": r["sequence"], "timestamp": float(r["timestamp"]), "action": r["action"],
            "category": r["category"], "key": r["key"], "scope": r["scope"], "value_sha256": r["value_sha256"],
            "prev_hash": r["prev_hash"], "event_hash": r["event_hash"], "author_id": r["author_id"],
            # The crate takes the metadata as canonical JSON (the Python hash canonicalizes the parsed dict).
            "metadata_json": None if not r["metadata_json"] else json.dumps(
                json.loads(r["metadata_json"]), sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            "format": r["format"],
        }
        for r in v._conn.execute("SELECT * FROM audit_journal ORDER BY sequence").fetchall()
    ]


def _native_head(v):
    h = v._conn.execute("SELECT sequence, event_hash, mac FROM audit_head WHERE id = 1").fetchone()
    return None if h is None else dict(h)


def test_python_and_rust_verifiers_agree_on_the_same_rows(tmp_path, monkeypatch):
    """The same rows and head give the same verdict in kibisis_native.verify_chain and the Python
    ChainVerifier, on the sound journal and on every tampering below. The crate's AuditEvent keeps
    whole seconds, so the journal is written with whole-second timestamps for the comparison."""
    import time as time_module

    kibisis_native = pytest.importorskip("kibisis_native")
    from kibisis._vault_audit import verify_journal_rows

    if not hasattr(kibisis_native, "verify_chain"):
        pytest.skip("kibisis_native was built before verify_chain was exported")
    real_time = time_module.time
    monkeypatch.setattr(time_module, "time", lambda: float(int(real_time())))
    p = _seeded(tmp_path / "v.sqlite")
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    key = v._signing_key
    rows, head = _native_rows(v), _native_head(v)

    def python_verdict(rows_, head_, head_required):
        from kibisis.models import AuditEvent
        events = [
            AuditEvent(sequence=r["sequence"], timestamp=r["timestamp"], action=r["action"],
                       category=r["category"], key=r["key"], scope=r["scope"], value_sha256=r["value_sha256"],
                       prev_hash=r["prev_hash"], event_hash=r["event_hash"], author_id=r["author_id"],
                       metadata=json.loads(r["metadata_json"] or "{}"), format=r["format"])
            for r in rows_
        ]
        return verify_journal_rows(events, head_, key, format_floor=3, head_required=head_required) is None

    cases = {
        "sound": (rows, head),
        "tail cut": (rows[:-1], head),
        "middle cut": (rows[:1] + rows[2:], head),
        "payload edit": ([dict(r, author_id="mallory") if r["sequence"] == 2 else r for r in rows], head),
        "no head": (rows, None),
        "empty": ([], None),
        "head without rows": ([], head),
        "head mac": (rows, dict(head, mac="00" * 32)),
        "format 2 row": ([dict(r, format=2) if r["sequence"] == 1 else r for r in rows], head),
    }
    for name, (rows_, head_) in cases.items():
        for head_required in (False, True):
            native = kibisis_native.verify_chain(rows_, head_, key, head_required)
            assert (native is None) == python_verdict(rows_, head_, head_required), (name, head_required, native)
    assert kibisis_native.verify_chain(rows, head, key, True) is None
    assert kibisis_native.verify_chain([], None, key, True) is not None
    assert kibisis_native.verify_chain([], None, key, False) is None
    with pytest.raises(ValueError, match="whole number of seconds"):
        kibisis_native.verify_chain([dict(rows[0], timestamp=rows[0]["timestamp"] + 0.5)], head, key)
    v.close()
