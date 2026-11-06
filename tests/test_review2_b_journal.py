"""Review 2, area B: journal / tombstone / meta laundering against a file writer (R2-B1, R2-B4, R2-B8,
R2-B9; F2, F4, F13 second pass).

Vault opened WITHOUT SQLCipher, with a passphrase (allow_plaintext). Regression tests converted from the
review's repro file: ``test_attack_*`` assert the fixed behaviour.
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
    # pin_quorum=True: the stored-quorum tests below need the file to carry one, as a person's first
    # verdict would leave it (R3-E1: a plain open no longer pins).
    v = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False, pin_quorum=True)
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


def _reset_meta(c, *, delete_format=False):
    """What a file writer does to re-enter the format 1 migration: integrity_format -> 1 (or deleted),
    key_check and meta_mac deleted (kdf_salt kept), every tenant_sig blanked."""
    if delete_format:
        c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac', 'integrity_format')")
    else:
        c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
        c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac')")
    c.execute("UPDATE entities SET tenant_sig = NULL")


def test_attack_full_meta_reset_is_refused_not_remigrated(tmp_path):
    """R2-B1: a file writer removes integrity_format, key_check and meta_mac (kdf_salt kept), blanks every
    tenant_sig, deletes the tombstone row and its journal event, re-chains the rest as format 1 and drops
    the head. The next honest open must not re-migrate (which would re-sign the forged state): a vault
    with a salt and no key check is only taken for 0.1.0a5 when nothing format 2+ wrote remains, and the
    journal floor and anchoring stay in force (they still hang on the salt, not on the format claim)."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM rejected_value_tombstones")
    c.execute("DELETE FROM audit_journal WHERE action = 'tombstone'")
    _reset_meta(c)
    _legacy_rechain(c)
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="keyed .* no key check"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    c = _conn(p)
    assert int(c.execute("SELECT value FROM vault_meta WHERE key='integrity_format'").fetchone()[0]) == 1
    assert c.execute("SELECT count(*) FROM audit_head").fetchone()[0] == 0  # nothing was signed
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key IN ('key_check', 'meta_mac')").fetchone()[0] == 0
    c.close()


def test_attack_meta_reset_without_tombstone_deletion_is_refused(tmp_path):
    """R2-B1: the same reset with the tombstone row and its event left in place (re-migration would
    double-key the digests so the live value no longer matches) is refused too."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    _reset_meta(c)
    _legacy_rechain(c)
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="keyed .* no key check"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_same_reset_with_integrity_format_row_deleted(tmp_path):
    """R2-B1: the integrity_format row deleted outright (int(None or 0) == 0 < 2) is no road in either."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    _reset_meta(c, delete_format=True)
    _legacy_rechain(c)
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="keyed .* no key check"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_meta_reset_with_every_artefact_scrubbed_still_fails_the_floor(tmp_path):
    """R2-B1: with every format 2+ artefact removed as well (floor, anchoring, head, tombstone MACs,
    sealed entries' bindings cannot be: they are inside the ciphertext), what is left of a seeded vault
    still carries entries sealed with their binding, so it is not taken for a5."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM rejected_value_tombstones")
    c.execute("DELETE FROM audit_journal WHERE action = 'tombstone'")
    c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac', 'integrity_format', "
              "'journal_format_floor', 'journal_anchored')")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    _legacy_rechain(c)
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="sealed with its binding"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_row_relabelled_format_4_is_refused_by_python_and_rust(tmp_path, monkeypatch):
    """R2-B8: a row relabelled format 4 is refused by the Python verifier (as by the crate's
    UnsupportedFormat) instead of being hashed like format 3. The crate keeps whole seconds, so the
    journal is written with whole-second timestamps for the comparison."""
    import json
    import time as time_module
    real_time = time_module.time
    monkeypatch.setattr(time_module, "time", lambda: float(int(real_time())))
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE audit_journal SET format = 4 WHERE sequence = 2")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verify_audit_chain() is False
        assert "format 4" in (v.last_chain_error or "")
    finally:
        v.close()
    native = pytest.importorskip("kibisis_native")
    if not hasattr(native, "verify_chain"):
        pytest.skip("kibisis_native was built before verify_chain was exported")
    from kibisis.crypto import derive_vault_keys
    c = _conn(p)
    salt = bytes(c.execute("SELECT value FROM vault_meta WHERE key='kdf_salt'").fetchone()[0])
    rows = [
        {"sequence": r["sequence"], "timestamp": int(r["timestamp"]), "action": r["action"], "category": r["category"],
         "key": r["key"], "scope": r["scope"], "value_sha256": r["value_sha256"], "prev_hash": r["prev_hash"],
         "event_hash": r["event_hash"], "author_id": r["author_id"],
         "metadata_json": None if not r["metadata_json"] else json.dumps(
             json.loads(r["metadata_json"]), sort_keys=True, separators=(",", ":"), ensure_ascii=False),
         "format": r["format"]}
        for r in _rows(c)
    ]
    head = dict(c.execute("SELECT sequence, event_hash, mac FROM audit_head WHERE id = 1").fetchone())
    c.close()
    verdict = native.verify_chain(rows, head, derive_vault_keys(PASS, salt)[0], True)
    assert verdict is not None and "format" in verdict.lower(), verdict


def test_attack_non_json_metadata_is_a_failed_verification_not_an_exception(tmp_path):
    """R2-B9: a row whose metadata_json is not JSON makes verify_audit_chain() return False with
    last_chain_error set, instead of raising out of the verifier."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE audit_journal SET metadata_json = 'not json' WHERE sequence = 2")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verify_audit_chain() is False
        assert "unreadable metadata_json" in (v.last_chain_error or "")
    finally:
        v.close()


def test_attack_verification_quorum_in_vault_meta_is_under_the_meta_mac(tmp_path, monkeypatch):
    """R2-B4: vault_meta.verification_quorum is one of VAULT_META_BOUND_KEYS, so a file writer lowering
    it to 1 breaks the meta MAC and the next open refuses instead of adopting it."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    stored = int(c.execute("SELECT value FROM vault_meta WHERE key='verification_quorum'").fetchone()[0])
    assert stored >= 2
    c.execute("UPDATE vault_meta SET value = '1' WHERE key='verification_quorum'")
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="meta MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_control_raising_the_quorum_re_signs_the_meta_mac(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    p = _seeded(tmp_path / "v.sqlite")
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=5, pin_quorum=True)
    v.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verification_quorum == 5
    finally:
        v.close()


def test_control_meta_mac_written_before_the_quorum_was_bound_is_re_signed_once(tmp_path, monkeypatch):
    """A vault whose meta MAC predates the bound quorum (the legacy key set) opens; the writable open
    replaces the MAC with one that covers the quorum, after which lowering it is refused."""
    from kibisis.crypto import VAULT_META_BOUND_KEYS_V1, vault_meta_mac
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    p = _seeded(tmp_path / "v.sqlite")
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, read_only=True)
    legacy = vault_meta_mac(v._signing_key, v._meta_mac_fields(), VAULT_META_BOUND_KEYS_V1)
    v.close()
    c = _conn(p)
    c.execute("UPDATE vault_meta SET value = ? WHERE key='meta_mac'", (legacy,))
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, read_only=True)  # accepted as it is
    v.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # re-signed
    v.close()
    c = _conn(p)
    assert c.execute("SELECT value FROM vault_meta WHERE key='meta_mac'").fetchone()[0] != legacy
    c.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('verification_quorum', '1')")
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="meta MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_control_r3ab4_legacy_meta_mac_keeps_a_stored_quorum_at_or_above_the_default(tmp_path, monkeypatch):
    """R3-AB4, tightened by R4-2: under a legacy (V1) meta MAC NO stored quorum is trusted, whatever
    its value (the MAC never covered it, so a person's pinned 3 and a file writer's 3 look the same).
    It is ignored, dropped before the re-sign (the new MAC covers no quorum nobody signed), and the
    next pinning verdict restores it under the full-set MAC."""
    from kibisis.crypto import VAULT_META_BOUND_KEYS_V1, vault_meta_mac
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=3, pin_quorum=True)
    legacy = vault_meta_mac(v._signing_key, v._meta_mac_fields(), VAULT_META_BOUND_KEYS_V1)
    v.close()
    c = _conn(p)
    c.execute("UPDATE vault_meta SET value = ? WHERE key='meta_mac'", (legacy,))
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, read_only=True)
    try:
        assert v.verification_quorum == 2 and v.verification_quorum_stored is None  # the default; nothing trusted
    finally:
        v.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # re-signed over no quorum
    try:
        assert v.verification_quorum == 2 and v.verification_quorum_stored is None
    finally:
        v.close()
    c = _conn(p)
    assert c.execute("SELECT value FROM vault_meta WHERE key='verification_quorum'").fetchone() is None
    assert c.execute("SELECT value FROM vault_meta WHERE key='meta_mac'").fetchone()[0] != legacy
    c.execute("INSERT INTO vault_meta (key, value) VALUES ('verification_quorum', '3')")  # not under the new MAC
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="meta MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    c = _conn(p)
    c.execute("DELETE FROM vault_meta WHERE key='verification_quorum'")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=3, pin_quorum=True)
    try:
        assert v.verification_quorum == 3 and v.verification_quorum_stored == 3  # the person re-pins
    finally:
        v.close()


def test_control_genuine_a5_vault_holds_no_format_2_artefacts_and_still_migrates(tmp_path):
    """The a5 discriminator does not refuse what a5 wrote: the 0.1.0a5 fixture (salt, no key check, no
    integrity format) holds nothing format 2+ writes, so it migrates as before, here without SQLCipher."""
    import shutil
    from pathlib import Path
    fixture = Path(__file__).parent / "fixtures" / "vault-0.1.0a5-fallback.sqlite"
    p = tmp_path / "legacy.db"
    shutil.copyfile(fixture, p)
    v = SQLiteMemoryVault(str(p), passphrase="legacy fixture passphrase (test only)", auto_gate=False)
    try:
        assert v.integrity_upgrade is not None and "entries_resealed" in v.integrity_upgrade
        assert v.verify_audit_chain() is True, v.last_chain_error
    finally:
        v.close()
    # Afterwards it is a keyed format 3 vault: the same reset is now refused.
    c = _conn(p)
    _reset_meta(c)
    c.commit(); c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="keyed .* no key check"):
        SQLiteMemoryVault(str(p), passphrase="legacy fixture passphrase (test only)", auto_gate=False)
