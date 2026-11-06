"""Review 3, area A+B seams: format-1 migration discriminator (R2-B1, R3-AB2), plain-file auth (R2-B2),
salt removal (R2-B5), meta MAC re-sign paths (R2-B4, R3-AB4).

Convention: ``test_control_*`` = secure behaviour; ``test_attack_*`` = the round-3 defect scenario,
asserting the FIXED behaviour (R3-AB4 is fixed on fix/round3-entry and skipped here until the merge).
Vaults opened WITHOUT SQLCipher, with a passphrase (allow_plaintext) = SECURITY.md's file-writer model.
"""

import shutil
import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis.crypto import VAULT_META_BOUND_KEYS_V1, vault_meta_mac
from kibisis.vault import _event_hash

PASS = "review3-ab passphrase (test only)"
FIXTURE_A5 = "tests/fixtures/vault-0.1.0a5-fallback.sqlite"
FIXTURE_A5_PASS = "legacy fixture passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _seeded(path):
    v = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    for i in range(3):
        v.remember("decision", f"k{i}", f"fact number {i}", origin="user", author_id=f"author{i}")
    v.remember("decision", "bad", "deploy on fridays", origin="user", author_id="alice")
    v.tombstone("decision", "bad", reason="wrong", author_id="alice", scope="default", origin="user")
    assert v.verify_audit_chain() is True
    v.close()
    return path


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


def _legacy_rechain(conn, fmt=1):
    prev = "0" * 64
    for r in conn.execute("SELECT * FROM audit_journal ORDER BY sequence").fetchall():
        h = _event_hash(r["sequence"], r["timestamp"], r["action"], r["category"], r["key"], r["scope"],
                        r["value_sha256"], prev, r["author_id"], None, fmt=fmt)
        conn.execute("UPDATE audit_journal SET prev_hash = ?, event_hash = ?, format = ? WHERE sequence = ?",
                     (prev, h, fmt, r["sequence"]))
        prev = h
    conn.execute("DELETE FROM audit_head")


def _scrub_everything_but_entries(c):
    """R2-B1's full reset: every format 2+ artefact the discriminator lists, except the sealed entries."""
    c.execute("DELETE FROM rejected_value_tombstones")
    c.execute("DELETE FROM audit_journal WHERE action IN ('tombstone', 'tombstone_reaffirmed')")
    c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac', 'integrity_format', "
              "'journal_format_floor', 'journal_anchored')")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    _legacy_rechain(c)


# --- R2-B1: the a5 discriminator -------------------------------------------------------------------


def test_control_r2b1_full_reset_with_sealed_entries_is_refused(tmp_path):
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    _scrub_everything_but_entries(c)
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="sealed with its binding"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_r2b1_discriminator_is_defeated_by_flipping_is_encrypted_to_0(tmp_path):
    """R3-AB2 fixed. The 'entry sealed with its binding' witness used to be queried as ``is_encrypted =
    1 AND envelope LIKE binding``; a file writer flipped ``is_encrypted`` to 0 (envelope untouched) and
    the file passed for a5. The witness now reads the envelope alone: the open is refused and nothing
    is written (no head, no key check, no meta MAC, tombstone-free journal not re-signed)."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    _scrub_everything_but_entries(c)
    c.execute("UPDATE entities SET is_encrypted = 0")
    c.commit()
    c.close()
    before = p.read_bytes()
    with pytest.raises(vault_module.VaultIntegrityError, match="sealed with its binding"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    assert p.read_bytes() == before
    c = _conn(p)
    assert c.execute("SELECT count(*) FROM audit_head").fetchone()[0] == 0
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key IN ('key_check','meta_mac')").fetchone()[0] == 0
    c.close()


def test_control_r3ab2_plaintext_row_with_an_envelope_is_refused_by_the_migration(tmp_path):
    """A row marked plaintext that carries an envelope is refused (here the binding is scrubbed from
    the envelope text too, so the plaintext mark and the envelope that does not open are what the
    discriminator names)."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    _scrub_everything_but_entries(c)
    c.execute("UPDATE entities SET is_encrypted = 0, encrypted_envelope_json = "
              "replace(encrypted_envelope_json, 'binding', 'bndng')")
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="marked plaintext"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_attack_r2b1_discriminator_is_defeated_by_deleting_every_entry(tmp_path):
    """R3-AB2 fixed. Same reset plus ``DELETE FROM entities``: no entry witness is left, but the
    journal of a keyed vault records entries that were put and never purged while the table is empty,
    which no genuine a5 file looks like: refused, nothing re-signed."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    _scrub_everything_but_entries(c)
    c.execute("DELETE FROM entities")
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="entity table that is empty"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    c = _conn(p)
    assert c.execute("SELECT count(*) FROM audit_head").fetchone()[0] == 0
    assert c.execute("SELECT count(*) FROM audit_journal WHERE action = 'migrate'").fetchone()[0] == 0
    c.close()


def test_control_r3ab2_keyed_format1_chain_is_not_accepted_under_the_path_key(tmp_path, monkeypatch):
    """A vault with a salt had its format-1 head signed under the passphrase's legacy key; a head that
    verifies only under the path-derived key (one a file writer computes) is refused by the migration
    itself. The head is a witness the a5 discriminator already refuses, so the discriminator is
    stubbed out here to exercise the migration's own check (defence in depth)."""
    monkeypatch.setattr(vault_module.SQLiteMemoryVault, "_refuse_unless_genuine_a5", lambda self, passphrase: None)
    import hashlib

    from kibisis._vault_audit import _head_mac

    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k", "fact", origin="user", author_id="alice")
    v.close()
    c = _conn(p)
    c.execute("DELETE FROM vault_meta WHERE key IN ('key_check', 'meta_mac', 'integrity_format', "
              "'journal_format_floor', 'journal_anchored')")
    c.execute("UPDATE entities SET tenant_sig = NULL")
    _legacy_rechain(c)
    last = c.execute("SELECT sequence, event_hash FROM audit_journal ORDER BY sequence DESC LIMIT 1").fetchone()
    path_key = hashlib.sha256(f"kibisis-tenant-sig:{p}".encode("utf-8")).digest()
    mac = _head_mac(path_key, int(last["sequence"]), last["event_hash"])
    c.execute("INSERT INTO audit_head (id, sequence, event_hash, mac) VALUES (1, ?, ?, ?)",
              (last["sequence"], last["event_hash"], mac))
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="audit journal does not verify"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


# --- R2-B2: plain file authenticated before conversion ----------------------------------------------


def test_control_r2b2_a5_fixture_wrong_passphrase_leaves_plain_file_untouched(tmp_path, monkeypatch):
    src = FIXTURE_A5
    dst = tmp_path / "a5.sqlite"
    shutil.copy(src, dst)
    before = dst.read_bytes()
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: True)
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(dst), passphrase="not the passphrase", auto_gate=False)
    assert dst.read_bytes() == before
    assert not (tmp_path / "a5.sqlite.tmp_enc").exists()


# --- R2-B4: meta MAC re-sign path ------------------------------------------------------------------


def _bound(c):
    return {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM vault_meta").fetchall()}


def test_attack_r2b4_legacy_v1_meta_mac_re_signs_an_attacker_quorum(tmp_path, caplog):
    """R3-AB4 fixed. A meta MAC over the legacy key set (``VAULT_META_BOUND_KEYS_V1``) never covered
    ``verification_quorum``, so a pre-R2-B4 copy of a file's ``meta_mac`` (a backup; the signing key
    stands in for it here) plus ``verification_quorum = 1`` used to be adopted and re-signed under the
    full set. Now the stored quorum is not trusted while only the V1 MAC verifies: a value below the
    default is ignored (the process runs with the default 2), dropped before the re-sign, and logged
    at WARNING; the next open sees a full-set MAC over a file with no stored quorum. The vault was
    created with quorum 2 pinned."""
    import logging

    from kibisis.crypto import VAULT_META_BOUND_KEYS

    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=2, pin_quorum=True)
    v.remember("decision", "d", "ship it", origin="user", author_id="alice", epistemic_state="verified")
    assert v.get("decision", "d").epistemic_state == "candidate"  # 1 of 2
    # The MAC such a file carried before R2-B4 (the signing key only stands in for the backup copy).
    v1_mac = vault_meta_mac(v._signing_key, v._meta_mac_fields(), VAULT_META_BOUND_KEYS_V1)
    signing_key = v._signing_key
    v.close()
    c = _conn(p)
    assert c.execute("SELECT value FROM vault_meta WHERE key='verification_quorum'").fetchone()[0] == "2"
    c.execute("UPDATE vault_meta SET value = ? WHERE key = 'meta_mac'", (v1_mac,))
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'verification_quorum'")
    c.commit()
    c.close()
    with caplog.at_level(logging.WARNING, logger="kibisis"):
        v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # names no quorum
    assert any("predates the bound verification quorum" in r.getMessage() and r.levelno == logging.WARNING
               for r in caplog.records), [r.getMessage() for r in caplog.records]
    assert any("not covered by the meta MAC" in r.getMessage() and " 1 " in r.getMessage()
               and r.levelno == logging.WARNING for r in caplog.records)  # the dropped value is named
    try:
        assert v.verification_quorum == 2 and v.verification_quorum_stored is None  # the forged 1 was ignored
        v.remember("decision", "e", "single attestation does not mint verified", origin="user", author_id="bob",
                   epistemic_state="verified")
        assert v.get("decision", "e").epistemic_state == "candidate"
    finally:
        v.close()
    c = _conn(p)
    fields = _bound(c)
    c.close()
    # The forged quorum is gone, and the re-signed MAC is a full-set MAC over the file as it now stands.
    assert "verification_quorum" not in fields
    assert fields["meta_mac"] == vault_meta_mac(signing_key, {k: fields.get(k) for k in VAULT_META_BOUND_KEYS})
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verification_quorum == 2 and v.verification_quorum_stored is None
    finally:
        v.close()
    # Restoring the forged row under the new MAC is an integrity failure, as for any bound value.
    c = _conn(p)
    c.execute("INSERT INTO vault_meta (key, value) VALUES ('verification_quorum', '1')")
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="meta MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


def test_control_r2b4_quorum_edit_under_a_full_set_mac_is_refused(tmp_path):
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=2, pin_quorum=True)  # R3-E1: a plain open no longer stores it
    v.close()
    c = _conn(p)
    c.execute("UPDATE vault_meta SET value = '1' WHERE key = 'verification_quorum'")
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError, match="meta MAC"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


# --- R2-B5: salt removal -----------------------------------------------------------------------------


@pytest.mark.parametrize("read_only", [False, True])
def test_control_r2b5_salt_removed_is_refused_and_no_salt_written(tmp_path, read_only):
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM vault_meta WHERE key = 'kdf_salt'")
    c.commit()
    c.close()
    with pytest.raises(vault_module.VaultIntegrityError):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, read_only=read_only)
    c = _conn(p)
    assert c.execute("SELECT count(*) FROM vault_meta WHERE key='kdf_salt'").fetchone()[0] == 0
    c.close()


# --- regressions: the legacy fixture, read-only and writable, idempotent ------------------------------


def test_control_a5_fixture_opens_read_only_before_and_after_migration(tmp_path):
    dst = tmp_path / "a5.sqlite"
    shutil.copy(FIXTURE_A5, dst)
    before = dst.read_bytes()
    # By design a legacy file is refused read-only until a writable open upgrades it; and nothing is written.
    with pytest.raises(ValueError, match="needs an integrity upgrade"):
        SQLiteMemoryVault(str(dst), passphrase=FIXTURE_A5_PASS, auto_gate=False, read_only=True)
    assert dst.read_bytes() == before
    first = SQLiteMemoryVault(str(dst), passphrase=FIXTURE_A5_PASS, auto_gate=False)
    n_entities = len(first.list_entities())
    upgrade = first.integrity_upgrade
    assert first.verify_audit_chain() is True
    first.close()
    second = SQLiteMemoryVault(str(dst), passphrase=FIXTURE_A5_PASS, auto_gate=False)
    assert second.integrity_upgrade is None  # idempotent
    assert len(second.list_entities()) == n_entities
    assert second.verify_audit_chain() is True
    second.close()
    ro = SQLiteMemoryVault(str(dst), passphrase=FIXTURE_A5_PASS, auto_gate=False, read_only=True)
    assert len(ro.list_entities()) == n_entities
    ro.close()
    assert upgrade is not None and upgrade.get("entries_resealed", 0) >= 1


def test_control_in_memory_vault_with_passphrase_round_trips_tombstones():
    v = SQLiteMemoryVault(":memory:", passphrase=PASS, auto_gate=False)
    v.remember("decision", "k", "deploy on fridays", origin="model")
    v.tombstone("decision", "k", reason="no", author_id="alice", origin="user")
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "k2", "Deploy on Fridays!", origin="model")
    assert v.verify_audit_chain() is True
    v.close()
