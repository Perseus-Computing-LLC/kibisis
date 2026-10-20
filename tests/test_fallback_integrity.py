"""Integrity of the Python vault when sqlcipher3 does not load (a plain SQLite file with sealed entries),
and the upgrade of vaults written by Kibisis 0.1.0a5 to integrity format 2.

The first three tests reproduce problems found in review on throwaway vaults. In 0.1.0a5:
1. sealed content moved under another entry's name, with that entry's signature removed, was returned;
2. the journal and tombstones kept plain SHA-256 digests, so short values could be read back by hashing
   every candidate;
3. signatures were keyed by one SHA-256 of the passphrase, so a known value let anyone test passphrase
   guesses at hash speed instead of PBKDF2 speed.
"""

import hashlib
import hmac
import json
import re
import shutil
import sqlite3
from pathlib import Path

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault, TombstonedValueError

PASS = "correct horse battery staple 2026"
FIXTURE = Path(__file__).parent / "fixtures" / "vault-0.1.0a5-fallback.sqlite"
FIXTURE_PASS = "legacy fixture passphrase (test only)"  # see tests/fixtures/make_legacy_vault.py


@pytest.fixture(autouse=True)
def _no_passphrase_from_environment(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)


@pytest.fixture
def fallback(monkeypatch):
    """Run as when the sqlcipher3 driver fails to load: the vault file is plain SQLite."""
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)


def _raw(db):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    return con


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _file_bytes(db):
    return b"".join(p.read_bytes() for p in (Path(db), Path(f"{db}-wal")) if p.exists())


# The three problems from review, on throwaway vaults in fallback mode.


def test_sealed_content_moved_to_another_entry_is_refused(tmp_path, fallback):
    db = str(tmp_path / "v.db")
    vault = SQLiteMemoryVault(db, passphrase=PASS)
    vault.put("ops", "door_code", "4417", epistemic_state="verified")
    vault.put("ops", "public_note", "The lobby opens at 0700", epistemic_state="verified")
    vault.close()
    con = _raw(db)
    envelope, signature = con.execute(
        "SELECT encrypted_envelope_json, tenant_sig FROM entities WHERE key = 'door_code'"
    ).fetchone()
    for moved_signature in (None, "", signature):  # signature removed, emptied, or moved along with it
        con.execute(
            "UPDATE entities SET encrypted_envelope_json = ?, tenant_sig = ? WHERE key = 'public_note'",
            (envelope, moved_signature),
        )
        con.commit()
        vault = SQLiteMemoryVault(db, passphrase=PASS)
        try:
            with pytest.raises(PermissionError):
                vault.get("ops", "public_note")
            listed = {e.key: e.content for e in vault.list_entities(category="ops")}
            assert "public_note" not in listed
            assert listed["door_code"] == "4417"  # the entry the content belongs to is untouched
            assert [r.entity.key for r in vault.search("4417", category="ops")] == ["door_code"]
        finally:
            vault.close()
    con.close()


def test_journal_and_tombstones_do_not_reveal_short_values(tmp_path, fallback):
    db = str(tmp_path / "v.db")
    vault = SQLiteMemoryVault(db, passphrase=PASS)
    vault.put("ops", "door_code", "4417", epistemic_state="verified")
    vault.put("ops", "pin", "9031", epistemic_state="verified")
    vault.tombstone("ops", "pin", reason="user asked")
    with pytest.raises(TombstonedValueError):
        vault.put("ops", "pin_again", "9031")  # journaled as a refusal
    vault.close()
    con = _raw(db)
    stored = set()
    for row in con.execute("SELECT value_sha256, metadata_json FROM audit_journal"):
        stored.add(row["value_sha256"])
        stored.update(re.findall(r"[0-9a-f]{12,64}", row["metadata_json"]))
    for row in con.execute("SELECT value_sha256, canonical_sha256 FROM rejected_value_tombstones"):
        stored.update((row["value_sha256"], row["canonical_sha256"]))
    con.close()
    stored.discard("")
    assert stored, "premise: the journal and tombstone hold digests"
    digests = {f"{i:04d}": _sha(f"{i:04d}") for i in range(10_000)}
    revealed = sorted(code for code, d in digests.items() if any(d.startswith(s) for s in stored))
    assert revealed == []
    raw = _file_bytes(db)
    assert _sha("4417").encode() not in raw and _sha("9031").encode() not in raw


def test_signatures_offer_no_shortcut_around_pbkdf2(tmp_path, fallback):
    db = str(tmp_path / "v.db")
    vault = SQLiteMemoryVault(db, passphrase=PASS)
    vault.put("ops", "door_code", "4417", epistemic_state="verified")
    vault.close()
    con = _raw(db)
    scope, category, key, signature = con.execute("SELECT scope, category, key, tenant_sig FROM entities").fetchone()
    salt = bytes(con.execute("SELECT value FROM vault_meta WHERE key = 'kdf_salt'").fetchone()[0])
    con.close()
    # 0.1.0a5 keyed signatures with one SHA-256 of the passphrase: one hash per guess.
    fast_key = hashlib.sha256(f"kibisis-tenant-sig:{PASS}".encode()).digest()
    for message in (
        f"{scope}:{category}:{key}:4417",
        json.dumps(["kibisis-entry", 2, scope, category, key, "4417"], ensure_ascii=False, separators=(",", ":")),
    ):
        assert hmac.new(fast_key, message.encode(), hashlib.sha256).hexdigest() not in signature
    # The signing key comes from PBKDF2 (600,000 iterations) under the vault's salt.
    from kibisis.crypto import AESGCMCryptoEnvelopeProvider, derive_integrity_keys, sign_entry

    assert AESGCMCryptoEnvelopeProvider.ITERATIONS == 600_000
    signing_key, _ = derive_integrity_keys(PASS, salt)
    assert signature == sign_entry(signing_key, scope, category, key, "4417")


def test_a_wrong_passphrase_is_refused_without_sqlcipher(tmp_path, fallback):
    db = str(tmp_path / "v.db")
    SQLiteMemoryVault(db, passphrase=PASS).close()
    with pytest.raises(ValueError):
        SQLiteMemoryVault(db, passphrase="not the right passphrase")


def test_a_crypto_provider_without_associated_data_is_refused_at_open(tmp_path):
    class OldProvider:
        def encrypt(self, plaintext, passphrase):
            raise AssertionError("never called")

        def decrypt(self, envelope, passphrase):
            raise AssertionError("never called")

    db = tmp_path / "v.db"
    with pytest.raises(TypeError, match="aad"):
        SQLiteMemoryVault(str(db), crypto_provider=OldProvider(), passphrase=PASS)
    assert not db.exists()


def test_tombstones_travel_between_vaults_that_share_a_passphrase(tmp_path):
    source = SQLiteMemoryVault(str(tmp_path / "a.db"), passphrase=PASS)
    assert source.integrity_upgrade is None  # a new vault starts at the current format
    source.put("ops", "pin", "9031", epistemic_state="verified")
    assert source.tombstone("ops", "pin") == _sha("9031")  # the return value is unchanged
    snapshot = source.export_snapshot()
    source.close()
    assert snapshot["digest_scheme"] == "hmac-sha256"
    assert _sha("9031") not in json.dumps(snapshot)

    same = SQLiteMemoryVault(str(tmp_path / "b.db"), passphrase=PASS)
    same.import_snapshot(snapshot)
    with pytest.raises(TombstonedValueError):
        same.put("ops", "pin2", "9031")
    same.close()

    other = SQLiteMemoryVault(str(tmp_path / "c.db"), passphrase="a different passphrase 2026")
    other.import_snapshot(snapshot)
    other.put("ops", "pin2", "9031", epistemic_state="verified")  # the tombstone cannot apply here...
    notes = [e.metadata for e in other.list_audit_events(limit=100) if e.action == "refuse"]
    assert notes == [{"path": "import_snapshot", "reason": "tombstones from a vault with another passphrase",
                      "detail": {"tombstones": 1}}]  # ...and the import says so
    other.close()


# Upgrade of a vault written by the released 0.1.0a5 (tests/fixtures/make_legacy_vault.py).

LEGACY = {
    ("default", "ops", "door_code"): "4417",
    ("default", "ops", "public_note"): "The lobby opens at 0700",
    ("team", "contacts", "alice"): "Alice prefers email",
    ("default", "notes", "draft"): "Maybe move the standup to Tuesday",
    ("default", "notes", "old"): "Retired note",
}
UNSIGNED = ("default", "ops", "unsigned_legacy", "Written before signatures existed")
TOMBSTONED = "9031"


def _legacy_copy(tmp_path):
    db = tmp_path / "legacy.db"
    shutil.copyfile(FIXTURE, db)
    return str(db)


def _stored_state(db):
    con = _raw(db)
    try:
        return [
            [tuple(r) for r in con.execute(sql)]
            for sql in (
                "SELECT id, encrypted_envelope_json, tenant_sig FROM entities ORDER BY id",
                "SELECT id, value_sha256, canonical_sha256 FROM rejected_value_tombstones ORDER BY id",
                "SELECT sequence, value_sha256, event_hash, metadata_json FROM audit_journal ORDER BY sequence",
            )
        ]
    finally:
        con.close()


@pytest.mark.parametrize("mode", ["fallback", "sqlcipher"])
def test_upgrade_from_0_1_0a5(tmp_path, monkeypatch, mode):
    if mode == "fallback":
        monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    elif not vault_module._sqlcipher_available():
        pytest.skip("sqlcipher3 is not installed")
    db = _legacy_copy(tmp_path)
    assert _sha(TOMBSTONED).encode() in _file_bytes(db)  # premise: 0.1.0a5 stored the plain digest

    vault = SQLiteMemoryVault(db, passphrase=FIXTURE_PASS)
    try:
        report = vault.integrity_upgrade
        assert report["entries_resealed"] == len(LEGACY)
        # The file had no whole-file encryption before this open, so an entry without a signature
        # cannot be told apart from one whose signature was removed: it waits for a person.
        assert report["entries_left_unsigned"] == 1
        assert report["entries_failed_signature"] == report["entries_undecryptable"] == 0
        assert report["tombstones_rekeyed"] == 1
        assert report["journal_events_rekeyed"] >= 8
        for (scope, category, key), content in LEGACY.items():
            assert vault.get(category, key, scope=scope).content == content
        scope, category, key, content = UNSIGNED
        with pytest.raises(PermissionError):
            vault.get(category, key, scope=scope)
        assert vault.integrity_status()["unsigned"] == 1
        assert vault.adopt_unsigned_entries(author_id="human:reviewer") == 1
        assert vault.get(category, key, scope=scope).content == content
        assert vault.integrity_status() == {
            "integrity_format": 2, "entries": len(LEGACY) + 1, "unsigned": 0, "legacy_signature": 0, "unbound": 0,
        }
        events = vault.list_audit_events(limit=1000)
        assert [e.action for e in events][-2:] == ["migrate", "adopt"]
        assert events[-2].metadata["previous_chain_valid"] is True
        assert vault.verify_audit_chain()
        for value in (TOMBSTONED, f" {TOMBSTONED}."):  # exact, and a look-alike with the same canonical form
            with pytest.raises(TombstonedValueError):
                vault.put("secrets", "pin_new", value)
    finally:
        vault.close()

    if mode == "fallback":  # the file is still plain SQLite: no old digest, or prefix of one, is left in it
        raw = _file_bytes(db)
        for value in [*LEGACY.values(), UNSIGNED[3], TOMBSTONED]:
            assert _sha(value).encode() not in raw, value
        assert _sha(TOMBSTONED)[:12].encode() not in raw

    again = SQLiteMemoryVault(db, passphrase=FIXTURE_PASS)
    assert again.integrity_upgrade is None
    again.close()
    with pytest.raises(ValueError):
        SQLiteMemoryVault(db, passphrase="not the fixture passphrase")


def test_an_upgrade_under_a_wrong_passphrase_changes_no_data(tmp_path, fallback):
    db = _legacy_copy(tmp_path)
    before = _stored_state(db)
    with pytest.raises(ValueError):
        SQLiteMemoryVault(db, passphrase="not the fixture passphrase")
    assert _stored_state(db) == before
    vault = SQLiteMemoryVault(db, passphrase=FIXTURE_PASS)
    try:
        assert vault.integrity_upgrade["entries_resealed"] == len(LEGACY)
    finally:
        vault.close()


def test_a_tampered_entry_is_left_refused_by_the_upgrade(tmp_path, fallback):
    db = _legacy_copy(tmp_path)
    con = _raw(db)
    envelope = con.execute("SELECT encrypted_envelope_json FROM entities WHERE key = 'door_code'").fetchone()[0]
    con.execute("UPDATE entities SET encrypted_envelope_json = ? WHERE key = 'public_note'", (envelope,))
    con.commit()
    con.close()
    vault = SQLiteMemoryVault(db, passphrase=FIXTURE_PASS)
    try:
        assert vault.integrity_upgrade["entries_failed_signature"] == 1
        with pytest.raises(PermissionError):
            vault.get("ops", "public_note")
        assert vault.adopt_unsigned_entries() == 1  # only the unsigned entry; never the tampered one
        with pytest.raises(PermissionError):
            vault.get("ops", "public_note")
        assert vault.get("ops", "door_code").content == "4417"
    finally:
        vault.close()
