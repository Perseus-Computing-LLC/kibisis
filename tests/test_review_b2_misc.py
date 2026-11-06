"""Review B (part 2): remaining checklist probes — signature-failure handling, allow_plaintext
fallback, SQLCipher conversion under a wrong passphrase, lease-file deletion.

``test_attack_*`` replay the review's probes and assert the fixed behaviour (F14 drops are logged,
counted and raisable; F15 plaintext fallback is opt-in; F13 a wrong passphrase never converts the
file; L7 fencing tokens only go up).
"""

import logging
import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import EntryIntegrityError, SQLiteMemoryVault

PASS = "review-b2 passphrase (test only)"
WRONG = "review-b2 wrong passphrase (test only)"


@pytest.fixture
def no_sqlcipher(monkeypatch):
    """Open vaults as plain SQLite files (as a deployment without sqlcipher3 does)."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _seeded(path):
    v = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    v.remember("decision", "a", "alpha fact about widgets", origin="user")
    v.remember("decision", "b", "beta fact about widgets", origin="user")
    v.close()
    return path


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


# ---------------------------------------------------------------- checklist 3: signature failures

def test_attack_bad_signature_row_is_dropped_loudly_from_search_and_list(no_sqlcipher, tmp_path, caplog):
    """F14: a row whose tenant_sig was overwritten is left out of search(), list_entities() and the
    snapshot export, but never silently: each drop is logged at WARNING with category and key, counted
    in vault.integrity_failures, and under strict=True it raises instead."""
    def tampered(name):
        p = _seeded(tmp_path / name)
        c = _conn(p)
        c.execute("UPDATE entities SET tenant_sig = substr(tenant_sig, 1, length(tenant_sig) - 1) || "
                  "CASE substr(tenant_sig, -1) WHEN 'x' THEN 'y' ELSE 'x' END WHERE key = 'b'")
        c.commit(); c.close()
        return p

    p = tampered("v.sqlite")
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    # The open builds the term index and meets the row there: dropped from the index with a WARNING.
    assert v.integrity_failures["count"] == 1
    with caplog.at_level(logging.WARNING, logger="kibisis"):
        with pytest.raises(EntryIntegrityError):
            v.get("decision", "b")
        hits = v.search("widgets", include_unverified=True, limit=10)
        listed = v.list_entities(include_unverified=True)
        snap = v.export_snapshot()
    failures = dict(v.integrity_failures)
    v.close()
    assert sorted(r.entity.key for r in hits) == ["a"]
    assert sorted(e.key for e in listed) == ["a"]
    assert snap["unreadable_entity_count"] == 1
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING and "decision:b" in r.getMessage()]
    assert len(warnings) >= 2, [r.getMessage() for r in caplog.records]  # list and export each said so
    assert failures["count"] >= 3  # index build, list, export
    assert ("decision", "b") in failures["recent"]
    assert len(failures["recent"]) <= 10

    # strict=True: the open never raises for an entry (R2-B7); the bad row met while the term index is
    # built is counted and left queued, and the first read through the index raises for it ...
    strict = SQLiteMemoryVault(str(tampered("w.sqlite")), passphrase=PASS, auto_gate=False, strict=True)
    assert strict.integrity_failures["count"] == 1
    with pytest.raises(EntryIntegrityError):
        strict.search("widgets", include_unverified=True, limit=10)
    strict.close()
    # ... and on the already indexed file, in list and export.
    strict = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, strict=True)
    with pytest.raises(EntryIntegrityError):
        strict.list_entities(include_unverified=True)
    with pytest.raises(EntryIntegrityError):
        strict.export_snapshot()
    strict.close()


# ---------------------------------------------------------------- checklist 2: allow_plaintext reachability

def test_attack_passphrase_without_sqlcipher_is_refused_unless_opted_in(tmp_path, monkeypatch, caplog):
    """F15: with a passphrase but no sqlcipher3 an on-disk vault is refused (EncryptionRequiredError
    naming what would lie in plain text) unless allow_plaintext=True or KIBISIS_ALLOW_PLAINTEXT=1; the
    opted-in file is plain SQLite with sealed content, encrypted_at_rest says so, and an in-memory vault
    is unaffected."""
    from kibisis import EncryptionRequiredError

    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    p = tmp_path / "v.sqlite"
    with pytest.raises(EncryptionRequiredError) as refused:
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    assert "plain text" in str(refused.exception if hasattr(refused, "exception") else refused.value)
    assert "audit journal" in str(refused.value)
    assert not p.exists() or p.stat().st_size == 0

    mem = SQLiteMemoryVault(":memory:", passphrase=PASS, auto_gate=False)
    mem.remember("decision", "m", "in memory", origin="user")
    mem.close()

    with caplog.at_level(logging.WARNING, logger="kibisis"):
        v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, allow_plaintext=True)
    assert v.encrypted_at_rest is False
    v.remember("decision", "a", "alpha fact about widgets", origin="user")
    v.close()
    assert any("not encrypted as a whole file" in r.getMessage() for r in caplog.records)
    with open(p, "rb") as f:
        assert f.read(16).startswith(b"SQLite format 3")
    c = _conn(p)
    ent = c.execute("SELECT category, key, is_encrypted, content FROM entities WHERE key='a'").fetchone()
    c.close()
    assert ent["is_encrypted"] == 1 and not ent["content"]  # content is sealed; the rest is plain, by choice

    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    again = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    assert again.get("decision", "a").content == "alpha fact about widgets"
    again.close()


# ---------------------------------------------------------------- checklist 2/crypto: wrong passphrase + SQLCipher

def test_attack_wrong_passphrase_with_sqlcipher_leaves_plain_vault_untouched(tmp_path, monkeypatch):
    """F13: a vault file written without sqlcipher3 (plain SQLite, sealed content) opened on a host with
    sqlcipher3 under the WRONG passphrase: the key check is compared against the plain file first,
    'Failed to authenticate' is raised, the file is byte for byte as it was, and the right passphrase
    then opens it and converts it."""
    import sqlcipher3  # noqa: F401  (the real driver must be importable for this test)
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    p = _seeded(tmp_path / "v.sqlite")
    monkeypatch.undo()
    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT", raising=False)
    assert vault_module._sqlcipher_available() is True
    before = p.read_bytes()
    assert before.startswith(b"SQLite format 3")
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase=WRONG, auto_gate=False)
    assert p.read_bytes() == before  # untouched
    assert not list(tmp_path.glob("*.tmp*")), "no conversion temp file left behind"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    assert v.encrypted_at_rest is True
    assert v.get("decision", "a").content == "alpha fact about widgets"
    v.close()
    assert not p.read_bytes().startswith(b"SQLite format 3")  # converted under the right passphrase
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase=WRONG, auto_gate=False)


# ---------------------------------------------------------------- checklist 7: lease state-file deletion

def test_attack_deleting_lease_state_file_does_not_reset_fencing_token(tmp_path):
    """L7: a per-resource highest-token file, written before the lease that carries the token, keeps
    fencing tokens going up even when the state file is deleted or an older copy is put back; a stale
    holder's old token never validates again."""
    import hashlib
    import kibisis_native as native
    d = tmp_path / "leases"
    coord = native.FileLeaseCoordinator(str(d))
    first = coord.acquire("doc", "A", 60.0)
    assert first.fencing_token == 1
    assert coord.release(first) is True
    second = coord.acquire("doc", "B", 60.0)
    assert second.fencing_token == 2
    assert coord.release(second) is True
    state = d / (hashlib.sha256(b"doc").hexdigest() + ".lease")
    highest = d / (hashlib.sha256(b"doc").hexdigest() + ".highest")
    assert highest.read_text().strip() == "2"
    stale = state.read_bytes()
    state.unlink()
    third = coord.acquire("doc", "C", 60.0)
    assert third.fencing_token == 3
    assert coord.validate_fencing_token("doc", "A", 1) is False
    assert coord.release(third) is True
    state.write_bytes(stale)  # an older copy of the state file comes back
    fourth = coord.acquire("doc", "D", 60.0)
    assert fourth.fencing_token == 4
    assert highest.read_text().strip() == "4"
