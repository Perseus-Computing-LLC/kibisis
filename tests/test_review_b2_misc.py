"""Review B (part 2): remaining checklist probes — signature-failure handling, allow_plaintext
fallback, SQLCipher conversion under a wrong passphrase, lease-file deletion.

``test_control_*`` assert the SECURE behaviour (failing = bug); ``test_attack_*`` DEMONSTRATE an
insecure behaviour (passing = bug).
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

def test_attack_bad_signature_row_vanishes_silently_from_search_and_list(no_sqlcipher, tmp_path, caplog):
    """DEMONSTRATES (passing = bug, medium): a file writer who overwrites one row's tenant_sig (no
    passphrase needed) makes that entry disappear from search(), list_entities() and the snapshot
    export with no exception and no log line; only get() raises EntryIntegrityError
    (_vault_crypto.py:217-225 returns None, _vault_search.py:194-196 and vault.py:1644-1646 `continue`).
    """
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("UPDATE entities SET tenant_sig = substr(tenant_sig, 1, length(tenant_sig) - 1) || "
              "CASE substr(tenant_sig, -1) WHEN 'x' THEN 'y' ELSE 'x' END WHERE key = 'b'")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    with caplog.at_level(logging.DEBUG, logger="kibisis"):
        with pytest.raises(EntryIntegrityError):
            v.get("decision", "b")
        hits = v.search("widgets", include_unverified=True, limit=10)
        listed = v.list_entities(include_unverified=True)
        snap = v.export_snapshot() if hasattr(v, "export_snapshot") else None
    v.close()
    keys = sorted(r.entity.key for r in hits)
    listed_keys = sorted(e.key for e in listed)
    print("search ->", keys, "| list ->", listed_keys, "| snapshot unreadable ->",
          None if snap is None else snap.get("unreadable_entity_count"))
    print("log records mentioning integrity:", [r.getMessage() for r in caplog.records if "ntegrity" in r.getMessage()])
    assert keys == ["a"] and listed_keys == ["a"]  # <-- silently gone
    assert not any("ntegrity" in r.getMessage() for r in caplog.records)  # <-- nothing logged


# ---------------------------------------------------------------- checklist 2: allow_plaintext reachability

def test_attack_passphrase_without_sqlcipher_opens_plain_sqlite_with_only_a_log_warning(no_sqlcipher, tmp_path, caplog):
    """DEMONSTRATES (passing = observation, medium): with a passphrase but no sqlcipher3, the vault opens
    and writes a plain SQLite file (vault.py:305-310 logs a warning, raises nothing; allow_plaintext is
    never consulted on this path). Everything but entry content is readable with the stock sqlite3
    module: categories, keys, scopes, metadata JSON, timestamps, epistemic state, origin, the whole
    audit journal, tombstone digests, vault_meta and the HMAC term tokens."""
    with caplog.at_level(logging.WARNING, logger="kibisis"):
        p = _seeded(tmp_path / "v.sqlite")
    with open(p, "rb") as f:
        assert f.read(16).startswith(b"SQLite format 3")
    c = _conn(p)
    tables = sorted(r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'"))
    ent = c.execute("SELECT category, key, scope, metadata_json, origin, epistemic_state, created_at, "
                    "is_encrypted, content FROM entities WHERE key='a'").fetchone()
    journal = c.execute("SELECT action, category, key, scope, author_id FROM audit_journal").fetchall()
    terms = c.execute("SELECT count(*) FROM entities_terms").fetchone()[0] if "entities_terms" in tables else None
    c.close()
    print("tables:", tables)
    print("entity row (plain columns):", dict(ent))
    print("journal rows:", [tuple(r) for r in journal])
    print("term tokens:", terms, "| warnings:", [r.getMessage()[:60] for r in caplog.records])
    assert ent["is_encrypted"] == 1 and not ent["content"]  # content is sealed ...
    assert ent["category"] == "decision" and ent["key"] == "a"  # ... but everything else is plain
    assert len(journal) >= 2 and all(r["key"] in ("a", "b") for r in journal)
    assert any("not encrypted as a whole file" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------- checklist 2/crypto: wrong passphrase + SQLCipher

def test_attack_wrong_passphrase_with_sqlcipher_reencrypts_plain_vault_and_bricks_it(tmp_path, monkeypatch):
    """DEMONSTRATES (passing = bug, high): a vault file written without sqlcipher3 (plain SQLite, sealed
    content) is later opened on a host that has sqlcipher3 — with the WRONG passphrase. vault.py:311-323
    converts the whole file to SQLCipher under that wrong passphrase BEFORE the key_check runs
    (_vault_crypto.py:284), the open then raises 'Failed to authenticate', and the right passphrase can
    no longer open the file either. No attacker needed: one typo bricks the vault."""
    import sqlcipher3  # noqa: F401  (the real driver must be importable for this test)
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    # 1. create as a plain SQLite file (deployment without sqlcipher3)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    p = _seeded(tmp_path / "v.sqlite")
    monkeypatch.undo()
    assert vault_module._sqlcipher_available() is True
    with open(p, "rb") as f:
        assert f.read(16).startswith(b"SQLite format 3")
    # 2. open with sqlcipher3 present and a wrong passphrase
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase=WRONG, auto_gate=False)
    with open(p, "rb") as f:
        hdr = f.read(16)
    print("header after wrong-passphrase open:", hdr)
    assert not hdr.startswith(b"SQLite format 3")  # <-- file was re-encrypted under the wrong passphrase
    # 3. the right passphrase is now refused too
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)


# ---------------------------------------------------------------- checklist 7: lease state-file deletion

def test_attack_deleting_lease_state_file_resets_fencing_token(tmp_path):
    """DEMONSTRATES (passing = documented weakness, low; precondition: write access to the lease directory,
    which is 0o700 owner-only): file_lease.rs:171-183 treats a missing state file as 'never leased' and
    hands out fencing token 1 again, so a stale holder's old token 1 validates against the new lease.
    file_lease.rs:34-39 discloses this ('Deleting a state file resets that resource's token to 1'), but
    README.md:23 ('fencing tokens that only go up') and lib.rs:10-12 do not carry the caveat."""
    import hashlib
    import kibisis_native as native
    d = tmp_path / "leases"
    coord = native.FileLeaseCoordinator(str(d))
    first = coord.acquire("doc", "A", 60.0)
    assert first.fencing_token == 1
    assert coord.release(first) is True
    second = coord.acquire("doc", "B", 60.0)
    assert second.fencing_token == 2
    (d / (hashlib.sha256(b"doc").hexdigest() + ".lease")).unlink()
    third = coord.acquire("doc", "C", 60.0)
    print("tokens:", first.fencing_token, second.fencing_token, third.fencing_token)
    assert third.fencing_token == 1  # <-- reused
    assert coord.validate_fencing_token("doc", "C", 1) is True
