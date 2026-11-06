"""Review B: entry cryptography against a local file writer (no SQLCipher, passphrase set).

``test_control_*`` assert behaviour that was already secure; ``test_attack_*`` replay the review's attacks
and assert they are now refused (L5 foreign envelope salts, L4 missing key check).
"""

import base64
import json
import sqlite3
import time

import pytest

import kibisis.vault as vault_module
from kibisis import EntryIntegrityError, SQLiteMemoryVault
from kibisis.crypto import AESGCMCryptoEnvelopeProvider, derive_vault_keys

PASS = "review-b crypto passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")  # the file writer's position: a plain SQLite file


def _seeded(path):
    v = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    v.remember("decision", "a", "value of A", origin="user")
    v.remember("decision", "b", "value of B", origin="user")
    v.remember("other", "a", "value of A in other category", origin="user")
    v.close()
    return path


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


def test_control_ciphertext_swap_between_rows_is_caught(tmp_path):
    """Asserts secure behaviour: moving row b's envelope (and signature) onto row a fails the AAD check."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    b = c.execute("SELECT encrypted_envelope_json, tenant_sig FROM entities WHERE key='b'").fetchone()
    c.execute("UPDATE entities SET encrypted_envelope_json=?, tenant_sig=? WHERE key='a' AND category='decision'",
              (b[0], b[1]))
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    with pytest.raises(EntryIntegrityError):
        v.get("decision", "a")
    v.close()


def test_control_same_key_other_category_swap_is_caught(tmp_path):
    """Asserts secure behaviour: AAD binds category too (entry_aad = [tag, 2, scope, category, key])."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    o = c.execute("SELECT encrypted_envelope_json, tenant_sig FROM entities WHERE category='other'").fetchone()
    c.execute("UPDATE entities SET encrypted_envelope_json=?, tenant_sig=? WHERE key='a' AND category='decision'",
              (o[0], o[1]))
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    with pytest.raises(EntryIntegrityError):
        v.get("decision", "a")
    v.close()


def test_control_nonce_fresh_per_encrypt_and_salt_per_vault(tmp_path):
    """Asserts secure behaviour: nonces are 96-bit random and distinct per seal; the envelope salt equals the
    vault's single kdf_salt (one PBKDF2 per vault, not per entry)."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    envs = [json.loads(r[0]) for r in c.execute("SELECT encrypted_envelope_json FROM entities")]
    salt = c.execute("SELECT value FROM vault_meta WHERE key='kdf_salt'").fetchone()[0]
    c.close()
    nonces = [e["nonce_b64"] for e in envs]
    assert len(set(nonces)) == len(nonces) == 3
    assert all(len(base64.b64decode(n)) == 12 for n in nonces)
    assert all(base64.b64decode(e["salt_b64"]) == bytes(salt) for e in envs)
    assert len(bytes(salt)) == 16
    # re-sealing the same content yields a new nonce
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "a", "value of A", origin="user")
    v.close()
    c = _conn(p)
    n2 = json.loads(c.execute("SELECT encrypted_envelope_json FROM entities WHERE key='a' AND category='decision'")
                    .fetchone()[0])["nonce_b64"]
    c.close()
    assert n2 not in nonces


def test_control_key_separation_labels():
    """Asserts secure behaviour: signing, digest and term keys differ (distinct HKDF info labels)."""
    s, d, t = derive_vault_keys("x" * 16, b"\x01" * 16)
    assert len({s, d, t}) == 3 and all(len(k) == 32 for k in (s, d, t))
    # and the content key (PBKDF2 under the bare salt) is not any of them
    ck = AESGCMCryptoEnvelopeProvider(salt=b"\x01" * 16).stretched_key("x" * 16, b"\x01" * 16)
    assert ck not in (s, d, t)


def test_attack_per_row_salt_is_refused_before_any_key_derivation(tmp_path):
    """L5: the envelope's salt and iteration count no longer choose the key or the cost of a read. A
    provider bound to the vault salt refuses an envelope naming another salt before any PBKDF2 runs
    (an integrity failure for the row, counted and logged), and a forged iteration count is ignored."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    env = json.loads(c.execute("SELECT encrypted_envelope_json FROM entities WHERE key='b'").fetchone()[0])
    env["salt_b64"] = base64.b64encode(b"\xaa" * 16).decode()
    env["iterations"] = AESGCMCryptoEnvelopeProvider.MAX_ITERATIONS
    c.execute("UPDATE entities SET encrypted_envelope_json=? WHERE key='b'", (json.dumps(env),))
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.get("decision", "a")
    t0 = time.perf_counter(); v.get("decision", "a"); t_good = time.perf_counter() - t0  # warm
    # The open's index drain already met the row: dropped from the index with a WARNING and counted.
    assert v.integrity_failures["count"] >= 1
    assert ("decision", "b") in v.integrity_failures["recent"]
    v.crypto_provider._cache.clear()
    t0 = time.perf_counter()
    with pytest.raises(EntryIntegrityError):  # a direct read raises; it is never silent
        v.get("decision", "b")
    t_bad = time.perf_counter() - t0
    # No PBKDF2 ran for the forged salt: the refusal costs about what a good read costs, not 600k rounds.
    assert t_bad < max(50 * t_good, 0.05), (t_good, t_bad)
    assert not any(b"\xaa" * 16 in k for k in v.crypto_provider._cache)  # the forged salt never reached the KDF
    # An iteration count edited on an envelope that keeps the vault salt is ignored, not honoured.
    c = _conn(p)
    env = json.loads(c.execute("SELECT encrypted_envelope_json FROM entities WHERE key='a'").fetchone()[0])
    env["iterations"] = 1
    c.execute("UPDATE entities SET encrypted_envelope_json=? WHERE key='a'", (json.dumps(env),))
    c.commit(); c.close()
    assert v.get("decision", "a").content == "value of A"
    v.close()


def test_control_wrong_passphrase_refused_by_key_check(tmp_path):
    """Asserts secure behaviour: a wrong passphrase is refused at open via vault_meta.key_check."""
    p = _seeded(tmp_path / "v.sqlite")
    with pytest.raises(ValueError, match="Failed to authenticate"):
        SQLiteMemoryVault(str(p), passphrase="definitely the wrong passphrase", auto_gate=False)


def test_attack_key_check_deletion_refuses_every_passphrase(tmp_path):
    """L4: a keyed vault (integrity_format >= 2, kdf_salt present) whose vault_meta.key_check was removed
    is refused at open, under the wrong passphrase and under the right one alike, so a wrong key can
    neither read the vault as 'empty' nor write rows under a second key set into the same file."""
    p = _seeded(tmp_path / "v.sqlite")
    c = _conn(p)
    c.execute("DELETE FROM vault_meta WHERE key='key_check'")
    c.commit(); c.close()
    for passphrase in ("definitely the wrong passphrase", PASS):
        with pytest.raises(vault_module.VaultIntegrityError, match="no key check"):
            SQLiteMemoryVault(str(p), passphrase=passphrase, auto_gate=False)
    c = _conn(p)
    assert c.execute("SELECT count(*) FROM entities WHERE key='c'").fetchone()[0] == 0  # nothing was written
    c.close()
