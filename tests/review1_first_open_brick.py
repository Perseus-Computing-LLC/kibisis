"""severity: high
finding: a kill during the first open of a new keyed vault, after the kdf_salt commit and before the format 3 integrity records commit (the whole 600,000-iteration PBKDF2 stretch is in that window), leaves a file that every later open refuses as tampered, right passphrase included

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes). ``test_attack_*``
asserts the correct post-crash behaviour (the same passphrase reopens the vault, or the half-made
file is treated as the fresh vault it is) and FAILS on this head.

Write path (vault.py ``SQLiteMemoryVault.__init__``): ``_init_schema`` commits the current schema
(vault.py:967, ``audit_head``, ``audit_journal.format``, ``tombstone_mac``), then ``_vault_salt``
commits ``kdf_salt`` in its own transaction (_vault_crypto.py:305-317), then ``derive_vault_keys``
runs PBKDF2 (vault.py:529), and only then does ``_upgrade_integrity`` -> ``_upgrade_to_format_3``
write ``integrity_format``, ``key_check`` and ``meta_mac`` (_vault_crypto.py:932-978). A file stopped
between those commits has a salt and no key check. The next open treats that as a keyed vault whose
key check was removed (``_upgrade_integrity``, _vault_crypto.py:831-841), and the a5 discriminator
refuses it because ``_init_schema`` already added the later-format tables: VaultIntegrityError for good.
"""

from __future__ import annotations

import pytest

import kibisis.vault as vault_mod
from kibisis import SQLiteMemoryVault, VaultIntegrityError

PASS = "correct horse battery staple 1"


class _Killed(BaseException):
    """Stands in for the process dying at this point."""


def test_control_uninterrupted_first_open_reopens(tmp_path):
    db = tmp_path / "vault.sqlite"
    SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False).close()
    v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    try:
        v.put("c", "k", "hello", origin="user")
        assert v.get("c", "k").content == "hello"
    finally:
        v.close()


def test_control_kill_before_salt_commit_reopens(tmp_path, monkeypatch):
    db = tmp_path / "vault.sqlite"

    def die(self):
        raise _Killed()

    monkeypatch.setattr(vault_mod.SQLiteMemoryVault, "_vault_salt", die)
    with pytest.raises(_Killed):
        SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    monkeypatch.undo()
    v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    v.close()


def test_attack_kill_during_kdf_after_salt_commit_bricks_vault(tmp_path, monkeypatch):
    db = tmp_path / "vault.sqlite"
    calls = []

    def die_in_kdf(passphrase, salt):
        calls.append(salt)
        raise _Killed()  # the salt transaction has committed; the PBKDF2 stretch is running

    monkeypatch.setattr(vault_mod, "derive_vault_keys", die_in_kdf)
    with pytest.raises(_Killed):
        SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    monkeypatch.undo()
    assert calls, "the kill point was not reached"

    v = None
    refusal = None
    try:
        v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    except VaultIntegrityError as exc:
        refusal = str(exc)
    assert refusal is None, f"a vault interrupted in its first open no longer opens with its own passphrase: {refusal}"
    assert v is not None
    try:
        v.put("c", "k", "hello", origin="user")
        assert v.get("c", "k").content == "hello"
    finally:
        v.close()
