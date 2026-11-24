"""severity: low
finding: generate_keyfile creates the key file at its final path before writing the key, so a kill in between leaves an empty key file that the CLI then refuses to replace and resolve_passphrase reads as "no key"

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes). ``test_attack_*``
asserts the correct post-crash behaviour (a key file that exists at its final path holds a usable key,
or the path is free to be created again) and FAILS on this head.

Write path: ``generate_keyfile`` (keys.py:34-38) runs ``os.open(path, O_CREAT|O_EXCL, 0o600)``, then
``secrets.token_urlsafe(32)``, then the write; nothing removes the file if the process stops in between
(no temp name and rename, no cleanup, no fsync). ``main`` (keys.py:51-55) then answers "already exists;
not overwriting it" and exits 1, and ``resolve_passphrase`` (keys.py:28-30) returns ``None`` for the
empty file, so ``open_vault`` sees no key at all (refused, or plaintext if plaintext is allowed).
The crash is modelled by raising a BaseException from ``secrets.token_urlsafe``, the step between the
create and the write; ``generate_keyfile`` has no handler, so this is what a kill leaves.
"""

from __future__ import annotations

import os

import pytest

import kibisis.keys as keys


class _Killed(BaseException):
    """Stands in for the process dying at this point."""


def test_control_generated_keyfile_is_usable(tmp_path):
    path = str(tmp_path / "kibisis.key")
    assert keys.main([path]) == 0
    pw = keys.resolve_passphrase(env={keys.ENV_FILE: path})
    assert pw is not None and len(pw) >= keys.MIN_PASSPHRASE_LENGTH
    assert keys.main([path]) == 1  # never overwrites a real key


def test_attack_kill_between_create_and_write(tmp_path, monkeypatch):
    path = str(tmp_path / "kibisis.key")

    def die(_n):
        raise _Killed()

    monkeypatch.setattr(keys.secrets, "token_urlsafe", die)
    with pytest.raises(_Killed):
        keys.generate_keyfile(path)
    monkeypatch.undo()

    if os.path.exists(path):
        pw = keys.resolve_passphrase(env={keys.ENV_FILE: path})
        assert pw is not None, "an empty key file sits at the final path after the crash; it reads as 'no key'"
    assert keys.main([path]) == 0 or keys.resolve_passphrase(env={keys.ENV_FILE: path}), (
        "the operator cannot create the key again: the CLI refuses to replace the empty file"
    )
