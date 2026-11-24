"""severity: low
finding: generate_keyfile links the fsynced temp file into place and unlinks the temp afterwards; a kill between the two leaves a hidden second name of the installed key that no later run removes, because every later run refuses at the existing key before it sweeps.

Round 1 rewrote ``generate_keyfile`` (keys.py:91-127): write + fsync ``.<name>.tmp-<pid>-<hex>``
(:111), ``os.link(temp, path)`` (:113), ``_fsync_dir`` (:122), then ``os.unlink(temp)`` in ``finally``
(:123-125). The docstring says a killed run "leaves at most a temporary file (removed by the next run)" and the sweep
(:58-78) says the temp files "hold a key that was never installed, so nothing can depend on them". A kill
after the link and before the unlink leaves a temp file that IS the installed key (a hard link to the same
inode). The next ``python -m kibisis.keys <path>`` returns at ``os.path.lexists(path)`` (:100) before
``_sweep_stale_temps`` (:104) runs, so the copy stays for good: an operator who later deletes or shreds
``path`` to retire the key still has it on disk under a hidden name, and a backup of the directory
carries it twice.

The kill is modelled at the ``os.unlink`` of the temp (the ``finally`` cleanup a SIGKILL would not run).

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes); ``test_attack_*``
asserts the correct post-crash behaviour and fails today because of the defect.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

import kibisis.keys as keys


class _Killed(BaseException):
    """Stands in for the process dying at this point."""


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _kill_at_temp_unlink(monkeypatch):
    real_unlink = os.unlink

    def unlink(p, *a, **k):
        if keys._TEMP_MARK in os.path.basename(os.fspath(p)):
            raise _Killed()
        return real_unlink(p, *a, **k)

    monkeypatch.setattr(keys.os, "unlink", unlink)


def _holders_of(directory, key):
    out = []
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), encoding="utf-8") as fh:
            if fh.read().strip() == key:
                out.append(name)
    return out


def test_control_uninterrupted_run_leaves_only_the_key_file(tmp_path):
    path = str(tmp_path / "kibisis.key")
    assert keys.main([path]) == 0
    assert sorted(os.listdir(tmp_path)) == ["kibisis.key"]


def test_attack_kill_after_link_leaves_a_hidden_copy_of_the_installed_key_for_good(tmp_path, monkeypatch):
    path = str(tmp_path / "kibisis.key")
    _kill_at_temp_unlink(monkeypatch)
    with pytest.raises(_Killed):
        keys.generate_keyfile(path)
    monkeypatch.undo()
    key = keys.resolve_passphrase(env={keys.ENV_FILE: path})
    assert key and os.path.isfile(path), "fixture: the key was installed before the kill"
    # The killed run's pid is gone, as it would be after a real kill: give its temp a dead pid.
    (temp,) = [n for n in os.listdir(tmp_path) if n != "kibisis.key"]
    rest = temp[len(keys._temp_prefix(path)):].split("-", 1)[1]
    os.rename(tmp_path / temp, tmp_path / f"{keys._temp_prefix(path)}{_dead_pid()}-{rest}")
    assert keys.main([path]) == 1  # the next run: the key exists, nothing is overwritten (and nothing swept)
    others = [n for n in _holders_of(tmp_path, key) if n != "kibisis.key"]
    assert others == [], f"the installed key is also held, for good, by {others}"
