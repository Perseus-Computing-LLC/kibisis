"""severity: medium
finding: export_snapshot(path=...) writes the decrypted snapshot to "<out>.tmp.<pid>" with O_EXCL and nothing ever sweeps it: a kill before the rename leaves the vault's plaintext beside the snapshot for good, and a later export from the same pid (every run of a container entrypoint is pid 1) fails with FileExistsError.

``export_snapshot`` (_vault_snapshot.py:155-172) creates ``out_p.with_suffix(".tmp.<pid>")`` with
``O_CREAT | O_EXCL`` (:158-162), dumps the whole snapshot (decrypted entry content: the comment at :159-161
says so) into it, fsyncs and ``os.replace``s it over ``out``; its ``except`` handler unlinks the temp, which
a SIGKILL never runs. Round 1 added leftover sweeping to the OKF export and the key file for exactly this
window (R1-6, R1-7) but not here: nothing removes ``<out>.tmp.<pid>``. Effects of one kill between the
write and the rename:

* the snapshot's plaintext (SQLCipher protects the vault file, not this one) stays next to the output,
  whatever later exports do;
* a later ``export_snapshot`` to the same path from a process with the same pid refuses with
  ``FileExistsError`` at the ``O_EXCL`` open, every time. In a container the exporter is pid 1 on every run,
  so scheduled snapshots stop working after the first kill until someone deletes the file by hand.

The kill is modelled at the ``os.fsync`` of the temp (its data written, not yet renamed); the
``except``-handler unlink is disabled for that one call, as a SIGKILL would skip it.

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes); ``test_attack_*``
asserts the correct post-crash behaviour and fails today because of the defect.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

import kibisis._vault_snapshot as snap_mod
from kibisis import SQLiteMemoryVault

PASS = "correct horse battery staple 5"
SECRET = "the vendor's private quote is 88231"


class _Killed(BaseException):
    """Stands in for the process dying at this point."""


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


@pytest.fixture
def vault(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    v.put("notes", "quote", SECRET, origin="model")
    yield v
    v.close()


def _killed_export(v, out, monkeypatch):
    real_unlink = os.unlink

    def die(_fd):
        raise _Killed()

    def unlink(p, *a, **k):
        if ".tmp." in os.path.basename(os.fspath(p)):
            return None  # the except handler's cleanup: never runs after a SIGKILL
        return real_unlink(p, *a, **k)

    monkeypatch.setattr(snap_mod.os, "fsync", die)
    monkeypatch.setattr(snap_mod.os, "unlink", unlink)
    with pytest.raises(_Killed):
        v.export_snapshot(path=str(out))
    monkeypatch.undo()
    left = [n for n in os.listdir(out.parent) if n.startswith(out.stem + ".tmp.")]
    assert len(left) == 1 and SECRET in (out.parent / left[0]).read_text(encoding="utf-8")
    return out.parent / left[0]


def _plaintext_leftovers(directory, out):
    return sorted(
        n for n in os.listdir(directory)
        if n != out.name and n.startswith(out.stem) and SECRET in (directory / n).read_text(encoding="utf-8")
    )


def test_control_uninterrupted_export_leaves_only_the_snapshot(tmp_path, vault):
    snaps = tmp_path / "snaps"
    out = snaps / "nightly.json"
    vault.export_snapshot(path=str(out))
    assert sorted(os.listdir(snaps)) == ["nightly.json"]
    assert json.loads(out.read_text(encoding="utf-8"))["manifest_sha256"]


def test_attack_export_after_a_killed_export_from_the_same_pid_works(tmp_path, vault, monkeypatch):
    out = tmp_path / "snaps" / "nightly.json"
    _killed_export(vault, out, monkeypatch)
    try:
        vault.export_snapshot(path=str(out))  # the next run of a pid-1 container entrypoint
    except FileExistsError as exc:
        pytest.fail(f"every later snapshot to {out.name} is refused after one killed export: {exc!r}")
    assert out.is_file()


def test_attack_decrypted_leftover_of_a_killed_export_does_not_outlive_the_next_export(tmp_path, vault, monkeypatch):
    out = tmp_path / "snaps" / "nightly.json"
    left = _killed_export(vault, out, monkeypatch)
    os.rename(left, out.parent / f"{out.stem}.tmp.{_dead_pid()}")  # the killed process's pid is gone
    vault.export_snapshot(path=str(out))
    leftovers = _plaintext_leftovers(out.parent, out)
    assert leftovers == [], f"the vault's decrypted content is still on disk beside the snapshot: {leftovers}"
