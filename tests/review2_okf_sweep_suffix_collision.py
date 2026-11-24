"""severity: medium
finding: the round-1 OKF leftover sweep matches a set-aside previous bundle to its output by name suffix, so exporting to "bundle" deletes the only copy of "shared.bundle" left aside by a run killed between the fallback's two renames.

``_swap_into_place`` (okf/export.py:763-781), on a platform or filesystem without an exchange call,
renames the previous bundle to ``.okf-old-<pid>-<hex>.<out name>`` and then the stage to ``out``.
A kill between the two renames leaves ``out`` missing and its previous bundle (with ``log.md``, the
bundle's export history, which no later export can regenerate) only at the set-aside name.
Round 1 added ``_sweep_stale_leftovers`` (okf/export.py:693-733), run at the start of every export
into the same parent (:862-863). It decides whether a dead run's set-aside bundle belongs to the
output being exported with ``name.endswith("." + out.name)`` (:720, :727). ``.okf-old-1-<hex>.shared.bundle``
ends with ``.bundle``, so an export to ``bundle`` treats ``shared.bundle``'s previous bundle as its
own: with ``bundle`` present it is ``rmtree``d (:733); with ``bundle`` absent it is renamed into
``bundle`` (:729) and then replaced. Either way the previous ``shared.bundle`` is destroyed and
``shared.bundle`` stays missing. The control shows the same leftover is restored correctly when no
other output's name is a dot-suffix of it.

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes); ``test_attack_*``
asserts the correct post-crash behaviour and fails today because of the defect.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.okf import export as okf_export
from kibisis.okf.export import export_bundle
from kibisis.okf.profile import parse_profile

PASS = "correct horse battery staple 2"
PROFILE = (
    '{"schema": "kibisis.okf_export_profile/1", "audience": "owner",'
    ' "allow": {"scopes": ["default"], "categories": ["decision"]},'
    ' "named": [], "exclude": {"keys": [], "categories": []}}'
)


class _Killed(BaseException):
    """Stands in for the process dying at this point."""


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _gate(_stage, _files):
    return True


def _export(v, out, day):
    return export_bundle(v, parse_profile(PROFILE), out, at=day, bundle_gate=_gate)


def _kill_between_the_two_renames(monkeypatch, v, out, day):
    """Run an export of an existing ``out`` through the two-rename fallback and kill it after the first
    rename (``out`` -> set-aside name). The leftover is renamed to carry a dead pid, as a killed run's
    would; returns its path."""
    monkeypatch.setattr(okf_export, "_exchange_dirs", lambda a, b: False)  # no RENAME_EXCHANGE here
    real_rename = os.rename
    calls = []

    def rename(src, dst):
        calls.append((src, dst))
        if len(calls) == 1:
            return real_rename(src, dst)  # out -> .okf-old-<pid>-<hex>.<name>
        raise _Killed()  # the process dies before the stage is renamed in (and before any restore)

    monkeypatch.setattr(okf_export.os, "rename", rename)
    with pytest.raises(_Killed):
        _export(v, out, day)
    monkeypatch.undo()
    aside = calls[0][1]
    assert not out.exists() and os.path.isdir(aside), "fixture: killed between the two renames"
    name = os.path.basename(aside)
    rest = name[len(okf_export._OLD_PREFIX):].partition("-")[2]
    dead = os.path.join(os.path.dirname(aside), f"{okf_export._OLD_PREFIX}{_dead_pid()}-{rest}")
    os.rename(aside, dead)
    return dead


@pytest.fixture
def vault(tmp_path):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    v.put("decision", "alpha", "Alpha is decided.", origin="model")
    yield v
    v.close()


def _log(out):
    return (out / "log.md").read_text(encoding="utf-8")


def test_control_killed_runs_bundle_is_restored_when_no_name_collides(tmp_path, vault, monkeypatch):
    parent = tmp_path / "exports"
    parent.mkdir()
    shared, other = parent / "shared_bundle", parent / "bundle"
    _export(vault, shared, "2026-11-01")
    _export(vault, other, "2026-11-01")
    _kill_between_the_two_renames(monkeypatch, vault, shared, "2026-11-02")
    _export(vault, other, "2026-11-03")  # an unrelated export into the same parent
    _export(vault, shared, "2026-11-04")  # the sweep puts shared_bundle's previous bundle back first
    assert "2026-11-01" in _log(shared) and "2026-11-04" in _log(shared)
    assert sorted(os.listdir(parent)) == ["bundle", "shared_bundle"]


def test_attack_export_to_bundle_destroys_shared_bundles_set_aside_previous_bundle(tmp_path, vault, monkeypatch):
    parent = tmp_path / "exports"
    parent.mkdir()
    shared, other = parent / "shared.bundle", parent / "bundle"
    _export(vault, shared, "2026-11-01")
    _export(vault, other, "2026-11-01")
    aside = _kill_between_the_two_renames(monkeypatch, vault, shared, "2026-11-02")
    _export(vault, other, "2026-11-03")  # an unrelated export into the same parent
    kept = os.path.isdir(aside) or shared.is_dir()
    assert kept, (
        "the export of 'bundle' swept away 'shared.bundle''s previous bundle, its only copy "
        f"(left: {sorted(os.listdir(parent))})"
    )
    _export(vault, shared, "2026-11-04")
    assert "2026-11-01" in _log(shared), "shared.bundle's export history was lost"
