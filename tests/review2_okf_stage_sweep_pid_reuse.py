"""severity: low
finding: the round-1 OKF leftover sweep decides a killed export's stage is live from its pid alone, so in a container (every run is pid 1) or after pid reuse the ungated plaintext stage of a killed export is never removed, the leak round 1 meant to close.

``_write_stage`` (okf/export.py:736-760) renders every concept (before any bundle gate has seen it) into
``.okf-stage-<pid>-XXXX`` beside the output. Round 1's ``_sweep_stale_leftovers`` (:693-733) removes a
stage at the next export only when ``_is_stale`` (:684-690) says its owner is gone: ``owner !=
os.getpid() and not _pid_alive(owner)``. A pid is not an owner: an export run as a container's entrypoint
is pid 1 in every run (``docker run --rm ... okf-export``), so the next run sees its own pid and leaves the
stage; on a host the killed run's pid can be reused by any live process, and pid 1 is always alive. The
killed run's ungated plaintext then stays beside the bundle for as long as that holds (in a container:
for good), readable by anything that reads the export directory.

The leftover here is produced by a real export killed while its bundle gate runs (the ``rmtree`` in its
``except`` handler, which a SIGKILL would not run, is disabled for that export); it is then renamed to the
name the same run would have had as pid 1 in a container. The control gives it a dead pid and shows the
sweep removes it.

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

PASS = "correct horse battery staple 3"
SECRET = "Gate would have withheld this: vendor quote 88231."
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


def _leftover_with_owner(tmp_path, monkeypatch, owner: int):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    v.put("decision", "alpha", SECRET, origin="model")
    parent = tmp_path / "exports"
    parent.mkdir()

    def gate_killed(_stage, _files):
        raise _Killed()  # the process dies while the bundle gate is running

    monkeypatch.setattr(okf_export.shutil, "rmtree", lambda *a, **k: None)  # a SIGKILL runs no cleanup
    with pytest.raises(_Killed):
        export_bundle(v, parse_profile(PROFILE), parent / "bundle", at="2026-11-01", bundle_gate=gate_killed)
    monkeypatch.undo()
    (stage,) = [n for n in os.listdir(parent) if n.startswith(okf_export._STAGE_PREFIX)]
    rest = stage[len(okf_export._STAGE_PREFIX):].split("-", 1)[1]
    renamed = parent / f"{okf_export._STAGE_PREFIX}{owner}-{rest}"
    os.rename(parent / stage, renamed)
    assert SECRET in (renamed / "default" / "decision" / "alpha.md").read_text(encoding="utf-8")
    return v, parent


def _next_export(v, parent):
    try:
        export_bundle(v, parse_profile(PROFILE), parent / "bundle", at="2026-11-02", bundle_gate=lambda s, f: True)
    finally:
        v.close()
    return sorted(n for n in os.listdir(parent) if n.startswith(okf_export._STAGE_PREFIX))


def test_control_stage_of_a_killed_run_with_a_dead_pid_is_swept(tmp_path, monkeypatch):
    v, parent = _leftover_with_owner(tmp_path, monkeypatch, _dead_pid())
    assert _next_export(v, parent) == []


def test_attack_stage_of_a_killed_pid_1_run_is_never_swept(tmp_path, monkeypatch):
    v, parent = _leftover_with_owner(tmp_path, monkeypatch, 1)
    left = _next_export(v, parent)
    assert left == [], f"the killed run's ungated plaintext stage is still beside the bundle: {left}"
