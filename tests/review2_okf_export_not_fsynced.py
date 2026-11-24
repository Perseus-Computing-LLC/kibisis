"""severity: low
finding: OKF export swaps its staged bundle into place without ever fsyncing a staged file or directory and then deletes the previous bundle, so a power loss after the swap can leave a bundle of empty or missing files and no previous bundle (its log.md history included).

``_write_stage`` (okf/export.py:736-760) writes each document with ``os.open`` + ``write`` + close and no
``os.fsync``; ``_swap_into_place`` (:763-781) renames or exchanges the stage into ``out`` and then
``rmtree``s the previous bundle; neither the stage directory nor the parent is fsynced. Round 1 made the
key file (keys.py:111, :122) and the vault commit (``synchronous = FULL``, vault.py:1006-1010) durable
before they are reported done, but not this temp-and-rename. The file data of a freshly created file is
not ordered before the rename by POSIX (and not by ext4 for new files in a new directory, nor by XFS or
btrfs), so after an OS crash ``out`` may name a bundle whose ``index.md``, ``log.md`` and concept files are
empty, with the previous bundle already gone. ``log.md`` carries every earlier export's entry forward
(``_log_text``), so that history is lost with it.

The test records every ``os.fsync`` and checks, at the moment the swap is called, that each staged file
has been synced. It cannot cut power; the observable defect is that the export commits (renames) data it
never made durable.

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes); ``test_attack_*``
asserts the correct post-crash behaviour and fails today because of the defect.
"""

from __future__ import annotations

import os

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.okf import export as okf_export
from kibisis.okf.export import export_bundle
from kibisis.okf.profile import parse_profile

PASS = "correct horse battery staple 4"
PROFILE = (
    '{"schema": "kibisis.okf_export_profile/1", "audience": "owner",'
    ' "allow": {"scopes": ["default"], "categories": ["decision"]},'
    ' "named": [], "exclude": {"keys": [], "categories": []}}'
)


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    v = SQLiteMemoryVault(tmp_path / "v.sqlite", passphrase=PASS, auto_gate=False)
    v.put("decision", "alpha", "Alpha is decided.", origin="model")
    synced = set()
    at_swap = {}
    real_fsync = os.fsync
    real_swap = okf_export._swap_into_place

    def fsync(fd):
        st = os.fstat(fd)
        synced.add((st.st_dev, st.st_ino))
        return real_fsync(fd)

    def swap(stage, out, existed):
        files = okf_export._staged_files(stage)
        at_swap["files"] = files
        at_swap["unsynced"] = sorted(
            os.path.relpath(f, stage) for f in files if (os.stat(f).st_dev, os.stat(f).st_ino) not in synced
        )
        return real_swap(stage, out, existed)

    monkeypatch.setattr(okf_export.os, "fsync", fsync)
    monkeypatch.setattr(okf_export, "_swap_into_place", swap)
    yield v, at_swap
    v.close()


def _export(v, out, day):
    return export_bundle(v, parse_profile(PROFILE), out, at=day, bundle_gate=lambda s, f: True)


def test_control_export_replaces_the_previous_bundle(tmp_path, recorded):
    v, at_swap = recorded
    out = tmp_path / "bundle"
    _export(v, out, "2026-11-01")
    _export(v, out, "2026-11-02")
    log = (out / "log.md").read_text(encoding="utf-8")
    assert "2026-11-01" in log and "2026-11-02" in log
    assert at_swap["files"], "fixture: the swap was observed with the staged files"


def test_attack_staged_files_are_durable_before_they_replace_the_previous_bundle(tmp_path, recorded):
    v, at_swap = recorded
    out = tmp_path / "bundle"
    _export(v, out, "2026-11-01")
    _export(v, out, "2026-11-02")  # replaces (and deletes) the previous bundle
    assert at_swap["files"]
    assert at_swap["unsynced"] == [], (
        f"swapped into place, and the previous bundle deleted, with never-fsynced files: {at_swap['unsynced']}"
    )
