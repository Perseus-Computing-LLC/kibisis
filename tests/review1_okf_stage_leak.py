"""severity: low
finding: a kill while OKF export runs its bundle gate (or between the directory exchange and the rmtree) leaves a full plaintext .okf-stage-* bundle beside the output, ungated, and no later export removes it

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes: an export that
finishes, or one the gate refuses in-process, leaves no staging directory). ``test_attack_*`` asserts
the correct post-crash behaviour (once a later export has finished, nothing of the killed run's staged
bundle is left beside the output) and FAILS on this head.

Write path: ``export_bundle`` (okf/export.py:760-852) writes every rendered document to
``tempfile.mkdtemp(prefix=".okf-stage-", dir=out.parent)`` (okf/export.py:653-677), then calls
``bundle_gate`` on the staged tree (okf/export.py:826-827; ``command_gate`` allows 900 s), then
``_swap_into_place`` (okf/export.py:680-698). Only an ``except BaseException`` handler
(okf/export.py:843-845) removes the stage, and a killed process never runs it. ``_prepare_out``
(okf/export.py:587) and ``_write_stage`` do not sweep stale stages, so the text the gate was asked
to judge stays on disk under a hidden name. The kill is a real SIGKILL in a child process.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

from kibisis import SQLiteMemoryVault
from kibisis.okf.export import export_bundle
from kibisis.okf.profile import parse_profile

PASS = "correct horse battery staple 1"
PROFILE = (
    '{"schema": "kibisis.okf_export_profile/1", "audience": "owner",'
    ' "allow": {"scopes": ["default"], "categories": ["decision"]},'
    ' "named": [], "exclude": {"keys": [], "categories": []}}'
)
MARK = "zanzibarquokkaledger"

CHILD = textwrap.dedent(
    """
    import os, signal, sys
    from kibisis import SQLiteMemoryVault
    from kibisis.okf.export import export_bundle
    from kibisis.okf.profile import parse_profile

    db, out, profile, pw = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    vault = SQLiteMemoryVault(db, passphrase=pw, auto_gate=False)

    def gate(stage, files):  # the external scanner is still running when the process is killed
        os.kill(os.getpid(), signal.SIGKILL)

    export_bundle(vault, parse_profile(profile), out, at="2026-11-01", bundle_gate=gate)
    """
)


def _vault(tmp_path):
    db = tmp_path / "vault.sqlite"
    v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    v.put("decision", "alpha", f"Alpha is decided; the token is {MARK}.", origin="model")
    return db, v


def _stale_with_mark(parent):
    hits = []
    for name in os.listdir(parent):
        if not name.startswith(".okf-"):
            continue
        for dirpath, _d, files in os.walk(parent / name):
            for f in files:
                with open(os.path.join(dirpath, f), "rb") as fh:
                    if MARK.encode() in fh.read():
                        hits.append(os.path.join(name, os.path.relpath(os.path.join(dirpath, f), parent / name)))
    return hits


def test_control_refused_export_cleans_its_stage(tmp_path):
    db, v = _vault(tmp_path)
    parent = tmp_path / "exports"
    parent.mkdir()
    try:
        try:
            export_bundle(v, parse_profile(PROFILE), parent / "bundle", at="2026-11-01", bundle_gate=lambda s, f: False)
        except Exception:
            pass
        report = export_bundle(v, parse_profile(PROFILE), parent / "bundle", at="2026-11-01", bundle_gate=lambda s, f: True)
    finally:
        v.close()
    assert report.concepts
    assert sorted(os.listdir(parent)) == ["bundle"]


def test_attack_killed_export_leaves_ungated_stage_forever(tmp_path):
    db, v = _vault(tmp_path)
    v.close()
    parent = tmp_path / "exports"
    parent.mkdir()
    out = parent / "bundle"
    script = tmp_path / "child.py"
    script.write_text(CHILD)
    env = {k: val for k, val in os.environ.items() if k not in ("KIBISIS_PASSPHRASE", "KIBISIS_PASSPHRASE_FILE")}
    env["PYTHONPATH"] = os.pathsep.join([p for p in sys.path if p] + [env.get("PYTHONPATH", "")])
    proc = subprocess.run([sys.executable, str(script), str(db), str(out), PROFILE, PASS],
                          env=env, capture_output=True, text=True, timeout=180)
    assert proc.returncode == -9, (proc.returncode, proc.stderr[-2000:])

    # The next run finishes normally.
    v = SQLiteMemoryVault(db, passphrase=PASS, auto_gate=False)
    try:
        report = export_bundle(v, parse_profile(PROFILE), out, at="2026-11-01", bundle_gate=lambda s, f: True)
    finally:
        v.close()
    assert report.concepts
    leftovers = _stale_with_mark(parent)
    assert leftovers == [], f"the killed run's staged bundle is still beside the output: {leftovers}"
