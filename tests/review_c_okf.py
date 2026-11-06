"""Review C (alpha.16, commit 1299c28): OKF export/import CLI findings and positive controls.

Docstrings say whether a PASS demonstrates a defect ("passing = bug") or asserts correct behaviour
("failing = bug", positive controls). Temp vaults and bundles live under tmp_path only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from kibisis import config as kcfg
from kibisis.__main__ import main
from kibisis.okf.export import GateRefused, command_gate, export_bundle
from kibisis.okf.importer import import_bundle
from kibisis.okf.profile import default_profile, parse_profile
from kibisis.vault import SQLiteMemoryVault

sys.path.append(str(Path(__file__).resolve().parent))
from _okf_fixtures import DEFAULT_PROFILE_JSON, PASSPHRASE, build_probe_vault, open_vault, write_profile  # noqa: E402

SRC = str(Path(__file__).resolve().parents[1] / "src")


# ---------------------------------------------------------------- B.5 default --db


def _okf_default_db(env: dict) -> str:
    """DEFAULT_DB_PATH as the okf-export/okf-import argparse defaults see it (computed at import time)."""
    full = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": SRC, **env}
    out = subprocess.run([sys.executable, "-c", "import kibisis.__main__ as m; print(m.DEFAULT_DB_PATH)"],
                         env=full, capture_output=True, text=True, timeout=60, check=True)
    return out.stdout.strip()


def test_okf_cli_default_db_differs_from_the_vault_the_server_and_admit_use(tmp_path):
    """passing = bug. __main__.py l.20 hard-codes ~/.hermes/kibisis/vault.sqlite for okf-export/okf-import,
    while the MCP server, admit and review resolve config.default_db_path() (XDG data dir). Only
    KIBISIS_DB_PATH makes them agree. CHANGELOG alpha.15 says admit moved off the ~/.hermes path; the okf
    commands did not. Both okf commands refuse a missing file (l.95, l.145), so the usual outcome is a
    confusing 'no vault at ~/.hermes/...' error; if a stale vault still exists there, okf-import writes into
    it and the server never sees the rows."""
    home = tmp_path / "h"
    base = {"HOME": str(home)}
    assert _okf_default_db(base) != kcfg.default_db_path(base, platform="linux")
    assert _okf_default_db(base) == str(home / ".hermes" / "kibisis" / "vault.sqlite")
    assert kcfg.default_db_path(base, platform="linux") == str(home / ".local" / "share" / "kibisis" / "vault.sqlite")
    xdg = dict(base, XDG_DATA_HOME=str(tmp_path / "xdg"))
    assert _okf_default_db(xdg) == str(home / ".hermes" / "kibisis" / "vault.sqlite")  # XDG ignored
    assert kcfg.default_db_path(xdg, platform="linux") == str(tmp_path / "xdg" / "kibisis" / "vault.sqlite")
    explicit = dict(base, KIBISIS_DB_PATH=str(tmp_path / "explicit.sqlite"))
    assert _okf_default_db(explicit) == kcfg.default_db_path(explicit) == str(tmp_path / "explicit.sqlite")


def test_okf_cli_ignores_KIBISIS_ALLOW_PLAINTEXT_that_the_server_and_admit_honour(tmp_path, monkeypatch, capsys):
    """passing = bug (low). _okf_export/_okf_import open with SQLiteMemoryVault(args.db) (l.99, l.149), not
    config.open_vault, so a vault that the MCP server/admit open under KIBISIS_ALLOW_PLAINTEXT=1 is refused
    by okf-export with exit 1 'cannot open the vault ... EncryptionRequiredError'."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    db = tmp_path / "plain.sqlite"
    SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False).close()
    kcfg.open_vault(str(db)).close()  # the server's path opens it
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out"),
               "--db", str(db), "--ungated"])
    err = capsys.readouterr().err
    assert rc == 1 and "cannot open the vault" in err and "EncryptionRequiredError" in err


# ---------------------------------------------------------------- B.4 / docs: "reads the vault only" / "--dry-run writes nothing"


def _sha(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_okf_export_and_import_dry_run_rewrite_a_plaintext_vault_when_a_passphrase_is_in_the_env(tmp_path, monkeypatch, capsys):
    """passing = bug. __main__.py l.3-5 and CHANGELOG say okf-export 'reads the vault and never changes it'
    and okf-import --dry-run 'writes nothing'. Both open with SQLiteMemoryVault(args.db) (l.99, l.149), whose
    constructor converts a plain-SQLite file to SQLCipher in place when a passphrase resolves from the
    environment (vault.py l.311-323) and runs the integrity upgrade. The file's bytes and header change
    under a 'read-only' command, and a process that opened it with allow_plaintext=True can no longer."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    db = tmp_path / "plain.sqlite"
    v = SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False)
    v.put("decision", "a", "Alpha.", scope="default", origin="model")
    v.close()
    assert db.read_bytes().startswith(b"SQLite format 3")
    before = _sha(db)
    bundle = tmp_path / "b"
    (bundle / "default" / "decision").mkdir(parents=True)
    (bundle / "default" / "decision" / "a.md").write_text("---\ntype: decision\n---\nAlpha.")
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    assert main(["okf-import", "--bundle", str(bundle), "--db", str(db), "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["written"] == 0
    assert _sha(db) != before and not db.read_bytes().startswith(b"SQLite format 3")  # re-encrypted in place
    monkeypatch.delenv("KIBISIS_PASSPHRASE")
    with pytest.raises(Exception):  # the plaintext opener that wrote it ('file is not a database')
        SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False).close()
    # okf-export, "reads the vault only": same constructor, same conversion on a fresh plaintext file.
    db2 = tmp_path / "plain2.sqlite"
    SQLiteMemoryVault(str(db2), allow_plaintext=True, auto_gate=False).close()
    before2 = _sha(db2)
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    assert main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out"), "--db", str(db2), "--ungated"]) == 0
    assert _sha(db2) != before2 and not db2.read_bytes().startswith(b"SQLite format 3")


# ---------------------------------------------------------------- B.1 --gate-cmd (positive controls)


def test_gate_cmd_timeout_and_non_zero_exit_refuse_the_bundle_and_leave_nothing(tmp_path):
    """failing = bug (positive control). command_gate (export.py l.855-874): a timeout, a launch failure or a
    non-zero exit all return False, export_bundle raises GateRefused and the staging dir is removed."""
    vault = build_probe_vault(tmp_path / "v.sqlite")
    try:
        profile = parse_profile(DEFAULT_PROFILE_JSON)
        out = tmp_path / "bundle"
        slow = command_gate(f"{sys.executable} -c 'import time; time.sleep(5)'", timeout=0.5)
        t0 = time.monotonic()
        with pytest.raises(GateRefused):
            export_bundle(vault, profile, out, bundle_gate=slow)
        assert time.monotonic() - t0 < 4
        with pytest.raises(GateRefused):
            export_bundle(vault, profile, out, bundle_gate=command_gate(f"{sys.executable} -c 'raise SystemExit(3)'"))
        with pytest.raises(GateRefused):
            export_bundle(vault, profile, out, bundle_gate=command_gate("/nonexistent/okf-gate-binary"))
        assert not out.exists() and [p.name for p in tmp_path.iterdir() if p.name.startswith(".okf-stage")] == []
        ok = command_gate(f"{sys.executable} -c 'import sys; sys.exit(0 if len(sys.argv) > 1 else 9)'")
        export_bundle(vault, profile, out, bundle_gate=ok)
        assert (out / "index.md").is_file()
    finally:
        vault.close()


def test_gate_cmd_stdout_is_copied_to_stderr_verbatim(tmp_path, capsys):
    """passing = documents a caveat (low). Whatever the gate prints (export.py l.870-871) is written to the
    exporter's stderr unchanged; a gate that echoes matched text puts vault content on the operator's
    terminal/log. Not a code defect by itself; the docstring says gates should print labels only."""
    vault = build_probe_vault(tmp_path / "v.sqlite")
    try:
        gate = command_gate(f"{sys.executable} -c 'print(open(__import__(\"sys\").argv[1]).read()[:40])'")
        export_bundle(vault, parse_profile(DEFAULT_PROFILE_JSON), tmp_path / "bundle", bundle_gate=gate)
    finally:
        vault.close()
    err = capsys.readouterr().err
    assert err.startswith("---\ntype:")  # the first staged file's frontmatter went to the exporter's stderr


# ---------------------------------------------------------------- B.2 bundle path handling (positive control)


def test_import_never_follows_symlinks_out_of_the_bundle(tmp_path):
    """failing = bug (positive control). importer._scan/_read_capped: symlinked dirs and files are counted as
    'symlink' and never read, so a bundle cannot pull a file from outside itself into the vault."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.md"
    secret.write_text("---\ntype: decision\n---\nOUTSIDE-CONTENT-MARKER\n")
    bundle = tmp_path / "bundle"
    (bundle / "default" / "decision").mkdir(parents=True)
    (bundle / "default" / "decision" / "ok.md").write_text("---\ntype: decision\n---\nInside the bundle.\n")
    os.symlink(secret, bundle / "default" / "decision" / "linked.md")
    os.symlink(outside, bundle / "default" / "convention")  # a symlinked category directory
    (bundle / "default" / "decision" / "deep").mkdir()
    (bundle / "default" / "decision" / "deep" / "x.md").write_text("---\ntype: decision\n---\nToo deep.\n")
    vault = open_vault(tmp_path / "v.sqlite")
    try:
        report = import_bundle(vault, bundle, profile=default_profile())
        assert report.skipped.get("symlink") == 2 and report.skipped.get("unexpected_path") == 1
        assert report.new == ["default/decision/ok.md"]
        contents = [r.content for r in vault.list_entities(scope="*", include_unverified=True)]
        assert all("OUTSIDE-CONTENT-MARKER" not in c for c in contents)
    finally:
        vault.close()


# ---------------------------------------------------------------- B.3 origin cap (positive control)


def test_imported_rows_cannot_declare_origin_state_identity_or_reserved_metadata(tmp_path):
    """failing = bug (positive control). Frontmatter origin/epistemic_state/author_id/tenant_id/human_reviews/
    origin_class/lineage_* are dropped (is_vault_owned_key) and the row lands origin=model, candidate,
    author kibisis:okf-import. B.4 (tombstones, dry-run) is already covered by tests/test_okf_import.py."""
    bundle = tmp_path / "bundle"
    (bundle / "default" / "decision").mkdir(parents=True)
    (bundle / "default" / "decision" / "claim.md").write_text(
        "---\ntype: decision\norigin: user\nepistemic_state: verified\nkibisis_state: verified\n"
        "author_id: root\ntenant_id: t1\nhuman_reviews: [{by: ceo}]\norigin_class: person\nact_class: act\n"
        "lineage_parent: x\ncolour: blue\n---\nImported claim.\n")
    vault = open_vault(tmp_path / "v.sqlite")
    try:
        report = import_bundle(vault, bundle, profile=default_profile())
        assert report.new == ["default/decision/claim.md"]
        for key in ("origin", "epistemic_state", "author_id", "tenant_id", "human_reviews", "origin_class", "act_class", "lineage_parent"):
            assert report.dropped_keys.get(key) == 1, key
        (row,) = [r for r in vault.list_entities(scope="default", include_unverified=True) if r.key == "claim"]
        assert row.origin == "model"
        state = row.epistemic_state.value if hasattr(row.epistemic_state, "value") else row.epistemic_state
        assert state == "candidate"
        meta = row.metadata or {}
        assert meta.get("author_id") == "kibisis:okf-import" and "human_reviews" not in meta and meta.get("tenant_id") is None
        assert meta.get("act_class") in (None, "inform")
        assert json.loads(meta["okf_extra"]) == {"colour": "blue"}
    finally:
        vault.close()
