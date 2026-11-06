"""Review C (alpha.16): OKF export/import CLI regression tests.

Tests that used to demonstrate a defect ("passing = bug") now assert the fixed behaviour; the positive
controls are kept. Temp vaults and bundles live under tmp_path only.
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


# ---------------------------------------------------------------- F17 / C-5 / C-11: one default vault path


def _okf_default_db(env: dict) -> str:
    """DEFAULT_DB_PATH as the okf-export/okf-import commands resolve it (lazily, from the environment)."""
    full = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": SRC, **env}
    code = "import importlib; m = importlib.import_module('kibisis.' + '__main__'); print(m.DEFAULT_DB_PATH)"
    out = subprocess.run([sys.executable, "-c", code], env=full, capture_output=True, text=True, timeout=60, check=True)
    return out.stdout.strip()


def test_okf_cli_default_db_is_the_vault_the_server_and_admit_use(tmp_path):
    """F17: okf-export/okf-import resolve config.default_db_path() (KIBISIS_DB_PATH, else the XDG data dir)
    like the MCP server, admit and review; the old ~/.hermes path is gone."""
    home = tmp_path / "h"
    base = {"HOME": str(home)}
    assert _okf_default_db(base) == kcfg.default_db_path(base, platform=sys.platform)
    assert ".hermes" not in _okf_default_db(base)
    xdg = dict(base, XDG_DATA_HOME=str(tmp_path / "xdg"))
    assert _okf_default_db(xdg) == kcfg.default_db_path(xdg, platform=sys.platform)
    explicit = dict(base, KIBISIS_DB_PATH=str(tmp_path / "explicit.sqlite"))
    assert _okf_default_db(explicit) == kcfg.default_db_path(explicit) == str(tmp_path / "explicit.sqlite")


def test_okf_commands_without_db_open_KIBISIS_DB_PATH(tmp_path, monkeypatch, capsys):
    """F17: with no --db, okf-export and okf-import use the vault the environment names, and say which
    path they looked at when it is missing."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    db = tmp_path / "env.sqlite"
    monkeypatch.setenv("KIBISIS_DB_PATH", str(db))
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out"), "--ungated"])
    assert rc == 1 and f"no vault at {db}" in capsys.readouterr().err
    v = SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False, verification_quorum=1)
    v.put("decision", "a", "Alpha.", scope="default", origin="user", epistemic_state="verified")
    v.close()
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out"), "--ungated"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["exported"] == 1
    assert main(["okf-import", "--bundle", str(tmp_path / "out"), "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True


def test_okf_cli_honours_KIBISIS_ALLOW_PLAINTEXT_like_the_server_and_admit(tmp_path, monkeypatch, capsys):
    """C-11: the okf commands open the vault through config.open_vault, so a vault the MCP server/admit open
    under KIBISIS_ALLOW_PLAINTEXT=1 exports; without the allowance they refuse with the same message."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    db = tmp_path / "plain.sqlite"
    SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False).close()
    kcfg.open_vault(str(db)).close()  # the server's path opens it
    args = ["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out"), "--db", str(db), "--ungated"]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["exported"] == 0
    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT")
    rc = main(args)
    err = capsys.readouterr().err
    assert rc == 2 and err.startswith("refused: No key:")


# ---------------------------------------------------------------- C-6: "reads the vault only" / "--dry-run writes nothing"


def _sha(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_okf_export_and_import_dry_run_leave_every_byte_of_the_vault_alone(tmp_path, monkeypatch, capsys):
    """C-6: okf-export and okf-import --dry-run open the vault read-only. A plain-SQLite file is not converted
    to SQLCipher even when a passphrase is in the environment, no integrity upgrade or index build runs, and
    the file's bytes are identical afterwards; the plaintext opener that wrote it can still open it."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    db = tmp_path / "plain.sqlite"
    v = SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False, verification_quorum=1)
    v.put("decision", "a", "Alpha.", scope="default", origin="user", epistemic_state="verified")
    v.close()
    assert db.read_bytes().startswith(b"SQLite format 3")
    before = _sha(db)
    bundle = tmp_path / "b"
    (bundle / "default" / "decision").mkdir(parents=True)
    (bundle / "default" / "decision" / "a.md").write_text("---\ntype: decision\n---\nAlpha.")
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    # R5-1: a passphrase against a plain file that holds entries is refused outright (the OKF commands never
    # pass the adopt_keyless opt-in), and the refusal writes nothing either
    assert main(["okf-import", "--bundle", str(bundle), "--db", str(db), "--dry-run"]) == 1
    assert "plaintext entries and no salt" in capsys.readouterr().err
    assert _sha(db) == before and db.read_bytes().startswith(b"SQLite format 3")
    assert main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out"), "--db", str(db), "--ungated"]) == 1
    assert "plaintext entries and no salt" in capsys.readouterr().err
    assert _sha(db) == before and db.read_bytes().startswith(b"SQLite format 3")
    # opened as the plain file it is (no passphrase, plaintext allowed): read-only, nothing written
    monkeypatch.delenv("KIBISIS_PASSPHRASE")
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    assert main(["okf-import", "--bundle", str(bundle), "--db", str(db), "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["written"] == 0
    assert _sha(db) == before and db.read_bytes().startswith(b"SQLite format 3")
    assert main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out"), "--db", str(db), "--ungated"]) == 0
    assert json.loads(capsys.readouterr().out)["exported"] == 1
    assert _sha(db) == before and db.read_bytes().startswith(b"SQLite format 3")
    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT")
    SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False).close()  # still a plaintext vault
    # An encrypted vault: same guarantee (no integrity or index rewrite, no WAL growth into the main file).
    enc = tmp_path / "enc.sqlite"
    v = SQLiteMemoryVault(str(enc), passphrase=PASSPHRASE, auto_gate=False, verification_quorum=1)
    v.put("decision", "a", "Alpha.", scope="default", origin="user", epistemic_state="verified")
    v.close()
    before = _sha(enc)
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    assert main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "out2"), "--db", str(enc), "--ungated"]) == 0
    assert json.loads(capsys.readouterr().out)["exported"] == 1
    assert main(["okf-import", "--bundle", str(tmp_path / "out2"), "--db", str(enc), "--dry-run"]) == 0
    capsys.readouterr()
    assert _sha(enc) == before


def test_read_only_vault_refuses_writes_and_a_real_import_still_writes(tmp_path, monkeypatch, capsys):
    """C-6: SQLiteMemoryVault(read_only=True) raises ReadOnlyVaultError on any write and never creates a
    file; okf-import without --dry-run opens writable and lands the rows."""
    from kibisis.vault import ReadOnlyVaultError

    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    db = tmp_path / "v.sqlite"
    SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False).close()
    ro = SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False, read_only=True)
    try:
        with pytest.raises(ReadOnlyVaultError):
            ro.put("decision", "x", "No.", scope="default", origin="model")
        assert ro.read_only is True and ro.get("decision", "x", scope="default") is None
    finally:
        ro.close()
    with pytest.raises(FileNotFoundError):
        SQLiteMemoryVault(str(tmp_path / "missing.sqlite"), allow_plaintext=True, read_only=True)
    with pytest.raises(kcfg.ConfigError):
        kcfg.open_vault(str(tmp_path / "missing.sqlite"), read_only=True)
    assert not (tmp_path / "missing.sqlite").exists()
    bundle = tmp_path / "b"
    (bundle / "default" / "decision").mkdir(parents=True)
    (bundle / "default" / "decision" / "a.md").write_text("---\ntype: decision\n---\nAlpha.")
    assert main(["okf-import", "--bundle", str(bundle), "--db", str(db)]) == 0
    assert json.loads(capsys.readouterr().out)["written"] == 1


# ---------------------------------------------------------------- --gate-cmd (positive controls) and L9


def test_gate_cmd_timeout_and_non_zero_exit_refuse_the_bundle_and_leave_nothing(tmp_path):
    """failing = bug (positive control). command_gate: a timeout, a launch failure or a non-zero exit all
    return False, export_bundle raises GateRefused and the staging dir is removed."""
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


def test_gate_cmd_stdout_is_summarised_unless_verbose(tmp_path, capsys):
    """L9: whatever the gate prints is summarised on stderr (verdict, exit status, file and line counts); a
    gate that echoes matched text no longer puts vault content on the operator's terminal unless
    --gate-verbose / verbose=True asks for it."""
    vault = build_probe_vault(tmp_path / "v.sqlite")
    cmd = f"{sys.executable} -c 'print(open(__import__(\"sys\").argv[1]).read()[:40])'"
    try:
        export_bundle(vault, parse_profile(DEFAULT_PROFILE_JSON), tmp_path / "bundle", bundle_gate=command_gate(cmd))
        err = capsys.readouterr().err
        assert err.startswith("gate: passed (exit 0, ") and "lines of output; --gate-verbose shows them" in err
        assert "---\ntype:" not in err
        export_bundle(vault, parse_profile(DEFAULT_PROFILE_JSON), tmp_path / "bundle2",
                      bundle_gate=command_gate(cmd, verbose=True))
        err = capsys.readouterr().err
        assert err.startswith("gate: passed (exit 0, ") and "---\ntype:" in err
    finally:
        vault.close()


def test_gate_verbose_flag_is_wired(tmp_path, monkeypatch, capsys):
    """L9: the CLI summarises gate output by default and copies it only with --gate-verbose."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    db = tmp_path / "v.sqlite"
    build_probe_vault(db).close()
    gate = f"{sys.executable} -c 'print(\"hit-marker\")'"
    base = ["okf-export", "--profile", str(write_profile(tmp_path)), "--db", str(db), "--gate-cmd", gate]
    assert main(base + ["--out", str(tmp_path / "o1")]) == 0
    err = capsys.readouterr().err
    assert "gate: passed" in err and "hit-marker" not in err
    assert main(base + ["--out", str(tmp_path / "o2"), "--gate-verbose"]) == 0
    assert "hit-marker" in capsys.readouterr().err

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
