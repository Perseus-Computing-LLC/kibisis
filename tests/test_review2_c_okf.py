"""Second-pass review (R2) of the area C fixes: OKF / CLI vault paths and read-only opens, as regression
tests. ``test_control_*`` asserts behaviour that was already correct; ``test_fixed_*`` (formerly
``test_attack_*``) asserts the behaviour after the R2-C fixes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _okf_fixtures import write_profile  # noqa: E402

from kibisis import config as kcfg  # noqa: E402
from kibisis.__main__ import main  # noqa: E402
from kibisis.vault import ReadOnlyVaultError, SQLiteMemoryVault, VaultIntegrityError  # noqa: E402

PASSPHRASE = "review2-c-okf-passphrase-not-secret"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("KIBISIS_PASSPHRASE", "KIBISIS_PASSPHRASE_FILE", "KIBISIS_ALLOW_PLAINTEXT", "KIBISIS_DB_PATH"):
        monkeypatch.delenv(name, raising=False)


def _sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _sidecars(db: Path) -> dict:
    return {s: Path(str(db) + s).exists() for s in ("-wal", "-shm")}


def _make(db: Path, **kw) -> None:
    v = SQLiteMemoryVault(str(db), auto_gate=False, verification_quorum=1, **kw)
    v.put("decision", "a", "Alpha.", scope="default", origin="user", epistemic_state="verified")
    v.put("decision", "b", "Beta.", scope="default", origin="user", epistemic_state="verified")
    v.close()


# ---------------------------------------------------------------- C-6 read-only opens


@pytest.mark.parametrize("kw", [dict(allow_plaintext=True), dict(passphrase=PASSPHRASE)], ids=["plain", "keyed"])
def test_fixed_read_only_open_leaves_the_vault_file_untouched_and_only_empty_sidecars(tmp_path, kw):
    """R2-C-3, settled by documenting it: a read-only open of a WAL-mode vault needs SQLite's shared-memory
    index, so it may create and leave ``-wal`` (empty) and ``-shm`` beside the file. The vault file's bytes
    and mtime are unchanged, any ``-wal`` left behind is empty (no frames: nothing was written), and the next
    writable open removes both; SECURITY.md, ``__main__`` and ``config.open_vault`` now say exactly that."""
    db = tmp_path / "v.sqlite"
    _make(db, **kw)
    assert _sidecars(db) == {"-wal": False, "-shm": False}
    before = (_sha(db), db.stat().st_mtime_ns)
    ro = SQLiteMemoryVault(str(db), read_only=True, auto_gate=False, **kw)
    try:
        assert [r.key for r in ro.list_entities(scope="*", include_unverified=True)] == ["a", "b"]
    finally:
        ro.close()
    assert (_sha(db), db.stat().st_mtime_ns) == before  # the vault file itself is untouched
    wal = Path(str(db) + "-wal")
    assert not wal.exists() or wal.stat().st_size == 0
    writer = SQLiteMemoryVault(str(db), auto_gate=False, verification_quorum=1, **kw)
    writer.close()
    assert _sidecars(db) == {"-wal": False, "-shm": False}  # the next writable open cleans up
    assert _sha(db) == before[0]


def test_control_read_only_refuses_every_write_path_and_reads_a_live_writer(tmp_path):
    db = tmp_path / "v.sqlite"
    _make(db, allow_plaintext=True)
    writer = SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False, verification_quorum=1)
    ro = SQLiteMemoryVault(str(db), allow_plaintext=True, read_only=True, auto_gate=False)
    try:
        writer.put("decision", "c", "Gamma.", scope="default", origin="user", epistemic_state="verified")
        assert ro.get("decision", "c", scope="default").content == "Gamma."  # sees the writer's WAL frames
        assert [h.entity.key for h in ro.search("Gamma", scope="default", include_unverified=True)] == ["c"]
        for write in (lambda: ro.put("decision", "d", "x", scope="default"),
                      lambda: ro.tombstone("decision", "a", scope="default"),
                      lambda: ro.archive("decision", "a", scope="default"),
                      lambda: ro.put_batch([dict(category="decision", key="e", content="x", scope="default")])):
            with pytest.raises(ReadOnlyVaultError):
                write()
        assert ro.verify_audit_chain() is True
    finally:
        ro.close()
        writer.close()
    assert _sidecars(db) == {"-wal": False, "-shm": False}  # the writer's close cleaned up


def test_control_read_only_open_edge_cases(tmp_path):
    for name, content in [("empty.sqlite", b""), ("notdb.sqlite", b"not a database at all" * 200)]:
        (tmp_path / name).write_bytes(content)
    os.mkdir(tmp_path / "dir.sqlite")
    for name in ("missing.sqlite", "empty.sqlite", "dir.sqlite"):
        with pytest.raises(FileNotFoundError):
            SQLiteMemoryVault(str(tmp_path / name), allow_plaintext=True, read_only=True)
    with pytest.raises(FileNotFoundError):
        SQLiteMemoryVault(":memory:", allow_plaintext=True, read_only=True)
    with pytest.raises(Exception):
        SQLiteMemoryVault(str(tmp_path / "notdb.sqlite"), allow_plaintext=True, read_only=True)
    assert not (tmp_path / "missing.sqlite").exists()
    assert (tmp_path / "empty.sqlite").stat().st_size == 0
    # a plain file with a passphrase in hand: read as plain, no conversion, no sidecar rewrite of the file
    db = tmp_path / "plain.sqlite"
    _make(db, allow_plaintext=True)
    before = _sha(db)
    ro = SQLiteMemoryVault(str(db), passphrase=PASSPHRASE, read_only=True, auto_gate=False)
    try:
        assert ro.passphrase is None and ro.encrypted_at_rest is False
        assert [r.content for r in ro.list_entities(scope="*", include_unverified=True)] == ["Alpha.", "Beta."]
    finally:
        ro.close()
    assert _sha(db) == before and db.read_bytes().startswith(b"SQLite format 3")
    # wrong passphrase on a keyed vault, read-only
    enc = tmp_path / "enc.sqlite"
    _make(enc, passphrase=PASSPHRASE)
    with pytest.raises(ValueError, match="authenticate"):
        SQLiteMemoryVault(str(enc), passphrase="wrong-passphrase-0123456789", read_only=True)


def test_fixed_read_only_refusal_of_an_edited_down_integrity_format_names_the_edit(tmp_path):
    """R2-C-5: a keyed vault whose ``integrity_format`` was edited to 1 (F13) is refused read-only with the
    same reason the writable open gives (the record was edited), not with "open it writable once first";
    and a wrong passphrase on a vault that carries a key check is a key failure, not an upgrade notice."""
    import sqlcipher3

    enc = tmp_path / "enc.sqlite"
    _make(enc, passphrase=PASSPHRASE)
    conn = sqlcipher3.connect(str(enc))
    conn.execute(f"PRAGMA key = '{PASSPHRASE}'")
    conn.execute("UPDATE vault_meta SET value = '1' WHERE key = 'integrity_format'")
    conn.commit()
    conn.close()
    with pytest.raises(VaultIntegrityError, match="edited") as exc:
        SQLiteMemoryVault(str(enc), passphrase=PASSPHRASE, read_only=True)
    assert "writable" not in str(exc.value)
    with pytest.raises(VaultIntegrityError, match="edited"):
        SQLiteMemoryVault(str(enc), passphrase=PASSPHRASE)
    # the plain-file keyed fallback (no sqlcipher3) is where a wrong passphrase used to read as "needs an
    # upgrade"; with a key check present it is reported as the key failure it is
    import kibisis.vault as kv

    plain = tmp_path / "plain.sqlite"
    _make(plain, allow_plaintext=True)
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
        monkey.setattr(kv, "sqlcipher3", __import__("sqlite3"))
        keyed = SQLiteMemoryVault(str(plain), passphrase=PASSPHRASE, auto_gate=False)  # keys the plain file
        keyed.close()
        with pytest.raises(ValueError, match="authenticate"):
            SQLiteMemoryVault(str(plain), passphrase="wrong-passphrase-0123456789", read_only=True)
        ro = SQLiteMemoryVault(str(plain), passphrase=PASSPHRASE, read_only=True, auto_gate=False)
        try:
            row = ro.get("decision", "a", scope="default")
            assert row is not None and row.content == "Alpha."
        finally:
            ro.close()
    finally:
        monkey.undo()


# ---------------------------------------------------------------- F17 / C-5 / C-11: one vault path, same rules


def test_control_db_flag_beats_env_beats_data_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    explicit, env_db = tmp_path / "flag.sqlite", tmp_path / "env.sqlite"
    _make(explicit, allow_plaintext=True)
    profile = write_profile(tmp_path)
    monkeypatch.setenv("KIBISIS_DB_PATH", str(env_db))
    assert main(["okf-export", "--profile", str(profile), "--out", str(tmp_path / "o1"), "--db", str(explicit), "--ungated"]) == 0
    assert json.loads(capsys.readouterr().out)["exported"] == 2
    assert main(["okf-export", "--profile", str(profile), "--out", str(tmp_path / "o2"), "--ungated"]) == 1
    assert f"no vault at {env_db}" in capsys.readouterr().err and not env_db.exists()
    monkeypatch.delenv("KIBISIS_DB_PATH")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    expected = str(tmp_path / "xdg" / "kibisis" / "vault.sqlite") if not sys.platform.startswith(("darwin", "win")) else kcfg.default_db_path()
    assert main(["okf-import", "--bundle", str(tmp_path / "o1"), "--dry-run"]) == 1
    assert f"no vault at {expected}" in capsys.readouterr().err and not Path(expected).exists()
    import kibisis.__main__ as cli

    assert cli.DEFAULT_DB_PATH == expected


def test_control_import_writing_path_honours_allow_plaintext_and_scope(tmp_path, monkeypatch, capsys):
    db = tmp_path / "v.sqlite"
    _make(db, allow_plaintext=True)
    bundle = tmp_path / "b"
    for scope in ("default", "other"):
        (bundle / scope / "decision").mkdir(parents=True)
        (bundle / scope / "decision" / "z.md").write_text("---\ntype: decision\n---\nZed.")
    args = ["okf-import", "--bundle", str(bundle), "--db", str(db)]
    assert main(args) == 2 and "No key" in capsys.readouterr().err
    assert main(args + ["--dry-run"]) == 2 and "No key" in capsys.readouterr().err
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    assert main(args + ["--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["written"] == 0
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["written"] == 1  # the out-of-profile scope is skipped
    v = SQLiteMemoryVault(str(db), allow_plaintext=True, auto_gate=False)
    try:
        row = v.get("decision", "z", scope="default")
        assert row is not None and row.origin == "model" and row.epistemic_state == "candidate"
        assert v.get("decision", "z", scope="other") is None
    finally:
        v.close()


def test_control_export_round_trip_and_gate_cmd_argv(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    db = tmp_path / "enc.sqlite"
    _make(db, passphrase=PASSPHRASE)
    before = _sha(db)
    profile = write_profile(tmp_path)
    gate = tmp_path / "gate dir" / "gate.py"
    gate.parent.mkdir()
    gate.write_text("import sys\nprint('matched: Alpha.')\nsys.exit(0 if len(sys.argv) > 1 else 1)\n")
    cmd = f'"{sys.executable}" "{gate}"'
    assert main(["okf-export", "--profile", str(profile), "--out", str(tmp_path / "o"), "--db", str(db), "--gate-cmd", cmd]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["exported"] == 2 and "gate: passed" in captured.err and "Alpha." not in captured.err
    assert main(["okf-export", "--profile", str(profile), "--out", str(tmp_path / "o2"), "--db", str(db), "--gate-cmd", cmd, "--gate-verbose"]) == 0
    assert "matched: Alpha." in capsys.readouterr().err
    assert main(["okf-check", str(tmp_path / "o")]) == 0
    assert main(["okf-import", "--bundle", str(tmp_path / "o"), "--db", str(db), "--dry-run"]) == 0
    assert _sha(db) == before
