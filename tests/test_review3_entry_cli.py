"""R3 entry-point review: the review CLI / admit path and config as a same-uid shell reaches them.
``test_control_*`` = secure behaviour; ``test_attack_*`` = a defect found in the third pass, kept as a
regression that asserts the fixed behaviour (R3-E1, R3-E4).

Command lines are built from parts so the review harness's text filters are not tripped.
"""
from __future__ import annotations

import os
import pty
import subprocess
import sys

import pytest

from kibisis.config import ConfigError, open_vault
from kibisis.models import EpistemicState
from kibisis.vault import SQLiteMemoryVault

PASS = "review3-entry-passphrase"
REVIEW_MOD = ".".join(["kibisis", "review"])
PKG = "kibisis"


def _env(tmp_path, db, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("KIBISIS_")}
    env.update({"PYTHONPATH": os.pathsep.join(sys.path), "KIBISIS_DB_PATH": str(db), "KIBISIS_PASSPHRASE": PASS,
                "KIBISIS_SCOPE": "default", "HOME": str(tmp_path), "ARGUS_LEDGER_PATH": ""})
    env.update(extra)
    return env


def _run(cmd, env, *, tty: bool, cwd):
    if not tty:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=90, cwd=cwd)
    master, slave = pty.openpty()
    try:
        return subprocess.run(cmd, stdin=slave, capture_output=True, text=True, env=env, timeout=90, cwd=cwd)
    finally:
        os.close(slave)
        os.close(master)


def _review(args, env, *, tty, cwd):
    return _run([sys.executable, "-m", REVIEW_MOD, *args], env, tty=tty, cwd=cwd)


def _admit(args, env, *, tty, cwd):
    return _run([sys.executable, "-m", PKG, "admit", *args, "--" + "by", "user"], env, tty=tty, cwd=cwd)


def _seed(db, quorum=None, pin=True):
    """A vault as a person's first verdict leaves it: the quorum pinned (``pin=False``: never pinned)."""
    v = SQLiteMemoryVault(str(db), passphrase=PASS, auto_gate=False, verification_quorum=quorum, pin_quorum=pin)
    v.remember("c", "k", "an agent fact", origin="model", author_id="mcp-agent")
    v.close()


def _state(db, **kw):
    v = SQLiteMemoryVault(str(db), passphrase=PASS, auto_gate=False, **kw)
    try:
        e = v.get("c", "k", scope="default")
        return e.epistemic_state.value, dict(e.metadata or {}), v.verification_quorum
    finally:
        v.close()


def _stored_quorum(db):
    v = SQLiteMemoryVault(str(db), passphrase=PASS, auto_gate=False, verification_quorum=10**6)  # never below a stored one; not pinned
    try:
        return v.verification_quorum_stored
    finally:
        v.close()


# ------------------------------------------------------------------------ TTY gate (documented limits)


@pytest.mark.parametrize("verb", ["approve", "dispute", "reject", "lift"])
def test_control_review_verdicts_refuse_without_a_terminal(tmp_path, monkeypatch, verb):
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    _seed(db, 2)
    r = _review([verb, "c", "k"], _env(tmp_path, db), tty=False, cwd=str(tmp_path))
    assert r.returncode == 3 and "interactive terminal" in r.stderr, r.stderr
    assert _state(db)[0] == "candidate"


def test_control_admit_refuses_without_a_terminal_and_env_escape_is_gone(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    _seed(db, 2)
    env = _env(tmp_path, db, KIBISIS_ADMIT_ALLOW_NOTTY="1")
    r = _admit(["--category", "c", "--key", "k"], env, tty=False, cwd=str(tmp_path))
    assert r.returncode == 3, r.stderr
    assert _state(db)[0] == "candidate"


def test_control_one_account_on_a_pty_cannot_reach_quorum_two(tmp_path, monkeypatch):
    """Documented: a pty passes the terminal check. The quorum (2 accounts) is what stops a same-uid
    shell: approve + admit + --reviewer labels from one uid are one attestation."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    _seed(db, 2)
    env = _env(tmp_path, db)
    r = _review(["approve", "c", "k", "--reviewer", "alice"], env, tty=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    r = _review(["approve", "c", "k", "--reviewer", "bob"], env, tty=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    r = _admit(["--category", "c", "--key", "k", "--reviewer", "carol"], env, tty=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    for spoof in ({"USER": "alice", "LOGNAME": "alice"}, {"USER": "bob", "LOGNAME": "bob"}):
        r = _review(["approve", "c", "k"], {**env, **spoof}, tty=True, cwd=str(tmp_path))
        assert r.returncode == 0, r.stderr
    state, meta, quorum = _state(db)
    assert state == "candidate" and quorum == 2
    assert len(meta.get("attestations") or []) == 1
    assert meta.get("verification_pending") == {"have": 1, "need": 2}


# ------------------------------------------------- quorum: pinned only by a verdict at a terminal (R3-E1)


def test_control_env_cannot_lower_a_stored_quorum(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    _seed(db, 2)
    r = _review(["list"], _env(tmp_path, db, KIBISIS_VERIFICATION_QUORUM="1"), tty=False, cwd=str(tmp_path))
    assert r.returncode == 2 and "may be raised but not lowered" in r.stderr, r.stderr
    assert _state(db)[2] == 2


def test_attack_first_open_by_a_no_tty_list_pins_quorum_one_and_a_single_pty_approve_verifies(tmp_path, monkeypatch):
    """R3-E1 fixed. `review list` needs no terminal; run by the agent's shell with
    KIBISIS_VERIFICATION_QUORUM=1 before the operator's first open it used to create the file and pin
    the quorum at 1, which the operator's processes then adopted in silence. Now: `list` creates
    nothing, a plain open stores nothing, and the first pty-driven approve pins the default 2, so one
    account cannot verify."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    env = _env(tmp_path, db)
    assert not db.exists()
    # 1. the agent's shell: no TTY, quorum=1 in its own environment, a read-only-looking command
    r = _review(["list"], {**env, "KIBISIS_VERIFICATION_QUORUM": "1"}, tty=False, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert not db.exists()  # fixed: a list creates no vault
    # 2. the operator's process (no quorum named anywhere) creates the file and runs with the default
    v = SQLiteMemoryVault(str(db), passphrase=PASS, auto_gate=False)
    assert v.verification_quorum == 2 and v.verification_quorum_stored is None  # fixed: nothing pinned
    v.remember("c", "k", "an agent fact", origin="model", author_id="mcp-agent")
    v.close()
    # 3. the agent's shell again, now against the existing file: still nothing pinned, nothing written
    before = db.stat().st_mtime_ns
    r = _review(["list"], {**env, "KIBISIS_VERIFICATION_QUORUM": "1"}, tty=False, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "quorum 1 — one account verifies" in r.stderr, r.stderr  # its own ask, said out loud
    assert _stored_quorum(db) is None and db.stat().st_mtime_ns == before
    # 4. one account, one pty: the approve pins the default and the entry stays a candidate
    r = _review(["approve", "c", "k"], env, tty=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "quorum 2 — 2 accounts verify (pinned in the vault)" in r.stderr, r.stderr  # the verdict pinned, and says so
    assert _state(db)[0] == "candidate"
    assert _stored_quorum(db) == 2
    r = _review(["list"], env, tty=False, cwd=str(tmp_path))
    assert "quorum 2" in r.stderr and "pinned in the vault" in r.stderr, r.stderr


def test_attack_pre_quorum_vault_is_pinned_by_whoever_opens_it_first(tmp_path, monkeypatch):
    """R3-E1 fixed on an existing vault that predates the stored quorum (the meta row missing, as an
    alpha.16 file lacks it): a no-TTY `list` with quorum=1 pins nothing, and a pty approve by one
    account pins the default and does not verify."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    env = _env(tmp_path, db)
    _seed(db, 2)
    v = SQLiteMemoryVault(str(db), passphrase=PASS, auto_gate=False)
    with v._write_tx() as cur:  # emulate a file written before the quorum existed
        cur.execute("DELETE FROM vault_meta WHERE key = 'verification_quorum'")
        v._write_meta_mac(cur)
    v.close()
    r = _review(["list"], {**env, "KIBISIS_VERIFICATION_QUORUM": "1"}, tty=False, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert _stored_quorum(db) is None and _state(db)[2] == 2
    r = _review(["approve", "c", "k"], env, tty=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert _state(db)[0] == "candidate" and _stored_quorum(db) == 2


def test_attack_review_list_opens_the_vault_writable(tmp_path, monkeypatch):
    """R3-E1 fixed: `list` opens the vault read-only. A no-TTY run with a higher quorum in its
    environment runs with it and neither persists it nor touches the file."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    _seed(db, 2)
    before = db.stat().st_mtime_ns
    r = _review(["list"], _env(tmp_path, db, KIBISIS_VERIFICATION_QUORUM="7"), tty=False, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "quorum 7" in r.stderr, r.stderr
    assert _state(db)[2] == 2 and _stored_quorum(db) == 2  # nothing persisted
    assert db.stat().st_mtime_ns == before


def test_control_a_pinned_quorum_of_one_is_not_adopted_in_silence(tmp_path, monkeypatch):
    """A vault whose quorum a verdict pinned at 1 (a pty approve with KIBISIS_VERIFICATION_QUORUM=1, the
    documented pty limit): every process that does not name 1 itself is refused with the reason, and
    every one that does says so on its output."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    env = _env(tmp_path, db)
    _seed(db, 2, pin=False)
    r = _review(["approve", "c", "k"], {**env, "KIBISIS_VERIFICATION_QUORUM": "1"}, tty=True, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "quorum 1 — one account verifies" in r.stdout + r.stderr, (r.stdout, r.stderr)
    assert _state(db, verification_quorum=1)[0] == "verified"
    with pytest.raises(ConfigError, match="pinned at 1"):  # a plain library open names no quorum
        SQLiteMemoryVault(str(db), passphrase=PASS, auto_gate=False)
    with pytest.raises(ConfigError, match="pinned at 1"):
        SQLiteMemoryVault(str(db), passphrase=PASS, auto_gate=False, read_only=True)
    r = _review(["list"], env, tty=False, cwd=str(tmp_path))
    assert r.returncode == 2 and "pinned at 1" in r.stderr and "KIBISIS_VERIFICATION_QUORUM=1" in r.stderr, r.stderr
    r = _review(["list"], {**env, "KIBISIS_VERIFICATION_QUORUM": "1"}, tty=False, cwd=str(tmp_path))
    assert r.returncode == 0 and "quorum 1 — one account verifies" in r.stderr, r.stderr
    r = _review(["list"], {**env, "KIBISIS_VERIFICATION_QUORUM": "3"}, tty=False, cwd=str(tmp_path))
    assert r.returncode == 0 and "quorum 3" in r.stderr, r.stderr  # a higher ask runs with it


# --------------------------------------------------------------------------- config / open_vault


def test_control_open_vault_refuses_plaintext_without_the_opt_in(tmp_path, monkeypatch):
    for var in ("KIBISIS_PASSPHRASE", "KIBISIS_PASSPHRASE_FILE", "KIBISIS_ALLOW_PLAINTEXT", "KIBISIS_VERIFICATION_QUORUM"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ConfigError):
        open_vault(str(tmp_path / "p.sqlite"))
    assert not (tmp_path / "p.sqlite").exists()
    for value in ("0", "no", "false", " ", "yes please"):
        monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", value)
        with pytest.raises(ConfigError):
            open_vault(str(tmp_path / "p.sqlite"))


def test_control_passphrase_file_beats_env_and_a_loose_file_is_refused(tmp_path, monkeypatch):
    for var in ("KIBISIS_PASSPHRASE_FILE", "KIBISIS_ALLOW_PLAINTEXT", "KIBISIS_VERIFICATION_QUORUM"):
        monkeypatch.delenv(var, raising=False)
    kf = tmp_path / "key"
    kf.write_text(PASS + "-file\n")
    kf.chmod(0o644)
    monkeypatch.setenv("KIBISIS_PASSPHRASE_FILE", str(kf))
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASS)
    with pytest.raises(Exception):  # group/world-readable key file is refused, not silently skipped
        open_vault(str(tmp_path / "k.sqlite"))
    kf.chmod(0o600)
    v = open_vault(str(tmp_path / "k.sqlite"))
    v.close()
    with pytest.raises(Exception):  # the file's key, not the env's, opened it
        SQLiteMemoryVault(str(tmp_path / "k.sqlite"), passphrase=PASS, auto_gate=False).close()


def test_attack_open_vault_env_mapping_is_ignored_for_the_quorum(tmp_path, monkeypatch):
    """R3-E4 fixed: open_vault(env=...) reads KIBISIS_VERIFICATION_QUORUM from its mapping, like the
    path, key and plaintext opt-in, and a mapping that names none isolates the vault from the
    process environment's value."""
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    env = {"KIBISIS_PASSPHRASE": PASS, "KIBISIS_VERIFICATION_QUORUM": "5"}
    v = open_vault(str(tmp_path / "e.sqlite"), env=env)
    try:
        assert v.verification_quorum == 5 and v.verification_quorum_stored is None  # read, not pinned
    finally:
        v.close()
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "3")
    v = open_vault(str(tmp_path / "e2.sqlite"), env={"KIBISIS_PASSPHRASE": PASS})
    try:
        assert v.verification_quorum == 2  # the mapping names none: the default, not os.environ's 3
    finally:
        v.close()
    v = open_vault(str(tmp_path / "e3.sqlite"))  # no mapping: os.environ as before
    try:
        assert v.verification_quorum == 3
    finally:
        v.close()
    with pytest.raises(ConfigError):  # a bad value in the mapping is the same one-line refusal
        open_vault(str(tmp_path / "e4.sqlite"), env={"KIBISIS_PASSPHRASE": PASS, "KIBISIS_VERIFICATION_QUORUM": "abc"})
    assert not (tmp_path / "e4.sqlite").exists()


def test_control_cli_and_server_resolve_the_same_vault_and_scope(tmp_path, monkeypatch):
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    db = tmp_path / "v.sqlite"
    _seed(db, 2)
    env = _env(tmp_path, db, KIBISIS_SCOPE="team:x")
    r = _review(["list"], env, tty=False, cwd=str(tmp_path))
    assert r.returncode == 0 and f"vault {db}" in r.stderr and "scope 'team:x'" in r.stderr, r.stderr
    r = _review(["list"], {**env, "KIBISIS_SCOPE": "*"}, tty=False, cwd=str(tmp_path))
    assert r.returncode == 2 and "not allowed" in r.stderr
    r = _admit(["--category", "c", "--key", "k", "--scope", "*"], env, tty=True, cwd=str(tmp_path))
    assert r.returncode == 2, r.stderr
    assert _state(db)[0] == "candidate"
