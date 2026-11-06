"""A2 review doors: what the TTY guard and the uid identity do and do not stop (kibisis 1299c28).

Every test here states in its docstring whether it asserts the INSECURE behaviour (it passes, which
proves the gap is present at this commit) or the SECURE behaviour (its failure would prove the gap).
Positive controls are kept beside each bypass so a pass cannot come from a broken harness.

Run: cd <worktree> && ARGUS_LEDGER_PATH=$TMPDIR/argus_a2.jsonl PYTHONPATH=src <venv>/python -m pytest -q -p no:cacheprovider tests/review_a2_review_doors.py
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys

import pytest

from kibisis import EpistemicState
from kibisis._operator import account_identity
from kibisis.config import login_name, open_vault

KEY = "review-a2 test key only, not a secret"
PYTHONPATH = os.pathsep.join(sys.path)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")
    for name in [k for k in os.environ if k.startswith("KIBISIS_")]:
        monkeypatch.delenv(name)


@pytest.fixture
def on_disk(tmp_path, monkeypatch):
    """A passphrase vault in scope ``proj-a`` holding one model-origin candidate ``c:k``; quorum 1 so one
    approval shows the full effect of a bypass."""
    db = tmp_path / "vault.db"
    monkeypatch.setenv("KIBISIS_DB_PATH", str(db))
    monkeypatch.setenv("KIBISIS_PASSPHRASE", KEY)
    monkeypatch.setenv("KIBISIS_SCOPE", "proj-a")
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "1")
    v = open_vault()
    v.remember("c", "k", "fact", origin="model", scope="proj-a")
    v.close()
    return db


def _state(category="c", key="k"):
    v = open_vault()
    try:
        e = v.get(category, key, scope="proj-a")
        return e.epistemic_state, dict(e.metadata)
    finally:
        v.close()


def _env_for_subprocess():
    return {**os.environ, "PYTHONPATH": PYTHONPATH}


def _run_no_tty(argv):
    """Run ``argv`` exactly as an agent's shell tool does: stdin on /dev/null, no controlling terminal."""
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=_env_for_subprocess(), timeout=60)


REVIEW_APPROVE = [sys.executable, "-m", "kibisis.review", "approve", "c", "k"]
ADMIT = [sys.executable, "-m", "kibisis", "admit", "--category", "c", "--key", "k", "--by", "user"]


# --- positive control: the guard does stop a plain pipe ---------------------------------------------------


@pytest.mark.parametrize("argv", [REVIEW_APPROVE, ADMIT], ids=["review-approve", "admit"])
def test_control_plain_pipe_is_refused(on_disk, argv):
    """Positive control (SECURE behaviour, passes): with stdin on /dev/null both commands exit 3 and change nothing."""
    r = _run_no_tty(argv)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "interactive terminal" in r.stderr
    state, meta = _state()
    assert state == EpistemicState.CANDIDATE
    assert "attestations" not in meta


# --- finding: the guard is a TTY check, and a shell can make a TTY -------------------------------------------


@pytest.mark.parametrize("argv", [REVIEW_APPROVE, ADMIT], ids=["review-approve", "admit"])
def test_pty_spawn_from_a_non_tty_shell_drives_the_verdict(on_disk, argv):
    """INSECURE behaviour (passes = bypass present): ``python -c 'import pty; pty.spawn(...)'`` run with stdin
    on /dev/null gives the command a pseudo-terminal, so the verdict lands and the entry is verified.
    This is the same technique tests/test_atlas_limits_20261105.py::_run uses to test the happy path."""
    wrapper = [sys.executable, "-c", "import pty, sys; sys.exit(pty.spawn(sys.argv[1:]))", *argv]
    r = _run_no_tty(wrapper)
    assert r.returncode == 0, r.stdout + r.stderr
    state, meta = _state()
    assert state == EpistemicState.VERIFIED
    assert meta["attestations"] == [account_identity()]


@pytest.mark.skipif(shutil.which("script") is None, reason="util-linux script(1) not installed")
@pytest.mark.parametrize("argv", [REVIEW_APPROVE, ADMIT], ids=["review-approve", "admit"])
def test_script_qec_from_a_non_tty_shell_drives_the_verdict(on_disk, argv):
    """INSECURE behaviour (passes = bypass present): ``script -qec '<cmd>' /dev/null`` with stdin on /dev/null
    is enough; no Python is needed, any shell tool can do it."""
    r = _run_no_tty(["script", "-qec", shlex.join(argv), "/dev/null"])
    assert r.returncode == 0, r.stdout + r.stderr
    state, _ = _state()
    assert state == EpistemicState.VERIFIED


# --- finding: the guard lives only in the CLI wrappers ---------------------------------------------------


def test_review_entity_and_admit_have_no_terminal_check_at_all(on_disk):
    """INSECURE behaviour (passes = gap present): ``vault.review_entity`` and ``vault.admit`` are the functions
    the CLIs call after their check; a Python process with stdin on /dev/null calls them directly, choosing
    any ``reviewer_id`` string, and mints ``verified`` with no terminal and no account lookup."""
    code = (
        "import sys; assert not sys.stdin.isatty()\n"
        "from kibisis.config import open_vault\n"
        "v = open_vault()\n"
        "v.admit('c', 'k', reviewer='not-an-account', reviewer_origin='user', scope='proj-a')\n"
        "v.close()\n"
    )
    r = _run_no_tty([sys.executable, "-c", code])
    assert r.returncode == 0, r.stdout + r.stderr
    state, meta = _state()
    assert state == EpistemicState.VERIFIED
    assert meta["attestations"] == ["not-an-account"]


# --- finding: login_name() (pre-a15 identity) and account_identity() disagree under USER/LOGNAME ----------------


def test_login_name_follows_env_while_account_identity_does_not(monkeypatch):
    """INSECURE-adjacent behaviour (passes = the two identity functions can disagree): ``login_name`` is
    ``getpass.getuser``, which reads LOGNAME/USER/LNAME/USERNAME first; ``account_identity`` reads the uid.
    An environment variable therefore makes the pre-a15 record name differ from today's account name."""
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.setenv(name, "someone-else")
    assert login_name() == "someone-else"
    assert account_identity() != "someone-else"


def test_one_person_pre_a15_typed_name_plus_post_a15_account_reaches_quorum_two(tmp_path, monkeypatch):
    """INSECURE behaviour (passes = gap present): the default quorum is 2 distinct accounts. An approval
    recorded by the a14 CLI under a typed ``--reviewer`` label (here written through ``review_entity`` with the
    same ``reviewer_id`` the old CLI stored) plus one approval by the same person's OS account today is two
    attestations, and the entry is verified by one person. README.md:127 documents the old names 'still
    count'; this test pins that the sum crosses the quorum."""
    db = tmp_path / "vault.db"
    monkeypatch.setenv("KIBISIS_DB_PATH", str(db))
    monkeypatch.setenv("KIBISIS_PASSPHRASE", KEY)
    monkeypatch.setenv("KIBISIS_SCOPE", "proj-a")
    v = open_vault()
    assert v.verification_quorum == 2
    v.remember("c", "k", "fact", origin="model", scope="proj-a")
    old = v.review_entity("c", "k", "verified", scope="proj-a", reviewer_id="alice")  # a14-style typed name
    assert old.epistemic_state == EpistemicState.CANDIDATE and old.metadata["verification_pending"] == {"have": 1, "need": 2}
    v.close()
    wrapper = [sys.executable, "-c", "import pty, sys; sys.exit(pty.spawn(sys.argv[1:]))", *REVIEW_APPROVE]
    r = _run_no_tty(wrapper)
    assert r.returncode == 0, r.stdout + r.stderr
    state, meta = _state()
    assert state == EpistemicState.VERIFIED
    assert meta["attestations"] == ["alice", account_identity()]


def test_account_identity_falls_back_to_uid_string_without_passwd(monkeypatch):
    """Control (passes): without a passwd entry the identity is ``uid-<n>``, the same string ``login_name`` gives
    only when no USER/LOGNAME variable is set. With one set, ``login_name`` returns the variable instead."""
    import pwd

    def no_entry(uid):
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", no_entry)
    assert account_identity() == f"uid-{os.getuid()}"
    monkeypatch.setenv("LOGNAME", "typed-name")
    assert login_name() == "typed-name"
