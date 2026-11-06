"""A1 review, atlas fix #5: do the MCP server, ``kibisis admit`` and ``kibisis-review`` open the same
vault and scope under identical environment? And the okf-* defaults.

Convention: each test ASSERTS THE SECURE/CONSISTENT BEHAVIOUR; a failure is the evidence.
Tests marked "documents" pass and record what the code does.
"""

import os
import subprocess
import sys

import pytest


def finding(fid):
    """Defect present at 1299c28: the test's assertion fails. strict xfail -> the suite is green while the
    defect exists and turns RED when it is fixed (remove the marker then). ``pytest --runxfail`` shows raw failures."""
    return pytest.mark.xfail(strict=True, reason=f"{fid}: see review_notes/A1_trust_boundary.md")

from kibisis import KibisisMCPServer
from kibisis.config import default_db_path, open_vault, resolve_scope

KEY = "a1 config test key only, not a secret"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")
    for name in [k for k in os.environ if k.startswith("KIBISIS_")]:
        monkeypatch.delenv(name)


def _git_repo(path):
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    return path


def test_server_admit_and_review_agree_when_scope_env_is_set(tmp_path, monkeypatch):
    """Positive control (what the atlas test covers): with KIBISIS_DB_PATH and KIBISIS_SCOPE set, all
    three resolve the same vault and scope, wherever they run."""
    monkeypatch.setenv("KIBISIS_DB_PATH", str(tmp_path / "vault.db"))
    monkeypatch.setenv("KIBISIS_PASSPHRASE", KEY)
    monkeypatch.setenv("KIBISIS_SCOPE", "proj-a")
    repo = _git_repo(tmp_path / "checkout")
    assert resolve_scope(cwd=str(repo)) == resolve_scope(cwd=str(tmp_path)) == "proj-a"
    assert default_db_path() == str(tmp_path / "vault.db")


def test_without_scope_env_the_scope_depends_on_the_callers_cwd(tmp_path, monkeypatch):
    """Documents (passes): resolve_scope (config.py:113-127) derives the scope from the git checkout
    around the process's cwd. The MCP server inherits its client's cwd; ``kibisis admit`` and
    ``kibisis-review`` take the person's shell cwd. Same env, different directory: different scope,
    and the admit lands on a namesake or on "not found" rather than on the agent's entry."""
    monkeypatch.setenv("KIBISIS_DB_PATH", str(tmp_path / "vault.db"))
    monkeypatch.setenv("KIBISIS_PASSPHRASE", KEY)
    repo_a = _git_repo(tmp_path / "project-a")
    repo_b = _git_repo(tmp_path / "project-b")
    plain = tmp_path / "plain"
    plain.mkdir()
    s_a, s_b, s_plain = resolve_scope(cwd=str(repo_a)), resolve_scope(cwd=str(repo_b)), resolve_scope(cwd=str(plain))
    assert s_a.startswith("project:project-a-") and s_b.startswith("project:project-b-") and s_plain == "default"
    assert len({s_a, s_b, s_plain}) == 3
    # The server built from inside repo_a works in repo_a's scope; the same server class from `plain` does not.
    monkeypatch.chdir(repo_a)
    v = open_vault()
    server = KibisisMCPServer(vault=v, scope=None)
    assert server.scope == s_a
    v.close()


def test_admit_from_another_directory_names_the_scope_that_holds_the_entry(tmp_path, monkeypatch):
    """Atlas #5 residual, as fixed: the scope still comes from the cwd (a git checkout gets its own
    scope, by design), so an admit run from the home directory does not find the entry the server wrote
    inside the checkout. What changed: every run prints the vault path and the scope it resolved, and a
    miss lists the scopes that DO hold ``category:key`` so the person can pass ``--scope``. With
    ``--scope`` the admit succeeds."""
    import pty

    db = tmp_path / "vault.db"
    monkeypatch.setenv("KIBISIS_DB_PATH", str(db))
    monkeypatch.setenv("KIBISIS_PASSPHRASE", KEY)
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "1")
    repo = _git_repo(tmp_path / "checkout")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.chdir(repo)
    v = open_vault()
    server = KibisisMCPServer(vault=v, scope=None)
    server_scope = server.scope
    resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": "kibisis_remember", "arguments": {"category": "c", "key": "k", "content": "Ship on Tuesdays"}}})
    assert not resp["result"]["isError"]
    v.close()

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    master, slave = pty.openpty()
    try:
        r = subprocess.run([sys.executable, "-m", "kibisis", "admit", "--category", "c", "--key", "k", "--by", "user"],
                           stdin=slave, capture_output=True, text=True, env=env, timeout=60, cwd=str(home))
    finally:
        os.close(slave)
        os.close(master)
    assert r.returncode == 1, (r.stdout, r.stderr, server_scope)
    assert f"vault {db}" in r.stderr and "scope 'default'" in r.stderr, r.stderr
    assert repr(server_scope) in r.stderr and "--scope" in r.stderr or "KIBISIS_SCOPE" in r.stderr, r.stderr

    master, slave = pty.openpty()
    try:
        r = subprocess.run([sys.executable, "-m", "kibisis", "admit", "--category", "c", "--key", "k", "--by", "user",
                            "--scope", server_scope],
                           stdin=slave, capture_output=True, text=True, env=env, timeout=60, cwd=str(home))
    finally:
        os.close(slave)
        os.close(master)
    assert r.returncode == 0, (r.stdout, r.stderr, server_scope)
    assert f"[scope={server_scope}]" in r.stdout, (r.stdout, r.stderr, server_scope)


@pytest.mark.skip(reason="okf-export/okf-import default db path is area C (__main__.py okf wiring); fixed on that branch")
def test_okf_commands_default_to_a_different_vault_path_than_the_server(tmp_path, monkeypatch):
    """FAILS if the defect exists. __main__.py:20 hard-codes ``~/.hermes/kibisis/vault.sqlite`` for
    okf-export/okf-import, while the server, admit and review use config.default_db_path()
    (``~/.local/share/kibisis/vault.sqlite`` on Linux). An operator who runs okf-import without --db
    on a fresh install gets "no vault" instead of the server's vault (fails closed), or imports into a
    stale ~/.hermes vault if one exists."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    code = (
        "import kibisis.__main__ as m, kibisis.config as c; "
        "print(m.DEFAULT_DB_PATH); print(c.default_db_path())"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path), "HOME": str(tmp_path)}, timeout=60)
    assert out.returncode == 0, out.stderr
    okf_default, server_default = out.stdout.strip().splitlines()
    assert okf_default == server_default, (okf_default, server_default)
