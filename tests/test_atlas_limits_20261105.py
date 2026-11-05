"""The limits the Agent Memory Atlas named in its reading of e9ddf61, each closed (0.1.0a15).

- ``kibisis_forget`` could tombstone an entry a person verified. It is now refused, journaled, and
  listed for a person, who carries it out by rejecting the entry. The same holds for a value a
  reviewed entry shares, which the tombstone would otherwise purge with it.
- ``kibisis-review`` had no terminal check. Its verdicts now need one, as ``kibisis admit`` does.
- The verification quorum counted typed ``--reviewer`` names, so one person with two names reached
  ``verified``. The review CLI and ``admit`` now record the operating-system account they run as.
- MCP recall called ``search()``. It now goes through the gated ``recall()``.
- ``admit`` opened ``~/.hermes/kibisis/vault.sqlite`` in scope ``default``. It now resolves the vault,
  key and scope as the MCP server does.
"""

import io
import os
import subprocess
import sys
from unittest import mock

import pytest

from kibisis import EpistemicState, KibisisMCPServer, SQLiteMemoryVault
from kibisis._operator import NotInteractive, account_identity, require_terminal
from kibisis.config import open_vault
from kibisis.review import main as review_main
from kibisis.vault import ReviewedEntryError

KEY = "atlas limits test key only, not a secret"


class _Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")
    for name in [k for k in os.environ if k.startswith("KIBISIS_")]:
        monkeypatch.delenv(name)


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


@pytest.fixture
def server(vault):
    return KibisisMCPServer(vault=vault, scope="default")


@pytest.fixture
def on_disk(tmp_path, monkeypatch):
    """Environment for the CLIs: a passphrase vault in scope ``proj-a``, as the MCP server would open it."""
    db = tmp_path / "vault.db"
    monkeypatch.setenv("KIBISIS_DB_PATH", str(db))
    monkeypatch.setenv("KIBISIS_PASSPHRASE", KEY)
    monkeypatch.setenv("KIBISIS_SCOPE", "proj-a")
    return db


def _call(server, tool, arguments):
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    )
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


def _verified(vault, category, key, content, **kw):
    entity = vault.put(category, key, content, origin="user", author_id="alice", epistemic_state="verified", **kw)
    assert entity.epistemic_state == EpistemicState.VERIFIED
    return entity


def _run(module_args, *, tty):
    """Run ``python -m <module_args>`` with stdin on a pseudo-terminal (``tty=True``) or on /dev/null."""
    import pty

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    cmd = [sys.executable, "-m", *module_args]
    if not tty:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=60)
    master, slave = pty.openpty()
    try:
        return subprocess.run(cmd, stdin=slave, capture_output=True, text=True, env=env, timeout=60)
    finally:
        os.close(slave)
        os.close(master)


# --- kibisis_forget on a reviewed entry ------------------------------------------------------------


def test_mcp_forget_refuses_a_verified_entry_and_records_the_request(vault, server):
    _verified(vault, "ops", "deploy_day", "Deploys go out on Tuesdays.")
    is_error, text = _call(server, "kibisis_forget", {"category": "ops", "key": "deploy_day", "reason": "outdated"})
    assert is_error and text.startswith("Refused")
    assert "kibisis.review reject ops deploy_day" in text
    assert vault.get("ops", "deploy_day").content == "Deploys go out on Tuesdays."
    assert not vault.is_tombstoned("ops", "deploy_day", "Deploys go out on Tuesdays.")
    refusal = [e for e in vault.list_audit_events(limit=10_000) if e.action == "refuse"][-1]
    assert (refusal.category, refusal.key, refusal.author_id) == ("ops", "deploy_day", "mcp-agent")
    assert refusal.metadata["reason"] == "reviewed_entry"
    assert refusal.metadata["detail"] == {"tool": "kibisis_forget", "requested_reason": "outdated"}
    [request] = vault.forget_requests("default")
    assert (request["category"], request["key"], request["reason"]) == ("ops", "deploy_day", "outdated")
    assert vault.verify_audit_chain()


def test_mcp_forget_refuses_an_entry_a_person_disputed(vault, server):
    vault.remember("ops", "pager", "The pager rotation is weekly.", origin="model")
    vault.review_entity("ops", "pager", verdict="disputed", reviewer_id="alice")
    is_error, _ = _call(server, "kibisis_forget", {"category": "ops", "key": "pager"})
    assert is_error
    assert vault.get("ops", "pager") is not None


def test_mcp_forget_refuses_an_entry_a_person_wrote_before_any_review(vault, server):
    """K-R1 for deletes: an agent cannot delete a principal-class entry, reviewed or not."""
    vault.put("ops", "note", "Budget reviews are on the first Monday.", origin="user", author_id="alice")
    assert vault.get("ops", "note").epistemic_state == EpistemicState.CANDIDATE
    is_error, text = _call(server, "kibisis_forget", {"category": "ops", "key": "note"})
    assert is_error and "principal class" in text
    assert vault.get("ops", "note") is not None
    assert [r["key"] for r in vault.forget_requests("default")] == ["note"]


def test_a_tool_origin_request_cannot_delete_an_agents_entry(vault):
    vault.remember("notes", "agent_note", "The cache warms at boot.", origin="model")
    with pytest.raises(ReviewedEntryError, match="agent class"):
        vault.tombstone("notes", "agent_note", origin="tool")
    vault.tombstone("notes", "agent_note", origin="model")  # an equal class may
    assert vault.get("notes", "agent_note") is None


def test_mcp_forget_refuses_a_copy_of_a_reviewed_value(vault, server):
    """A tombstone purges every copy of its value, so forgetting a copy would delete the reviewed one."""
    _verified(vault, "ops", "deploy_day", "Deploys go out on Tuesdays.")
    vault.remember("notes", "copy", "deploys go out on tuesdays", origin="model")  # canonically the same value
    is_error, text = _call(server, "kibisis_forget", {"category": "notes", "key": "copy"})
    assert is_error and "ops:deploy_day" in text
    assert vault.get("ops", "deploy_day") is not None
    assert vault.get("notes", "copy") is not None


def test_mcp_forget_still_deletes_what_no_person_reviewed(vault, server):
    vault.remember("notes", "draft", "Try the blue theme first.", origin="model")
    is_error, text = _call(server, "kibisis_forget", {"category": "notes", "key": "draft"})
    assert not is_error, text
    assert vault.get("notes", "draft") is None
    assert vault.is_tombstoned("notes", "draft", "Try the blue theme first.")
    assert vault.forget_requests("default") == []


def test_a_person_carries_out_a_forget_request_by_rejecting(vault, server):
    _verified(vault, "ops", "deploy_day", "Deploys go out on Tuesdays.")
    _call(server, "kibisis_forget", {"category": "ops", "key": "deploy_day"})
    vault.review_entity("ops", "deploy_day", verdict="revoked", reviewer_id="alice")
    assert vault.get("ops", "deploy_day") is None
    assert vault.is_tombstoned("ops", "deploy_day", "Deploys go out on Tuesdays.")
    assert vault.forget_requests("default") == []


def test_a_later_review_settles_a_forget_request_and_keeps_the_entry(vault, server):
    _verified(vault, "ops", "deploy_day", "Deploys go out on Tuesdays.")
    _call(server, "kibisis_forget", {"category": "ops", "key": "deploy_day"})
    assert len(vault.forget_requests("default")) == 1
    vault.review_entity("ops", "deploy_day", verdict="verified", reviewer_id="alice")
    assert vault.forget_requests("default") == []
    assert vault.get("ops", "deploy_day") is not None


@pytest.mark.parametrize("origin", ["model", "tool", "unknown"])
def test_library_tombstone_from_a_non_principal_origin_spares_reviewed_entries(vault, origin):
    _verified(vault, "ops", "deploy_day", "Deploys go out on Tuesdays.")
    with pytest.raises(ReviewedEntryError):
        vault.tombstone("ops", "deploy_day", reason="agent asked", origin=origin)
    assert vault.get("ops", "deploy_day") is not None
    assert vault.list_tombstones() == []


@pytest.mark.parametrize("origin", ["user", None])
def test_library_tombstone_from_a_person_or_unstated_origin_still_deletes(vault, origin):
    _verified(vault, "ops", "deploy_day", "Deploys go out on Tuesdays.")
    vault.tombstone("ops", "deploy_day", reason="user asked", origin=origin)
    assert vault.get("ops", "deploy_day") is None


def test_a_model_origin_revocation_cannot_delete_a_reviewed_entry(vault):
    _verified(vault, "ops", "deploy_day", "Deploys go out on Tuesdays.")
    with pytest.raises(ReviewedEntryError):
        vault.review_entity("ops", "deploy_day", verdict="revoked", reviewer_id="bot", reviewer_origin="model")
    entity = vault.get("ops", "deploy_day")
    assert entity is not None and entity.epistemic_state == EpistemicState.VERIFIED
    # The refused verdict rolled back whole: no review by the model was recorded either.
    assert all(r.get("reviewer_id") != "bot" for r in entity.metadata.get("human_reviews") or [])


# --- kibisis-review: terminal check -------------------------------------------------------------


def test_require_terminal_refuses_a_pipe_and_accepts_a_terminal():
    with mock.patch("sys.stdin", io.StringIO("")), pytest.raises(NotInteractive):
        require_terminal("kibisis-review approve")
    with mock.patch("sys.stdin", None), pytest.raises(NotInteractive):
        require_terminal("kibisis-review approve")
    with mock.patch("sys.stdin", _Terminal("")):
        require_terminal("kibisis-review approve")


@pytest.mark.parametrize("verdict", ["approve", "dispute", "reject"])
def test_review_verdicts_refuse_without_a_terminal_before_opening_the_vault(on_disk, verdict):
    with mock.patch("sys.stdin", io.StringIO("")):
        assert review_main([verdict, "c", "k"]) == 3
    assert not on_disk.exists()


def test_review_cli_from_a_pipe_changes_nothing_and_at_a_terminal_approves(on_disk, monkeypatch):
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "1")
    v = open_vault()
    v.remember("c", "k", "fact", origin="model", scope="proj-a")
    v.close()
    piped = _run(["kibisis.review", "approve", "c", "k"], tty=False)
    assert piped.returncode == 3, piped.stdout + piped.stderr
    assert "interactive terminal" in piped.stderr
    v = open_vault()
    assert v.get("c", "k", scope="proj-a").epistemic_state == EpistemicState.CANDIDATE
    v.close()
    at_terminal = _run(["kibisis.review", "approve", "c", "k"], tty=True)
    assert at_terminal.returncode == 0, at_terminal.stdout + at_terminal.stderr
    v = open_vault()
    assert v.get("c", "k", scope="proj-a").epistemic_state == EpistemicState.VERIFIED
    v.close()


def test_review_list_needs_no_terminal_and_shows_forget_requests(on_disk, capsys):
    v = open_vault()
    v.remember("c", "pending", "an unreviewed note", origin="model", scope="proj-a")
    v.put("c", "kept", "a reviewed fact", origin="user", author_id="alice", epistemic_state="verified", scope="proj-a")
    server = KibisisMCPServer(vault=v, scope="proj-a")
    _call(server, "kibisis_forget", {"category": "c", "key": "kept", "reason": "agent thinks it is stale"})
    v.close()
    with mock.patch("sys.stdin", io.StringIO("")):
        assert review_main(["list"]) == 0
    out = capsys.readouterr().out
    assert "c:pending" in out
    assert "Requests to forget reviewed entries" in out
    assert "c:kept" in out and "agent thinks it is stale" in out


# --- quorum: accounts, not typed names --------------------------------------------------------------


def test_one_account_with_two_reviewer_names_is_one_approval(on_disk, capsys):
    v = open_vault()  # default quorum: two distinct accounts
    assert v.verification_quorum == 2
    v.remember("c", "k", "fact", origin="model", scope="proj-a")
    v.close()
    with mock.patch("sys.stdin", _Terminal("")):
        assert review_main(["approve", "c", "k", "--reviewer", "alice"]) == 0
        assert review_main(["approve", "c", "k", "--reviewer", "bob"]) == 0
    assert "1 of 2 approvals" in capsys.readouterr().out
    v = open_vault()
    entity = v.get("c", "k", scope="proj-a")
    v.close()
    assert entity.epistemic_state == EpistemicState.CANDIDATE
    assert entity.metadata["attestations"] == [account_identity()]
    assert entity.metadata["verification_pending"] == {"have": 1, "need": 2}
    labels = [r.get("reviewer_label") for r in entity.metadata["human_reviews"]]
    assert labels == ["alice", "bob"]
    assert {r["reviewer_id"] for r in entity.metadata["human_reviews"]} == {account_identity()}


def test_admit_and_review_from_one_account_are_one_approval(on_disk):
    v = open_vault()
    v.remember("c", "k", "fact", origin="model", scope="proj-a")
    v.close()
    admitted = _run(["kibisis", "admit", "--category", "c", "--key", "k", "--by", "user", "--reviewer", "alice"], tty=True)
    assert admitted.returncode == 0, admitted.stdout + admitted.stderr
    assert "1 of 2 approvals" in admitted.stdout
    with mock.patch("sys.stdin", _Terminal("")):
        assert review_main(["approve", "c", "k", "--reviewer", "bob"]) == 0
    v = open_vault()
    entity = v.get("c", "k", scope="proj-a")
    v.close()
    assert entity.epistemic_state == EpistemicState.CANDIDATE
    assert entity.metadata["attestations"] == [account_identity()]


def test_account_identity_ignores_user_and_logname(monkeypatch):
    import pwd

    try:
        expected = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        expected = f"uid-{os.getuid()}"
    for name in ("USER", "LOGNAME", "LNAME", "USERNAME"):
        monkeypatch.setenv(name, "someone-else")
    assert account_identity() == expected


# --- MCP recall goes through the gate ------------------------------------------------------------------


def test_mcp_recall_withholds_and_names_conflicting_verified_entries(vault, server):
    _verified(vault, "profile", "p1", "prefers dark mode in the editor", metadata={"slot": "theme"})
    _verified(vault, "profile", "p2", "prefers light mode in the editor", metadata={"slot": "theme"})
    # Positive control: search() alone returns both sides of the conflict.
    assert {r.entity.key for r in vault.search("mode editor", match="any", scope="default")} == {"p1", "p2"}
    is_error, text = _call(server, "kibisis_recall", {"query": "prefers mode editor"})
    assert not is_error, text
    assert 'count="0"' in text and 'withheld="2"' in text
    assert '<withheld ref="profile:p1" reason="conflict_unresolved" conflicts_with="profile:p2"/>' in text
    assert '<withheld ref="profile:p2" reason="conflict_unresolved" conflicts_with="profile:p1"/>' in text
    assert "dark mode" not in text and "light mode" not in text


def test_mcp_recall_counts_hits_below_the_gate_without_showing_them(vault, server):
    vault.remember("ops", "backup", "The backup runs nightly at two.", origin="model")
    query = "backup retention policy owner"  # one word of four: under the default half
    assert [r.entity.key for r in vault.search(query, match="any", scope="default")] == ["backup"]
    _, text = _call(server, "kibisis_recall", {"query": query})
    assert 'count="0"' in text
    assert '<withheld reason="below_gate" count="1"/>' in text
    assert "nightly" not in text


def test_mcp_recall_still_returns_a_matching_candidate(vault, server):
    vault.remember("ops", "backup", "The backup runs nightly at two.", origin="model")
    _, text = _call(server, "kibisis_recall", {"query": "when does the backup run nightly"})
    assert 'count="1"' in text and 'state="candidate"' in text and "withheld=" not in text


# --- admit resolves the vault and scope like the MCP server -------------------------------------------


def test_admit_without_db_or_scope_opens_the_mcp_servers_vault_and_scope(on_disk, monkeypatch):
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "1")
    v = open_vault()
    server = KibisisMCPServer(vault=v, scope=None)  # scope from KIBISIS_SCOPE, as the stdio server does
    assert server.scope == "proj-a"
    _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "Ship on Tuesdays"})
    v.close()
    r = _run(["kibisis", "admit", "--category", "c", "--key", "k", "--by", "user"], tty=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[scope=proj-a]" in r.stdout and str(on_disk) in r.stdout
    v = open_vault()
    assert v.get("c", "k", scope="proj-a").epistemic_state == EpistemicState.VERIFIED
    v.close()


def test_admit_refuses_an_unusable_scope(on_disk):
    r = _run(["kibisis", "admit", "--scope", "*", "--category", "c", "--key", "k", "--by", "user"], tty=True)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "not allowed" in r.stderr
