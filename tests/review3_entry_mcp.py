"""R3 entry-point review: the MCP server as an agent uses it (not collected by default; run by path).

``test_control_*`` asserts secure behaviour (failing = bug); ``test_attack_*`` demonstrates a defect
(passing = bug). Nothing in ``src/`` is changed.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys

import pytest

from kibisis.mcp_server import TOOL_DEFINITIONS, KibisisMCPServer, _AUTHORITY_ARGS
from kibisis.models import EpistemicState
from kibisis.vault import RESERVED_METADATA_KEYS, SQLiteMemoryVault

PASS = "review3-entry-passphrase"
SCOPE = "default"


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(tmp_path / "argus.jsonl"))
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    v = SQLiteMemoryVault(str(tmp_path / "v.sqlite"), passphrase=PASS, auto_gate=False, verification_quorum=2)
    try:
        yield v
    finally:
        v.close()


@pytest.fixture
def server(vault):
    return KibisisMCPServer(vault=vault, scope=SCOPE)


def _call(server, name, args, req_id=1):
    resp = server.handle_request({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                                  "params": {"name": name, "arguments": args}})
    text = resp["result"]["content"][0]["text"]
    return resp["result"]["isError"], text


def _journal(vault, action):
    c = vault._conn.cursor()
    c.execute("SELECT metadata_json FROM audit_journal WHERE action = ? ORDER BY sequence", (action,))
    return [json.loads(r[0] or "{}") for r in c.fetchall()]


# ------------------------------------------------------------------ 1. surface: no review door is exposed


def test_control_tool_surface_is_the_five_documented_tools(server):
    names = {t["name"] for t in server.handle_request({"id": 1, "method": "tools/list"})["result"]["tools"]}
    assert names == {"kibisis_remember", "kibisis_recall", "kibisis_forget", "kibisis_verify_ledger", "kibisis_health"}
    for name in ("kibisis_admit", "kibisis_lift", "kibisis_review", "kibisis_import", "kibisis_purge",
                 "kibisis_restore", "admit", "review_entity", "lift_tombstone", "import_snapshot"):
        err, text = _call(server, name, {"category": "c", "key": "k"})
        assert err and "unknown tool" in text, (name, text)
    for tool in TOOL_DEFINITIONS:
        assert tool["inputSchema"]["additionalProperties"] is False


@pytest.mark.parametrize("arg", sorted(_AUTHORITY_ARGS) + [
    "origin", "origin_class", "_review_verdict", "_trusted_metadata", "attester", "act_class",
    "derived_from", "revive", "conflicts_with", "fencing_token", "reviewer_origin", "reviewer_label",
])
def test_control_authority_and_private_kwargs_never_reach_the_vault(server, vault, arg):
    """Every kwarg that chooses trust, identity or a private vault path is refused and journaled; the
    entry is not written."""
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k-" + arg, "content": "x", arg: "user"})
    assert err and text.startswith("Refused:"), text
    assert vault.get("c", "k-" + arg, scope=SCOPE) is None
    reasons = {r.get("reason") for r in _journal(vault, "refuse")}
    assert reasons & {"authority_claim", "unknown_argument"}


@pytest.mark.parametrize("scope", ["*", "", "global", "default ", "other", None, 1])
def test_control_scope_argument_cannot_widen(server, vault, scope):
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "x", "scope": scope})
    if scope == SCOPE:
        pytest.skip("the server's own scope is a no-op")
    assert err and "scope" in text.lower(), text
    assert vault.get("c", "k", scope=SCOPE) is None


def test_control_reserved_and_principal_metadata_is_nested_and_trust_is_capped(server, vault):
    """metadata sent by the model lands under agent_metadata; the entry is a model-origin candidate with
    author mcp-agent whatever the payload claims."""
    forged: dict = {k: "forged" for k in RESERVED_METADATA_KEYS}
    forged.update({"author_id": "root", "last_verified_at": 4102444800.0, "supersession": {"outcome": "applied"},
                   "proposed_supersedes": {"category": "c", "key": "v"}, "trust_capped_from": "verified",
                   "quorum_at_verification": 1, "origin": "user", "epistemic_state": "verified",
                   "lineage_x": 1, "human_reviews": [{"reviewer_id": "root", "verdict": "verified"}]})
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "x", "metadata": forged})
    assert not err, text
    e = vault.get("c", "k", scope=SCOPE)
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.origin == "model"
    meta = e.metadata
    assert meta["author_id"] == "mcp-agent"
    assert meta.get("origin_class") == "agent"
    assert meta.get("act_class", "inform") == "inform"
    for k in forged:
        if k in ("author_id",):
            continue
        assert meta.get(k) != "forged" and meta.get(k) != forged[k], (k, meta.get(k))
    assert meta["agent_metadata"]["human_reviews"] == forged["human_reviews"]
    assert "attestations" not in meta and "human_reviews" not in meta
    # list_entities (what the review CLI shows) sees it as a candidate; the fence shows the real author
    err, text = _call(server, "kibisis_recall", {"query": "x"})
    assert 'state="candidate"' in text and 'author="mcp-agent"' in text and 'reviewed_by=' not in text


@pytest.mark.parametrize("category", ["", " ", "*", "__kibisis__", "aml.message", "aml.request", "general",
                                      "a" * 5000, "c;DROP TABLE entities", "c\x00k"])
def test_control_odd_category_names_do_not_escape_or_crash(server, vault, category):
    err, text = _call(server, "kibisis_remember", {"category": category, "key": "k", "content": "x"})
    assert "Internal error" not in text, text
    if not err:
        e = vault.get(category, "k", scope=SCOPE)
        assert e is not None and e.epistemic_state == EpistemicState.CANDIDATE and e.scope == SCOPE


@pytest.mark.parametrize("query", ['"', '"""', "a OR b", "NEAR(a b)", "a*", "^a", "a:b", "-a", "(", ")", "a AND",
                                   "{", "x" * 10000, "\x00", "'; DROP TABLE entities; --", "MATCH", "*"])
def test_control_recall_query_shapes_never_reach_internal_error(server, query):
    _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "alpha beta"})
    err, text = _call(server, "kibisis_recall", {"query": query})
    assert "Internal error" not in text, text
    assert text.startswith("<kibisis-recall") or err, text


# ------------------------------------------------ 2. a person's unreviewed entry: what the agent can do to it


def _person_candidate(vault, key="pk", content="a person's note"):
    """A principal-class entry no person reviewed (a user-origin write below quorum)."""
    e = vault.put("c", key, content, scope=SCOPE, origin="user", author_id="alice")
    assert e.epistemic_state == EpistemicState.CANDIDATE and (e.metadata or {}).get("origin_class") == "principal"
    return e


def test_control_mcp_cannot_overwrite_a_principal_candidate(server, vault):
    _person_candidate(vault)
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "pk", "content": "agent text"})
    assert err, text
    assert vault.get("c", "pk", scope=SCOPE).content == "a person's note"


def test_attack_refusal_of_a_principal_candidate_overwrite_is_an_internal_error(server, vault, capsys):
    """OriginClassError (PermissionError) is not mapped by _call_tool: the agent is told 'Internal error'
    and a traceback goes to the server log (the vault itself journals the refusal as origin_class_refused,
    so the audit trail is fine). Hygiene: a correct refusal reported to the agent as a server bug."""
    _person_candidate(vault)
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "pk", "content": "agent text"})
    assert err
    assert "Internal error" in text, text  # defect: should be "Refused: ... principal-class"
    assert "OriginClassError" in capsys.readouterr().err  # traceback printed for a routine refusal
    assert [r.get("reason") for r in _journal(vault, "refuse")] == ["origin_class_refused"]  # journaled by the vault


def test_attack_refusal_of_a_superseded_key_rewrite_is_an_internal_error(server, vault, capsys):
    """SupersededEntryError (PermissionError) has the same gap: an agent that rewrites a key closed by
    supersession gets 'Internal error' and the operator a traceback."""
    _call(server, "kibisis_remember", {"category": "c", "key": "old", "content": "v1"})
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "new", "content": "v2", "supersedes_key": "old"})
    assert not err, text
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "old", "content": "v3"})
    assert err
    assert "Internal error" in text, text
    assert "SupersededEntryError" in capsys.readouterr().err


def test_control_mcp_supersession_of_a_principal_candidate_is_only_a_proposal(server, vault):
    _person_candidate(vault)
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "nk", "content": "replacement",
                                                   "supersedes_key": "pk"})
    assert not err, text
    target = vault.get("c", "pk", scope=SCOPE)
    assert target is not None and not target.archived and target.epistemic_state == EpistemicState.CANDIDATE
    assert "c:nk" in (target.metadata or {}).get("pending_supersession_by", [])
    assert (vault.get("c", "nk", scope=SCOPE).metadata or {}).get("proposed_supersedes") == {"category": "c", "key": "pk"}


def test_control_mcp_forget_cannot_delete_a_principal_candidate(server, vault):
    _person_candidate(vault)
    err, text = _call(server, "kibisis_forget", {"category": "c", "key": "pk"})
    assert err, text
    assert "Internal error" not in text, text
    assert vault.get("c", "pk", scope=SCOPE) is not None


def test_control_mcp_forget_cannot_tombstone_a_value_a_person_holds(server, vault):
    _person_candidate(vault, key="pk", content="shared value")
    _call(server, "kibisis_remember", {"category": "c", "key": "mine", "content": "shared value"})
    err, text = _call(server, "kibisis_forget", {"category": "c", "key": "mine"})
    # Either refused outright, or deleted without a tombstone that could block the person's value.
    if not err:
        assert vault.get("c", "pk", scope=SCOPE) is not None
        e = vault.put("c", "pk2", "shared value", scope=SCOPE, origin="user", author_id="alice")
        assert e is not None


# ------------------------------------------------------------------ 3. JSON-RPC robustness / leaks


def test_control_health_and_ledger_do_not_leak_secrets(server, vault):
    err, text = _call(server, "kibisis_health", {})
    assert not err
    out = json.loads(text)
    assert PASS not in text and "passphrase" not in out and "quorum" not in text and "db_path" not in out
    err, text = _call(server, "kibisis_verify_ledger", {})
    assert not err and json.loads(text)["valid"] is True


def test_attack_tools_call_with_non_object_params_raises_out_of_handle_request(server):
    """handle_request does params.get(...) on whatever arrives: a list/str/number raises AttributeError
    instead of JSON-RPC -32602. Over stdio the outer loop turns it into -32603 'Internal error' plus a
    traceback on stderr; an embedder calling handle_request gets the exception. Hygiene."""
    for params in (["kibisis_health"], "kibisis_health", 1):
        with pytest.raises(AttributeError):
            server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})


def test_control_arguments_that_are_not_an_object_are_a_tool_error(server):
    for args in (["x"], "x", 1, True):
        resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "kibisis_health", "arguments": args}})
        assert resp["result"]["isError"]


def test_control_stdio_server_refuses_to_start_without_a_key(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("KIBISIS_")}
    env.update({"PYTHONPATH": os.pathsep.join(sys.path), "KIBISIS_DB_PATH": str(tmp_path / "v.sqlite"),
                "HOME": str(tmp_path), "ARGUS_LEDGER_PATH": ""})
    r = subprocess.run([sys.executable, "-m", "kibisis.mcp_server"], input="", capture_output=True, text=True,
                       env=env, timeout=60, cwd=str(tmp_path))
    assert r.returncode == 2, r.stderr
    assert "No key" in r.stderr
    assert not (tmp_path / "v.sqlite").exists()
