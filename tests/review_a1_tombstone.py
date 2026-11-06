"""A1 review: can an untrusted (model/tool) origin delete or deny what a person vouched for?

Convention: unless the docstring says otherwise, each test ASSERTS THE SECURE BEHAVIOUR, so a
FAILING test is the evidence that the defect exists. Tests marked "documents insecure behaviour"
assert what the code does today and pass.
"""

import pytest


def finding(fid):
    """Defect present at 1299c28: the test's assertion fails. strict xfail -> the suite is green while the
    defect exists and turns RED when it is fixed (remove the marker then). ``pytest --runxfail`` shows raw failures."""
    return pytest.mark.xfail(strict=True, reason=f"{fid}: see review_notes/A1_trust_boundary.md")

from kibisis import EpistemicState, KibisisMCPServer, SQLiteMemoryVault
from kibisis.vault import ReviewedEntryError, TombstonedValueError

VALUE = "Deploys go out on Tuesdays."


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


@pytest.fixture
def server(vault):
    return KibisisMCPServer(vault=vault, scope="default")


def _call(server, tool, arguments):
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    )
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


def _verified(vault, category="ops", key="deploy_day", content=VALUE, **kw):
    e = vault.put(category, key, content, origin="user", author_id="alice", epistemic_state="verified", **kw)
    assert e.epistemic_state == EpistemicState.VERIFIED
    return e


# --- positive control ---------------------------------------------------------------------------


def test_control_model_tombstone_without_content_is_refused(vault):
    """Positive control for atlas fix #1: the straightforward call is refused."""
    _verified(vault)
    with pytest.raises(ReviewedEntryError):
        vault.tombstone("ops", "deploy_day", origin="model")
    assert vault.get("ops", "deploy_day") is not None


# --- F1: tombstone(content=...) skips the origin check on the target --------------------------------


@finding("F1")
@pytest.mark.parametrize("content", [VALUE, "some other text that is stored nowhere"])
def test_model_tombstone_with_content_argument_must_not_delete_a_verified_entry(vault, content):
    """FAILS if the defect exists. _vault_tombstone.py:185-204: when ``content`` is given, ``target``
    stays None, so ``protected(target, ...)`` is never evaluated; line 212 then skips the entry itself in
    the copy scan as "checked above", and line 237 deletes it by category/key regardless of content."""
    _verified(vault)
    with pytest.raises(ReviewedEntryError):
        vault.tombstone("ops", "deploy_day", content=content, origin="model", author_id="mcp-agent")
    assert vault.get("ops", "deploy_day") is not None, "verified entry was deleted by a model-origin tombstone"


@finding("F1")
def test_model_tombstone_with_content_must_not_delete_a_person_written_candidate(vault):
    """FAILS if the defect exists. Same path; the K-R1 class check is skipped too."""
    vault.put("ops", "note", "Budget reviews are on the first Monday.", origin="user", author_id="alice")
    with pytest.raises(ReviewedEntryError):
        vault.tombstone("ops", "note", content="x", origin="model")
    assert vault.get("ops", "note") is not None


# --- F2: purge() has no origin at all ----------------------------------------------------------------


def test_purge_has_no_origin_parameter_documents_insecure_behaviour(vault):
    """Documents insecure behaviour (passes). ``purge`` (_vault_tombstone.py:25) takes no ``origin``
    and deletes a verified principal entry with no check; any library caller relaying an agent has no
    way to pass the agent's origin."""
    _verified(vault)
    import inspect

    assert "origin" not in inspect.signature(vault.purge).parameters
    assert vault.purge("ops", "deploy_day", author_id="mcp-agent") is True
    assert vault.get("ops", "deploy_day") is None


# --- F3: an agent can permanently deny a value to a person through MCP (remember + forget) ----------


@finding("F3")
def test_mcp_remember_then_forget_must_not_block_a_persons_later_write_of_that_value(vault, server):
    """FAILS if the defect exists. kibisis_forget on the agent's own candidate records a value
    tombstone in the scope (_vault_tombstone.py:223-235); _put refuses every later write of that value
    (vault.py:1066-1078) including a person's, and no API lifts a tombstone."""
    ok, _ = _call(server, "kibisis_remember", {"category": "notes", "key": "guess", "content": VALUE})
    assert not ok
    is_error, text = _call(server, "kibisis_forget", {"category": "notes", "key": "guess"})
    assert not is_error, text
    try:
        _verified(vault)  # a person now writes the same fact under their own key
    except TombstonedValueError as exc:
        pytest.fail(f"person's write refused by an agent-made tombstone: {exc}")
    assert vault.get("ops", "deploy_day") is not None


@finding("F3")
def test_mcp_forget_canonical_lookalike_also_denies_the_person(vault, server):
    """FAILS if the defect exists. The tombstone matches on the canonical digest, so the denial covers
    look-alikes of the value as well."""
    _call(server, "kibisis_remember", {"category": "notes", "key": "guess", "content": "deploys go out on tuesdays"})
    _call(server, "kibisis_forget", {"category": "notes", "key": "guess"})
    try:
        vault.put("ops", "deploy_day", VALUE, origin="user", author_id="alice", epistemic_state="verified")
    except TombstonedValueError as exc:
        pytest.fail(f"person's write refused by an agent-made tombstone on a look-alike: {exc}")


# --- F4: scope='*' tombstone from a model origin --------------------------------------------------------


@finding("F4")
def test_model_origin_tombstone_with_content_and_wildcard_scope_must_not_write_a_global_tombstone(vault):
    """FAILS if the defect exists. With ``content`` and ``scope='*'`` nothing is looked up (no KeyError),
    the copy scan finds nothing, and a '*' tombstone is inserted that refuses the value in every scope."""
    try:
        vault.tombstone("any", "thing", content="A value nobody stored yet", origin="model", scope="*")
    except (ReviewedEntryError, KeyError, ValueError):
        return  # refused: secure
    assert vault.is_tombstoned("c", "k", "A value nobody stored yet", scope="proj-a") is False, (
        "a model-origin request wrote a wildcard tombstone that binds every scope"
    )


# --- atlas fix #1 at the MCP layer: the client cannot choose origin/content -----------------------------


@pytest.mark.parametrize("arg", ["origin", "content", "author_id", "scope"])
def test_mcp_forget_refuses_client_chosen_origin_content_author_or_scope(vault, server, arg):
    """Positive control: the MCP layer does not let the client reach ``content``/``origin``."""
    _verified(vault)
    value = {"origin": "user", "content": VALUE, "author_id": "alice", "scope": "proj-b"}[arg]
    is_error, text = _call(server, "kibisis_forget", {"category": "ops", "key": "deploy_day", arg: value})
    assert is_error, text
    assert vault.get("ops", "deploy_day") is not None


def test_mcp_forget_refuses_a_copy_in_the_same_scope_only(vault, server):
    """Documents behaviour (passes): a reviewed copy in ANOTHER scope does not protect the value, but
    the tombstone is scoped too, so the other scope's entry survives. Not a finding; recorded for coverage."""
    vault.put("ops", "deploy_day", VALUE, origin="user", author_id="alice", epistemic_state="verified", scope="proj-b")
    _call(server, "kibisis_remember", {"category": "notes", "key": "copy", "content": VALUE})
    is_error, _ = _call(server, "kibisis_forget", {"category": "notes", "key": "copy"})
    assert not is_error
    assert vault.get("ops", "deploy_day", scope="proj-b") is not None
    assert vault.is_tombstoned("x", "y", VALUE, scope="proj-b") is False
