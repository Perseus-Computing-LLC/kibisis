"""A1 review: write paths that reach a person's entry or a reviewed state without the gate in ``_put``.

Convention: unless the docstring says otherwise, each test ASSERTS THE SECURE BEHAVIOUR, so a
FAILING test is the evidence that the defect exists. Tests marked "documents insecure behaviour"
assert what the code does today and pass. Positive controls are marked "control".
"""

import json

import pytest


def finding(fid):
    """Defect present at 1299c28: the test's assertion fails. strict xfail -> the suite is green while the
    defect exists and turns RED when it is fixed (remove the marker then). ``pytest --runxfail`` shows raw failures."""
    return pytest.mark.xfail(strict=True, reason=f"{fid}: see review_notes/A1_trust_boundary.md")

from kibisis import EpistemicState, KibisisMCPServer, SQLiteMemoryVault
from kibisis.vault import OriginClassError, ReviewedEntryError, _is_reviewed

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


def _row(vault, category, key, scope="default"):
    cur = vault._conn.cursor()
    cur.execute(
        "SELECT epistemic_state, metadata_json, origin FROM entities WHERE category=? AND key=? AND scope=?",
        (category, key, scope),
    )
    return cur.fetchone()


# --- controls -------------------------------------------------------------------------------------------


def test_control_model_rewrite_of_verified_entry_is_refused(vault):
    _verified(vault)
    with pytest.raises((ReviewedEntryError, OriginClassError)):  # the class check (vault.py:896) fires first
        vault.remember("ops", "deploy_day", "Deploys go out on Fridays.", origin="model")
    with pytest.raises(OriginClassError):
        vault.remember("ops", "deploy_day", "Deploys go out on Fridays.", origin="tool")
    assert vault.get("ops", "deploy_day").content == VALUE


@pytest.mark.parametrize("arg", ["origin", "epistemic_state", "author_id", "trust_ceiling", "reviewer_id", "auto_gate"])
def test_control_mcp_remember_refuses_authority_arguments(vault, server, arg):
    is_error, text = _call(server, "kibisis_remember", {"key": "k", "content": "x", arg: "user"})
    assert is_error and ("cannot be set through MCP" in text or "unknown argument" in text), text


def test_control_top_level_reserved_metadata_keys_are_dropped(vault):
    e = vault.remember("c", "k", "x", origin="model", metadata={"human_reviews": [{"reviewer_id": "alice"}], "origin_class": "principal"})
    assert "human_reviews" not in e.metadata and e.metadata["origin_class"] == "agent"
    assert not _is_reviewed(_row(vault, "c", "k"))


# --- F5: an agent's supersession of its own entry flips a person's verified entry to disputed ---------


@finding("F5")
def test_agent_supersession_cascade_must_not_change_a_person_verified_entry(vault, server):
    """FAILS if the defect exists. _cascade_invalidate (_vault_review.py:205-241) marks every dependent
    ``disputed`` whatever its origin class or reviewed state; an MCP ``supersedes_key`` on the agent's
    own unreviewed entry triggers it (vault.py:989-991, 1062)."""
    _call(server, "kibisis_remember", {"category": "notes", "key": "summary", "content": "The deploy window is Tuesday."})
    _verified(vault, derived_from=["notes:summary"])  # a person's fact citing the agent's note
    is_error, text = _call(
        server, "kibisis_remember",
        {"category": "notes", "key": "summary2", "content": "The deploy window moved.", "supersedes_key": "summary"},
    )
    assert not is_error, text
    e = vault.get("ops", "deploy_day")
    assert e.epistemic_state == EpistemicState.VERIFIED, f"person's entry is now {e.epistemic_state} via an agent cascade"
    assert "invalidated_by" not in e.metadata


def test_after_the_cascade_the_persons_entry_no_longer_counts_as_reviewed(vault, server):
    """Documents insecure behaviour (passes). Once disputed by the cascade the entry has no
    ``human_reviews`` and is not ``verified``, so ``_is_reviewed`` is False; only the class check is left."""
    _call(server, "kibisis_remember", {"category": "notes", "key": "summary", "content": "The deploy window is Tuesday."})
    _verified(vault, derived_from=["notes:summary"])
    _call(server, "kibisis_remember", {"category": "notes", "key": "s2", "content": "moved", "supersedes_key": "summary"})
    row = _row(vault, "ops", "deploy_day")
    assert row["epistemic_state"] == "disputed"
    assert _is_reviewed(row) is False


# --- F6: review_entity accepts a model-origin 'disputed' verdict ---------------------------------------


@finding("F6")
def test_model_origin_review_verdict_disputed_must_not_change_a_person_verified_entry(vault):
    """FAILS if the defect exists. review_entity refuses a model-origin ``revoked`` (through tombstone's
    origin) but ``disputed``/``verified`` verdicts go to put() with origin=None and _trusted_metadata=True
    (_vault_review.py:487-504); nothing checks ``reviewer_origin`` for them."""
    _verified(vault)
    try:
        vault.review_entity("ops", "deploy_day", verdict="disputed", reviewer_id="bot", reviewer_origin="model")
    except PermissionError:
        return
    e = vault.get("ops", "deploy_day")
    assert e.epistemic_state == EpistemicState.VERIFIED, f"a model-origin verdict made it {e.epistemic_state}"


@finding("F6")
def test_model_origin_review_verdict_must_not_make_an_agent_candidate_count_as_reviewed(vault):
    """FAILS if the defect exists. A model-origin ``disputed`` on the agent's own candidate stores a
    ``human_reviews`` record with reviewer_origin=model; ``_is_reviewed`` then treats the agent's entry
    as person-reviewed, and list_entities() (default: verified+disputed) shows it beside verified ones."""
    vault.remember("notes", "mine", "The cache warms at boot.", origin="model")
    try:
        vault.review_entity("notes", "mine", verdict="disputed", reviewer_id="bot", reviewer_origin="model")
    except PermissionError:
        return
    row = _row(vault, "notes", "mine")
    assert not _is_reviewed(row), json.loads(row["metadata_json"]).get("human_reviews")
    assert [e.key for e in vault.list_entities(scope="default")] == []


# --- F7: a model-origin write can state epistemic_state='revoked' ------------------------------------------


@finding("F12")
def test_model_remember_must_not_store_revoked(vault):
    """FAILS if the defect exists. remember() docstring: a model write "is stored as candidate whatever
    epistemic_state says"; _put caps only verified/disputed (vault.py:808-812)."""
    e = vault.remember("notes", "a", "x", origin="model", epistemic_state="revoked")
    assert e.epistemic_state == EpistemicState.CANDIDATE, e.epistemic_state


# --- F8: snapshot round trip strips origin, downgrading principal entries to external/candidate ---------


@finding("F8")
def test_snapshot_round_trip_must_keep_a_person_verified_entry_verified_and_principal(vault):
    """FAILS if the defect exists. export_snapshot (_vault_snapshot.py:43-85) exports no ``origin``;
    import_snapshot (276-291) calls put() with origin=None and epistemic_state='verified', which _put
    caps to candidate for a non-principal writer (817-823) and stores origin 'unknown' (1111)."""
    _verified(vault)
    snap = vault.export_snapshot()
    other = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    try:
        assert other.import_snapshot(snap) == 1
        e = other.get("ops", "deploy_day")
        assert e is not None
        assert (e.origin, e.metadata.get("origin_class"), e.epistemic_state) == ("user", "principal", EpistemicState.VERIFIED), (
            e.origin, e.metadata.get("origin_class"), e.epistemic_state, e.metadata.get("trust_capped_from"))
    finally:
        other.close()


@finding("F8")
def test_after_a_snapshot_restore_an_agent_can_overwrite_and_delete_the_persons_entry(vault):
    """FAILS if the defect exists. Consequence of F8: the restored row is external-class candidate with no
    human_reviews, so both the K-R1 class check and the reviewed check let a model write and a model
    tombstone through."""
    _verified(vault)
    snap = vault.export_snapshot()
    other = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    try:
        other.import_snapshot(snap)
        with pytest.raises((ReviewedEntryError, OriginClassError)):
            other.remember("ops", "deploy_day", "Deploys go out on Fridays.", origin="model")
        with pytest.raises(ReviewedEntryError):
            other.tombstone("ops", "deploy_day", origin="model")
        assert other.get("ops", "deploy_day").content == VALUE
    finally:
        other.close()


def test_snapshot_import_trusts_file_metadata_documents_insecure_behaviour(vault):
    """Documents insecure behaviour (passes). import_snapshot passes _trusted_metadata=True, so a
    hand-made snapshot (manifest_sha256 is optional and unkeyed) plants ``human_reviews`` and
    ``attestations``; and its tombstone list is applied with no origin check."""
    from kibisis._vault_crypto import value_digests

    exact, canonical = value_digests(VALUE)
    snap = {
        "format_version": "1.1", "scope": "*", "digest_scheme": "sha256",
        "entities": [{"category": "notes", "key": "planted", "content": "The agent wrote this.",
                      "metadata": {"human_reviews": [{"reviewer_id": "alice", "verdict": "verified", "timestamp": 1.0}],
                                   "attestations": ["alice"]},
                      "epistemic_state": "verified", "scope": "default"}],
        "tombstones": [{"category": "x", "key": "y", "scope": "default",
                        "value_sha256": exact, "canonical_sha256": canonical}],
        "audit_events": [],
    }
    assert vault.import_snapshot(snap) == 1
    row = _row(vault, "notes", "planted")
    assert _is_reviewed(row) is True  # planted review counts as a person's
    assert vault.is_tombstoned("a", "b", VALUE)  # planted tombstone denies the value


# --- F9: hidden supersession applied on approval -------------------------------------------------------


@finding("F9")
def test_review_list_must_name_a_candidates_pending_supersession_of_a_verified_entry(vault, server, capsys, monkeypatch):
    """FAILS if the defect exists. An MCP candidate with supersedes_key on a verified entry is stored
    as a proposal (vault.py:992-1013); review.py:_list prints author/version/content only, and approving
    the candidate on its own merits applies the supersession (_vault_review.py:484-501): the verified
    entry is revoked, its key closed, and its dependents disputed, with no mention to the person."""
    from kibisis.review import _list

    _verified(vault)
    is_error, text = _call(
        server, "kibisis_remember",
        {"category": "ops", "key": "deploy_day_v2", "content": "Deploys go out on Fridays.", "supersedes_key": "deploy_day"},
    )
    assert not is_error and "proposal" in text, text
    _list(vault, "default", None)
    out = capsys.readouterr().out
    assert "deploy_day_v2" in out
    assert "supersede" in out.lower() or "deploy_day " in out or "ops:deploy_day\n" in out, (
        "review list does not tell the person that approving deploy_day_v2 retires ops:deploy_day:\n" + out)


def test_approving_the_proposal_retires_the_verified_entry_documents_behaviour(vault, server):
    """Documents behaviour (passes): what a person's 'approve' of the candidate does."""
    _verified(vault)
    _call(server, "kibisis_remember",
          {"category": "ops", "key": "v2", "content": "Deploys go out on Fridays.", "supersedes_key": "deploy_day"})
    vault.review_entity("ops", "v2", verdict="verified", reviewer_id="alice")
    old = vault.get("ops", "deploy_day")
    assert old.epistemic_state == EpistemicState.REVOKED and old.superseded_by == "ops:v2"


# --- F10: _record_edges writes into a person's entry from a model write ------------------------------------


@finding("F10")
def test_model_conflicts_with_must_not_modify_a_person_verified_entrys_metadata(vault):
    """FAILS if the defect exists. _record_edges (_vault_review.py:164-203) updates the target row's
    metadata (back-edge) with no class or reviewed check."""
    _verified(vault)
    before = _row(vault, "ops", "deploy_day")["metadata_json"]
    vault.remember("notes", "claim", "Deploys go out on Fridays.", origin="model", conflicts_with=["ops:deploy_day"])
    after = _row(vault, "ops", "deploy_day")["metadata_json"]
    assert before == after, json.loads(after).get("conflicts_with")


# --- F11: forget_requests window can be flooded through MCP --------------------------------------------------


@finding("F11")
def test_forget_requests_must_survive_a_flood_of_agent_refusals(vault, server):
    """FAILS if the defect exists. forget_requests (vault.py:1394-1397) reads the newest 5000 ``refuse``
    rows of the scope before filtering; every refused MCP call (unknown argument, scope, authority
    claim) adds one, so the agent can push its own earlier request out of the person's review list.
    Scaled down: the window is 5000 rows, so 5001 refusals suffice."""
    _verified(vault)
    is_error, _ = _call(server, "kibisis_forget", {"category": "ops", "key": "deploy_day", "reason": "stale"})
    assert is_error
    assert len(vault.forget_requests("default")) == 1
    for _ in range(5001):
        _call(server, "kibisis_health", {"bogus": 1})  # unknown_argument -> record_refusal
    assert len(vault.forget_requests("default")) == 1, "the forget request vanished behind agent refusals"


# --- F12: put() exposes its internal review flags to every caller ------------------------------------------


@finding("F7")
@pytest.mark.parametrize("origin", ["tool", "unknown", None])
def test_put_internal_flags_must_not_mint_verified_for_a_non_principal(vault, origin):
    """FAILS if the defect exists. ``_review_verdict`` and ``_trusted_metadata`` are keyword arguments of
    the public put() (vault.py:1200-1201) and are forwarded by put_batch's dict items (1503).
    With ``_review_verdict=True`` the quorum block (938-957) and the verified cap (817-825) are skipped;
    with ``_trusted_metadata=True`` a caller-supplied ``human_reviews`` is kept. Only origin='model'
    is still capped, by trust_ceiling (767, 808)."""
    e = vault.put("notes", "minted", "x", origin=origin, epistemic_state="verified",
                  metadata={"human_reviews": [{"reviewer_id": "alice", "verdict": "verified", "timestamp": 1.0}]},
                  _review_verdict=True, _trusted_metadata=True)
    assert e.epistemic_state == EpistemicState.CANDIDATE, (e.epistemic_state, e.metadata.get("origin_class"))
    assert "human_reviews" not in e.metadata


@finding("F7")
def test_put_batch_forwards_internal_flags_from_dict_items(vault):
    """FAILS if the defect exists. Same path through put_batch(items=[dict])."""
    [e] = vault.put_batch([{"category": "notes", "key": "b", "content": "x", "origin": "tool",
                            "epistemic_state": "verified", "_review_verdict": True}])
    assert e.epistemic_state == EpistemicState.CANDIDATE, e.epistemic_state


# --- atlas fix #4: MCP recall goes through recall(); no other tool exposes search() -----------------------------


def test_control_mcp_exposes_only_five_tools_and_recall_withholds(vault, server):
    """Positive control for atlas fix #4 (passes): the tool list has no list/get/search tool, and a pair of
    conflicting verified entries that search() returns is withheld by kibisis_recall."""
    resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = sorted(t["name"] for t in resp["result"]["tools"])
    assert names == ["kibisis_forget", "kibisis_health", "kibisis_recall", "kibisis_remember", "kibisis_verify_ledger"]
    _verified(vault, "profile", "p1", "prefers dark mode in the editor", metadata={"slot": "theme"})
    _verified(vault, "profile", "p2", "prefers light mode in the editor", metadata={"slot": "theme"})
    assert {r.entity.key for r in vault.search("mode editor", match="any", scope="default")} == {"p1", "p2"}
    _, text = _call(server, "kibisis_recall", {"query": "prefers mode editor", "include_candidates": False})
    assert 'withheld="2"' in text and "dark mode" not in text and "light mode" not in text


# --- reserved keys: nested, cased, later update ------------------------------------------------------------


def test_nested_and_cased_reserved_keys_are_inert(vault, server):
    """Documents behaviour (passes): nested (agent_metadata) and differently-cased keys are stored but
    nothing reads them; a later update cannot add a top-level one either."""
    _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "x",
                                       "metadata": {"human_reviews": [{"reviewer_id": "alice"}], "origin_class": "principal"}})
    vault.remember("c", "k2", "y", origin="model", metadata={"Human_Reviews": [{"reviewer_id": "alice"}],
                                                             "ｈuman_reviews": [{"reviewer_id": "alice"}]})
    vault.remember("c", "k2", "y2", origin="model", metadata={"human_reviews": [{"reviewer_id": "alice"}]})
    for key in ("k", "k2"):
        assert not _is_reviewed(_row(vault, "c", key))
        assert vault.get("c", key).metadata.get("origin_class") == "agent"
    assert vault.list_entities(scope="default") == []


def test_unreserved_trust_adjacent_keys_are_caller_settable_documents_behaviour(vault):
    """Documents insecure behaviour (passes): ``author_id``, ``last_verified_at``, ``proposed_supersedes``,
    ``supersession`` and ``slot`` are not reserved. A library model write can claim an author (shown as
    author= in the MCP recall envelope) and a future ``last_verified_at`` (recall's TTL clock)."""
    from kibisis.mcp_server import fence_recall

    e = vault.remember("notes", "m", "x", origin="model", author_id="mcp-agent",
                       metadata={"author_id": "alice", "last_verified_at": 4102444800.0,
                                 "supersession": {"outcome": "applied", "target": "ops:deploy_day"}})
    assert e.metadata["author_id"] == "alice"
    assert 'author="alice"' in fence_recall("default", [e])
    assert e.metadata["last_verified_at"] == 4102444800.0


# --- archive / set_persona_slot / put_batch: no origin, documented --------------------------------------------


def test_archive_and_persona_slot_have_no_origin_gate_documents_behaviour(vault):
    """Documents insecure behaviour (passes): archive() takes no origin and hides a verified entry from
    recall; set_persona_slot defaults origin='user' so a caller that forgets to pass the agent's origin
    writes a principal-class attested entry."""
    _verified(vault)
    assert vault.archive("ops", "deploy_day", author_id="mcp-agent") is True
    assert vault.get("ops", "deploy_day").archived is True
    assert vault.list_entities(scope="default") == []
    slot = vault.set_persona_slot("I am the agent's idea of the user.", author_id="mcp-agent")
    assert slot.origin == "user" and slot.metadata["origin_class"] == "principal"
    assert slot.epistemic_state == EpistemicState.VERIFIED
