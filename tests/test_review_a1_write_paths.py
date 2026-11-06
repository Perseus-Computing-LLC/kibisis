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


def test_agent_cascade_leaves_the_persons_entry_reviewed_and_annotates_it(vault, server):
    """F6 fixed: a cascade an agent's supersession starts does not change the state of a dependent a
    person verified. The person's entry stays verified (so ``_is_reviewed`` still protects it) and gets
    an ``invalidation_notice`` naming what was retired; the cascade does not continue through it."""
    _call(server, "kibisis_remember", {"category": "notes", "key": "summary", "content": "The deploy window is Tuesday."})
    _verified(vault, derived_from=["notes:summary"])
    _call(server, "kibisis_remember", {"category": "notes", "key": "s2", "content": "moved", "supersedes_key": "summary"})
    row = _row(vault, "ops", "deploy_day")
    assert row["epistemic_state"] == "verified"
    assert _is_reviewed(row) is True
    meta = json.loads(row["metadata_json"])
    assert "invalidated_by" not in meta
    assert [n["retired"] for n in meta["invalidation_notice"]] == ["notes:summary"]
    assert meta["invalidation_notice"][0]["by_class"] == "agent"


# --- F6: review_entity accepts a model-origin 'disputed' verdict ---------------------------------------


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


def test_model_remember_must_not_store_revoked(vault):
    """FAILS if the defect exists. remember() docstring: a model write "is stored as candidate whatever
    epistemic_state says"; _put caps only verified/disputed (vault.py:808-812)."""
    e = vault.remember("notes", "a", "x", origin="model", epistemic_state="revoked")
    assert e.epistemic_state == EpistemicState.CANDIDATE, e.epistemic_state


# --- F8: snapshot round trip strips origin, downgrading principal entries to external/candidate ---------


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


def test_snapshot_import_drops_planted_trust_facts_from_a_foreign_snapshot(vault):
    """F7 fixed: a hand-made snapshot (no manifest, not this vault's digest key) cannot plant
    ``human_reviews`` or ``attestations``: they are dropped, the state is re-derived from what survives
    (candidate), and the drop is journaled. Its tombstones still apply (a restore cannot resurrect a
    deleted value) but carry principal class only if the snapshot says so; a tombstone with no class is
    principal, as rows from before the column were."""
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
    assert _is_reviewed(row) is False
    meta = json.loads(row["metadata_json"])
    assert "human_reviews" not in meta and "attestations" not in meta
    assert row["epistemic_state"] == "candidate" and meta["trust_capped_from"] == "verified"
    assert sorted(meta["trust_facts_dropped_on_import"]) == ["attestations", "human_reviews"]
    assert vault.is_tombstoned("a", "b", VALUE)
    assert any(e.metadata.get("path") == "import_snapshot" and "trust facts" in e.metadata.get("reason", "")
               for e in vault.list_audit_events(limit=50) if e.action == "refuse")


def test_snapshot_import_keeps_trust_facts_only_for_this_vaults_key_and_a_manifest(tmp_path):
    """F7 fixed, the positive side: a keyed vault restoring its own snapshot (its digest key id, manifest
    present and verifying) gets reviews and attestations back, and so does a vault with the same
    passphrase (the snapshot's trust_seal opens there); a vault with another passphrase, or the same
    snapshot with the manifest removed, does not."""
    a = SQLiteMemoryVault(str(tmp_path / "a.db"), passphrase="k" * 32, auto_gate=False, verification_quorum=1)
    try:
        a.put("ops", "deploy_day", VALUE, origin="user", author_id="alice", epistemic_state="verified")
        a.review_entity("ops", "deploy_day", verdict="verified", reviewer_id="bob")
        snap = a.export_snapshot()
        assert snap.get("manifest_sha256")
        assert a.purge("ops", "deploy_day", origin="user") is True
        assert a.import_snapshot(snap) == 1
        e = a.get("ops", "deploy_day")
        assert e.epistemic_state == EpistemicState.VERIFIED and e.metadata.get("human_reviews")
        assert e.origin == "user" and e.metadata.get("origin_class") == "principal"

        same_pass = SQLiteMemoryVault(str(tmp_path / "b.db"), passphrase="k" * 32, auto_gate=False, verification_quorum=1)
        try:
            assert same_pass.import_snapshot(snap) == 1
            e = same_pass.get("ops", "deploy_day")
            assert e.epistemic_state == EpistemicState.VERIFIED and e.metadata.get("human_reviews")
        finally:
            same_pass.close()

        other = SQLiteMemoryVault(str(tmp_path / "c.db"), passphrase="z" * 32, auto_gate=False, verification_quorum=1)
        try:
            assert other.import_snapshot(snap) == 1
            e = other.get("ops", "deploy_day")
            assert e.epistemic_state == EpistemicState.CANDIDATE and "human_reviews" not in e.metadata
            assert e.origin == "user"  # the class survives; the trust facts do not
        finally:
            other.close()

        stripped = {k: v for k, v in snap.items() if k != "manifest_sha256"}
        assert a.purge("ops", "deploy_day", origin="user") is True
        assert a.import_snapshot(stripped) == 1
        e = a.get("ops", "deploy_day")
        assert e.epistemic_state == EpistemicState.CANDIDATE and "human_reviews" not in e.metadata
    finally:
        a.close()


# --- F9: hidden supersession applied on approval -------------------------------------------------------


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


def test_model_conflicts_with_must_not_modify_a_person_verified_entrys_metadata(vault):
    """FAILS if the defect exists. _record_edges (_vault_review.py:164-203) updates the target row's
    metadata (back-edge) with no class or reviewed check."""
    _verified(vault)
    before = _row(vault, "ops", "deploy_day")["metadata_json"]
    vault.remember("notes", "claim", "Deploys go out on Fridays.", origin="model", conflicts_with=["ops:deploy_day"])
    after = _row(vault, "ops", "deploy_day")["metadata_json"]
    assert before == after, json.loads(after).get("conflicts_with")


# --- F11: forget_requests window can be flooded through MCP --------------------------------------------------


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


@pytest.mark.parametrize("origin", ["tool", "unknown", None])
def test_put_internal_flags_must_not_mint_verified_for_a_non_principal(vault, origin):
    """F8 fixed: ``_review_verdict`` and ``_trusted_metadata`` are no longer parameters of the public
    put(); passing them is a TypeError and nothing is written. A plain non-principal write of the same
    payload is stored as a candidate with the planted ``human_reviews`` dropped."""
    with pytest.raises(TypeError):
        vault.put("notes", "minted", "x", origin=origin, epistemic_state="verified",
                  metadata={"human_reviews": [{"reviewer_id": "alice", "verdict": "verified", "timestamp": 1.0}]},
                  _review_verdict=True, _trusted_metadata=True)
    assert vault.get("notes", "minted") is None
    e = vault.put("notes", "minted", "x", origin=origin, epistemic_state="verified",
                  metadata={"human_reviews": [{"reviewer_id": "alice", "verdict": "verified", "timestamp": 1.0}]})
    assert e.epistemic_state == EpistemicState.CANDIDATE, (e.epistemic_state, e.metadata.get("origin_class"))
    assert "human_reviews" not in e.metadata


def test_put_batch_forwards_internal_flags_from_dict_items(vault):
    """F8 fixed: put_batch rejects dict items with keys put() does not take, before writing anything."""
    with pytest.raises(TypeError):
        vault.put_batch([{"category": "notes", "key": "b", "content": "x", "origin": "tool",
                          "epistemic_state": "verified", "_review_verdict": True}])
    assert vault.get("notes", "b") is None
    [e] = vault.put_batch([{"category": "notes", "key": "b", "content": "x", "origin": "tool",
                            "epistemic_state": "verified"}])
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


def test_trust_adjacent_keys_are_moved_under_agent_metadata_on_a_model_write(vault):
    """L3 fixed: ``author_id``, ``last_verified_at``, ``proposed_supersedes``, ``supersession`` and
    ``slot`` are principal-only at the top level. A model write that sets them has them moved under
    ``agent_metadata``: the author shown is the write's author_id, the TTL clock is untouched."""
    from kibisis.mcp_server import fence_recall

    e = vault.remember("notes", "m", "x", origin="model", author_id="mcp-agent",
                       metadata={"author_id": "alice", "last_verified_at": 4102444800.0, "slot": "theme",
                                 "supersession": {"outcome": "applied", "target": "ops:deploy_day"}})
    assert e.metadata["author_id"] == "mcp-agent"
    assert 'author="mcp-agent"' in fence_recall("default", [e])
    assert "last_verified_at" not in e.metadata and "supersession" not in e.metadata and "slot" not in e.metadata
    assert e.metadata["agent_metadata"] == {
        "author_id": "alice", "last_verified_at": 4102444800.0, "slot": "theme",
        "supersession": {"outcome": "applied", "target": "ops:deploy_day"},
    }
    # A person's write may set them.
    p = vault.put("notes", "p", "y", origin="user", author_id="alice", metadata={"slot": "theme"})
    assert p.metadata["slot"] == "theme"


# --- archive / set_persona_slot / put_batch: no origin, documented --------------------------------------------


def test_archive_and_persona_slot_run_the_origin_check(vault):
    """L3 fixed: archive() and set_persona_slot() take ``origin`` and run the same protected() check as
    tombstone(): a model-origin request cannot archive a verified entry or replace a person's verified
    persona slot, and its own slot write is a candidate. ``origin=None`` on archive keeps the library
    contract (the caller vouches); set_persona_slot still defaults to the person's own origin."""
    _verified(vault)
    with pytest.raises(ReviewedEntryError):
        vault.archive("ops", "deploy_day", author_id="mcp-agent", origin="model")
    assert vault.get("ops", "deploy_day").archived is False
    assert vault.archive("ops", "deploy_day", author_id="alice", origin="user") is True
    assert vault.get("ops", "deploy_day").archived is True

    slot = vault.set_persona_slot("I like terse answers.", author_id="alice")
    assert slot.origin == "user" and slot.metadata["origin_class"] == "principal"
    assert slot.epistemic_state == EpistemicState.VERIFIED
    with pytest.raises(ReviewedEntryError):
        vault.set_persona_slot("I am the agent's idea of the user.", author_id="mcp-agent", origin="model")
    assert vault.get_persona_slot().content == "I like terse answers."
    mine = vault.set_persona_slot("agent's guess", author_id="mcp-agent", origin="model", scope="other")
    assert mine.epistemic_state == EpistemicState.CANDIDATE and mine.metadata["origin_class"] == "agent"
