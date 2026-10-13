import time
import pytest
from kibisis import EpistemicState, MemoryEntity, SQLiteMemoryVault


def test_epistemic_lifecycle_and_unverified_filtering():
    vault = SQLiteMemoryVault()
    # 1. Candidate ingestion
    entity = vault.admit_candidate(
        category="theories",
        key="quantum_gravity",
        content="Loop Quantum Gravity formulation",
        scope="lab_alpha",
    )
    assert entity.epistemic_state == EpistemicState.CANDIDATE

    # By default, candidates are suppressed from active recall
    res = vault.search(query="Quantum", scope="lab_alpha", include_unverified=False)
    assert len(res) == 0

    # Search with include_unverified finds candidate
    res_unv = vault.search(query="Quantum", scope="lab_alpha", include_unverified=True)
    assert len(res_unv) == 1
    assert res_unv[0].entity.key == "quantum_gravity"

    # Human review promotes to verified
    reviewed = vault.review_entity(
        category="theories",
        key="quantum_gravity",
        verdict=EpistemicState.VERIFIED.value,
        scope="lab_alpha",
        reviewer_id="human_peer_reviewer_42",
        notes="Empirical math checks pass.",
    )
    assert reviewed.epistemic_state == EpistemicState.VERIFIED
    assert len(reviewed.metadata["human_reviews"]) == 1

    # Now standard search finds it
    res_verified = vault.search(query="Quantum", scope="lab_alpha", include_unverified=False)
    assert len(res_verified) == 1
    assert res_verified[0].entity.epistemic_state == EpistemicState.VERIFIED

    # Human review revokes it -> automatic tombstone & purge
    revoked = vault.review_entity(
        category="theories",
        key="quantum_gravity",
        verdict=EpistemicState.REVOKED.value,
        scope="lab_alpha",
        reviewer_id="human_lead",
        notes="Superseded by string theory experiment",
    )
    assert revoked.epistemic_state == EpistemicState.REVOKED
    assert vault.get("theories", "quantum_gravity", scope="lab_alpha") is None

    # Cannot re-insert tombstoned payload into same scope
    with pytest.raises(ValueError, match="matches rejected tombstone"):
        vault.put(
            category="theories",
            key="quantum_gravity",
            content="Loop Quantum Gravity formulation",
            scope="lab_alpha",
        )


def test_scope_enforcement_and_tenant_isolation():
    vault = SQLiteMemoryVault()
    vault.put(
        category="creds",
        key="api_token",
        content="secret_token_alpha",
        scope="tenant_alpha",
    )
    vault.put(
        category="creds",
        key="api_token",
        content="secret_token_beta",
        scope="tenant_beta",
    )

    # Retrieval isolation
    alpha_ent = vault.get(category="creds", key="api_token", scope="tenant_alpha")
    beta_ent = vault.get(category="creds", key="api_token", scope="tenant_beta")
    gamma_ent = vault.get(category="creds", key="api_token", scope="tenant_gamma")

    assert alpha_ent is not None and alpha_ent.content == "secret_token_alpha"
    assert beta_ent is not None and beta_ent.content == "secret_token_beta"
    assert gamma_ent is None

    # Search isolation
    search_alpha = vault.search("secret_token", scope="tenant_alpha")
    assert len(search_alpha) == 1
    assert search_alpha[0].entity.content == "secret_token_alpha"

    search_beta = vault.search("secret_token", scope="tenant_beta")
    assert len(search_beta) == 1
    assert search_beta[0].entity.content == "secret_token_beta"

    search_gamma = vault.search("secret_token", scope="tenant_gamma")
    assert len(search_gamma) == 0


def test_bitemporal_validity_point_in_time():
    vault = SQLiteMemoryVault()
    # Event valid from t=1000 to t=2000
    vault.put(
        category="regulations",
        key="tariffs",
        content="Steel imports subjected to 25% duty",
        valid_from=1000.0,
        valid_until=2000.0,
        scope="trade_dept",
    )

    # Point-in-time search at t=500 (before validity) -> 0
    res_past = vault.search("Steel", scope="trade_dept", as_of_valid_time=500.0)
    assert len(res_past) == 0

    # Point-in-time search at t=1500 (valid window) -> 1
    res_now = vault.search("Steel", scope="trade_dept", as_of_valid_time=1500.0)
    assert len(res_now) == 1
    assert res_now[0].entity.key == "tariffs"

    # Point-in-time search at t=2500 (after expiry) -> 0
    res_future = vault.search("Steel", scope="trade_dept", as_of_valid_time=2500.0)
    assert len(res_future) == 0

    # List entities also enforces bi-temporal bounds
    ents_valid = vault.list_entities(scope="trade_dept", as_of_valid_time=1500.0)
    assert len(ents_valid) == 1
    ents_expired = vault.list_entities(scope="trade_dept", as_of_valid_time=3000.0)
    assert len(ents_expired) == 0


def test_tamper_evident_audit_log_and_chain_verification():
    vault = SQLiteMemoryVault()
    vault.put("audit_test", "k1", "payload alpha", scope="sec_team", author_id="agent_1")
    vault.put("audit_test", "k2", "payload beta", scope="sec_team", author_id="agent_2")
    vault.put("audit_test", "k1", "payload alpha updated", scope="sec_team", author_id="agent_1")
    vault.archive("audit_test", "k2", scope="sec_team", author_id="agent_3")

    # Chain verification
    assert vault.verify_audit_chain(scope="sec_team") is True

    events = vault.list_audit_events(scope="sec_team")
    assert len(events) == 4
    assert [e.action for e in events] == ["put", "put", "update", "archive"]
    assert events[0].prev_hash == "0" * 64
    assert events[1].prev_hash == events[0].event_hash
    assert events[2].prev_hash == events[1].event_hash
    assert events[3].prev_hash == events[2].event_hash


def test_negative_contract_assertions():
    vault = SQLiteMemoryVault()
    # 1. Invalid epistemic status rejected
    with pytest.raises(ValueError):
        vault.put("cat", "k", "test", epistemic_state="non_existent_state")

    # 2. Review invalid verdict rejected
    vault.admit_candidate("cat", "k", "test")
    with pytest.raises(ValueError, match="Verdict must be one of"):
        vault.review_entity("cat", "k", verdict="invalid_verdict")

    # 3. Review non-existent entity raises KeyError
    with pytest.raises(KeyError, match="Entity not found for review"):
        vault.review_entity("non_cat", "non_k", verdict=EpistemicState.VERIFIED.value)
