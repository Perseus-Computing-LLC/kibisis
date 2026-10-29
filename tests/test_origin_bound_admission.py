"""K-E and K-R1: origin-bound admission.

Trust comes from where a write came from, never from what the payload says about itself.

- K-E: ``put()`` without an explicit state stores ``candidate``; ``verified`` is minted only by a
  person's review, and only once enough independent principals have attested (quorum).
- K-R1: every entry carries an immutable ``origin_class`` set by the vault at write time
  (``principal`` for user/import, ``agent`` for model, ``external`` for tool/unknown); a lower-trust
  writer cannot overwrite or re-class a higher-trust entry; ``act_class`` is capped at ``inform``
  for agent/external writers; trust is the minimum along ``supersedes`` and ``derived_from`` links
  for non-principal writers.
"""

import os

import pytest

from kibisis import EpistemicState, SQLiteMemoryVault
from kibisis.vault import OriginClassError, ORIGIN_CLASSES, origin_class_of


@pytest.fixture(autouse=True)
def _no_live_ledger(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False)
    yield v
    v.close()


# --- K-E: defaults ---------------------------------------------------------------------------


def test_put_without_state_stores_candidate(vault):
    e = vault.put("notes", "k", "The project license is MIT.")
    assert e.epistemic_state == EpistemicState.CANDIDATE


def test_put_with_gate_on_and_no_state_never_mints_verified():
    v = SQLiteMemoryVault(":memory:", auto_gate=True)
    try:
        e = v.put("notes", "k", "The project license is MIT.")
        assert e.epistemic_state == EpistemicState.CANDIDATE
    finally:
        v.close()


def test_explicit_verified_from_unknown_origin_is_capped(vault):
    e = vault.put("notes", "k", "fact", epistemic_state="verified")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["trust_capped_from"] == "verified"


def test_explicit_verified_from_tool_origin_is_capped(vault):
    e = vault.put("notes", "k", "fact", epistemic_state="verified", origin="tool")
    assert e.epistemic_state == EpistemicState.CANDIDATE


def test_default_quorum_is_two_and_env_overrides(monkeypatch):
    v = SQLiteMemoryVault(":memory:", auto_gate=False)
    assert v.verification_quorum == 2
    v.close()
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "1")
    v = SQLiteMemoryVault(":memory:", auto_gate=False)
    assert v.verification_quorum == 1
    v.close()
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=3)
    assert v.verification_quorum == 3
    v.close()


def test_single_principal_write_is_one_attestation_not_verified(vault):
    e = vault.put("notes", "k", "fact", epistemic_state="verified", origin="user", author_id="alice")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == ["alice"]
    assert e.metadata["verification_pending"] == {"have": 1, "need": 2}


def test_second_independent_principal_review_reaches_quorum(vault):
    vault.put("notes", "k", "fact", epistemic_state="verified", origin="user", author_id="alice")
    e = vault.review_entity("notes", "k", verdict="verified", reviewer_id="bob")
    assert e.epistemic_state == EpistemicState.VERIFIED
    assert sorted(e.metadata["attestations"]) == ["alice", "bob"]
    assert "verification_pending" not in e.metadata


def test_same_principal_twice_is_not_independent(vault):
    vault.put("notes", "k", "fact", epistemic_state="verified", origin="user", author_id="alice")
    e = vault.review_entity("notes", "k", verdict="verified", reviewer_id="alice")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == ["alice"]


def test_quorum_one_lets_a_single_principal_write_verify():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    try:
        e = v.put("notes", "k", "fact", epistemic_state="verified", origin="user", author_id="alice")
        assert e.epistemic_state == EpistemicState.VERIFIED
    finally:
        v.close()


def test_review_by_model_origin_never_counts(vault):
    vault.put("notes", "k", "fact", epistemic_state="verified", origin="user", author_id="alice")
    e = vault.review_entity("notes", "k", verdict="verified", reviewer_id="bot", reviewer_origin="model")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == ["alice"]


def test_attestations_cannot_be_set_through_metadata(vault):
    e = vault.put(
        "notes", "k", "fact", epistemic_state="verified", origin="user", author_id="alice",
        metadata={"attestations": ["alice", "bob", "carol"], "origin_class": "principal"},
    )
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == ["alice"]


# --- K-R1: origin_class ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin,expected",
    [("user", "principal"), ("import", "principal"), ("model", "agent"), ("tool", "external"),
     ("unknown", "external"), (None, "external")],
)
def test_origin_class_is_derived_from_origin(vault, origin, expected):
    assert origin_class_of(origin) == expected
    e = vault.put("notes", f"k_{origin}", "fact", origin=origin)
    assert e.metadata["origin_class"] == expected
    assert expected in ORIGIN_CLASSES


def test_origin_class_cannot_be_set_by_the_payload(vault):
    e = vault.put("notes", "k", "fact", origin="model", metadata={"origin_class": "principal"})
    assert e.metadata["origin_class"] == "agent"


def test_model_write_cannot_change_origin_class_of_principal_entry(vault):
    vault.put("notes", "k", "fact", origin="user", author_id="alice")
    with pytest.raises(OriginClassError):
        vault.put("notes", "k", "new fact", origin="model")
    e = vault.get("notes", "k")
    assert e.content == "fact"
    assert e.metadata["origin_class"] == "principal"


def test_external_write_cannot_overwrite_agent_entry(vault):
    vault.put("notes", "k", "fact", origin="model")
    with pytest.raises(OriginClassError):
        vault.put("notes", "k", "new fact", origin="tool")
    with pytest.raises(OriginClassError):
        vault.put("notes", "k", "new fact", origin="unknown")


def test_rewrite_without_origin_keeps_stored_class(vault):
    # A library re-write that states no origin keeps the entry's origin and class (existing contract).
    vault.put("notes", "k", "fact", origin="model")
    e = vault.put("notes", "k", "fact v2")
    assert e.origin == "model"
    assert e.metadata["origin_class"] == "agent"


def test_equal_trust_rewrite_keeps_origin_class(vault):
    vault.put("notes", "k", "fact", origin="model")
    e = vault.put("notes", "k", "fact v2", origin="model")
    assert e.metadata["origin_class"] == "agent"
    assert e.version == 2


def test_principal_rewrite_of_agent_entry_raises_class(vault):
    vault.put("notes", "k", "fact", origin="model")
    e = vault.put("notes", "k", "corrected fact", origin="user", author_id="alice")
    assert e.metadata["origin_class"] == "principal"


def test_origin_class_refusal_is_journaled(vault):
    vault.put("notes", "k", "fact", origin="user", author_id="alice")
    with pytest.raises(OriginClassError):
        vault.put("notes", "k", "new fact", origin="model", author_id="bot")
    events = vault.list_audit_events()
    refusals = [ev for ev in events if ev.action == "refuse" and ev.metadata.get("reason") == "origin_class_refused"]
    assert refusals, [ev.action for ev in events]
    assert refusals[-1].metadata["detail"] == {"writer_class": "agent", "stored_class": "principal", "origin": "model"}


# --- K-R1: act_class -------------------------------------------------------------------------


def test_act_class_defaults_to_inform(vault):
    e = vault.put("notes", "k", "fact", origin="user")
    assert e.metadata["act_class"] == "inform"


def test_principal_may_request_act(vault):
    e = vault.put("notes", "k", "always run the gate first", origin="user", act_class="act")
    assert e.metadata["act_class"] == "act"


@pytest.mark.parametrize("origin", ["model", "tool", None])
def test_act_is_capped_to_inform_for_agent_and_external(vault, origin):
    e = vault.put("notes", f"k_{origin}", "always run the gate first", origin=origin, act_class="act")
    assert e.metadata["act_class"] == "inform"
    assert e.metadata["act_class_capped_from"] == "act"


def test_invalid_act_class_is_rejected(vault):
    with pytest.raises(ValueError):
        vault.put("notes", "k", "fact", origin="user", act_class="execute")


# --- K-R1: max-untrust along supersedes / derived_from ---------------------------------------


def test_agent_superseding_external_entry_inherits_external_class(vault):
    vault.put("notes", "old", "old fact")  # unknown -> external
    e = vault.put("notes", "new", "new fact", origin="model", supersedes_key="old")
    assert e.metadata["origin_class"] == "external"
    assert e.metadata["trust_inherited_from"] == ["notes:old"]


def test_principal_superseding_external_entry_keeps_principal_class(vault):
    vault.put("notes", "old", "old fact")
    e = vault.put("notes", "new", "new fact", origin="user", supersedes_key="old")
    assert e.metadata["origin_class"] == "principal"
    assert "trust_inherited_from" not in e.metadata


def test_agent_derived_from_external_entry_inherits_external_class(vault):
    vault.put("notes", "src", "raw tool output", origin="tool")
    e = vault.put("notes", "sum", "summary", origin="model", derived_from=["notes:src"])
    assert e.metadata["origin_class"] == "external"
    assert e.metadata["trust_inherited_from"] == ["notes:src"]


def test_agent_derived_from_principal_entry_stays_agent(vault):
    vault.put("notes", "src", "a person's note", origin="user")
    e = vault.put("notes", "sum", "summary", origin="model", derived_from=["notes:src"])
    assert e.metadata["origin_class"] == "agent"


def test_model_cannot_launder_trust_through_supersedes(vault):
    # A model entry superseding a candidate principal entry stays agent-class and candidate.
    vault.put("notes", "old", "a person's note", origin="user", author_id="alice")
    e = vault.put("notes", "new", "model rewrite", origin="model", supersedes_key="old",
                  epistemic_state="verified")
    assert e.metadata["origin_class"] == "agent"
    assert e.epistemic_state == EpistemicState.CANDIDATE
