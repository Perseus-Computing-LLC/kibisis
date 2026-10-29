"""K-R2: three-way supersession, cascading invalidation, bitemporal non-revival.

Retirement happens only through an explicit ``supersedes`` edge (or a person's review / forget), never
through a score. A supersession resolves one of three ways:

- ``applied``: the writer outranks or equals the target's origin class and the target is not a
  person-reviewed entry the writer may not retire; the target is revoked and closed (``valid_until``).
- ``needs_confirmation``: a lower-class writer, or any non-principal writer against a reviewed entry;
  the new entry is stored as a proposal, the target stays active and is marked
  ``pending_supersession_by``; a person's ``verified`` review of the proposal applies it.
- ``refused``: the target is itself already superseded (no re-pointing a retired edge) or the target
  does not exist in the scope.

Cascading invalidation: retiring an entry marks every active entry that ``derived_from`` it as
``disputed`` with ``invalidated_by`` set, and continues through their dependents. Bitemporal
non-revival: a superseded key stays closed; a write to it is refused unless ``revive=True`` from a
principal, which opens a new version with a new ``valid_from`` and never reopens the old interval.
"""

import pytest

from kibisis import EpistemicState, SQLiteMemoryVault
from kibisis.vault import SupersessionRefused, SupersededEntryError


@pytest.fixture(autouse=True)
def _no_live_ledger(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()




# --- three-way outcome -----------------------------------------------------------------------


def test_principal_supersession_is_applied(vault):
    vault.put("fact", "old", "Paris is the capital", origin="user", author_id="a")
    new = vault.put("fact", "new", "Paris is still the capital", origin="user", author_id="a", supersedes_key="old")
    assert new.metadata["supersession"] == {"outcome": "applied", "target": "fact:old"}
    old = vault.get("fact", "old")
    assert old.epistemic_state == EpistemicState.REVOKED
    assert old.superseded_by == "fact:new"
    assert old.valid_until is not None


def test_equal_class_agent_supersession_of_unreviewed_agent_entry_is_applied(vault):
    vault.put("fact", "old", "model note", origin="model")
    new = vault.put("fact", "new", "model note v2", origin="model", supersedes_key="old")
    assert new.metadata["supersession"]["outcome"] == "applied"
    assert vault.get("fact", "old").epistemic_state == EpistemicState.REVOKED


def test_agent_supersession_of_principal_entry_needs_confirmation(vault):
    vault.put("fact", "old", "a person's note", origin="user", author_id="a", epistemic_state="candidate")
    new = vault.put("fact", "new", "model rewrite", origin="model", supersedes_key="old")
    assert new.metadata["supersession"] == {"outcome": "needs_confirmation", "target": "fact:old"}
    assert new.metadata["proposed_supersedes"] == {"category": "fact", "key": "old"}
    old = vault.get("fact", "old")
    assert old.epistemic_state == EpistemicState.CANDIDATE  # untouched
    assert old.superseded_by is None
    assert old.metadata["pending_supersession_by"] == ["fact:new"]


def test_external_supersession_of_agent_entry_needs_confirmation(vault):
    vault.put("fact", "old", "model note", origin="model")
    new = vault.put("fact", "new", "tool output", origin="tool", supersedes_key="old")
    assert new.metadata["supersession"]["outcome"] == "needs_confirmation"
    assert vault.get("fact", "old").epistemic_state != EpistemicState.REVOKED


def test_agent_supersession_of_reviewed_entry_needs_confirmation(vault):
    vault.put("fact", "old", "fact", origin="user", author_id="a", epistemic_state="verified")
    assert vault.get("fact", "old").epistemic_state == EpistemicState.VERIFIED
    new = vault.put("fact", "new", "model rewrite", origin="model", supersedes_key="old")
    assert new.metadata["supersession"]["outcome"] == "needs_confirmation"
    assert vault.get("fact", "old").epistemic_state == EpistemicState.VERIFIED


def test_confirmation_by_a_person_applies_the_pending_supersession(vault):
    vault.put("fact", "old", "a person's note", origin="user", author_id="a", epistemic_state="candidate")
    vault.put("fact", "new", "model rewrite", origin="model", supersedes_key="old")
    confirmed = vault.review_entity("fact", "new", verdict="verified", reviewer_id="b")
    assert confirmed.epistemic_state == EpistemicState.VERIFIED
    assert confirmed.metadata["supersession"] == {"outcome": "applied", "target": "fact:old", "confirmed_by": "b"}
    old = vault.get("fact", "old")
    assert old.epistemic_state == EpistemicState.REVOKED
    assert old.superseded_by == "fact:new"
    assert "pending_supersession_by" not in old.metadata


def test_rejecting_the_proposal_clears_the_pending_mark(vault):
    vault.put("fact", "old", "a person's note", origin="user", author_id="a", epistemic_state="candidate")
    vault.put("fact", "new", "model rewrite", origin="model", supersedes_key="old")
    vault.review_entity("fact", "new", verdict="revoked", reviewer_id="b")
    old = vault.get("fact", "old")
    assert old.epistemic_state == EpistemicState.CANDIDATE
    assert "pending_supersession_by" not in old.metadata


def test_superseding_a_missing_target_is_refused(vault):
    with pytest.raises(SupersessionRefused):
        vault.put("fact", "new", "x", origin="user", supersedes_key="nope")
    assert vault.get("fact", "new") is None


def test_superseding_an_already_superseded_target_is_refused(vault):
    vault.put("fact", "old", "v1", origin="user", author_id="a")
    vault.put("fact", "mid", "v2", origin="user", author_id="a", supersedes_key="old")
    with pytest.raises(SupersessionRefused):
        vault.put("fact", "new", "v3", origin="user", author_id="a", supersedes_key="old")
    assert vault.get("fact", "old").superseded_by == "fact:mid"


def test_supersession_outcome_is_journaled(vault):
    vault.put("fact", "old", "a person's note", origin="user", author_id="a", epistemic_state="candidate")
    vault.put("fact", "new", "model rewrite", origin="model", supersedes_key="old")
    actions = [(ev.action, ev.metadata.get("outcome")) for ev in vault.list_audit_events() if ev.action == "supersession"]
    assert ("supersession", "needs_confirmation") in actions


# --- retirement only through an edge ----------------------------------------------------------


def test_low_confidence_or_many_writes_never_retire_a_neighbour(vault):
    vault.put("fact", "a", "the sky is blue", origin="model", confidence=0.95)
    for i in range(20):
        vault.put("fact", f"b{i}", "the sky is blue today", origin="model", confidence=0.05)
    assert vault.get("fact", "a").epistemic_state == EpistemicState.CANDIDATE
    revoked = [ev for ev in vault.list_audit_events()
               if ev.action == "state_transition" and ev.metadata.get("to") == "revoked"]
    assert revoked == []


def test_every_revocation_has_an_explicit_cause(vault):
    vault.put("fact", "a", "v1", origin="user", author_id="a")
    vault.put("fact", "b", "v2", origin="user", author_id="a", supersedes_key="a")
    vault.put("fact", "c", "v3", origin="user", author_id="a")
    vault.review_entity("fact", "c", verdict="revoked", reviewer_id="b")
    causes = {ev.metadata.get("cause") for ev in vault.list_audit_events()
              if ev.action == "state_transition" and ev.metadata.get("to") == "revoked"}
    assert causes and causes <= {"supersede", "review", "forget", "cascade"}


# --- cascading invalidation --------------------------------------------------------------------


def test_retiring_a_source_disputes_everything_derived_from_it(vault):
    vault.put("src", "report", "raw figures", origin="user", author_id="a")
    vault.put("sum", "s1", "summary of the figures", origin="model", derived_from=["src:report"],
              epistemic_state="candidate")
    vault.put("sum", "s2", "second-order note", origin="model", derived_from=["sum:s1"])
    vault.put("sum", "unrelated", "nothing to do with it", origin="model")
    vault.put("src", "report_v2", "corrected figures", origin="user", author_id="a", supersedes_key="report")
    s1, s2 = vault.get("sum", "s1"), vault.get("sum", "s2")
    assert s1.epistemic_state == EpistemicState.DISPUTED
    assert s1.metadata["invalidated_by"] == "src:report"
    assert s2.epistemic_state == EpistemicState.DISPUTED
    assert s2.metadata["invalidated_by"] == "sum:s1"
    assert vault.get("sum", "unrelated").epistemic_state == EpistemicState.CANDIDATE


def test_cascade_reaches_verified_dependents_and_is_journaled(vault):
    vault.put("src", "report", "raw figures", origin="user", author_id="a")
    vault.put("sum", "s1", "summary", origin="user", author_id="a", derived_from=["src:report"], epistemic_state="verified")
    assert vault.get("sum", "s1").epistemic_state == EpistemicState.VERIFIED
    vault.review_entity("src", "report", verdict="revoked", reviewer_id="b")
    s1 = vault.get("sum", "s1")
    assert s1.epistemic_state == EpistemicState.DISPUTED
    assert s1.metadata["invalidated_by"] == "src:report"
    cascade = [ev for ev in vault.list_audit_events() if ev.action == "state_transition" and ev.metadata.get("cause") == "cascade"]
    assert [ev.key for ev in cascade] == ["s1"]


def test_cascade_terminates_on_cycles(vault):
    vault.put("n", "a", "a", origin="user", author_id="u")
    vault.put("n", "b", "b", origin="user", author_id="u", derived_from=["n:a"])
    # a also derives from b (a cycle written later as a re-write that states its lineage)
    vault.put("n", "a", "a2", origin="user", author_id="u", derived_from=["n:b"])
    vault.review_entity("n", "a", verdict="revoked", reviewer_id="r")
    assert vault.get("n", "b").epistemic_state == EpistemicState.DISPUTED


def test_forget_cascades_too(vault):
    vault.put("src", "report", "raw figures", origin="user", author_id="a")
    vault.put("sum", "s1", "summary", origin="model", derived_from=["src:report"])
    vault.archive("src", "report")
    assert vault.get("sum", "s1").epistemic_state == EpistemicState.DISPUTED


# --- bitemporal non-revival --------------------------------------------------------------------


def test_writing_to_a_superseded_key_is_refused(vault):
    vault.put("fact", "old", "v1", origin="user", author_id="a")
    vault.put("fact", "new", "v2", origin="user", author_id="a", supersedes_key="old")
    with pytest.raises(SupersededEntryError):
        vault.put("fact", "old", "v1 again", origin="user", author_id="a")
    with pytest.raises(SupersededEntryError):
        vault.put("fact", "old", "v1 again", origin="model")
    old = vault.get("fact", "old")
    assert old.epistemic_state == EpistemicState.REVOKED
    assert old.content == "v1"


def test_refused_revival_is_journaled(vault):
    vault.put("fact", "old", "v1", origin="user", author_id="a")
    vault.put("fact", "new", "v2", origin="user", author_id="a", supersedes_key="old")
    with pytest.raises(SupersededEntryError):
        vault.put("fact", "old", "v1 again", origin="model")
    refusals = [ev for ev in vault.list_audit_events() if ev.action == "refuse" and ev.metadata.get("reason") == "superseded_entry"]
    assert refusals


def test_principal_revive_opens_a_new_interval_without_reopening_the_old_one(vault):
    vault.put("fact", "old", "v1", origin="user", author_id="a")
    vault.put("fact", "new", "v2", origin="user", author_id="a", supersedes_key="old")
    closed = vault.get("fact", "old")
    revived = vault.put("fact", "old", "v1 again", origin="user", author_id="a", revive=True)
    assert revived.epistemic_state == EpistemicState.CANDIDATE
    assert revived.valid_from is not None and revived.valid_from >= closed.valid_until
    assert revived.valid_until is None
    assert revived.superseded_by is None
    assert revived.metadata["revived_from"] == {"version": closed.version, "superseded_by": "fact:new"}
    # The closed interval is still visible as-of its own time.
    as_of = vault.get_as_of("fact", "old", closed.valid_from) if hasattr(vault, "get_as_of") else None
    if as_of is not None:
        assert as_of.content == "v1"
        assert as_of.valid_until == closed.valid_until


def test_agent_cannot_revive(vault):
    vault.put("fact", "old", "v1", origin="user", author_id="a")
    vault.put("fact", "new", "v2", origin="user", author_id="a", supersedes_key="old")
    with pytest.raises(SupersededEntryError):
        vault.put("fact", "old", "v1 again", origin="model", revive=True)


def test_revive_cannot_backdate_valid_from(vault):
    vault.put("fact", "old", "v1", origin="user", author_id="a")
    vault.put("fact", "new", "v2", origin="user", author_id="a", supersedes_key="old")
    closed = vault.get("fact", "old")
    with pytest.raises(ValueError):
        vault.put("fact", "old", "v1 again", origin="user", author_id="a", revive=True, valid_from=closed.valid_until - 10)
