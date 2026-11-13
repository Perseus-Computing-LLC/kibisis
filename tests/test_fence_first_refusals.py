"""Every mutating call that takes a fencing token checks the fence before its origin, scope, class or
protection checks, and a protection decision shares one write transaction with the write it guards.

- On an ``enforce_fencing`` vault, a stale or missing token raises ``LeaseConflictError`` and changes
  nothing: no entry, no tombstone, no audit-journal row (no ``refuse`` event), whatever the call would
  otherwise have been refused for.
- When the fence passes, or is not evaluated at all, a refused call raises the same exception and
  journals the same ``refuse`` event (path and reason) as it always did.
"""

import pytest

from kibisis import FileLeaseCoordinator, LeaseConflictError, SQLiteMemoryVault
from kibisis.vault import ReviewedEntryError, TombstonedValueError

RESOURCE = "memory/shared"


def _fence(lease):
    return {"fencing_token": lease.fencing_token, "resource": lease.resource, "holder_id": lease.holder_id}


def _state(v):
    entries = sorted(
        (e.category, e.key, e.content, e.version, e.archived, e.epistemic_state.value)
        for e in v.list_entities(include_archived=True, include_unverified=True)
    )
    return entries, len(v.list_tombstones()), len(v.list_audit_events(limit=10_000))


def _refusals(v):
    out = []
    for event in v.list_audit_events(limit=10_000):
        if event.action == "refuse":
            meta = event.metadata or {}
            out.append((meta.get("path"), meta.get("reason"), event.category, event.key))
    return out


def _seed(vault, **kw):
    vault.set_persona_slot("prefers short answers", **kw)  # a principal's slot: verified
    vault.put("notes", "existing", "seeded value", **kw)
    vault.put("notes", "gone", "rejected value", **kw)
    vault.tombstone("notes", "gone", **kw)


# name -> (call, exception type raised when the fence passes or is not evaluated, journaled refusal)
CALLS = {
    "set_persona_slot_model": (
        lambda v, kw: v.set_persona_slot("model's idea of the user", origin="model", **kw),
        ReviewedEntryError, ("set_persona_slot", "protected entry", "persona", "user_profile"),
    ),
    "tombstone_all_scopes_tool": (
        lambda v, kw: v.tombstone("notes", "existing", scope="*", origin="tool", **kw),
        PermissionError, ("tombstone", "scope not allowed", "notes", "existing"),
    ),
    "tombstone_reviewed_model": (
        lambda v, kw: v.tombstone("persona", "user_profile", origin="model", **kw),
        ReviewedEntryError, ("tombstone", "protected entry", "persona", "user_profile"),
    ),
    "lift_tombstone_model": (
        lambda v, kw: v.lift_tombstone("notes", "gone", origin="model", **kw),
        PermissionError, ("lift_tombstone", "scope not allowed", "notes", "gone"),
    ),
    "archive_reviewed_model": (
        lambda v, kw: v.archive("persona", "user_profile", origin="model", **kw),
        ReviewedEntryError, ("archive", "protected entry", "persona", "user_profile"),
    ),
    "purge_reviewed_model": (
        lambda v, kw: v.purge("persona", "user_profile", origin="model", **kw),
        ReviewedEntryError, ("purge", "protected entry", "persona", "user_profile"),
    ),
    "put_tombstoned_value_model": (
        lambda v, kw: v.put("notes", "gone", "rejected value", origin="model", **kw),
        TombstonedValueError, ("put", "tombstoned value", "notes", "gone"),
    ),
    "review_entity_model": (
        lambda v, kw: v.review_entity("notes", "existing", "verified", reviewer_id="someone", reviewer_origin="model", **kw),
        PermissionError, None,
    ),
    "admit_model": (
        lambda v, kw: v.admit("notes", "existing", reviewer="someone", reviewer_origin="model", **kw),
        PermissionError, None,
    ),
}


@pytest.fixture
def fenced(tmp_path):
    coordinator = FileLeaseCoordinator(str(tmp_path / "leases"))
    vault = SQLiteMemoryVault(":memory:", coordinator=coordinator, enforce_fencing=True)
    seeder = coordinator.acquire(RESOURCE, "seeder", ttl_seconds=30)
    _seed(vault, **_fence(seeder))
    assert coordinator.release(seeder)
    worker = coordinator.acquire(RESOURCE, "worker", ttl_seconds=30)  # takeover: seeder is now stale
    yield vault, seeder, worker
    vault.close()
    coordinator.close()


@pytest.mark.parametrize("token", ["stale", "missing"])
@pytest.mark.parametrize("name", sorted(CALLS))
def test_a_fenced_out_call_raises_lease_conflict_and_changes_nothing(fenced, name, token):
    vault, seeder, _worker = fenced
    call = CALLS[name][0]
    kw = _fence(seeder) if token == "stale" else {}
    before = _state(vault)
    with pytest.raises(LeaseConflictError):
        call(vault, kw)
    assert _state(vault) == before


@pytest.fixture
def unfenced():
    vault = SQLiteMemoryVault(":memory:")
    _seed(vault)
    yield vault, {}
    vault.close()


@pytest.fixture
def current_token(fenced):
    vault, _seeder, worker = fenced
    return vault, _fence(worker)


@pytest.mark.parametrize("mode", ["unfenced", "current_token"])
@pytest.mark.parametrize("name", sorted(CALLS))
def test_a_refusal_past_the_fence_is_raised_and_journaled_as_before(request, name, mode):
    vault, kw = request.getfixturevalue(mode)
    call, expected, refusal = CALLS[name]
    entries, tombstones, _ = _state(vault)
    assert _refusals(vault) == []
    with pytest.raises(expected) as raised:
        call(vault, kw)
    assert not isinstance(raised.value, LeaseConflictError)
    assert _state(vault)[:2] == (entries, tombstones)
    assert _refusals(vault) == ([refusal] if refusal else []), name


def test_a_current_token_still_writes_the_persona_slot_and_lifts(fenced):
    vault, _seeder, worker = fenced
    vault.set_persona_slot("prefers long answers", **_fence(worker))
    assert vault.get_persona_slot().content == "prefers long answers"
    assert vault.lift_tombstone("notes", "gone", **_fence(worker)) == 1
