"""severity: medium
finding: with enforce_fencing=True, origin/scope refusals run and are journaled before the token is checked, so a stale or token-less caller still appends a refuse event and gets no LeaseConflictError

``SQLiteMemoryVault`` (src/kibisis/vault.py:333-336) promises that with ``enforce_fencing=True`` "a
missing, stale or expired token raises ``LeaseConflictError`` and changes nothing", and
tests/test_enforce_fencing.py:3-6 counts the audit journal in what a refused call must not change.

Three calls run an origin or scope check before any token is looked at, outside the fenced
transaction, and ``_journal_protected_refusal`` (src/kibisis/_vault_tombstone.py:114-131) then writes
a ``refuse`` event in a fresh transaction:

- ``set_persona_slot`` with a non-principal origin over a protected slot (vault.py:2544-2551; the
  fenced ``put`` only comes at vault.py:2554);
- ``tombstone(scope="*")`` with a non-principal origin (_vault_tombstone.py:343-348; the fence is in
  ``_tombstone_locked`` at :373);
- ``lift_tombstone`` with a non-principal origin (_vault_tombstone.py:498-504; the fence is in
  ``_lift_tombstone_locked`` at :532).

A holder fenced out by a takeover (or a caller with no token at all) therefore still writes to the
vault: one journal row per call, carrying caller-chosen category, key, scope and author.
"""

import pytest

from kibisis import FileLeaseCoordinator, LeaseConflictError, SQLiteMemoryVault

RESOURCE = "memory/shared"


def _fence(lease):
    return {"fencing_token": lease.fencing_token, "resource": lease.resource, "holder_id": lease.holder_id}


def _state(v):
    entries = sorted(
        (e.category, e.key, e.content, e.version, e.archived, e.epistemic_state.value)
        for e in v.list_entities(include_archived=True, include_unverified=True)
    )
    return entries, len(v.list_tombstones()), len(v.list_audit_events(limit=10_000))


@pytest.fixture
def fenced(tmp_path):
    coordinator = FileLeaseCoordinator(str(tmp_path / "leases"))
    vault = SQLiteMemoryVault(":memory:", coordinator=coordinator, enforce_fencing=True)
    seeder = coordinator.acquire(RESOURCE, "seeder", ttl_seconds=30)
    vault.set_persona_slot("prefers short answers", **_fence(seeder))
    vault.put("notes", "existing", "seeded value", **_fence(seeder))
    vault.put("notes", "gone", "rejected value", **_fence(seeder))
    vault.tombstone("notes", "gone", **_fence(seeder))
    assert coordinator.release(seeder)
    worker = coordinator.acquire(RESOURCE, "worker", ttl_seconds=30)  # takeover: seeder is now stale
    yield vault, seeder, worker
    vault.close()
    coordinator.close()


CALLS = {
    "set_persona_slot_model": lambda v, kw: v.set_persona_slot("model's idea of the user", origin="model", **kw),
    "tombstone_all_scopes_tool": lambda v, kw: v.tombstone("notes", "existing", scope="*", origin="tool", **kw),
    "lift_tombstone_model": lambda v, kw: v.lift_tombstone("notes", "gone", origin="model", **kw),
}


def test_control_stale_principal_calls_are_fenced_and_current_token_works(fenced):
    vault, seeder, worker = fenced
    before = _state(vault)
    with pytest.raises(LeaseConflictError):
        vault.lift_tombstone("notes", "gone", **_fence(seeder))
    with pytest.raises(LeaseConflictError):
        vault.tombstone("notes", "existing", scope="*", **_fence(seeder))
    assert _state(vault) == before
    assert vault.lift_tombstone("notes", "gone", **_fence(worker)) == 1


@pytest.mark.parametrize("token", ["stale", "missing"])
@pytest.mark.parametrize("name", sorted(CALLS))
def test_unfenced_call_is_refused_by_the_fence_and_changes_nothing(fenced, name, token):
    vault, seeder, _worker = fenced
    kw = _fence(seeder) if token == "stale" else {}
    before = _state(vault)
    raised = None
    try:
        CALLS[name](vault, kw)
    except Exception as exc:  # noqa: BLE001 - the type is asserted below
        raised = exc
    after = _state(vault)
    assert after == before, (
        f"{name} with a {token} token changed the vault on an enforce_fencing vault "
        f"(audit events {before[2]} -> {after[2]}, raised {type(raised).__name__})"
    )
    assert isinstance(raised, LeaseConflictError), (
        f"{name} with a {token} token raised {type(raised).__name__}, not LeaseConflictError"
    )
