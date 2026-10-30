"""Fencing tokens checked by the vault itself.

A vault opened with a lease coordinator and ``enforce_fencing=True`` refuses any call that adds,
changes or removes entries unless it carries the caller's current ``fencing_token`` and
``resource`` (and, optionally, ``holder_id``). The token is checked while the vault holds its
write lock, and a refused call changes nothing: no entry, no tombstone, no audit event.
"""

import time

import tempfile

import pytest

from kibisis import LeaseConflictError, FileLeaseCoordinator, SQLiteMemoryVault

RESOURCE = "memory/shared"


@pytest.fixture(autouse=True)
def _no_passphrase(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)


@pytest.fixture
def coordinator():
    coord = FileLeaseCoordinator(tempfile.mkdtemp())
    yield coord
    coord.close()


@pytest.fixture
def vault(coordinator):
    v = SQLiteMemoryVault(":memory:", coordinator=coordinator, enforce_fencing=True)
    yield v
    v.close()


def fence(lease, with_holder=True):
    kw = {"fencing_token": lease.fencing_token, "resource": lease.resource}
    if with_holder:
        kw["holder_id"] = lease.holder_id
    return kw


def state(v):
    """Everything a write can change: entries, tombstones and the audit journal."""
    entries = sorted(
        (e.category, e.key, e.content, e.version, e.archived, e.epistemic_state.value)
        for e in v.list_entities(include_archived=True, include_unverified=True)
    )
    return entries, len(v.list_tombstones()), len(v.list_audit_events(limit=10_000))


def test_enforce_fencing_needs_a_coordinator():
    with pytest.raises(ValueError, match="coordinator"):
        SQLiteMemoryVault(":memory:", enforce_fencing=True)


def test_write_without_a_token_is_refused_and_changes_nothing(vault):
    before = state(vault)
    with pytest.raises(LeaseConflictError):
        vault.put("notes", "k", "v")
    assert state(vault) == before
    assert not vault._conn.in_transaction


@pytest.mark.parametrize("with_holder", [True, False])
def test_write_with_the_current_token_is_accepted(vault, coordinator, with_holder):
    lease = coordinator.acquire(RESOURCE, "worker-a", ttl_seconds=30)
    entity = vault.put("notes", "k", "v1", **fence(lease, with_holder))
    assert entity.version == 1
    assert vault.get("notes", "k").content == "v1"


@pytest.mark.parametrize("with_holder", [True, False])
def test_stale_token_after_a_takeover_is_refused(vault, coordinator, with_holder):
    a = coordinator.acquire(RESOURCE, "worker-a", ttl_seconds=30)
    vault.put("notes", "k", "from a", **fence(a, with_holder))
    assert coordinator.release(a)
    b = coordinator.acquire(RESOURCE, "worker-b", ttl_seconds=30)
    assert b.fencing_token == a.fencing_token + 1
    vault.put("notes", "k", "from b", **fence(b, with_holder))

    before = state(vault)
    with pytest.raises(LeaseConflictError):
        vault.put("notes", "k", "late write from a", **fence(a, with_holder))
    assert state(vault) == before
    assert vault.get("notes", "k").content == "from b"
    assert not vault._conn.in_transaction


def test_expired_lease_is_refused(vault, coordinator):
    lease = coordinator.acquire(RESOURCE, "worker-a", ttl_seconds=0.05)
    time.sleep(1.1)  # the shared deadline is a whole second, rounded up (K-C)
    with pytest.raises(LeaseConflictError):
        vault.put("notes", "k", "v", **fence(lease))
    assert vault.get("notes", "k") is None


def test_token_presented_by_another_holder_is_refused(vault, coordinator):
    lease = coordinator.acquire(RESOURCE, "worker-a", ttl_seconds=30)
    with pytest.raises(LeaseConflictError):
        vault.put("notes", "k", "v", fencing_token=lease.fencing_token, resource=RESOURCE, holder_id="worker-b")
    assert vault.get("notes", "k") is None


def test_without_enforce_fencing_writes_without_a_token_still_work(coordinator):
    v = SQLiteMemoryVault(":memory:", coordinator=coordinator)
    v.put("notes", "k", "v")
    assert v.get("notes", "k").content == "v"


def test_without_enforce_fencing_a_token_that_is_passed_is_still_checked(coordinator):
    v = SQLiteMemoryVault(":memory:", coordinator=coordinator)
    a = coordinator.acquire(RESOURCE, "worker-a", ttl_seconds=30)
    assert coordinator.release(a)
    coordinator.acquire(RESOURCE, "worker-b", ttl_seconds=30)
    with pytest.raises(LeaseConflictError):
        v.put("notes", "k", "late", **fence(a))
    assert v.get("notes", "k") is None


class _SpyCoordinator(FileLeaseCoordinator):
    """Records whether the vault had its write transaction open when the token was checked."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        super().__init__(self._tmp.name)
        self.vault = None
        self.in_transaction = []

    def validate_fencing_token(self, resource, holder_id, fencing_token):
        if self.vault is not None:
            self.in_transaction.append(self.vault._conn.in_transaction)
        return super().validate_fencing_token(resource, holder_id, fencing_token)

    def get_lease(self, resource):
        if self.vault is not None:
            self.in_transaction.append(self.vault._conn.in_transaction)
        return super().get_lease(resource)


@pytest.mark.parametrize("with_holder", [True, False])
def test_token_is_checked_while_the_vault_holds_its_write_lock(with_holder):
    spy = _SpyCoordinator()
    v = SQLiteMemoryVault(":memory:", coordinator=spy, enforce_fencing=True)
    lease = spy.acquire(RESOURCE, "worker-a", ttl_seconds=30)
    spy.vault = v
    v.put("notes", "k", "v", **fence(lease, with_holder))
    assert spy.in_transaction == [True]
    v.close()
    spy.close()


def test_vault_and_coordinators_sharing_one_encrypted_file(tmp_path):
    """The Hermes plugin's layout: encrypted vault file plus a lease directory beside it, two workers' coordinators."""
    path = str(tmp_path / "vault.sqlite")
    secret = "fencing-test-passphrase"
    coord_a = FileLeaseCoordinator(str(tmp_path / "leases"))
    coord_b = FileLeaseCoordinator(str(tmp_path / "leases"))
    v = SQLiteMemoryVault(path, passphrase=secret, coordinator=coord_a, enforce_fencing=True)

    a = coord_a.acquire(RESOURCE, "worker-a", ttl_seconds=30)
    v.put("notes", "k", "from a", **fence(a))
    assert coord_a.release(a)
    b = coord_b.acquire(RESOURCE, "worker-b", ttl_seconds=30)
    with pytest.raises(LeaseConflictError):
        v.put("notes", "k", "late write from a", **fence(a))
    v.put("notes", "k", "from b", **fence(b))
    assert v.get("notes", "k").content == "from b"
    assert v.get("notes", "k").version == 2
    v.close()
    coord_a.close()
    coord_b.close()


def _snapshot():
    src = SQLiteMemoryVault(":memory:")
    src.put("notes", "imported", "imported value")
    snap = src.export_snapshot()
    src.close()
    return snap


WRITES = {
    "put": lambda v, kw: v.put("notes", "new", "new value", **kw),
    "store": lambda v, kw: v.store("notes", "new", "new value", **kw),
    "put_batch": lambda v, kw: v.put_batch([{"category": "notes", "key": "new", "content": "new value"}], **kw),
    "archive": lambda v, kw: v.archive("notes", "existing", **kw),
    "purge": lambda v, kw: v.purge("notes", "existing", **kw),
    "tombstone": lambda v, kw: v.tombstone("notes", "existing", **kw),
    "admit_candidate": lambda v, kw: v.admit_candidate("notes", "new", "new value", **kw),
    "review_entity": lambda v, kw: v.review_entity("notes", "candidate", "verified", **kw),
    "review_entity_revoked": lambda v, kw: v.review_entity("notes", "candidate", "revoked", **kw),
    "set_persona_slot": lambda v, kw: v.set_persona_slot("prefers short answers", **kw),
    "import_snapshot": lambda v, kw: v.import_snapshot(_snapshot(), **kw),
}


@pytest.mark.parametrize("name", sorted(WRITES))
def test_every_write_call_is_fenced(name, vault, coordinator):
    seeder = coordinator.acquire(RESOURCE, "seeder", ttl_seconds=30)
    vault.put("notes", "existing", "seeded value", **fence(seeder))
    vault.admit_candidate("notes", "candidate", "candidate value", **fence(seeder))
    assert coordinator.release(seeder)
    write = WRITES[name]
    before = state(vault)

    with pytest.raises(LeaseConflictError):
        write(vault, {})
    assert state(vault) == before, f"{name} changed the vault without a token"

    worker = coordinator.acquire(RESOURCE, "worker", ttl_seconds=30)
    with pytest.raises(LeaseConflictError):
        write(vault, fence(seeder))
    assert state(vault) == before, f"{name} changed the vault with a stale token"

    write(vault, fence(worker))
    assert state(vault) != before, f"{name} with the current token changed nothing"
