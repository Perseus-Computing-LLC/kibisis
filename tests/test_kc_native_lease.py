"""K-C (telarch P7.3): one lease coordinator, in Rust, reached from Python through kibisis_native.

The Python package no longer carries its own SQLite lease table. ``kibisis.FileLeaseCoordinator`` is a thin
adapter over ``kibisis_native.FileLeaseCoordinator`` (one lock file and one state file per resource, directory
0700, files 0600, fencing tokens that only go up). The journal hash functions come from the same crate, so the
Python vault and the Rust verifier share one implementation. There is no Python fallback: an environment
without the extension fails at import, loudly, instead of silently coordinating nothing.
"""
from __future__ import annotations

import os
import stat
import time

import pytest

import kibisis
from kibisis import LeaseConflictError
from kibisis.lease import MAX_TTL_SECONDS, FileLeaseCoordinator


def test_native_extension_is_required_not_optional():
    import kibisis_native

    assert kibisis_native.crate_version().startswith("0.1.0")
    assert kibisis.lease._native is kibisis_native
    assert not hasattr(kibisis, "SQLiteLeaseCoordinator")
    assert kibisis.FileLeaseCoordinator is FileLeaseCoordinator


def test_lease_lifecycle_through_the_native_coordinator(tmp_path):
    d = tmp_path / "leases"
    c = FileLeaseCoordinator(str(d))
    a = c.acquire("vault", "worker-a", ttl_seconds=30)
    assert a.fencing_token == 1 and a.holder_id == "worker-a" and a.resource == "vault"
    assert a.local_deadline is not None and not a.is_locally_expired and not a.is_expired
    with pytest.raises(LeaseConflictError):
        c.acquire("vault", "worker-b", ttl_seconds=30)
    assert c.validate_fencing_token("vault", "worker-a", 1)
    assert not c.validate_fencing_token("vault", "worker-a", 2)
    assert c.renew(a, ttl_seconds=30)
    assert c.release(a)
    assert not c.release(a)
    b = c.acquire("vault", "worker-b", ttl_seconds=30)
    assert b.fencing_token == 2
    assert c.get_lease("vault").holder_id == "worker-b"
    assert not c.validate_fencing_token("vault", "worker-a", 1)
    # same holder re-acquiring gets the next token; the old one is dead
    b2 = c.acquire("vault", "worker-b", ttl_seconds=30)
    assert b2.fencing_token == 3 and not c.renew(b, ttl_seconds=30)
    c.close()


def test_two_coordinators_on_one_directory_see_one_lease(tmp_path):
    d = str(tmp_path / "leases")
    c1, c2 = FileLeaseCoordinator(d), FileLeaseCoordinator(d)
    a = c1.acquire("r", "a", ttl_seconds=30)
    with pytest.raises(LeaseConflictError):
        c2.acquire("r", "b", ttl_seconds=30)
    assert c2.validate_fencing_token("r", "a", a.fencing_token)
    assert c1.release(a)
    b = c2.acquire("r", "b", ttl_seconds=30)
    assert b.fencing_token == a.fencing_token + 1
    assert c1.get_lease("r").holder_id == "b"


def test_lease_files_are_private(tmp_path):
    d = tmp_path / "leases"
    c = FileLeaseCoordinator(str(d))
    c.acquire("r", "a", ttl_seconds=5)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    files = [p for p in d.iterdir() if p.is_file()]
    assert files and all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in files)


def test_ttl_bounds_and_expiry(tmp_path):
    c = FileLeaseCoordinator(str(tmp_path))
    for bad in (0, -1, MAX_TTL_SECONDS + 1):
        with pytest.raises(ValueError):
            c.acquire("r", "h", ttl_seconds=bad)
    a = c.acquire("r", "h", ttl_seconds=1)
    with pytest.raises(ValueError):
        c.renew(a, ttl_seconds=0)
    # the shared clock is whole seconds; wait it out
    time.sleep(2.1)
    assert a.is_expired
    assert not c.validate_fencing_token("r", "h", a.fencing_token)
    b = c.acquire("r", "other", ttl_seconds=5)
    assert b.fencing_token == a.fencing_token + 1


def test_vault_fencing_uses_the_native_coordinator(tmp_path):
    from kibisis import SQLiteMemoryVault

    c = FileLeaseCoordinator(str(tmp_path / "leases"))
    v = SQLiteMemoryVault(str(tmp_path / "vault.sqlite"), passphrase="kc-test-passphrase", coordinator=c, enforce_fencing=True)
    a = c.acquire("vault", "a", ttl_seconds=30)
    v.put("notes", "k", "from a", holder_id="a", fencing_token=a.fencing_token, resource="vault")
    c.release(a)
    b = c.acquire("vault", "b", ttl_seconds=30)
    with pytest.raises(LeaseConflictError):
        v.put("notes", "k", "late", holder_id="a", fencing_token=a.fencing_token, resource="vault")
    v.put("notes", "k", "from b", holder_id="b", fencing_token=b.fencing_token, resource="vault")
    assert v.get("notes", "k").content == "from b"
    v.close()


def test_journal_hashes_come_from_the_crate():
    import kibisis_native
    from kibisis import vault as vmod

    assert vmod._event_hash is kibisis_native.event_hash_v3 or getattr(vmod._event_hash, "__wrapped_native__", None) is kibisis_native.event_hash_v3
    assert vmod._head_mac is kibisis_native.head_mac_v1 or getattr(vmod._head_mac, "__wrapped_native__", None) is kibisis_native.head_mac_v1


def _hammer(args):
    """One holder process: acquire/release the same resource in a tight loop; return the tokens it saw."""
    lease_dir, holder, rounds = args
    from kibisis.lease import FileLeaseCoordinator
    from kibisis import LeaseConflictError
    c = FileLeaseCoordinator(lease_dir)
    tokens = []
    while len(tokens) < rounds:
        try:
            lease = c.acquire("shared", holder, ttl_seconds=5)
        except LeaseConflictError:
            continue
        tokens.append(lease.fencing_token)
        assert c.validate_fencing_token("shared", holder, lease.fencing_token)
        assert c.release(lease)
    return tokens


def test_fencing_tokens_are_strictly_monotonic_under_8_concurrent_holders(tmp_path):
    """P7.3 prereg bar: eight holder processes contend on one resource through the file coordinator;
    every token handed out is unique and the sequence is strictly increasing."""
    import multiprocessing as mp

    d = str(tmp_path / "leases")
    FileLeaseCoordinator(d)
    rounds = 25
    with mp.get_context("spawn").Pool(8) as pool:
        per_holder = pool.map(_hammer, [(d, f"h{i}", rounds) for i in range(8)])
    all_tokens = sorted(t for toks in per_holder for t in toks)
    assert len(all_tokens) == 8 * rounds
    assert len(set(all_tokens)) == len(all_tokens), "a fencing token was handed out twice"
    assert all_tokens == list(range(all_tokens[0], all_tokens[0] + len(all_tokens))), "a token was skipped or reused"
    for toks in per_holder:
        assert toks == sorted(toks) and len(set(toks)) == len(toks)
