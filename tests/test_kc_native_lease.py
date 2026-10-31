"""K-C (telarch P7.3): one lease coordinator, in Rust, reached from Python through kibisis_native.

The Python package no longer carries its own SQLite lease table. ``kibisis.FileLeaseCoordinator`` is a thin
adapter over ``kibisis_native.FileLeaseCoordinator`` (one lock file and one state file per resource, directory
0700, files 0600, fencing tokens that only go up). The journal hash functions come from the same crate, so the
Python vault and the Rust verifier share one implementation. There is no Python fallback: an environment
without the extension fails at import, loudly, instead of silently coordinating nothing.
"""
from __future__ import annotations

import os
import pathlib
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


def _run_holders(lease_dir, holders, rounds, timeout=150):
    """Start one OS process per holder as a script (no pickling: under the spawn start method a child
    cannot re-import a test module that pytest loaded as `tests.test_kc_native_lease`; at 6d26d53 the
    children died with ModuleNotFoundError and pool.map waited forever, hanging CI >1 h on every platform).
    Every wait is bounded so a repeat fails with the shortfall instead of hanging."""
    import json
    import os
    import subprocess
    import sys

    script = str(pathlib.Path(__file__).with_name("_kc_hammer.py"))
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    procs = [subprocess.Popen([sys.executable, script, lease_dir, h, str(rounds)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env, text=True) for h in holders]
    results = []
    for proc in procs:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            pytest.fail(f"holder process did not finish in {timeout}s: {err[-2000:]}")
        assert proc.returncode == 0, err[-2000:]
        results.append(json.loads(out))
    return results


def test_fencing_tokens_are_strictly_monotonic_under_8_concurrent_holders(tmp_path):
    """P7.3 prereg bar: eight holder processes contend on one resource through the file coordinator;
    every token handed out is unique and the sequence is strictly increasing."""
    d = str(tmp_path / "leases")
    FileLeaseCoordinator(d)
    rounds = 25
    per_holder = _run_holders(d, [f"h{i}" for i in range(8)], rounds)
    all_tokens = sorted(t for toks in per_holder for t in toks)
    assert len(all_tokens) == 8 * rounds
    assert len(set(all_tokens)) == len(all_tokens), "a fencing token was handed out twice"
    assert all_tokens == list(range(all_tokens[0], all_tokens[0] + len(all_tokens))), "a token was skipped or reused"
    for toks in per_holder:
        assert toks == sorted(toks) and len(set(toks)) == len(toks)
