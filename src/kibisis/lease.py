"""Concurrency leases with fencing tokens, coordinated by the kibisis Rust crate.

The coordinator lives in ``kibisis_native`` (``bindings/python``): one lock file and one state file per
resource under a directory, created ``0700``/``0600``, fencing tokens that only go up. This module adapts it
to :class:`~kibisis.protocols.LeaseCoordinator` and :class:`~kibisis.models.Lease`, bounds TTLs, and arms the
holder's own monotonic deadline. There is no Python fallback: without the extension the package does not
import, which is the honest failure for a component whose whole job is to coordinate writers.

Clock assumption. Expiry (``expires_at``) is compared against the wall clock of whichever process asks,
because the state file is shared by processes that have no common monotonic clock; tokens are ordered by the
file, not by any clock. Keep the hosts' clocks synchronised, keep TTLs short (at most :data:`MAX_TTL_SECONDS`),
renew rather than over-provision, and fence every write. Each :class:`~kibisis.models.Lease` handed out here
also carries ``local_deadline`` (``time.monotonic()``) so the holder can stop writing on its own clock.

Resolution. The shared ``expires_at`` is a whole second, rounded up (the crate's ``lease_deadline``): a lease
asked for ``ttl`` seconds is live until the first second boundary at or after ``now + ttl``, so it can outlive
the request by up to one second on the shared clock. ``local_deadline`` keeps the exact TTL.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

import kibisis_native as _native

from .models import Lease
from .protocols import LeaseConflictError, LeaseCoordinator

#: Longest lease a caller may ask for, in seconds. A lease that outlives its holder blocks every
#: other holder until the wall clock passes ``expires_at``; one day bounds that damage. Callers that
#: need longer hold renew.
MAX_TTL_SECONDS = 86_400.0


def _check_ttl(ttl_seconds: float) -> float:
    ttl = float(ttl_seconds)
    if not ttl > 0:
        raise ValueError("ttl_seconds must be positive")
    if ttl > MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be at most {MAX_TTL_SECONDS:.0f} (one day); renew to hold longer")
    return ttl


def _to_model(raw: "_native.Lease", local_deadline: Optional[float] = None) -> Lease:
    return Lease(resource=raw.resource, holder_id=raw.holder_id, fencing_token=raw.fencing_token,
                 acquired_at=float(raw.acquired_at), expires_at=float(raw.expires_at), local_deadline=local_deadline)


def _to_native(lease: Lease) -> "_native.Lease":
    return _native.Lease(lease.resource, lease.holder_id, int(lease.fencing_token), int(lease.acquired_at), int(lease.expires_at))


class FileLeaseCoordinator(LeaseCoordinator):
    """Lease coordinator over a directory of lock/state files, one per resource (``kibisis_native``).

    Every coordinator opened on the same directory, from any process or language that uses the crate, sees
    the same leases. The state is plain (a lease is not a secret); the directory is private to the owner.
    """

    def __init__(self, lease_dir: str) -> None:
        self.lease_dir = str(lease_dir)
        self._lock = threading.RLock()
        self._inner = _native.FileLeaseCoordinator(self.lease_dir)

    def acquire(self, resource: str, holder_id: str, ttl_seconds: float) -> Lease:
        ttl = _check_ttl(ttl_seconds)
        with self._lock:
            try:
                raw = self._inner.acquire(resource, holder_id, ttl)
            except _native.LeaseConflict as exc:
                raise LeaseConflictError(str(exc)) from None
        return _to_model(raw, local_deadline=time.monotonic() + ttl)

    def renew(self, lease: Lease, ttl_seconds: float) -> bool:
        ttl = _check_ttl(ttl_seconds)
        with self._lock:
            ok = self._inner.renew(_to_native(lease), ttl)
        if ok:
            current = self.get_lease(lease.resource)
            if current is not None:
                lease.expires_at = current.expires_at
            lease.local_deadline = time.monotonic() + ttl
        return bool(ok)

    def release(self, lease: Lease) -> bool:
        with self._lock:
            return bool(self._inner.release(_to_native(lease)))

    def get_lease(self, resource: str) -> Optional[Lease]:
        with self._lock:
            raw = self._inner.get_lease(resource)
        return None if raw is None else _to_model(raw)

    def validate_fencing_token(self, resource: str, holder_id: str, fencing_token: int) -> bool:
        with self._lock:
            return bool(self._inner.validate_fencing_token(resource, holder_id, int(fencing_token)))

    def close(self) -> None:
        """Nothing is held open between calls; kept for symmetry with the vault."""

    def __enter__(self) -> "FileLeaseCoordinator":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
