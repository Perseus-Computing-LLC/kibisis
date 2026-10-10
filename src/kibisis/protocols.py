"""Interface protocols for Kibisis components."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from .models import EncryptedEnvelope, Lease, MemoryEntity, SearchResult


class LeaseError(Exception):
    """Base exception for lease operations."""
    pass


class LeaseConflictError(LeaseError):
    """Raised when attempting to acquire a lease already held by another active worker."""
    pass


@runtime_checkable
class CryptoEnvelopeProvider(Protocol):
    """Cryptographic provider for encrypting and decrypting envelopes."""

    def encrypt(self, plaintext: bytes, passphrase: str) -> EncryptedEnvelope:
        """Encrypt plaintext bytes into an authenticated envelope using the passphrase."""
        ...

    def decrypt(self, envelope: EncryptedEnvelope, passphrase: str) -> bytes:
        """Decrypt an authenticated envelope into plaintext bytes using the passphrase."""
        ...


@runtime_checkable
class LeaseCoordinator(Protocol):
    """Protocol for managing atomic concurrency leases with fencing tokens."""

    def acquire(self, resource: str, holder_id: str, ttl_seconds: float) -> Lease:
        """Acquire a lease on the specified resource, raising LeaseConflictError if busy."""
        ...

    def renew(self, lease: Lease, ttl_seconds: float) -> bool:
        """Extend an active lease if the caller still holds it with the matching fencing token."""
        ...

    def release(self, lease: Lease) -> bool:
        """Release an active lease so other holders may acquire it."""
        ...


@runtime_checkable
class MemoryVault(Protocol):
    """Protocol for local memory persistence and full-text search."""

    def put(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryEntity:
        """Insert or update a memory entity."""
        ...

    def get(self, category: str, key: str) -> Optional[MemoryEntity]:
        """Fetch a memory entity by category and key."""
        ...

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
    ) -> List[SearchResult]:
        """Search memory entities using full-text indexing."""
        ...

    def archive(self, category: str, key: str) -> bool:
        """Soft-delete an entity by setting its archived flag."""
        ...

    def list_entities(
        self,
        category: Optional[str] = None,
        include_archived: bool = False,
    ) -> List[MemoryEntity]:
        """List entities matching optional category and archive filters."""
        ...

    def tombstone(
        self,
        category: str,
        key: str,
        reason: str = "revocation",
        author_id: Optional[str] = None,
    ) -> str:
        """Tombstone entity value by SHA-256 digest and purge plaintext content."""
        ...

    def is_tombstoned(self, category: str, key: str, content: str) -> bool:
        """Check if content value is tombstoned under category and key."""
        ...

    def list_tombstones(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """List active tombstone records (digests only, zero plaintext)."""
        ...
