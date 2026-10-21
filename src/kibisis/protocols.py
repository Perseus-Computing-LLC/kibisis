"""Interface protocols for Kibisis components."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, Sequence, Union, runtime_checkable
from .models import EncryptedEnvelope, EpistemicState, Lease, MemoryEntity, SearchResult


class LeaseError(Exception):
    """Base exception for lease operations."""
    pass


class EncryptionRequiredError(Exception):
    """Raised when a vault is opened without a passphrase and plaintext storage was not explicitly allowed."""
    pass


class LeaseConflictError(LeaseError):
    """Raised when attempting to acquire a lease already held by another active worker."""
    pass


@runtime_checkable
class CryptoEnvelopeProvider(Protocol):
    """Cryptographic provider for encrypting and decrypting envelopes."""

    def encrypt(self, plaintext: bytes, passphrase: str, aad: Optional[bytes] = None) -> EncryptedEnvelope:
        """Encrypt plaintext bytes into an authenticated envelope using the passphrase.

        ``aad`` (associated data) is authenticated but not encrypted or stored; the vault passes the
        entry's identity so sealed content cannot be moved to another entry.
        """
        ...

    def decrypt(self, envelope: EncryptedEnvelope, passphrase: str, aad: Optional[bytes] = None) -> bytes:
        """Decrypt an authenticated envelope into plaintext bytes; must fail if ``aad`` differs from encryption."""
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

    def get_lease(self, resource: str) -> Optional[Lease]:
        """Fetch current lease record for resource, if any."""
        ...

    def validate_fencing_token(self, resource: str, holder_id: str, fencing_token: int) -> bool:
        """Verify that ``holder_id`` holds an active, un-preempted lease on ``resource`` with ``fencing_token``."""
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
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
    ) -> MemoryEntity:
        """Insert or update a memory entity with epistemic status, bi-temporal bounds, scope, and fencing token validation."""
        ...

    def store(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
    ) -> MemoryEntity:
        """Alias for put() for ergonomic convenience."""
        ...

    def put_batch(
        self,
        items: Sequence[Union[Dict[str, Any], MemoryEntity]],
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> List[MemoryEntity]:
        """Insert or update several entities, in order, each in its own transaction."""
        ...

    def get(
        self,
        category: str,
        key: str,
        scope: str = "default",
    ) -> Optional[MemoryEntity]:
        """Fetch a memory entity by category, key, and scope."""
        ...

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
        scope: Optional[str] = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
        active_only: bool = True,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        authorized_lineage_roots: Optional[List[str]] = None,
        match: str = "all",
    ) -> List[SearchResult]:
        """Search memory entities with strict scope filtering, epistemic filtering, and bi-temporal point-in-time evaluation."""
        ...

    def archive(
        self,
        category: str,
        key: str,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        missing_ok: bool = True,
    ) -> bool:
        """Soft-delete an entity by setting its archived flag."""
        ...

    def list_entities(
        self,
        category: Optional[str] = None,
        include_archived: bool = False,
        scope: str = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
    ) -> List[MemoryEntity]:
        """List entities matching optional category, archive, epistemic, and scope filters."""
        ...

    def tombstone(
        self,
        category: str,
        key: str,
        reason: str = "revocation",
        author_id: Optional[str] = None,
        content: Optional[str] = None,
        scope: str = "default",
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        missing_ok: bool = False,
    ) -> str:
        """Tombstone entity value by SHA-256 digest and purge plaintext content."""
        ...

    def is_tombstoned(
        self,
        category: str,
        key: str,
        content: str,
        scope: str = "default",
    ) -> bool:
        """Check if content value is tombstoned under category, key, and scope."""
        ...

    def admit_candidate(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> MemoryEntity:
        """Stage an unverified memory candidate into the vault awaiting verification/human review."""
        ...

    def review_entity(
        self,
        category: str,
        key: str,
        verdict: str,
        scope: str = "default",
        reviewer_id: Optional[str] = None,
        notes: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> MemoryEntity:
        """Human review gate: update epistemic state based on review decision (verified, disputed, revoked)."""
        ...

    def list_audit_events(
        self,
        scope: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100,
    ) -> List[Any]:
        """Fetch chronological audit records from the tamper-evident hash chain."""
        ...

    def verify_audit_chain(self, scope: Optional[str] = None) -> bool:
        """Verify the cryptographic integrity of the append-only mutation journal hash chain."""
        ...

    def list_tombstones(
        self,
        category: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List active tombstone records (digests only, zero plaintext)."""
        ...

    def set_persona_slot(
        self,
        content: str,
        scope: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> MemoryEntity:
        """Store or update the dedicated user persona / preference slot."""
        ...

    def get_persona_slot(
        self,
        scope: str = "default",
    ) -> Optional[MemoryEntity]:
        """Fetch the dedicated persona / preference slot for the specified scope."""
        ...

    def get_persona_context_item(
        self,
        scope: str = "default",
        role: str = "system",
    ) -> Optional[Dict[str, Any]]:
        """Fetch persona slot formatted as a pinned Harpe ContextItem dict."""
        ...
