"""Data models for Kibisis encrypted memory vault and concurrency leases."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class EpistemicState(str, Enum):
    """Discrete epistemic status for cognitive assertions."""
    CANDIDATE = "candidate"          # Unverified hypothesis / provisional ingestion
    VERIFIED = "verified"            # Corroborated or empirically verified fact
    DISPUTED = "disputed"            # Contested or conflicting observation
    REVOKED = "revoked"              # Deprecated, superseded, or rejected assertion


class MemoryEntity(BaseModel):
    """An individual memory item stored in the vault."""
    category: str = Field(description="Category namespace (e.g. general, convention, insight).")
    key: str = Field(description="Unique key within the category and scope.")
    content: str = Field(description="Textual payload of the memory.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata dictionary.")
    id: Optional[int] = Field(default=None, description="Internal database ID.")
    version: int = Field(default=1, ge=1, description="Entity version counter.")
    archived: bool = Field(default=False, description="Whether the entity is soft-deleted.")
    created_at: float = Field(default_factory=time.time, description="Creation timestamp (system time).")
    updated_at: float = Field(default_factory=time.time, description="Last update timestamp (system time).")
    
    # Atlas Rubric Mark: Epistemic State
    epistemic_state: EpistemicState = Field(
        default=EpistemicState.VERIFIED,
        description="Discrete epistemic status (candidate, verified, disputed, revoked)."
    )
    
    # Atlas Rubric Mark: Bi-Temporal Validity
    valid_from: Optional[float] = Field(
        default=None,
        description="Real-world valid time start (epoch timestamp)."
    )
    valid_until: Optional[float] = Field(
        default=None,
        description="Real-world valid time end/expiration (epoch timestamp)."
    )
    
    # Atlas Rubric Mark: Scope Enforced in Retrieval
    scope: str = Field(
        default="default",
        description="Isolation scope partition (workspace, tenant, or project identifier)."
    )

    # Post-Retrieval Ownership Validation (MemLeak defense)
    tenant_sig: Optional[str] = Field(
        default=None,
        description="HMAC-SHA256 signature for post-retrieval tenant ownership validation."
    )

    # Provenance: who put the fact here, and how sure they were.
    origin: str = Field(
        default="unknown",
        description="Where the entry came from: user, model, tool, import, or unknown (predates provenance).",
    )
    source_ref: Optional[str] = Field(default=None, description="Opaque pointer to the source (session/turn, tool call, file).")
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Writer's confidence in [0, 1], if stated.")

    # Directional Supersession Linkage
    supersedes: Optional[str] = Field(
        default=None,
        description="Target entity identifier (category:key or key) superseded and invalidated by this assertion."
    )
    superseded_by: Optional[str] = Field(
        default=None,
        description="Successor entity identifier that supersedes and replaces this assertion."
    )

    def to_context_item(
        self,
        pinned: bool = False,
        priority: int = 1,
        role: str = "system",
    ) -> Dict[str, Any]:
        """Convert memory entity to a dictionary compatible with Harpe ContextItem."""
        meta = self.metadata.copy() if self.metadata else {}
        meta.setdefault("category", self.category)
        meta.setdefault("key", self.key)
        meta.setdefault("scope", self.scope)
        state_val = self.epistemic_state.value if isinstance(self.epistemic_state, EpistemicState) else str(self.epistemic_state)
        meta.setdefault("epistemic_state", state_val)
        if self.valid_from is not None:
            meta["valid_from"] = self.valid_from
        if self.valid_until is not None:
            meta["valid_until"] = self.valid_until
        if self.supersedes:
            meta["supersedes"] = self.supersedes
        if self.superseded_by:
            meta["superseded_by"] = self.superseded_by
        meta["created_at"] = self.created_at
        meta["updated_at"] = self.updated_at
        return {
            "id": f"kibisis_{self.category}_{self.key}",
            "item_id": f"kibisis_{self.category}_{self.key}",
            "content": self.content,
            "role": role,
            "priority": priority,
            "pinned": pinned,
            "metadata": meta,
        }


class EncryptedEnvelope(BaseModel):
    """Encrypted data envelope carrying ciphertext and KDF/cipher parameters."""
    cipher: str = Field(default="aes-256-gcm", description="Cipher identifier.")
    kdf: str = Field(default="pbkdf2-sha256", description="Key derivation function.")
    iterations: int = Field(
        default=100_000,
        ge=1,
        le=5_000_000,
        description=(
            "PBKDF2 iteration count. Envelopes written before this field existed used 100,000. The upper bound "
            "stops a tampered row from dictating an unbounded KDF cost before the tag check can reject it."
        ),
    )
    salt_b64: str = Field(description="Base64-encoded KDF salt.")
    nonce_b64: str = Field(description="Base64-encoded cipher initialization nonce/IV.")
    ciphertext_b64: str = Field(description="Base64-encoded ciphertext.")
    tag_b64: str = Field(default="", description="Base64-encoded authentication tag if separated.")
    binding: Optional[str] = Field(
        default=None,
        description=(
            "Associated data the ciphertext is bound to. 'entry-v2': the entry's scope, category and key, so the "
            "envelope cannot be moved to another entry. None: not bound (written by Kibisis 0.1.0a5 or earlier)."
        ),
    )


class Lease(BaseModel):
    """Concurrency lease representing exclusive lock ownership with a fencing token."""
    resource: str = Field(description="Resource identifier.")
    holder_id: str = Field(description="Identifier of the lease holder.")
    fencing_token: int = Field(ge=1, description="Monotonically increasing fencing counter.")
    acquired_at: float = Field(description="Unix timestamp when lease was granted.")
    expires_at: float = Field(description="Unix timestamp when lease expires (wall clock, shared across processes).")
    local_deadline: Optional[float] = Field(
        default=None,
        description=(
            "time.monotonic() deadline in the process that acquired or renewed the lease. Set by the coordinator; "
            "None for a lease read back from the table. Not meaningful in any other process."
        ),
    )

    @property
    def is_expired(self) -> bool:
        """Whether the lease has passed its expiration time by the wall clock."""
        return time.time() >= self.expires_at

    @property
    def is_locally_expired(self) -> bool:
        """Whether the acquiring process's monotonic clock has passed the deadline.

        Immune to wall-clock steps, so a holder can stop writing when its own TTL has run out even
        if the shared ``expires_at`` still looks live. Falls back to :attr:`is_expired` when the
        lease was not acquired in this process.
        """
        if self.local_deadline is None:
            return self.is_expired
        return time.monotonic() >= self.local_deadline


class AuditEvent(BaseModel):
    """Tamper-evident audit event recording memory mutations."""
    sequence: int = Field(ge=1, description="Monotonically increasing sequence number.")
    timestamp: float = Field(default_factory=time.time, description="Timestamp of event recording.")
    action: str = Field(description="Mutation action (e.g. put, update, archive, tombstone, purge).")
    category: str = Field(description="Target category.")
    key: str = Field(description="Target key.")
    scope: str = Field(default="default", description="Target scope.")
    value_sha256: str = Field(default="", description="SHA-256 digest of payload content.")
    prev_hash: str = Field(description="SHA-256 hash of previous audit event in chain.")
    event_hash: str = Field(description="SHA-256 hash of this event.")
    author_id: Optional[str] = Field(default=None, description="Identifier of author or agent.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context metadata.")
    format: int = Field(
        default=2,
        ge=1,
        description=(
            "Hash layout the row was written under. 1 and 2: ':'-joined fields, metadata not covered. "
            "3: canonical JSON array including a digest of the metadata."
        ),
    )


class SearchResult(BaseModel):
    """Result item returned from full-text search query."""
    entity: MemoryEntity
    rank_score: float = Field(default=0.0, description="Relevance score (e.g. BM25 rank).")
    snippet: str = Field(default="", description="Highlighted contextual match snippet.")


class SearchHit(BaseModel):
    """An entry that matched a search, without its content: what ``search_keys`` returns."""
    id: int = Field(description="Row id of the entry.")
    category: str = Field(description="Category of the entry.")
    key: str = Field(description="Key of the entry.")
    scope: str = Field(default="default", description="Scope of the entry.")
    rank_score: float = Field(default=0.0, description="Relevance score (BM25 rank, as in SearchResult: lower is better).")
