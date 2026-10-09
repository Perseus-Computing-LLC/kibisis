"""Data models for Kibisis encrypted memory vault and concurrency leases."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class MemoryEntity(BaseModel):
    """An individual memory item stored in the vault."""
    category: str = Field(description="Category namespace (e.g. general, convention, insight).")
    key: str = Field(description="Unique key within the category.")
    content: str = Field(description="Textual payload of the memory.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata dictionary.")
    id: Optional[int] = Field(default=None, description="Internal database ID.")
    version: int = Field(default=1, ge=1, description="Entity version counter.")
    archived: bool = Field(default=False, description="Whether the entity is soft-deleted.")
    created_at: float = Field(default_factory=time.time, description="Creation timestamp.")
    updated_at: float = Field(default_factory=time.time, description="Last update timestamp.")


class EncryptedEnvelope(BaseModel):
    """Encrypted data envelope carrying ciphertext and KDF/cipher parameters."""
    cipher: str = Field(default="aes-256-gcm", description="Cipher identifier.")
    kdf: str = Field(default="pbkdf2-sha256", description="Key derivation function.")
    salt_b64: str = Field(description="Base64-encoded KDF salt.")
    nonce_b64: str = Field(description="Base64-encoded cipher initialization nonce/IV.")
    ciphertext_b64: str = Field(description="Base64-encoded ciphertext.")
    tag_b64: str = Field(default="", description="Base64-encoded authentication tag if separated.")


class Lease(BaseModel):
    """Concurrency lease representing exclusive lock ownership with a fencing token."""
    resource: str = Field(description="Resource identifier.")
    holder_id: str = Field(description="Identifier of the lease holder.")
    fencing_token: int = Field(ge=1, description="Monotonically increasing fencing counter.")
    acquired_at: float = Field(description="Unix timestamp when lease was granted.")
    expires_at: float = Field(description="Unix timestamp when lease expires.")

    @property
    def is_expired(self) -> bool:
        """Whether the lease has passed its expiration time."""
        return time.time() >= self.expires_at


class SearchResult(BaseModel):
    """Result item returned from full-text search query."""
    entity: MemoryEntity
    rank_score: float = Field(default=0.0, description="Relevance score (e.g. BM25 rank).")
    snippet: str = Field(default="", description="Highlighted contextual match snippet.")
