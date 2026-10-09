"""kibisis: Local-first encrypted cognitive memory vault with atomic concurrency leases."""

from .models import EncryptedEnvelope, Lease, MemoryEntity, SearchResult
from .protocols import (
    CryptoEnvelopeProvider,
    LeaseConflictError,
    LeaseCoordinator,
    LeaseError,
    MemoryVault,
)
from .crypto import AESGCMCryptoEnvelopeProvider
from .lease import SQLiteLeaseCoordinator
from .vault import SQLiteMemoryVault

__version__ = "0.1.0a1"

__all__ = [
    "EncryptedEnvelope",
    "Lease",
    "MemoryEntity",
    "SearchResult",
    "CryptoEnvelopeProvider",
    "LeaseConflictError",
    "LeaseCoordinator",
    "LeaseError",
    "MemoryVault",
    "AESGCMCryptoEnvelopeProvider",
    "SQLiteLeaseCoordinator",
    "SQLiteMemoryVault",
]
