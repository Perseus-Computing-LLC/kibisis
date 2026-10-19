"""kibisis: Local-first encrypted cognitive memory vault with atomic concurrency leases."""

from .models import AuditEvent, EncryptedEnvelope, EpistemicState, Lease, MemoryEntity, SearchResult
from .protocols import (
    CryptoEnvelopeProvider,
    EncryptionRequiredError,
    LeaseConflictError,
    LeaseCoordinator,
    LeaseError,
    MemoryVault,
)
from .admission import AdmissionDecision, FactDisposition, MemoryAdmissionGate
from .crypto import AESGCMCryptoEnvelopeProvider
from .lease import SQLiteLeaseCoordinator
from .keys import generate_keyfile, resolve_passphrase
from .vault import SQLiteMemoryVault, TombstonedValueError
from .mcp_server import KibisisMCPServer

__version__ = "0.1.0a3"

__all__ = [
    "AuditEvent",
    "EncryptedEnvelope",
    "EpistemicState",
    "Lease",
    "MemoryEntity",
    "SearchResult",
    "AdmissionDecision",
    "FactDisposition",
    "MemoryAdmissionGate",
    "CryptoEnvelopeProvider",
    "EncryptionRequiredError",
    "LeaseConflictError",
    "LeaseCoordinator",
    "LeaseError",
    "MemoryVault",
    "AESGCMCryptoEnvelopeProvider",
    "SQLiteLeaseCoordinator",
    "SQLiteMemoryVault",
    "TombstonedValueError",
    "KibisisMCPServer",
    "generate_keyfile",
    "resolve_passphrase",
]
