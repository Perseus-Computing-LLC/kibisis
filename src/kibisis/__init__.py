"""kibisis: Local-first encrypted cognitive memory vault with atomic concurrency leases."""

from .models import AuditEvent, EncryptedEnvelope, EpistemicState, Lease, MemoryEntity, RecallResult, SearchHit, SearchResult, WithheldEntry
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
from .lease import FileLeaseCoordinator
from .keys import generate_keyfile, resolve_passphrase
from .vault import (
    ORIGINS,
    AdmissionRefused,
    EntryIntegrityError,
    Probe,
    ReviewedEntryError,
    SQLiteMemoryVault,
    TombstonedValueError,
)
from .mcp_server import KibisisMCPServer

__version__ = "0.1.0a12"

__all__ = [
    "AuditEvent",
    "EncryptedEnvelope",
    "EpistemicState",
    "Lease",
    "MemoryEntity",
    "SearchHit",
    "SearchResult",
    "RecallResult",
    "WithheldEntry",
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
    "FileLeaseCoordinator",
    "SQLiteMemoryVault",
    "Probe",
    "ReviewedEntryError",
    "AdmissionRefused",
    "ORIGINS",
    "EntryIntegrityError",
    "TombstonedValueError",
    "KibisisMCPServer",
    "generate_keyfile",
    "resolve_passphrase",
]
