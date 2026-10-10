//! # kibisis
//!
//! Local-first encrypted cognitive memory vault with atomic concurrency leases.
//!
//! Autonomous AI agents running parallel execution loops frequently corrupt shared state
//! when attempting concurrent read-modify-write cycles against flat files or SQLite databases.
//! Kibisis solves this by providing:
//!
//! 1. **Structured Memory Entities**: Key-value memory storage partitioned by category,
//!    with monotonic version tracking and soft-archival capabilities.
//! 2. **Single-Writer Multi-Reader (SWMR) Leases**: Atomic distributed leasing with
//!    strictly increasing fencing tokens to eliminate stale-worker race conditions.
//! 3. **Cryptographic Envelopes**: Envelope schema definitions for local ChaCha20-Poly1305
//!    authenticated encryption at rest.
//!
//! ## Architecture Overview
//!
//! - [`MemoryVault`]: Trait defining storage operations ([`MemoryVault::put`],
//!   [`MemoryVault::get`], [`MemoryVault::search`], [`MemoryVault::archive`]).
//! - [`InMemoryMemoryVault`]: Thread-safe reference implementation protected by mutex locks.
//! - [`LeaseCoordinator`]: Trait defining atomic lease acquisition, renewal, and release.
//! - [`InMemoryLeaseCoordinator`]: Reference lease coordinator using monotonic fencing tokens.
//!
//! ## Quick Start
//!
//! ```rust
//! use std::time::Duration;
//! use kibisis::{InMemoryLeaseCoordinator, InMemoryMemoryVault, LeaseCoordinator, MemoryEntity, MemoryVault};
//!
//! // 1. Store and retrieve memory records
//! let mut vault = InMemoryMemoryVault::new();
//! let note = MemoryEntity::new("agent_state", "step_4", "Compiled unit test binary");
//! let saved = vault.put(&note).expect("Put must succeed");
//! assert_eq!(saved.version, 1);
//!
//! let retrieved = vault.get("agent_state", "step_4").expect("Get must succeed").unwrap();
//! assert_eq!(retrieved.content, "Compiled unit test binary");
//!
//! // 2. Coordinate concurrent access with fencing tokens
//! let mut coordinator = InMemoryLeaseCoordinator::new();
//! let ttl = Duration::from_secs(30);
//!
//! let lease = coordinator.acquire("shared_database", "worker_alpha", ttl)
//!     .expect("Worker alpha acquires lease");
//! assert_eq!(lease.fencing_token, 1);
//!
//! // Competing worker is rejected while lease is held
//! assert!(coordinator.acquire("shared_database", "worker_beta", ttl).is_err());
//!
//! // Worker alpha releases lease
//! assert!(coordinator.release(&lease).expect("Release must succeed"));
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Structured cognitive memory record stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEntity {
    /// Optional auto-incrementing database identifier.
    pub id: Option<u64>,
    /// Logical partition or namespace (for example: conventions, user_prefs, agent_state).
    pub category: String,
    /// Unique identifier within the category namespace.
    pub key: String,
    /// Raw payload content of the memory entry.
    pub content: String,
    /// Monotonically increasing revision number, incremented on each update.
    pub version: u64,
    /// Soft deletion marker. Archived entities are excluded from normal search queries.
    pub archived: bool,
    /// Creation timestamp in seconds since the UNIX epoch.
    pub created_at: u64,
    /// Last update timestamp in seconds since the UNIX epoch.
    pub updated_at: u64,
}

impl MemoryEntity {
    /// Construct a new unarchived memory entity at version 1 with the current system time.
    pub fn new(
        category: impl Into<String>,
        key: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id: None,
            category: category.into(),
            key: key.into(),
            content: content.into(),
            version: 1,
            archived: false,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Cryptographic envelope schema for encrypted records at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    /// Cipher algorithm identifier (for example: ChaCha20-Poly1305).
    pub cipher: String,
    /// Key derivation function identifier (for example: Argon2id).
    pub kdf: String,
    /// Base64-encoded salt used during key derivation.
    pub salt_b64: String,
    /// Base64-encoded 96-bit initialization nonce.
    pub nonce_b64: String,
    /// Base64-encoded ciphertext.
    pub ciphertext_b64: String,
    /// Base64-encoded 128-bit authentication tag.
    pub tag_b64: String,
}

/// Distributed concurrency lease granting single-writer privileges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Name of the protected resource or table.
    pub resource: String,
    /// Unique identifier of the agent process holding the lease.
    pub holder_id: String,
    /// Monotonically increasing integer token to prevent stale writes.
    pub fencing_token: u64,
    /// Timestamp when the lease was granted in seconds since UNIX epoch.
    pub acquired_at: u64,
    /// Expiration deadline in seconds since UNIX epoch.
    pub expires_at: u64,
}

impl Lease {
    /// Check whether the current system time has passed the expiration deadline.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }
}

/// Search match returned from memory queries.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    /// The matching memory entity.
    pub entity: MemoryEntity,
    /// Relevance score between 0.0 and 1.0.
    pub score: f64,
}

/// Errors returned by memory vault storage operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Requested entity does not exist.
    NotFound(String),
    /// Underlying storage or locking failure.
    StorageError(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "Entity not found: {}", msg),
            Self::StorageError(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

/// Errors returned during lease acquisition, renewal, or release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    /// Resource is already held by another active worker.
    Conflict(String),
    /// Attempted operation on an expired lease.
    Expired(String),
    /// Fencing token mismatch indicating a superseded lease.
    InvalidToken(String),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(msg) => write!(f, "Lease conflict: {}", msg),
            Self::Expired(msg) => write!(f, "Lease expired: {}", msg),
            Self::InvalidToken(msg) => write!(f, "Invalid fencing token: {}", msg),
        }
    }
}

impl std::error::Error for LeaseError {}

/// Errors returned during encryption or decryption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Authentication tag verification failed or ciphertext is corrupted.
    DecryptionFailed(String),
    /// Supplied cryptographic key is malformed or invalid.
    InvalidKey(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Self::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Core trait defining persistent cognitive memory storage.
pub trait MemoryVault: Send + Sync {
    /// Insert or update a memory entity, automatically advancing version numbers.
    fn put(&mut self, entity: &MemoryEntity) -> Result<MemoryEntity, VaultError>;

    /// Fetch a memory entity by category and key. Returns Ok(None) if not found.
    fn get(&self, category: &str, key: &str) -> Result<Option<MemoryEntity>, VaultError>;

    /// Search unarchived memory entries matching the search query substring.
    fn search(
        &self,
        query: &str,
        category: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchResult>, VaultError>;

    /// Mark an entity as archived without deleting its record.
    fn archive(&mut self, category: &str, key: &str) -> Result<bool, VaultError>;
}

/// Trait defining atomic single-writer lease coordination.
pub trait LeaseCoordinator: Send + Sync {
    /// Attempt to acquire an exclusive lease for the named resource.
    fn acquire(
        &mut self,
        resource: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Lease, LeaseError>;

    /// Extend the expiration deadline of an actively held lease.
    fn renew(&mut self, lease: &Lease, ttl: Duration) -> Result<bool, LeaseError>;

    /// Voluntarily relinquish an actively held lease before expiration.
    fn release(&mut self, lease: &Lease) -> Result<bool, LeaseError>;
}

/// Trait defining symmetric encryption and decryption of payload slices.
pub trait CryptoEnvelope: Send + Sync {
    /// Encrypt a byte slice using the specified passphrase, returning an envelope.
    fn encrypt(&self, plaintext: &[u8], key: &str) -> Result<EncryptedEnvelope, CryptoError>;

    /// Decrypt an envelope using the specified passphrase, verifying the authentication tag.
    fn decrypt(&self, envelope: &EncryptedEnvelope, key: &str) -> Result<Vec<u8>, CryptoError>;
}

/// In-memory reference implementation of [`MemoryVault`].
#[derive(Default, Clone)]
pub struct InMemoryMemoryVault {
    entities: Arc<Mutex<HashMap<(String, String), MemoryEntity>>>,
}

impl InMemoryMemoryVault {
    /// Construct a new empty in-memory vault.
    pub fn new() -> Self {
        Self::default()
    }
}

impl MemoryVault for InMemoryMemoryVault {
    fn put(&mut self, entity: &MemoryEntity) -> Result<MemoryEntity, VaultError> {
        let mut store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let key_tuple = (entity.category.clone(), entity.key.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut saved = entity.clone();
        if let Some(existing) = store.get(&key_tuple) {
            saved.version = existing.version + 1;
            saved.created_at = existing.created_at;
        } else {
            saved.version = 1;
            saved.created_at = now;
        }
        saved.updated_at = now;
        saved.archived = false;

        store.insert(key_tuple, saved.clone());
        Ok(saved)
    }

    fn get(&self, category: &str, key: &str) -> Result<Option<MemoryEntity>, VaultError> {
        let store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        Ok(store.get(&(category.to_string(), key.to_string())).cloned())
    }

    fn search(
        &self,
        query: &str,
        category: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchResult>, VaultError> {
        let store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let q_lower = query.to_lowercase();
        let mut results = Vec::new();

        for ((cat, _), entity) in store.iter() {
            if entity.archived {
                continue;
            }
            if let Some(target_cat) = category {
                if cat != target_cat {
                    continue;
                }
            }
            if entity.content.to_lowercase().contains(&q_lower)
                || entity.key.to_lowercase().contains(&q_lower)
            {
                results.push(SearchResult {
                    entity: entity.clone(),
                    score: 1.0,
                });
                if results.len() >= limit {
                    break;
                }
            }
        }
        Ok(results)
    }

    fn archive(&mut self, category: &str, key: &str) -> Result<bool, VaultError> {
        let mut store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        if let Some(ent) = store.get_mut(&(category.to_string(), key.to_string())) {
            ent.archived = true;
            return Ok(true);
        }
        Ok(false)
    }
}

/// In-memory reference implementation of [`LeaseCoordinator`] with atomic fencing tokens.
#[derive(Default, Clone)]
pub struct InMemoryLeaseCoordinator {
    leases: Arc<Mutex<HashMap<String, Lease>>>,
}

impl InMemoryLeaseCoordinator {
    /// Construct a new empty in-memory lease coordinator.
    pub fn new() -> Self {
        Self::default()
    }
}

impl LeaseCoordinator for InMemoryLeaseCoordinator {
    fn acquire(
        &mut self,
        resource: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Lease, LeaseError> {
        let mut store = self
            .leases
            .lock()
            .map_err(|e| LeaseError::Conflict(e.to_string()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let new_expires_at = now + ttl.as_secs();

        if let Some(existing) = store.get(resource) {
            if existing.expires_at >= now && existing.holder_id != holder_id {
                return Err(LeaseError::Conflict(format!(
                    "Resource '{}' already held by '{}'",
                    resource, existing.holder_id
                )));
            }
            let fencing = existing.fencing_token + 1;
            let lease = Lease {
                resource: resource.to_string(),
                holder_id: holder_id.to_string(),
                fencing_token: fencing,
                acquired_at: now,
                expires_at: new_expires_at,
            };
            store.insert(resource.to_string(), lease.clone());
            Ok(lease)
        } else {
            let lease = Lease {
                resource: resource.to_string(),
                holder_id: holder_id.to_string(),
                fencing_token: 1,
                acquired_at: now,
                expires_at: new_expires_at,
            };
            store.insert(resource.to_string(), lease.clone());
            Ok(lease)
        }
    }

    fn renew(&mut self, lease: &Lease, ttl: Duration) -> Result<bool, LeaseError> {
        let mut store = self
            .leases
            .lock()
            .map_err(|e| LeaseError::Conflict(e.to_string()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(existing) = store.get_mut(&lease.resource) {
            if existing.holder_id == lease.holder_id
                && existing.fencing_token == lease.fencing_token
                && existing.expires_at >= now
            {
                existing.expires_at = now + ttl.as_secs();
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn release(&mut self, lease: &Lease) -> Result<bool, LeaseError> {
        let mut store = self
            .leases
            .lock()
            .map_err(|e| LeaseError::Conflict(e.to_string()))?;
        if let Some(existing) = store.get_mut(&lease.resource) {
            if existing.holder_id == lease.holder_id
                && existing.fencing_token == lease.fencing_token
            {
                existing.expires_at = 0;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_put_get_search() {
        let mut vault = InMemoryMemoryVault::new();
        let entity = MemoryEntity::new(
            "convention",
            "atomic_swmr",
            "Single-writer multi-reader coordination",
        );
        let saved = vault.put(&entity).unwrap();
        assert_eq!(saved.version, 1);

        let fetched = vault.get("convention", "atomic_swmr").unwrap().unwrap();
        assert_eq!(fetched.content, "Single-writer multi-reader coordination");

        let search_res = vault.search("swmr", None, 10).unwrap();
        assert_eq!(search_res.len(), 1);
        assert_eq!(search_res[0].entity.key, "atomic_swmr");

        // Archive
        assert!(vault.archive("convention", "atomic_swmr").unwrap());
        let search_after_archive = vault.search("swmr", None, 10).unwrap();
        assert_eq!(search_after_archive.len(), 0);
    }

    #[test]
    fn test_lease_coordination() {
        let mut coordinator = InMemoryLeaseCoordinator::new();
        let ttl = Duration::from_secs(10);

        let lease1 = coordinator.acquire("resource_x", "agent_1", ttl).unwrap();
        assert_eq!(lease1.fencing_token, 1);

        // Conflict check
        assert!(coordinator.acquire("resource_x", "agent_2", ttl).is_err());

        // Renew
        assert!(coordinator.renew(&lease1, Duration::from_secs(20)).unwrap());

        // Release
        assert!(coordinator.release(&lease1).unwrap());

        // Second agent acquires with fencing token 2
        let lease2 = coordinator.acquire("resource_x", "agent_2", ttl).unwrap();
        assert_eq!(lease2.fencing_token, 2);
    }
}
