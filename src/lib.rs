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
use zeroize::Zeroize;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Zeroizable secure passphrase wrapper for in-memory key hygiene.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroizingPassphrase(pub String);

impl ZeroizingPassphrase {
    pub fn new(pass: impl Into<String>) -> Self {
        Self(pass.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ZeroizingPassphrase {
    fn drop(&mut self) {
        unsafe {
            let vec = self.0.as_mut_vec();
            vec.zeroize();
        }
    }
}

/// Compute SHA-256 hex digest using pure Rust (FIPS 180-4 compliant).
pub fn sha256_hex(input: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }

    let mut result = String::with_capacity(64);
    for val in h {
        result.push_str(&format!("{:08x}", val));
    }
    result
}

/// Canonicalize text for evasion-resistant comparison and hashing.
pub fn canonicalize_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Discrete epistemic status for cognitive assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpistemicState {
    Candidate,
    Verified,
    Disputed,
    Revoked,
}

impl EpistemicState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Verified => "verified",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "candidate" => Some(Self::Candidate),
            "verified" => Some(Self::Verified),
            "disputed" => Some(Self::Disputed),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Structured cognitive memory record stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEntity {
    /// Optional auto-incrementing database identifier.
    pub id: Option<u64>,
    /// Logical partition or namespace (for example: conventions, user_prefs, agent_state).
    pub category: String,
    /// Unique identifier within the category namespace and scope.
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
    /// Epistemic status (Candidate, Verified, Disputed, Revoked).
    pub epistemic_state: EpistemicState,
    /// Real-world valid time start in seconds since UNIX epoch.
    pub valid_from: Option<u64>,
    /// Real-world valid time end/expiration in seconds since UNIX epoch.
    pub valid_until: Option<u64>,
    /// Scope partition for workspace or multi-tenant boundary isolation.
    pub scope: String,
}

impl MemoryEntity {
    /// Construct a new unarchived memory entity at version 1 with current timestamp.
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
            epistemic_state: EpistemicState::Verified,
            valid_from: None,
            valid_until: None,
            scope: "default".to_string(),
        }
    }

    /// Construct a scoped memory entity with epistemic state and bi-temporal bounds.
    pub fn new_scoped(
        category: impl Into<String>,
        key: impl Into<String>,
        content: impl Into<String>,
        scope: impl Into<String>,
        epistemic_state: EpistemicState,
        valid_from: Option<u64>,
        valid_until: Option<u64>,
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
            epistemic_state,
            valid_from,
            valid_until,
            scope: scope.into(),
        }
    }
}

/// Tamper-evident mutation audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub timestamp: u64,
    pub action: String,
    pub category: String,
    pub key: String,
    pub scope: String,
    pub value_sha256: String,
    pub prev_hash: String,
    pub event_hash: String,
    pub author_id: Option<String>,
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

    /// Fetch a memory entity by category, key, and scope. Returns Ok(None) if not found.
    fn get(&self, category: &str, key: &str) -> Result<Option<MemoryEntity>, VaultError>;

    /// Fetch a memory entity with explicit scope.
    fn get_scoped(
        &self,
        category: &str,
        key: &str,
        scope: &str,
    ) -> Result<Option<MemoryEntity>, VaultError>;

    /// Search unarchived memory entries matching query substring with default filters.
    fn search(
        &self,
        query: &str,
        category: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchResult>, VaultError>;

    /// Search memory entries with strict scope, epistemic status, and bi-temporal validity filtering.
    fn search_scoped(
        &self,
        query: &str,
        category: Option<&str>,
        limit: usize,
        scope: &str,
        epistemic_state: Option<EpistemicState>,
        as_of_valid_time: Option<u64>,
        include_unverified: bool,
    ) -> Result<Vec<SearchResult>, VaultError>;

    /// Mark an entity as archived without deleting its record.
    fn archive(&mut self, category: &str, key: &str) -> Result<bool, VaultError>;

    /// Mark an entity as archived within a specific scope.
    fn archive_scoped(&mut self, category: &str, key: &str, scope: &str) -> Result<bool, VaultError>;

    /// Tombstone an entity by digest and purge plaintext content.
    fn tombstone(
        &mut self,
        category: &str,
        key: &str,
        reason: &str,
        author_id: Option<&str>,
        scope: &str,
    ) -> Result<String, VaultError>;

    /// Check if a content string is tombstoned under category, key, and scope.
    fn is_tombstoned(&self, category: &str, key: &str, content: &str, scope: &str) -> bool;

    /// Stage a candidate assertion awaiting human review / empirical verification.
    fn admit_candidate(
        &mut self,
        category: &str,
        key: &str,
        content: &str,
        scope: &str,
        valid_from: Option<u64>,
        valid_until: Option<u64>,
    ) -> Result<MemoryEntity, VaultError>;

    /// Review and update epistemic status of an entity (Human-in-the-loop admission gate).
    fn review_entity(
        &mut self,
        category: &str,
        key: &str,
        verdict: EpistemicState,
        scope: &str,
        reviewer_id: Option<&str>,
        notes: Option<&str>,
    ) -> Result<MemoryEntity, VaultError>;

    /// Fetch chronological audit trail.
    fn list_audit_events(&self, scope: Option<&str>, limit: usize) -> Vec<AuditEvent>;

    /// Verify cryptographic integrity of append-only audit hash chain.
    fn verify_audit_chain(&self, scope: Option<&str>) -> bool;
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
    // Key: (category, key, scope)
    entities: Arc<Mutex<HashMap<(String, String, String), MemoryEntity>>>,
    // Key: (category, key, scope, value_sha256) -> reason
    tombstones: Arc<Mutex<HashMap<(String, String, String, String), String>>>,
    // Audit log
    audit_journal: Arc<Mutex<Vec<AuditEvent>>>,
}

impl InMemoryMemoryVault {
    /// Construct a new empty in-memory vault.
    pub fn new() -> Self {
        Self::default()
    }
}

impl MemoryVault for InMemoryMemoryVault {
    fn put(&mut self, entity: &MemoryEntity) -> Result<MemoryEntity, VaultError> {
        let val_hash = sha256_hex(entity.content.as_bytes());

        // Check tombstones only if any tombstones exist
        {
            let tombstones = self
                .tombstones
                .lock()
                .map_err(|e| VaultError::StorageError(e.to_string()))?;
            if !tombstones.is_empty() {
                let mut can_val_hash: Option<String> = None;
                for ((cat, k, sc, h), reason) in tombstones.iter() {
                    if cat == &entity.category
                        && (k == &entity.key || k == "*")
                        && (sc == &entity.scope || sc == "*")
                    {
                        if h == &val_hash {
                            return Err(VaultError::StorageError(format!(
                                "Write rejected by tombstone: entity '{}:{}' [scope={}] matches tombstone reason: {}",
                                cat, k, sc, reason
                            )));
                        }
                        if can_val_hash.is_none() {
                            can_val_hash = Some(sha256_hex(canonicalize_text(&entity.content).as_bytes()));
                        }
                        if Some(h) == can_val_hash.as_ref() {
                            return Err(VaultError::StorageError(format!(
                                "Write rejected by tombstone: entity '{}:{}' [scope={}] matches tombstone reason: {}",
                                cat, k, sc, reason
                            )));
                        }
                    }
                }
            }
        }

        let mut store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let key_tuple = (
            entity.category.clone(),
            entity.key.clone(),
            entity.scope.clone(),
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut saved = entity.clone();
        let action;
        if let Some(existing) = store.get(&key_tuple) {
            saved.version = existing.version + 1;
            saved.created_at = existing.created_at;
            action = "update".to_string();
        } else {
            saved.version = 1;
            saved.created_at = now;
            action = "put".to_string();
        }
        saved.updated_at = now;
        saved.archived = false;

        store.insert(key_tuple, saved.clone());

        // Append to audit journal
        let mut journal = self
            .audit_journal
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let seq = (journal.len() as u64) + 1;
        let prev_hash = if let Some(last) = journal.last() {
            last.event_hash.clone()
        } else {
            "0".repeat(64)
        };
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            seq, now, action, saved.category, saved.key, saved.scope, val_hash, prev_hash
        );
        let event_hash = sha256_hex(payload.as_bytes());
        journal.push(AuditEvent {
            sequence: seq,
            timestamp: now,
            action,
            category: saved.category.clone(),
            key: saved.key.clone(),
            scope: saved.scope.clone(),
            value_sha256: val_hash,
            prev_hash,
            event_hash,
            author_id: None,
        });

        Ok(saved)
    }

    fn get(&self, category: &str, key: &str) -> Result<Option<MemoryEntity>, VaultError> {
        self.get_scoped(category, key, "default")
    }

    fn get_scoped(
        &self,
        category: &str,
        key: &str,
        scope: &str,
    ) -> Result<Option<MemoryEntity>, VaultError> {
        let store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        Ok(store
            .get(&(category.to_string(), key.to_string(), scope.to_string()))
            .cloned())
    }

    fn search(
        &self,
        query: &str,
        category: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchResult>, VaultError> {
        self.search_scoped(query, category, limit, "default", None, None, false)
    }

    fn search_scoped(
        &self,
        query: &str,
        category: Option<&str>,
        limit: usize,
        scope: &str,
        epistemic_state: Option<EpistemicState>,
        as_of_valid_time: Option<u64>,
        include_unverified: bool,
    ) -> Result<Vec<SearchResult>, VaultError> {
        let store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let q_lower = query.to_lowercase();
        let mut results = Vec::new();

        for ((cat, _, sc), entity) in store.iter() {
            if entity.archived {
                continue;
            }
            if sc != scope && scope != "*" {
                continue;
            }
            if let Some(target_cat) = category {
                if cat != target_cat {
                    continue;
                }
            }

            // Epistemic state filtering
            if let Some(state) = epistemic_state {
                if entity.epistemic_state != state {
                    continue;
                }
            } else if !include_unverified {
                // By default only verified and disputed facts appear in search queries
                if entity.epistemic_state == EpistemicState::Candidate
                    || entity.epistemic_state == EpistemicState::Revoked
                {
                    continue;
                }
            }

            // Bi-temporal validity filtering
            if let Some(as_of) = as_of_valid_time {
                if let Some(vf) = entity.valid_from {
                    if as_of < vf {
                        continue;
                    }
                }
                if let Some(vu) = entity.valid_until {
                    if as_of >= vu {
                        continue;
                    }
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
        self.archive_scoped(category, key, "default")
    }

    fn archive_scoped(&mut self, category: &str, key: &str, scope: &str) -> Result<bool, VaultError> {
        let mut store = self
            .entities
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let key_tuple = (category.to_string(), key.to_string(), scope.to_string());
        if let Some(ent) = store.get_mut(&key_tuple) {
            ent.archived = true;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ent.updated_at = now;

            // Audit archive event
            let mut journal = self
                .audit_journal
                .lock()
                .map_err(|e| VaultError::StorageError(e.to_string()))?;
            let seq = (journal.len() as u64) + 1;
            let prev_hash = if let Some(last) = journal.last() {
                last.event_hash.clone()
            } else {
                "0".repeat(64)
            };
            let payload = format!(
                "{}:{}:archive:{}:{}:{}:{}:{}",
                seq, now, category, key, scope, "", prev_hash
            );
            let event_hash = sha256_hex(payload.as_bytes());
            journal.push(AuditEvent {
                sequence: seq,
                timestamp: now,
                action: "archive".to_string(),
                category: category.to_string(),
                key: key.to_string(),
                scope: scope.to_string(),
                value_sha256: "".to_string(),
                prev_hash,
                event_hash,
                author_id: None,
            });

            return Ok(true);
        }
        Ok(false)
    }

    fn tombstone(
        &mut self,
        category: &str,
        key: &str,
        reason: &str,
        author_id: Option<&str>,
        scope: &str,
    ) -> Result<String, VaultError> {
        let content_hash;
        let can_content_hash;
        {
            let mut store = self
                .entities
                .lock()
                .map_err(|e| VaultError::StorageError(e.to_string()))?;
            let key_tuple = (category.to_string(), key.to_string(), scope.to_string());
            if let Some(ent) = store.remove(&key_tuple) {
                content_hash = sha256_hex(ent.content.as_bytes());
                can_content_hash = sha256_hex(canonicalize_text(&ent.content).as_bytes());
            } else {
                return Err(VaultError::NotFound(format!("{}:{} [scope={}]", category, key, scope)));
            }
        }

        // Store tombstones
        {
            let mut tombstones = self
                .tombstones
                .lock()
                .map_err(|e| VaultError::StorageError(e.to_string()))?;
            tombstones.insert(
                (
                    category.to_string(),
                    key.to_string(),
                    scope.to_string(),
                    content_hash.clone(),
                ),
                reason.to_string(),
            );
            tombstones.insert(
                (
                    category.to_string(),
                    key.to_string(),
                    scope.to_string(),
                    can_content_hash,
                ),
                reason.to_string(),
            );
        }

        // Audit journal
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut journal = self
                .audit_journal
                .lock()
                .map_err(|e| VaultError::StorageError(e.to_string()))?;
            let seq = (journal.len() as u64) + 1;
            let prev_hash = if let Some(last) = journal.last() {
                last.event_hash.clone()
            } else {
                "0".repeat(64)
            };
            let payload = format!(
                "{}:{}:tombstone:{}:{}:{}:{}:{}",
                seq, now, category, key, scope, content_hash, prev_hash
            );
            let event_hash = sha256_hex(payload.as_bytes());
            journal.push(AuditEvent {
                sequence: seq,
                timestamp: now,
                action: "tombstone".to_string(),
                category: category.to_string(),
                key: key.to_string(),
                scope: scope.to_string(),
                value_sha256: content_hash.clone(),
                prev_hash,
                event_hash,
                author_id: author_id.map(|s| s.to_string()),
            });
        }

        Ok(content_hash)
    }

    fn is_tombstoned(&self, category: &str, key: &str, content: &str, scope: &str) -> bool {
        let val_hash = sha256_hex(content.as_bytes());
        let can_val_hash = sha256_hex(canonicalize_text(content).as_bytes());
        if let Ok(tombstones) = self.tombstones.lock() {
            for ((cat, k, sc, h), _) in tombstones.iter() {
                if cat == category
                    && (k == key || k == "*")
                    && (sc == scope || sc == "*")
                    && (h == &val_hash || h == &can_val_hash)
                {
                    return true;
                }
            }
        }
        false
    }

    fn admit_candidate(
        &mut self,
        category: &str,
        key: &str,
        content: &str,
        scope: &str,
        valid_from: Option<u64>,
        valid_until: Option<u64>,
    ) -> Result<MemoryEntity, VaultError> {
        let entity = MemoryEntity::new_scoped(
            category,
            key,
            content,
            scope,
            EpistemicState::Candidate,
            valid_from,
            valid_until,
        );
        self.put(&entity)
    }

    fn review_entity(
        &mut self,
        category: &str,
        key: &str,
        verdict: EpistemicState,
        scope: &str,
        reviewer_id: Option<&str>,
        notes: Option<&str>,
    ) -> Result<MemoryEntity, VaultError> {
        let mut entity = match self.get_scoped(category, key, scope)? {
            Some(e) => e,
            None => {
                return Err(VaultError::NotFound(format!(
                    "{}:{} [scope={}]",
                    category, key, scope
                )))
            }
        };

        if verdict == EpistemicState::Revoked {
            self.tombstone(
                category,
                key,
                notes.unwrap_or("revoked by human review"),
                reviewer_id,
                scope,
            )?;
            entity.archived = true;
            entity.epistemic_state = EpistemicState::Revoked;
            return Ok(entity);
        }

        entity.epistemic_state = verdict;
        self.put(&entity)
    }

    fn list_audit_events(&self, scope: Option<&str>, limit: usize) -> Vec<AuditEvent> {
        if let Ok(journal) = self.audit_journal.lock() {
            journal
                .iter()
                .filter(|ev| scope.map_or(true, |s| ev.scope == s || s == "*"))
                .take(limit)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    fn verify_audit_chain(&self, scope: Option<&str>) -> bool {
        if let Ok(journal) = self.audit_journal.lock() {
            let events: Vec<_> = journal
                .iter()
                .filter(|ev| scope.map_or(true, |s| ev.scope == s || s == "*"))
                .collect();
            if events.is_empty() {
                return true;
            }
            let mut expected_prev = "0".repeat(64);
            for ev in events {
                if ev.prev_hash != expected_prev {
                    return false;
                }
                let payload = format!(
                    "{}:{}:{}:{}:{}:{}:{}:{}",
                    ev.sequence,
                    ev.timestamp,
                    ev.action,
                    ev.category,
                    ev.key,
                    ev.scope,
                    ev.value_sha256,
                    ev.prev_hash
                );
                let recomputed = sha256_hex(payload.as_bytes());
                if recomputed != ev.event_hash {
                    return false;
                }
                expected_prev = ev.event_hash.clone();
            }
            true
        } else {
            false
        }
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

    #[test]
    fn test_zeroizing_passphrase_drops_cleanly() {
        let pass = ZeroizingPassphrase::new("super_secret_passphrase");
        assert_eq!(pass.as_str(), "super_secret_passphrase");
        drop(pass);
    }

    #[test]
    fn test_epistemic_lifecycle_and_human_review() {
        let mut vault = InMemoryMemoryVault::new();
        let entity = vault
            .admit_candidate("hypothesis", "dark_matter", "WIMP hypothesis", "team_astro", None, None)
            .unwrap();
        assert_eq!(entity.epistemic_state, EpistemicState::Candidate);

        // Candidate is withheld from active search by default
        let search_empty = vault
            .search_scoped("WIMP", None, 10, "team_astro", None, None, false)
            .unwrap();
        assert_eq!(search_empty.len(), 0);

        // Candidate visible when explicitly including unverified
        let search_cand = vault
            .search_scoped("WIMP", None, 10, "team_astro", None, None, true)
            .unwrap();
        assert_eq!(search_cand.len(), 1);

        // Human review verifies the candidate
        let reviewed = vault
            .review_entity(
                "hypothesis",
                "dark_matter",
                EpistemicState::Verified,
                "team_astro",
                Some("expert_dr_smith"),
                Some("Empirical corroboration confirmed"),
            )
            .unwrap();
        assert_eq!(reviewed.epistemic_state, EpistemicState::Verified);

        // Now returns in normal search
        let search_norm = vault
            .search_scoped("WIMP", None, 10, "team_astro", None, None, false)
            .unwrap();
        assert_eq!(search_norm.len(), 1);

        // Revocation purges and tombstones
        let revoked = vault
            .review_entity(
                "hypothesis",
                "dark_matter",
                EpistemicState::Revoked,
                "team_astro",
                Some("expert_dr_smith"),
                Some("Null result in detector"),
            )
            .unwrap();
        assert_eq!(revoked.epistemic_state, EpistemicState::Revoked);

        // Cannot write back the revoked assertion
        let reinsert_err = vault.put(&MemoryEntity::new_scoped(
            "hypothesis",
            "dark_matter",
            "WIMP hypothesis",
            "team_astro",
            EpistemicState::Candidate,
            None,
            None,
        ));
        assert!(reinsert_err.is_err());
    }

    #[test]
    fn test_scope_enforcement_and_isolation() {
        let mut vault = InMemoryMemoryVault::new();
        vault
            .put(&MemoryEntity::new_scoped(
                "api_keys",
                "openai",
                "sk-proj-tenant-a",
                "tenant_a",
                EpistemicState::Verified,
                None,
                None,
            ))
            .unwrap();

        vault
            .put(&MemoryEntity::new_scoped(
                "api_keys",
                "openai",
                "sk-proj-tenant-b",
                "tenant_b",
                EpistemicState::Verified,
                None,
                None,
            ))
            .unwrap();

        // Scope isolation in get
        let a = vault.get_scoped("api_keys", "openai", "tenant_a").unwrap().unwrap();
        assert_eq!(a.content, "sk-proj-tenant-a");
        let b = vault.get_scoped("api_keys", "openai", "tenant_b").unwrap().unwrap();
        assert_eq!(b.content, "sk-proj-tenant-b");

        // Scope isolation in search
        let res_a = vault
            .search_scoped("openai", None, 10, "tenant_a", None, None, false)
            .unwrap();
        assert_eq!(res_a.len(), 1);
        assert_eq!(res_a[0].entity.content, "sk-proj-tenant-a");

        let res_b = vault
            .search_scoped("openai", None, 10, "tenant_b", None, None, false)
            .unwrap();
        assert_eq!(res_b.len(), 1);
        assert_eq!(res_b[0].entity.content, "sk-proj-tenant-b");
    }

    #[test]
    fn test_bitemporal_validity() {
        let mut vault = InMemoryMemoryVault::new();
        let entity = MemoryEntity::new_scoped(
            "policy",
            "remote_work",
            "Remote work fully permitted",
            "default",
            EpistemicState::Verified,
            Some(1000),
            Some(2000),
        );
        vault.put(&entity).unwrap();

        // Query before valid_from (t=500) -> 0 matches
        let res_before = vault
            .search_scoped("Remote", None, 10, "default", None, Some(500), false)
            .unwrap();
        assert_eq!(res_before.len(), 0);

        // Query during validity window (t=1500) -> 1 match
        let res_during = vault
            .search_scoped("Remote", None, 10, "default", None, Some(1500), false)
            .unwrap();
        assert_eq!(res_during.len(), 1);

        // Query after valid_until (t=2500) -> 0 matches
        let res_after = vault
            .search_scoped("Remote", None, 10, "default", None, Some(2500), false)
            .unwrap();
        assert_eq!(res_after.len(), 0);
    }

    #[test]
    fn test_audit_hash_chain_verification() {
        let mut vault = InMemoryMemoryVault::new();
        vault
            .put(&MemoryEntity::new("convention", "t1", "payload 1"))
            .unwrap();
        vault
            .put(&MemoryEntity::new("convention", "t2", "payload 2"))
            .unwrap();
        vault
            .put(&MemoryEntity::new("convention", "t1", "payload 1 updated"))
            .unwrap();
        vault.archive("convention", "t2").unwrap();

        assert!(vault.verify_audit_chain(None));

        let events = vault.list_audit_events(None, 10);
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].action, "put");
        assert_eq!(events[1].action, "put");
        assert_eq!(events[2].action, "update");
        assert_eq!(events[3].action, "archive");
    }
}
