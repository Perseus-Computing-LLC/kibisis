//! # kibisis
//!
//! Local-first encrypted cognitive memory vault with atomic concurrency leases.
//! Clean-room implementation © 2026 Perseus Computing LLC.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEntity {
    pub id: Option<u64>,
    pub category: String,
    pub key: String,
    pub content: String,
    pub version: u64,
    pub archived: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

impl MemoryEntity {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub cipher: String,
    pub kdf: String,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub tag_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub resource: String,
    pub holder_id: String,
    pub fencing_token: u64,
    pub acquired_at: u64,
    pub expires_at: u64,
}

impl Lease {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub entity: MemoryEntity,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    NotFound(String),
    StorageError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    Conflict(String),
    Expired(String),
    InvalidToken(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    DecryptionFailed(String),
    InvalidKey(String),
}

pub trait MemoryVault: Send + Sync {
    fn put(&mut self, entity: &MemoryEntity) -> Result<MemoryEntity, VaultError>;
    fn get(&self, category: &str, key: &str) -> Result<Option<MemoryEntity>, VaultError>;
    fn search(
        &self,
        query: &str,
        category: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchResult>, VaultError>;
    fn archive(&mut self, category: &str, key: &str) -> Result<bool, VaultError>;
}

pub trait LeaseCoordinator: Send + Sync {
    fn acquire(
        &mut self,
        resource: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Lease, LeaseError>;
    fn renew(&mut self, lease: &Lease, ttl: Duration) -> Result<bool, LeaseError>;
    fn release(&mut self, lease: &Lease) -> Result<bool, LeaseError>;
}

pub trait CryptoEnvelope: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], key: &str) -> Result<EncryptedEnvelope, CryptoError>;
    fn decrypt(&self, envelope: &EncryptedEnvelope, key: &str) -> Result<Vec<u8>, CryptoError>;
}

/// In-memory reference implementation of MemoryVault.
#[derive(Default, Clone)]
pub struct InMemoryMemoryVault {
    entities: Arc<Mutex<HashMap<(String, String), MemoryEntity>>>,
}

impl InMemoryMemoryVault {
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

/// In-memory reference implementation of LeaseCoordinator with atomic fencing tokens.
#[derive(Default, Clone)]
pub struct InMemoryLeaseCoordinator {
    leases: Arc<Mutex<HashMap<String, Lease>>>,
}

impl InMemoryLeaseCoordinator {
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
            "clean_room",
            "Strict clean-room implementation",
        );
        let saved = vault.put(&entity).unwrap();
        assert_eq!(saved.version, 1);

        let fetched = vault.get("convention", "clean_room").unwrap().unwrap();
        assert_eq!(fetched.content, "Strict clean-room implementation");

        let search_res = vault.search("clean-room", None, 10).unwrap();
        assert_eq!(search_res.len(), 1);
        assert_eq!(search_res[0].entity.key, "clean_room");

        // Archive
        assert!(vault.archive("convention", "clean_room").unwrap());
        let search_after_archive = vault.search("clean-room", None, 10).unwrap();
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
