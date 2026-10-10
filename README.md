# kibisis

> Local-first encrypted memory vault with atomic leases for AI agents.

[![Crates.io](https://img.shields.io/crates/v/kibisis.svg)](https://crates.io/crates/kibisis)
[![docs.rs](https://docs.rs/kibisis/badge.svg)](https://docs.rs/kibisis)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Telarch Suite** (TCI / Telarch Cognitive Infrastructure) by [Perseus Computing LLC](https://github.com/Perseus-Computing-LLC).

---

## Why Kibisis exists

When multiple agent workers share memory without coordination, they overwrite each other's keys, read half-written state, and cause silent bugs.

Kibisis gives you an embedded memory vault with atomic Single-Writer Multi-Reader (SWMR) leases. Agents grab time-bounded write leases before modifying entries, and read concurrently without blocking. Payloads are encrypted locally with AES-256-GCM so memory at rest stays secure on disk.

---

## Key design goals

- **Atomic concurrency leases:** Fast lease acquisition with automatic timeout prevents competing workers from corrupting shared keys.
- **Local authenticated encryption:** Encrypts memory entries locally using AES-256-GCM with PBKDF2-SHA256 key derivation (100,000 iterations).
- **High throughput:** Handles over 1,560,000 lease operations per second under heavy thread contention.
- **Offline and partition resilient:** Tested in 10-node simulated edge partitions with zero split-brain errors.
- **Evasion-resistant tombstones:** Rejected-value tombstones use canonicalized text hashing (Unicode NFKC, casefold, punctuation stripping, whitespace normalization) to prevent prompt injection and evasion.

---

## Installation

Add `kibisis` to your `Cargo.toml`:

```toml
[dependencies]
kibisis = "0.1.0-alpha.2"
```

Or via Cargo:

```bash
cargo add kibisis
```

For Python environments:

```bash
pip install kibisis
```

---

## Examples

### Rust

```rust
use kibisis::{
    InMemoryLeaseCoordinator, InMemoryMemoryVault, LeaseCoordinator, MemoryEntity,
    MemoryVault,
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault = InMemoryMemoryVault::new();
    let coordinator = InMemoryLeaseCoordinator::new();

    // 1. Acquire time-bounded write lease
    let key = "target_vector_alpha";
    let lease = coordinator.acquire_write_lease(key, Duration::from_millis(50))?;
    println!("Acquired write lease: {}", lease.token);

    // 2. Commit encrypted memory entity under active lease
    let entity = MemoryEntity::new(
        "spatial_plan",
        key,
        "Waypoint 4 confirmed: telemetry coordinates locked.",
    );
    vault.put(&entity)?;

    // 3. Explicitly release lease upon completion
    coordinator.release_lease(&lease.token)?;
    println!("Lease released successfully.");

    // 4. Retrieve and query memory entities
    let query_results = vault.search("telemetry")?;
    for result in query_results {
        println!(
            "Matched entity [{}]: {} (score: {})",
            result.entity.category, result.entity.key, result.score
        );
    }

    Ok(())
}
```

### Python (with AES-256-GCM Envelope Encryption and Hardened Tombstones)

```python
from kibisis import SQLiteMemoryVault, AESGCMCryptoEnvelopeProvider, MemoryEntity

# 1. Initialize envelope encryption provider (AES-256-GCM / PBKDF2-SHA256)
crypto = AESGCMCryptoEnvelopeProvider.from_passphrase("agent-secure-passphrase")

# 2. Open vault with encryption wired to the storage engine
vault = SQLiteMemoryVault("memory.db", crypto_provider=crypto)

# 3. Store memory entity securely (encrypted on disk, FTS cleartext protected)
entity = MemoryEntity(
    category="tactical",
    key="target_coords",
    content="Waypoint 4 locked at sector 7-G."
)
vault.put(entity)

# 4. Enforce negative memory tombstones (evasion-resistant canonicalization)
vault.tombstone(category="tactical", content="Do Not Target Civilians")

# Any variant with different casing, whitespace, or punctuation is blocked:
# vault.put(MemoryEntity(category="tactical", key="k", content="do not target civilians!")) -> Rejected!
```

---

## Benchmark results

Measured on bare-metal Linux x86_64 (`rustc 1.85.0`, `opt-level = 3`, `lto = "fat"`):

| Metric | Measurement | Test condition |
| :--- | :--- | :--- |
| **Lease Throughput** | **1,560,000+ ops/s** | Multi-threaded read and write contention (8 threads) |
| **Write Throughput** | **2,100,000+ writes/s** | Sustained sequential envelope commits |
| **Contention Race Errors** | **0 Errors** | 100% thread contention |
| **Swarm Partition Split-Brain** | **0 Errors** | 10-node simulated partition under 50% packet drop |
| **Recovery Latency** | **0.42 ms** | Partition heal state convergence |

Run benchmarks yourself:

```bash
cargo run --release -p perseus-benchmarks
```

---

## License

Copyright &copy; 2026 Perseus Computing LLC. Released under the [MIT License](LICENSE).
