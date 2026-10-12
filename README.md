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
- **Encrypted by default:** An on-disk vault refuses to open without a passphrase. Full-database page-level encryption via SQLCipher ensures zero plaintext leakage (schema, tables, keys, categories, metadata, and indexes). Entry payloads additionally feature AES-256-GCM envelope encryption with PBKDF2-SHA256 (600,000 iterations). Raw disk scans reveal zero plaintext.
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

For Python environments (once wheels are built, or from source):

```bash
pip install .
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

    // 1. Acquire time-bounded write lease with fencing token
    let resource = "target_vector_alpha";
    let lease = coordinator.acquire(resource, "worker_0", Duration::from_millis(50))?;
    println!("Acquired write lease: fencing_token={}", lease.fencing_token);

    // 2. Commit encrypted memory entity under active lease
    let entity = MemoryEntity::new(
        "spatial_plan",
        "waypoint_4",
        "Waypoint 4 confirmed: telemetry coordinates locked.",
    );
    vault.put(&entity)?;

    // 3. Explicitly release lease upon completion
    coordinator.release(&lease)?;
    println!("Lease released successfully.");

    // 4. Retrieve and query memory entities
    let query_results = vault.search("telemetry", None, 10)?;
    for result in query_results {
        println!(
            "Matched entity [{}]: {} (score: {})",
            result.entity.category, result.entity.key, result.score
        );
    }

    Ok(())
}
```

### Python (encrypted by default)

```python
from kibisis import SQLiteMemoryVault, generate_keyfile

# One-time: create a random 256-bit key file readable only by you (mode 0600). It never overwrites.
generate_keyfile("/secure/location/kibisis.key")

# Point Kibisis at the key file. A file with group/other permissions is refused.
#   export KIBISIS_PASSPHRASE_FILE=/secure/location/kibisis.key
# (or pass passphrase="..." directly, 12+ characters; KIBISIS_PASSPHRASE also works)

vault = SQLiteMemoryVault("memory.db")          # no passphrase anywhere -> EncryptionRequiredError
vault.put("tactical", "waypoint", "Waypoint 4 locked at sector 7-G.")   # content is encrypted on disk
print(vault.encryption_status())                # {'encrypted': 1, 'plaintext': 0}

# Evasion-resistant tombstone: variants of the same text with different case or punctuation are rejected too.
vault.tombstone("tactical", "waypoint", reason="revoked")

# Opening a vault you want unencrypted takes an explicit opt-in:
#   SQLiteMemoryVault("memory.db", allow_plaintext=True)
# Moving an existing plaintext vault to encrypted (also clears old text from the search index, log and free pages):
#   SQLiteMemoryVault("old.db", passphrase="...", allow_plaintext=True).migrate_plaintext()
```


---

## Benchmark results

Measured on bare-metal Linux x86_64 (`rustc 1.85.0`, `opt-level = 3`, `lto = "fat"`):

| Metric | Measurement | Test condition | Operational Guarantee |
| :--- | :--- | :--- | :--- |
| **Write Throughput** | **2,098,000+ writes/s** | Sustained sequential envelope commits | Local zero-contention vault ingestion |
| **SWMR Contention (16 Workers)** | **1,696,000+ ops/s** | 16 concurrent worker threads (`adversarial_contention`) | 0.59 &micro;s latency; 0 split-brain conflicts |
| **SWMR Contention (32 Workers)** | **1,776,000+ ops/s** | 32 concurrent worker threads (`adversarial_contention`) | 0.56 &micro;s latency; 0 fencing regressions |
| **Swarm Partition Split-Brain** | **0 Errors** | 10-node simulated partition under 50% packet drop | 100% convergence across edge mesh (599k msgs/s) |
| **Partition Reconciliation** | **0.42 ms** | Partition heal state convergence | Monotonic vector clock reconciliation |

Run benchmarks yourself:

```bash
cargo run --release -p telarch-benchmarks
cargo run --release -p telarch-benchmarks --bin adversarial_contention
cargo run --release -p telarch-benchmarks --bin swarm_partition
```

---

## License

Copyright &copy; 2026 Perseus Computing LLC. Released under the [MIT License](LICENSE).
