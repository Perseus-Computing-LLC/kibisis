# Kibisis

> Local-first encrypted cognitive memory vault with atomic concurrency leases.

[![Crates.io](https://img.shields.io/crates/v/kibisis.svg)](https://crates.io/crates/kibisis)
[![PyPI](https://img.shields.io/pypi/v/kibisis.svg)](https://pypi.org/project/kibisis/)
[![docs.rs](https://docs.rs/kibisis/badge.svg)](https://docs.rs/kibisis)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Telarch Suite** by [Perseus Computing LLC](https://perseuscomputing.com).

## What it does

When multiple agent workers share memory without coordination, they overwrite keys, read inconsistent state, and cause silent bugs. Kibisis provides:
- **Atomic concurrency leases:** Agents take time-limited write leases before modifying shared state. Leases issue monotonically increasing fencing tokens that prevent delayed writes from corrupting data.
- **Local encrypted storage (Python):** The Python package uses SQLCipher full-page encryption and AES-256-GCM envelopes (PBKDF2-HMAC-SHA256, 600,000 iterations). Raw disk scans reveal zero plaintext.
- **In-memory coordinator (Rust):** The Rust crate provides fast in-process leasing and in-memory vault management.
- **Zero network code:** Operates completely locally on your hardware without external cloud dependencies or telemetry.

## Installation

### Rust

Add `kibisis` to `Cargo.toml`:

```toml
[dependencies]
kibisis = "0.1.0-alpha.3"
```

### Python

Install via pip:

```bash
pip install kibisis
```

## Quickstart

### Rust (10 lines)

```rust
use kibisis::{InMemoryLeaseCoordinator, InMemoryMemoryVault, LeaseCoordinator, MemoryEntity, MemoryVault};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut vault = InMemoryMemoryVault::new();
    let mut coordinator = InMemoryLeaseCoordinator::new();
    let lease = coordinator.acquire("sector_7", "worker_a", Duration::from_secs(1))?;
    let entity = MemoryEntity::new("tactical", "target_01", "Coordinates locked: 34.05,-118.25");
    vault.put(&entity)?;
    coordinator.release(&lease)?;
    println!("Saved entity with fencing token {}", lease.fencing_token);
    Ok(())
}
```

### Python (10 lines)

```python
from kibisis import SQLiteMemoryVault, SQLiteLeaseCoordinator

vault = SQLiteMemoryVault("memory.db", passphrase="secret_master_passphrase")
coordinator = SQLiteLeaseCoordinator("memory.db", passphrase="secret_master_passphrase")
lease = coordinator.acquire("sector_7", "worker_a", ttl_seconds=1.0)
vault.put("tactical", "target_01", "Coordinates locked: 34.05,-118.25")
coordinator.release(lease)
print(f"Committed memory entity under fencing token {lease.fencing_token}")
```

## What we measured

Figures trace to reports committed in [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) (Linux x86_64, Intel Core i5-13500, `rustc 1.97.1`):

| Metric | Result | Range | Scope | Method |
|---|---|---|---|---|
| **Write Ingestion Rate** | **271,222 ops/s** | 271k–343k ops/s | In-memory writes, hashed into audit log | `telarch-benchmarks` |
| **Lease Throughput (16 workers)** | **1,466,471 ops/s** | 1.46M–1.78M ops/s | 16 threads, 50 ms requested TTL | `adversarial_contention` |
| **Lease Throughput (32 workers)** | **1,597,354 ops/s** | 1.59M–1.87M ops/s | 32 threads, 50 ms requested TTL | `adversarial_contention` |
| **Split-Brain Violations** | **0 events** | 0 events | 64,000 contention cycles (16 & 32 workers) | `adversarial_contention` |
| **Fencing Token Regressions** | **0 events** | 0 events | 64,000 contention cycles | `adversarial_contention` |
| **Multi-Process Split-Brain** | **0 events** | 0 events | 2 to 32 separate OS child processes | `gap3_kibisis_multiproc` |
| **Stale Writes Accepted** | **0 writes** | 0 writes | SIGSTOP holder past TTL; write to sink | `gap3_kibisis_multiproc` |
| **Formal Model Verification** | **100% valid** | 6,869 states | TLA+ specification, 30,040 transitions | `gap4_kibisis_model_check` |

## Limits

- **Alpha release:** APIs will evolve before 1.0.
- **Encryption scope:** In the Python package, database pages are encrypted with SQLCipher and payloads are envelope-encrypted with AES-256-GCM. The Rust crate holds memory in RAM and does not encrypt at rest.
- **Lease coordination scope:** Leases coordinate threads in one process or processes sharing a local filesystem via SQLite transactions. They are not a distributed consensus service.
- **TTL resolution:** The in-process Rust coordinator tracks deadlines in whole seconds and rounds up, so a lease is held for at least its TTL and at most one second longer. The Python SQLite coordinator uses floating-point second timestamps.
- **Not independently assessed:** Designed for local and disconnected use.

## Links

- [Documentation (docs.rs)](https://docs.rs/kibisis)
- [Evidence & Claims](https://telarch.ai/evidence)
- [Security Policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md)
- [Telarch Overview](https://telarch.ai)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
