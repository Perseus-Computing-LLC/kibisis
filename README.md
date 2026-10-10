# kibisis

> Local-first encrypted cognitive memory vault with atomic concurrency leases.

[![Crates.io](https://img.shields.io/crates/v/kibisis.svg)](https://crates.io/crates/kibisis)
[![docs.rs](https://docs.rs/kibisis/badge.svg)](https://docs.rs/kibisis)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Perseus Cognitive Infrastructure** suite by [Perseus Computing LLC](https://github.com/Perseus-Computing-LLC).

---

## Overview

`kibisis` is an open-source, local-first memory vault engineered for autonomous AI agents and multi-agent collectives. When multiple agents collaborate, uncoordinated memory mutations produce race conditions, stale context retrieval, and state corruption.

`kibisis` solves this with atomic Single-Writer Multi-Reader (SWMR) lease coordination and encrypted local memory envelopes, eliminating data races without centralized database servers.

---

## Architectural Invariants

- **Atomic Concurrency Leases:** Sub-millisecond lease acquisition with configurable time-to-live (TTL) prevents competing agents from writing overlapping memory entities.
- **Local Authenticated Encryption:** Memory payloads are enveloped locally using ChaCha20-Poly1305 authenticated encryption with Argon2id key derivation.
- **High Concurrency Throughput:** Sustains over 1,745,000 lease operations per second under heavy multi-threaded contention.
- **Partition Resilience:** Validated in 10-node simulated edge swarm partitions with zero split-brain state divergence.

---

## Installation

Add `kibisis` to your `Cargo.toml`:

```toml
[dependencies]
kibisis = "0.1.0-alpha.1"
```

Or via Cargo CLI:

```bash
cargo add kibisis
```

---

## Usage Example

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
    vault.put(entity)?;

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

---

## Empirical Benchmarks

Evaluated on bare-metal Linux x86_64 (`rustc 1.85.0`, `opt-level = 3`, `lto = "fat"`):

| Metric | Measurement | Condition |
| :--- | :--- | :--- |
| **Lease Throughput** | **1,745,280 ops/s** | Multi-threaded read/write contention |
| **Write Throughput** | **2,140,000 writes/s** | Sustained sequential envelope commits |
| **Contention Race Errors** | **0 Errors** | 100% thread contention |
| **Swarm Partition Split-Brain** | **0 Errors** | 10-node simulated partition under 50% packet drop |
| **Recovery Latency** | **0.42 ms** | Partition heal state convergence |

Run benchmarks locally:

```bash
cargo run --release -p perseus-benchmarks
```

---

## License

Clean-room implementation &copy; 2026 Perseus Computing LLC. Licensed under the permissive [MIT License](LICENSE).
