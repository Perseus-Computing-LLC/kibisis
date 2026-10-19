# Kibisis

> Local, encrypted memory vault for AI agents: scoped recall, value tombstones, a hash-chained audit journal and concurrency leases.

[![Crates.io](https://img.shields.io/crates/v/kibisis.svg)](https://crates.io/crates/kibisis)
[![PyPI](https://img.shields.io/pypi/v/kibisis.svg)](https://pypi.org/project/kibisis/)
[![docs.rs](https://docs.rs/kibisis/badge.svg)](https://docs.rs/kibisis)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Part of the **Telarch Suite** by [Perseus Computing LLC](https://perseuscomputing.com).

## What it does

Kibisis keeps an agent's memories on the local machine and controls what comes back.

- **Encrypted at rest (Python).** Entry content is sealed with AES-256-GCM under a key derived by PBKDF2-HMAC-SHA256 with 600,000 iterations (`src/kibisis/crypto.py`). When the `sqlcipher3` dependency loads, SQLCipher also encrypts every page of the database file. If it does not load, the vault falls back to SQLite: content stays encrypted, but categories, keys, metadata and the audit journal are stored in the clear (`SQLiteMemoryVault.__init__` in `src/kibisis/vault.py`). An on-disk vault refuses to open without a passphrase unless opened with `allow_plaintext=True`.
- **Scopes.** Every memory belongs to a scope and carries an HMAC-SHA256 signature over its scope, category, key and content. `search` and `list_entities` skip, and `get` refuses, a row whose signature does not verify; rows written before signatures were added carry none and are not checked (`sign_tenant_payload` and `verify_tenant_payload` in `src/kibisis/crypto.py`, used in `src/kibisis/vault.py`).
- **Trust states and validity windows.** Each memory is a candidate, verified, disputed or revoked, and can carry valid-from and valid-until times. Search leaves out candidates and revoked memories unless asked, and can return what was valid at a given time (`src/kibisis/models.py`, `search` in `src/kibisis/vault.py`). `review_entity` records a reviewer's verdict; a revocation tombstones the value. `MemoryAdmissionGate` (`src/kibisis/admission.py`) is a heuristic classifier a caller can use to choose a memory's state; the vault does not run it on its own.
- **Tombstones.** `tombstone` records a value's SHA-256 digest and the digest of its canonical form (Unicode compatibility folding, case folding, invisible characters and punctuation removed, whitespace collapsed), then deletes every copy of the value in the scope. Afterwards the value is refused under any category or key in that scope, and `import_snapshot` will not restore it (`src/kibisis/vault.py`; the Rust vault in `src/lib.rs` matches values the same way).
- **Audit journal.** Every put, archive, tombstone and purge appends a SHA-256 hash-chained event in the same database transaction as the change, so a change cannot land without its event. `verify_audit_chain` re-checks the chain (`_record_audit_event` in `src/kibisis/vault.py`).
- **Leases.** `SQLiteLeaseCoordinator` (`src/kibisis/lease.py`) and the Rust `InMemoryLeaseCoordinator` (`src/lib.rs`) grant time-limited leases with increasing fencing tokens, and `SQLiteLeaseCoordinator.validate_fencing_token` checks a token.
- **MCP server.** `python -m kibisis.mcp_server` serves remember, recall, admit, forget, verify-ledger and health tools over stdio (`src/kibisis/mcp_server.py`).
- **No network code.** Neither package opens a network connection; the MCP server speaks over stdio.

## Installation

crates.io and PyPI have 0.1.0-alpha.2 (0.1.0a2 on PyPI). This README describes 0.1.0-alpha.4, which is not published yet. Until it is, install from this repository.

### Rust

```toml
[dependencies]
kibisis = { git = "https://github.com/Perseus-Computing-LLC/kibisis", branch = "main" }
```

### Python

```bash
pip install "kibisis @ git+https://github.com/Perseus-Computing-LLC/kibisis@main"
```

## Quickstart

### Python

```python
from kibisis import SQLiteMemoryVault

# The passphrase comes from KIBISIS_PASSPHRASE or KIBISIS_PASSPHRASE_FILE.
vault = SQLiteMemoryVault("memory.db")
vault.put("preferences", "indent", "Use tabs for indentation", scope="project-a")
print([hit.entity.content for hit in vault.search("indentation", scope="project-a")])

vault.tombstone("preferences", "indent", reason="user asked to forget", scope="project-a")
# Refused under any category or key in the scope, including look-alike spellings:
print(vault.is_tombstoned("notes", "style", "USE TABS FOR INDENTATION", scope="project-a"))  # True
```

### Rust

```rust
use kibisis::{InMemoryLeaseCoordinator, InMemoryMemoryVault, LeaseCoordinator, MemoryEntity, MemoryVault};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut vault = InMemoryMemoryVault::new();
    let mut coordinator = InMemoryLeaseCoordinator::new();
    let lease = coordinator.acquire("notes", "worker-a", Duration::from_secs(1))?;
    vault.put(&MemoryEntity::new("preferences", "indent", "Use tabs for indentation"))?;
    coordinator.release(&lease)?;
    println!("saved under fencing token {}", lease.fencing_token);
    Ok(())
}
```

## Measurements

Benchmark and model-checking reports, with hardware and method, are kept in [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) rather than repeated here.

## Limits

- **Alpha release:** APIs will change before 1.0.
- **Platforms:** CI tests the Python package on Linux and macOS (arm64). Windows is not tested.
- **Encryption scope:** In the Python package, entry content is always encrypted unless the vault is opened with `allow_plaintext=True`; whole-file encryption needs SQLCipher (see above). The Rust crate keeps memories in RAM and neither encrypts nor persists them.
- **Tombstones:** They stop exact and look-alike repeats of a value, not paraphrases. A tombstone covers one scope; tombstone with `scope="*"` to forget a value in every scope.
- **Scopes:** The caller names the scope. Kibisis keeps scopes apart but does not decide which caller may use which scope.
- **Fencing:** The vault does not check fencing tokens on write; callers check them with `SQLiteLeaseCoordinator.validate_fencing_token`.
- **Lease coordination scope:** Leases coordinate threads in one process, or processes sharing a local filesystem through SQLite transactions. They are not a distributed consensus service.
- **TTL resolution:** The in-process Rust coordinator tracks deadlines in whole seconds and rounds up, so a lease is held for at least its TTL and at most one second longer. The Python SQLite coordinator uses floating-point second timestamps.
- **Not independently assessed:** Designed for local and disconnected use.

## Links

- [Documentation (docs.rs)](https://docs.rs/kibisis)
- [Security Policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md)
- [Telarch Overview](https://telarch.ai)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
