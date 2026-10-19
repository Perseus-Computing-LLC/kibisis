# Kibisis

**Local, encrypted memory for AI agents.** Kibisis keeps what an agent learns on your own machine, decides what comes back, makes forgetting stick and lets one writer in at a time.

[![CI](https://github.com/Perseus-Computing-LLC/kibisis/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Perseus-Computing-LLC/kibisis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-informational.svg)](Cargo.toml)

Kibisis is one of the three [Telarch](https://telarch.ai) libraries from [Perseus Computing LLC](https://perseuscomputing.com). [Harpe](https://github.com/Perseus-Computing-LLC/harpe) decides what goes into each model call, and [Argus](https://github.com/Perseus-Computing-LLC/argus) keeps a tamper-evident record of what the agent did. Each one works on its own.

## Why

An agent that runs for hours learns things worth keeping: decisions, preferences, facts about the code it works on. In a plain file, anyone who copies the file can read them. In a hosted service, they leave your machine. And with no rules for what comes back, a memory that was wrong, unreviewed or deliberately forgotten can return in the next prompt. Kibisis keeps agent memory local, encrypted and deliberate.

## What you get

- **Encrypted on disk.** The Python vault seals every entry with AES-256-GCM in one SQLite file. With SQLCipher it encrypts the whole file.
- **Recall you can reason about.** Every memory is a candidate, verified, disputed or revoked. Search returns verified memories unless you ask for more, and it can answer "what was true on this date".
- **Forgetting that sticks.** A tombstoned value is deleted everywhere in its scope. Writing it again is refused, even under another key or with different case, spacing or punctuation.
- **Scopes that hold.** Each memory is signed over its scope, category, key and content, and a row that fails the check is never returned.
- **A journal of every change.** Every write, archive, tombstone and purge is recorded in a hash chain, in the same transaction as the change.
- **One writer at a time.** Leases carry fencing tokens that only go up. They work across threads in Rust, and across processes that share one SQLite file in Python. A Python vault opened with `enforce_fencing=True` refuses writes that do not carry the current token.
- **Ready for agents.** An MCP server over stdio offers remember, recall, admit, forget, verify-ledger and health tools.
- **Local only.** Kibisis contains no network code.

## Install

This README describes 0.1.0-alpha.4 (0.1.0a4 on PyPI). It is a pre-release, so name the version.

```toml
# Rust: Cargo.toml
[dependencies]
kibisis = "0.1.0-alpha.4"
```

```bash
# Python
pip install kibisis==0.1.0a4
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

### As an MCP server

```bash
python -m kibisis.mcp_server   # remember, recall, admit, forget, verify-ledger and health over stdio
```

## Measured

Medians of five runs of [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) at the v0.1.0-alpha.3 release, with synthetic data on one shared server. Every run, its range and the command that reproduces it are on [telarch.ai/evidence](https://telarch.ai/evidence).

| Measurement | Result |
| --- | --- |
| Times two holders had the same lease, in 64,000 contended attempts from 16 and 32 threads | 0 |
| Fencing tokens that went backwards | 0 |
| Times two processes held the lease at once, 2 to 32 processes sharing one SQLite file | 0 |
| Late write from a paused holder | rejected |
| Lease database after a holder is killed mid-write | usable |
| Lease operations per second, 16 threads, in memory (Rust) | 1,830,154 |

## How it works

- **Encryption (Python).** Entry content is sealed with AES-256-GCM under a key derived by PBKDF2-HMAC-SHA256 with 600,000 iterations (`src/kibisis/crypto.py`). When the `sqlcipher3` dependency loads, SQLCipher also encrypts every page of the database file. If it does not load, the vault falls back to SQLite: content stays encrypted, but categories, keys, metadata and the audit journal are stored in the clear, and a warning says so (`SQLiteMemoryVault.__init__` in `src/kibisis/vault.py`). An on-disk vault refuses to open without a passphrase unless opened with `allow_plaintext=True`.
- **Scopes.** Every memory belongs to a scope and carries an HMAC-SHA256 signature over its scope, category, key and content. `search` and `list_entities` skip, and `get` refuses, a row whose signature does not verify. Rows written before signatures were added carry none and are not checked (`sign_tenant_payload` and `verify_tenant_payload` in `src/kibisis/crypto.py`, used in `src/kibisis/vault.py`).
- **Trust states and validity windows.** Each memory is a candidate, verified, disputed or revoked, and can carry valid-from and valid-until times. Search leaves out candidates and revoked memories unless asked, and can return what was valid at a given time (`src/kibisis/models.py`, `search` in `src/kibisis/vault.py`). `review_entity` records a reviewer's verdict; a revocation tombstones the value. `MemoryAdmissionGate` (`src/kibisis/admission.py`) is a heuristic classifier a caller can use to choose a memory's state; the vault does not run it on its own.
- **Tombstones.** `tombstone` records a value's SHA-256 digest and the digest of its canonical form (Unicode compatibility folding, case folding, invisible characters and punctuation removed, whitespace collapsed), then deletes every copy of the value in the scope. Afterwards the value is refused under any category or key in that scope, and `import_snapshot` will not restore it (`src/kibisis/vault.py`; the Rust vault in `src/lib.rs` matches values the same way).
- **Audit journal.** Every put, archive, tombstone and purge appends a SHA-256 hash-chained event in the same database transaction as the change, so a change cannot land without its event. `verify_audit_chain` re-checks the chain (`_record_audit_event` in `src/kibisis/vault.py`).
- **Leases.** `SQLiteLeaseCoordinator` (`src/kibisis/lease.py`) and the Rust `InMemoryLeaseCoordinator` (`src/lib.rs`) grant time-limited leases with increasing fencing tokens, and `SQLiteLeaseCoordinator.validate_fencing_token` checks a token. A Python vault opened with `coordinator=` and `enforce_fencing=True` checks the caller's token on every write while it holds its write lock, and refuses a missing, stale or expired token with `LeaseConflictError` before anything changes (`_fence` in `src/kibisis/vault.py`).
- **MCP server.** `python -m kibisis.mcp_server` serves the tools over stdio (`src/kibisis/mcp_server.py`).

## Limits

- **Alpha release:** APIs will change before 1.0.
- **Platforms:** CI tests the Python package on Linux and macOS (arm64). Windows is not tested.
- **Encryption scope:** In the Python package, entry content is always encrypted unless the vault is opened with `allow_plaintext=True`; whole-file encryption needs SQLCipher (see above). The Rust crate keeps memories in RAM and neither encrypts nor persists them.
- **Tombstones:** They stop exact and look-alike repeats of a value, not paraphrases. A tombstone covers one scope; tombstone with `scope="*"` to forget a value in every scope.
- **Scopes:** The caller names the scope. Kibisis keeps scopes apart but does not decide which caller may use which scope.
- **Fencing:** The Python vault checks fencing tokens only when it is opened with `enforce_fencing=True` or a call passes a token. `migrate_plaintext`, which re-encrypts stored rows without changing them, takes no token. The MCP server opens its vault without a coordinator, and the Rust vault does not check tokens. Storage outside Kibisis must compare tokens itself.
- **Lease coordination scope:** Leases coordinate threads in one process, or processes sharing a local filesystem through SQLite transactions. They are not a distributed consensus service.
- **TTL resolution:** The in-process Rust coordinator tracks deadlines in whole seconds and rounds up, so a lease is held for at least its TTL and at most one second longer. The Python SQLite coordinator uses floating-point second timestamps.
- **Not independently assessed:** No security review or certification has been completed. Designed for local and disconnected use.

## Security

Report a vulnerability to contact@perseuscomputing.com with `[SECURITY]` in the subject; please do not open a public issue. See the [security policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md) for response times.

## Links

- [telarch.ai/kibisis](https://telarch.ai/kibisis): overview and a live demo of the lease coordinator
- [Documentation (docs.rs)](https://docs.rs/kibisis)
- [Changelog](CHANGELOG.md)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
