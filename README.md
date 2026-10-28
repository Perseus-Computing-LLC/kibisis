# Kibisis

**Local, encrypted memory for AI agents.** Kibisis keeps what an agent learns on your own machine, decides what comes back, makes forgetting stick and lets one writer in at a time.

[![CI](https://github.com/Perseus-Computing-LLC/kibisis/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Perseus-Computing-LLC/kibisis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.89](https://img.shields.io/badge/MSRV-1.89-informational.svg)](Cargo.toml)
[![M8ven Score](https://m8ven.ai/badge/mcp/perseus-computing-llc-kibisis-13szsu?v=c14fb7f48a3bfb2a15213c5988349ed2)](https://m8ven.ai/mcp/perseus-computing-llc-kibisis-13szsu?s=readme)

Kibisis is one of the three [Telarch](https://telarch.ai) libraries from [Perseus Computing LLC](https://perseuscomputing.com). [Harpe](https://github.com/Perseus-Computing-LLC/harpe) decides what goes into each model call, and [Argus](https://github.com/Perseus-Computing-LLC/argus) keeps a tamper-evident record of what the agent did. Each one works on its own.

## Why

An agent that runs for hours learns things worth keeping: decisions, preferences, facts about the code it works on. In a plain file, anyone who copies the file can read them. In a hosted service, they leave your machine. And with no rules for what comes back, a memory that was wrong, unreviewed or deliberately forgotten can return in the next prompt. Kibisis keeps agent memory local, encrypted and deliberate.

## What you get

- **Encrypted on disk.** The Python vault seals every entry with AES-256-GCM in one SQLite file. With SQLCipher it encrypts the whole file.
- **Recall you can reason about.** Every memory is a candidate, verified, disputed or revoked. Search returns verified memories unless you ask for more, and it can answer "what was true on this date".
- **Forgetting that sticks.** A tombstoned value is deleted everywhere in its scope. Writing it again is refused, even under another key or with different case, spacing or punctuation.
- **Scopes that hold.** Each memory is signed over its scope, category, key and content, and a row that fails the check is never returned.
- **A journal of every change.** Every write, archive, tombstone and purge is recorded in a hash chain, in the same transaction as the change.
- **One writer at a time.** Leases carry fencing tokens that only go up. They coordinate processes on one machine, through a shared SQLite file in Python or a shared directory in Rust, and threads within one Rust process. A Python vault opened with `enforce_fencing=True` refuses writes that do not carry the current token.
- **Ready for agents.** An MCP server over stdio offers remember, recall, forget, verify-ledger and health tools. It serves one scope fixed at startup, stores what an agent writes as an unreviewed candidate, and returns recall as escaped data, not instructions.
- **Local only.** Kibisis contains no network code.

## Install

This README describes 0.1.0-alpha.10 (0.1.0a10 on PyPI). It is a pre-release, so name the version.

```toml
# Rust: Cargo.toml
[dependencies]
kibisis = "0.1.0-alpha.10"
```

```bash
# Python
pip install kibisis==0.1.0a10
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
python -m kibisis.keys ~/.config/kibisis/kibisis.key     # once: creates a key file with mode 0600
export KIBISIS_PASSPHRASE_FILE=~/.config/kibisis/kibisis.key
export KIBISIS_SCOPE=project-a                            # optional; the default scope is "default"
python -m kibisis.mcp_server                              # remember, recall, forget, verify-ledger and health over stdio
```

The package also installs these as `kibisis-keygen`, `kibisis-mcp` and `kibisis-review`.

The server keeps its vault in your user data directory (`~/.local/share/kibisis/vault.sqlite` on Linux, `~/Library/Application Support/kibisis/` on macOS, `%LOCALAPPDATA%\kibisis\` on Windows) unless `KIBISIS_DB_PATH` names another file. It refuses to start without a key unless `KIBISIS_ALLOW_PLAINTEXT=1` is set. What an agent stores is a candidate written by `mcp-agent`; a person reviews candidates:

```bash
python -m kibisis.review list
python -m kibisis.review approve CATEGORY KEY      # or: dispute, reject
```

## Measured

Medians of five runs of [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) v0.1.0-alpha.8 against kibisis 0.1.0-alpha.9 (the Rust crate, and the Python package 0.1.0a9 for the multi-process rows), with synthetic data on one EC2 m8azn.metal-12xl bare-metal server. Every run, its range and the command that reproduces it are on [telarch.ai/evidence](https://telarch.ai/evidence).

| Measurement | Result |
| --- | --- |
| Times two holders had the same lease, in 64,000 contended attempts from 16 and 32 threads | 0 |
| Fencing tokens that went backwards | 0 |
| Times two processes held the lease at once, 2 to 32 processes sharing one SQLite file | 0 |
| Late write from a paused holder | rejected |
| Lease database after its holder is killed with SIGKILL while holding the lease | intact |
| Lease decisions per second under contention, 16 threads, in memory (Rust coordinator; counts every acquire attempt, about 95% of which were rejected, so this is not acquire-release cycles and not the Python vault, whose leases are SQLite transactions) | 1,307,225 |

## How it works

- **Encryption (Python).** Entry content is sealed with AES-256-GCM under a key derived by PBKDF2-HMAC-SHA256 with 600,000 iterations (`src/kibisis/crypto.py`). When the `sqlcipher3` dependency loads, SQLCipher also encrypts every page of the database file. If it does not load, the vault falls back to SQLite: content stays encrypted and bound to its entry, and the value digests in the journal and in tombstones are keyed, but categories, keys, metadata and the rest of the audit journal are stored in the clear, and a warning says so (`SQLiteMemoryVault.__init__` in `src/kibisis/vault.py`). Either way, a wrong passphrase is refused when the vault opens. An on-disk vault refuses to open without a passphrase unless opened with `allow_plaintext=True`.
- **Scopes and integrity.** Every memory belongs to a scope and carries an HMAC-SHA256 signature over its scope, category, key and content. In a vault with a passphrase, the signing key comes from PBKDF2 (600,000 iterations), so a stored signature is no quicker to test passphrase guesses against than sealed content, and sealed content is bound to its entry as associated data, so it cannot be moved under another entry's name. `search` and `list_entities` skip, and `get` refuses with `EntryIntegrityError`, a row whose signature is missing or does not verify, or whose sealed content was not sealed for it (`sign_entry`, `entry_aad` and `derive_integrity_keys` in `src/kibisis/crypto.py`, used in `src/kibisis/vault.py`). A vault without a passphrase has no secret to sign with, so there signatures only catch accidental damage.
- **Trust states and validity windows.** Each memory is a candidate, verified, disputed or revoked, and can carry valid-from and valid-until times. Search leaves out candidates, revoked memories and memories outside their validity window unless asked, and can return what was valid at a given time (`src/kibisis/models.py`, `search` in `src/kibisis/vault.py`). A write with `supersedes_key`, or `supersede()`, retires an earlier memory: it is marked revoked, its validity ends, and it links to its replacement. `review_entity` records a reviewer's verdict; a revocation tombstones the value. On writes that do not name a state, the vault runs `MemoryAdmissionGate` (`src/kibisis/admission.py`), a heuristic classifier that stores hedged or speculative text as a candidate; open the vault with `auto_gate=False` to turn it off.
- **Search.** `search` ranks results with BM25 (SQLite FTS5). By default it wants every word of the query; `match="any"` wants at least one and leaves out common words such as "what" and "the", for questions in natural language. With SQLCipher, a vault with a passphrase keeps a full-text index of entry content inside the encrypted file, so sealed entries rank as they would in a plaintext vault and only the top results are decrypted. Without SQLCipher no entry words are written to disk: search opens every entry to build an index in memory and builds it again after the vault changes, so its cost grows with the vault (`search` in `src/kibisis/vault.py`). `search_keys` takes the same arguments and returns only keys and scores, without opening (or decrypting) any entry, for callers that hold the text elsewhere; it does not check entry integrity, which `get` still does. Under SQLCipher, ranked search is several times slower with SQLCipher's `cipher_memory_security` on, which kibisis does by default (`memory_security=True`); it is a process-wide setting that wipes memory SQLite frees. Pages read from outside SQLite's page cache are decrypted again, so give a large SQLCipher vault a cache that holds it (`cache_mb`).
- **Tombstones.** `tombstone` records a value's SHA-256 digest and the digest of its canonical form (Unicode compatibility folding, case folding, invisible characters and punctuation removed, whitespace collapsed), then deletes every copy of the value in the scope. In a vault with a passphrase both digests are stored keyed (HMAC-SHA256 under a key derived from the passphrase), so they do not reveal short values such as codes or PINs. Afterwards the value is refused under any category or key in that scope, and `import_snapshot` will not restore it (`src/kibisis/vault.py`; the Rust vault in `src/lib.rs` matches values the same way). A snapshot carries each tombstone's digests sealed, so the tombstone also applies when the snapshot is imported into another vault opened with the same passphrase.
- **Audit journal.** Every put, archive, tombstone and purge appends a SHA-256 hash-chained event in the same database transaction as the change, so a change cannot land without its event; in a vault with a passphrase, the value digest it records is keyed, like a tombstone's. A write refused because its value is tombstoned, from the API or a snapshot import, is journaled as a `refuse` event, and so is an MCP call refused for its scope or trust arguments. `verify_audit_chain` re-checks the chain (`_record_audit_event` in `src/kibisis/vault.py`).
- **Leases.** `SQLiteLeaseCoordinator` (`src/kibisis/lease.py`), the Rust `InMemoryLeaseCoordinator` (`src/lib.rs`) and the Rust `FileLeaseCoordinator` (`src/file_lease.rs`) grant time-limited leases with increasing fencing tokens, and `validate_fencing_token` on the SQLite and file coordinators checks a token. `FileLeaseCoordinator` keeps each resource's lease in a small file and holds an operating-system lock on a companion lock file for every read-decide-write, so processes that open the same directory share one lease table. A damaged state file is reported as an error; it never resets the token. A Python vault opened with `coordinator=` and `enforce_fencing=True` checks the caller's token on every write while it holds its write lock, and refuses a missing, stale or expired token with `LeaseConflictError` before anything changes (`_fence` in `src/kibisis/vault.py`).
- **MCP server.** `python -m kibisis.mcp_server` (`src/kibisis/mcp_server.py`, settings in `src/kibisis/config.py`) serves one scope, fixed at startup, and refuses and journals calls that name another scope or try to set a trust state or an identity. It stores writes as candidates by `mcp-agent`; they cannot replace a reviewed entry, and a supersession of one waits as a proposal until a person approves. Recall comes back inside a `<kibisis-recall>` envelope with stored text escaped, each entry labeled with its state and author; candidates are included unless `include_candidates` is false, and recall wants any of the query's words unless `match` is `all`. Forget deletes the entry, tombstones its value, and rebuilds the search index, truncates the write-ahead log and vacuums the file. People review candidates with `python -m kibisis.review` (`src/kibisis/review.py`).

## Limits

- **Alpha release:** APIs will change before 1.0.
- **Platforms:** CI tests the Python package on Linux and macOS (arm64). Windows is not tested.
- **Encryption scope:** In the Python package, entry content is always encrypted unless the vault is opened with `allow_plaintext=True`; whole-file encryption needs SQLCipher (see above). With SQLCipher, the search index also holds each entry's words and their positions, protected by SQLCipher's encryption of the file rather than by the entry's own seal. The Rust crate keeps memories in RAM and neither encrypts nor persists them.
- **Tombstones:** They stop exact and look-alike repeats of a value, not paraphrases. A tombstone covers one scope; tombstone with `scope="*"` to forget a value in every scope.
- **Scopes:** A library caller names the scope. Kibisis keeps scopes apart but does not decide which caller may use which scope. The MCP server serves only the scope it was started with.
- **Review:** `python -m kibisis.review` records the operating-system user name (or `--reviewer`) as the reviewer. It is not an authentication boundary: anything that can run commands as that user can run it.
- **Fencing:** The Python vault checks fencing tokens only when it is opened with `enforce_fencing=True` or a call passes a token. `migrate_plaintext`, which re-encrypts stored rows without changing them, and `adopt_unsigned_entries` take no token. The MCP server opens its vault without a coordinator, and the Rust vault does not check tokens. Storage outside Kibisis must compare tokens itself.
- **Lease coordination scope:** Leases coordinate threads in one process, or processes on one machine that share a local filesystem: through SQLite transactions in Python, or through operating-system file locks on a shared directory with the Rust `FileLeaseCoordinator`. They are not a distributed consensus service, and network filesystems are not supported.
- **TTL resolution:** The Rust coordinators track deadlines in whole seconds and round up, so a lease is held for at least its TTL and at most one second longer. The Python SQLite coordinator uses floating-point second timestamps.
- **Upgrade from 0.1.0a5 or earlier:** The first open with the passphrase upgrades the vault in one transaction: entries are re-sealed, bound to their entry, and re-signed; digests in the journal and in tombstones are keyed; the journal's hashes are recomputed; and a `migrate` event records the counts and the old chain head. It refuses to run under a wrong passphrase. Older versions cannot read an upgraded vault, so upgrade every process that opens it at the same time. An entry without a signature, in a vault that was not already SQLCipher-encrypted, cannot be told apart from a tampered one, so it is refused until `adopt_unsigned_entries()` accepts it; `integrity_status()` counts such entries. Tombstones in a snapshot from a vault with a different passphrase are not applied, and the import journals that.
- **Upgrade from 0.1.0a6 or earlier (search index):** The first open of a SQLCipher vault with its passphrase builds the search index by opening each entry once. Older versions keep working on the vault: triggers queue the rows they write, and the next search indexes them.
- **Not independently assessed:** No security review or certification has been completed. Designed for local and disconnected use.

## Security

Report a vulnerability to contact@perseuscomputing.com with `[SECURITY]` in the subject; please do not open a public issue. See the [security policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md) for response times.

## Links

- [telarch.ai/kibisis](https://telarch.ai/kibisis): overview and a live demo of the lease coordinator
- [Documentation (docs.rs)](https://docs.rs/kibisis)
- [Changelog](CHANGELOG.md)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
