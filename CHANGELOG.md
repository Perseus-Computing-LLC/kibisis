# Changelog

All notable changes to `kibisis` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.5] - 2026-10-20

### Changed
- The MCP server serves one scope, fixed when it starts (`KIBISIS_SCOPE`, default `default`). Tools
  no longer take `scope`; a call that names another scope, `"*"` or an empty scope is refused, and the
  refusal is journaled.
- Writes through MCP are stored as `candidate` at most and recorded with author `mcp-agent`, whatever
  their content claims. `kibisis_remember` no longer takes `epistemic_state` or `auto_gate`; a call
  that sends them, or `author_id` or `reviewer_id`, is refused and journaled. Metadata from the model
  is stored under `agent_metadata`. An MCP write cannot replace an entry a person verified or
  reviewed, and a supersession of one is kept as a proposal that `review_entity` applies when a
  person approves the new entry.
- `kibisis_recall` returns entries inside a `<kibisis-recall>` envelope with their text escaped,
  instead of bare JSON. Each entry is labeled with its state and author. Candidates are included, so
  an agent's own writes still come back before review; `include_candidates=false` returns only
  reviewed entries.
- `kibisis_forget` deletes the entry and tombstones its value, then rebuilds the search index,
  truncates the write-ahead log and vacuums the file. Before, it only archived the entry, so the text
  stayed in the file and could be restated.
- The MCP server refuses to start without a key unless `KIBISIS_ALLOW_PLAINTEXT=1` is set. Before, it
  opened its vault unencrypted. Its default database moved from a fixed `/opt/data/...` path to the
  user data directory (`~/.local/share/kibisis/` on Linux, `~/Library/Application Support/kibisis/`
  on macOS, `%LOCALAPPDATA%\kibisis\` on Windows); `KIBISIS_DB_PATH` still overrides it.
- Tool errors no longer include a Python traceback.

### Added
- `python -m kibisis.review` lists candidates and approves, disputes or rejects them, recording the
  operating-system user (or `--reviewer`) as the reviewer.
- `python -m kibisis.keys PATH` creates a key file with mode 0600.
- `put(trust_ceiling="candidate")`, `record_refusal()`, `scrub()` and `ReviewedEntryError` in the
  Python vault; `kibisis.config` holds the settings the MCP server and review command share.
- A write refused because its value is tombstoned is journaled as a `refuse` event, from `put`,
  `store` and `import_snapshot`. Before, the refusal rolled back with the write and left no record.

### Removed
- The `kibisis_admit` MCP tool. It let an agent mark its own writes verified.
- The Rust crate's `CryptoEnvelope`, `EncryptedEnvelope`, `CryptoError` and `ZeroizingPassphrase`,
  and with them the `zeroize` dependency. The crate never implemented encryption; it keeps memory in
  RAM. Its description no longer says it is encrypted.

### Fixed
- The README said the vault does not run the admission gate on its own; it does, on writes that name
  no state, unless opened with `auto_gate=False`. Its measured table now matches telarch.ai/evidence:
  the kill test kills the lease holder with SIGKILL while it holds the lease (not mid-write), and the
  16-thread throughput is the v0.1.0-alpha.4 median.

## [0.1.0-alpha.4] - 2026-10-19

### Fixed
- `enforce_fencing=True` now takes effect. Before, the vault stored the flag and never checked a
  token. With it (it needs `coordinator=`), `put`, `store`, `put_batch`, `archive`, `purge`,
  `tombstone`, `admit_candidate`, `review_entity`, `set_persona_slot` and `import_snapshot` take
  `fencing_token`, `resource` and an optional `holder_id`. A missing, stale or expired token raises
  `LeaseConflictError` and changes nothing: no entry, tombstone or audit event. The vault checks the
  token after taking its write lock (`BEGIN IMMEDIATE`), so a write that passes is ordered before
  any write by a later lease holder. Without the flag, a token is checked only when a call passes
  one. `enforce_fencing=True` without a coordinator raises `ValueError`.
- `put_batch`'s docstring said it used one transaction. Each item is written in its own
  transaction; the batch stops at the first failure and keeps the items before it.
- Tombstones match a value by its exact and canonical SHA-256 digests under every category and key
  in the scope (or every scope for a `"*"` tombstone). Before, a forgotten value was refused only
  under the category and key it was rejected at, so it came back under a new key. Python and Rust.
- Tombstoning a value also deletes the other copies of it in the scope, each journaled as a purge.
- `import_snapshot()` imports tombstones first and never removes them, refuses entities whose value
  is tombstoned, restores archived entities archived, and journals the purges `clear_existing`
  makes. `clear_existing=True` failed outright before (it deleted from a table that does not exist).
- `kibisis_admit` over MCP records reviewer `mcp-agent` instead of a caller-supplied reviewer id, and
  its description says it is not a human review. The ledger tool's description now says what it
  checks: a linear SHA-256 hash chain.
- `cargo fmt` formatting (CI failed `cargo fmt --check` at v0.1.0-alpha.3).
- A vault opened with a passphrase on a system without `sqlcipher3` can be opened again. The second
  open tried to convert the plain SQLite file with `sqlcipher_export()`, which only SQLCipher has, and
  failed. Without `sqlcipher3`, entry content is still sealed but categories, keys and metadata are
  stored in plain text, and a warning says so. The first open with `sqlcipher3` converts the file.

### Added
- `TombstonedValueError`, a `ValueError` subclass raised when a write carries a tombstoned value.
- Tests named after the agent-memory-atlas acceptance tests they cover, in
  `tests/test_atlas_acceptance.py` and `src/lib.rs`, plus a test that every put, archive, tombstone
  and purge fails closed when the audit journal is unwritable.
- Release workflow: builds and attests the sdist, wheel and crate, installs the wheel with its
  dependencies on Ubuntu and macOS arm64, creates a GitHub release naming the commit, and publishes
  to PyPI and crates.io by trusted publishing from protected environments.

### Changed
- CI tests the Python package on Ubuntu and macOS arm64. Windows is no longer in the matrix: at
  v0.1.0-alpha.3 its job never got past the wheel step (a PowerShell glob), and once that was fixed,
  three tests failed there on POSIX file permissions and temporary-file locking. Windows is not tested.
- The Python dependency is `sqlcipher3>=0.5`, which ships wheels for macOS arm64. 0.1.0a2 on PyPI
  required `sqlcipher3-binary`, which has Linux wheels only.

## [0.1.0-alpha.3] - 2026-10-18

### Added
- Multi-process SQLiteLeaseCoordinator support with WAL mode and BEGIN IMMEDIATE atomic transactions.
- Zeroizing passphrase memory security via `zeroize`.
- SQLCipher full-page encryption with PBKDF2-HMAC-SHA256 (600,000 iterations).
- A TLA+ specification of the lease state machine and fencing tokens. Correction: it is in
  telarch-benchmarks (`spec/kibisis_lease_fencing.tla`), not in this repository.
- MSRV enforcement for `rust-version = "1.85"` in `Cargo.toml`.

### Changed
- Standardized clippy warnings with zero warnings under `-D warnings`.
- Documented whole-second TTL rounding in the in-process Rust coordinator.
- Corrected Python dependencies to include `pydantic`, `cryptography`, and `sqlcipher3-binary`.

## [0.1.0-alpha.2] - 2026-10-13

### Added
- Initial public release of Kibisis memory vault and atomic SWMR lease coordinator.
- Bi-temporal valid-time indexing and human review candidate admission lifecycle.
