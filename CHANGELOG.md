# Changelog

All notable changes to `kibisis` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.4] - Unreleased

### Fixed
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
