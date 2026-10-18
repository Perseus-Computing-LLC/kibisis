# Changelog

All notable changes to `kibisis` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.3] - 2026-10-18

### Added
- Multi-process SQLiteLeaseCoordinator support with WAL mode and BEGIN IMMEDIATE atomic transactions.
- Zeroizing passphrase memory security via `zeroize`.
- SQLCipher full-page encryption with PBKDF2-HMAC-SHA256 (600,000 iterations).
- Formal TLA+ specification for lease state machine and monotonic fencing tokens.
- MSRV enforcement for `rust-version = "1.85"` in `Cargo.toml`.

### Changed
- Standardized clippy warnings with zero warnings under `-D warnings`.
- Documented whole-second TTL rounding in the in-process Rust coordinator.
- Corrected Python dependencies to include `pydantic`, `cryptography`, and `sqlcipher3-binary`.

## [0.1.0-alpha.2] - 2026-10-13

### Added
- Initial public release of Kibisis memory vault and atomic SWMR lease coordinator.
- Bi-temporal valid-time indexing and human review candidate admission lifecycle.
