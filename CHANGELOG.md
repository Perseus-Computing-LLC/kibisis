# Changelog

All notable changes to `kibisis` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.9] - 2026-10-21

### Added
- Python: `SQLiteMemoryVault(..., cache_mb=N)` sets SQLite's page cache, in MiB. Under SQLCipher a page read from
  outside the cache is decrypted again, so ranked search over a vault larger than the cache slows down. On a
  97 MB SQLCipher vault (6,228 entries of one BEAM 10M conversation, `memory_security=False`), one-word
  `search_keys()` calls took 35.0 ms on average with the default cache, 10.8 ms with `cache_mb=64` and 2.6 ms
  with `cache_mb=512`; the same entries in a plaintext vault took 5.2 ms with the default cache. The default is
  unchanged.

## [0.1.0-alpha.8] - 2026-10-21

### Added
- Python: `search_keys()` returns the keys and BM25 scores of the entries that `search()` returns for the same
  arguments, filters and tenant, principal and lineage bounds, as `SearchHit` items, without opening any
  entry: nothing is decrypted and no snippet is built. Because it opens no entry, it checks no entry's
  integrity; `get()` still refuses an entry that fails its check. In a synthetic test (20,000 entries of 60
  words, one-word queries, 400 results each) it took 19.8 ms a query where `search()` took 35.3 ms under
  SQLCipher, and 2.7 ms against 7.4 ms in a plaintext vault.
- Python: `SQLiteMemoryVault(..., memory_security=False)` does not turn on SQLCipher's
  `cipher_memory_security`, which wipes the memory SQLite frees. The default stays `True`. The setting is
  process-wide in SQLCipher and slows ranked search over sealed entries: in the same test `search_keys()`
  took 9.2 ms a query with it off and `search()` 21.0 ms.

### Changed
- Python: `search()` checks the tenant, principal and lineage bounds on each entry's stored metadata before
  it opens the entry, so entries outside them are no longer decrypted. Results are unchanged.

## [0.1.0-alpha.7] - 2026-10-21

### Added
- Python: ranked search over sealed entries. With SQLCipher, a vault with a passphrase keeps a contentless
  FTS5 index (`entities_search`) of entry content inside the encrypted file, ranks sealed entries by BM25
  with the scores a plaintext vault gives the same entries, and decrypts only the results it returns.
  Without SQLCipher, search builds an FTS5 index of the opened entries in memory, never on disk, and builds
  it again after the vault changes.
- Python: `search(..., match="any")` finds entries with any of the query's words and leaves out common
  words, for questions in natural language. The MCP server's `kibisis_recall` takes `match` (`any`, the
  default, or `all`).

### Changed
- Python: search over sealed entries follows the word rules of plaintext search, where a word also matches
  longer words that start with it. It used to match substrings of entry text, in storage order, each with
  a score of -0.5. Results with equal scores now come in entry order.
- Python: the first open of a SQLCipher vault with its passphrase builds the index by opening each entry
  once. Older versions keep working on the vault: triggers queue the rows they write, and the next search
  indexes them. `scrub()` also rebuilds the index from the entries, leaving no words of deleted entries.

### Fixed
- Python: search no longer runs its full-text query once for every entry in the scope. With a scope filter,
  SQLite could start from the entities index on scope (added in 0.1.0-alpha.5) and evaluate the query row by
  row: an eight-word query over 2,000 entries took about 0.4 s, or 3.6 s under SQLCipher, against about 1 ms
  now. The full-text index now drives the join (`CROSS JOIN`).
- Python: under SQLCipher, a full-text query that SQLite rejects falls back to a substring match, as under
  SQLite (sqlcipher3 raises its own `OperationalError`, which search did not catch). Query words without a
  letter or digit are ignored.

## [0.1.0-alpha.6] - 2026-10-21

### Added
- Python: `SQLiteMemoryVault.integrity_status()` counts stored entries that reads refuse, `adopt_unsigned_entries()`
  signs entries that carry no signature after a person has checked them, `stored_digest()` gives the form in
  which the vault stores a value's digest, `integrity_upgrade` reports what an upgrade did, and
  `EntryIntegrityError` (a `PermissionError`) is raised for an entry that fails its integrity check.
- Rust: `FileLeaseCoordinator`, a lease coordinator for processes on one machine. Each resource's
  lease lives in a small state file in a shared directory, and every acquire, renew and release holds
  an operating-system lock on a companion lock file from reading the lease to writing its successor.
  New state is written to a temporary file and renamed into place. Fencing tokens never go backwards:
  a damaged state file, or one naming another resource, is an error rather than a fresh start. It
  follows the same rules as `InMemoryLeaseCoordinator` and adds `get_lease` and
  `validate_fencing_token`. Network filesystems are not supported.

### Changed
- Rust: the minimum supported Rust version is now 1.89 (was 1.85), for the standard library's file
  locks (`File::lock`). The crate still has no dependencies.
- Python: `CryptoEnvelopeProvider.encrypt` and `decrypt` take an `aad` keyword (associated data); a
  custom provider without it is refused when the vault opens. `EncryptedEnvelope` has a `binding` field.
- Python: snapshots are format 1.1. They record `digest_scheme`, `digest_key_id` and
  `unreadable_entity_count`, and each tombstone's `sealed_digests`.
- Python: the MCP forget response's `value_digest_prefix` is taken from the stored, keyed digest.
- Python: `migrate_plaintext` no longer seals an entry that fails its signature check.

### Security
- Python, when the `sqlcipher3` driver does not load (the file is plain SQLite; content stays sealed):
  - Sealed content is bound to its entry (AES-GCM associated data: scope, category and key), and a
    vault with a passphrase refuses an entry without a signature. Before, an entry whose signature was
    removed skipped the check, so sealed content copied under another entry's name was returned.
  - The journal and tombstones store value digests keyed with a key derived from the passphrase.
    Before, they stored plain SHA-256, so short values such as codes, PINs and yes/no answers could be
    recovered by hashing every candidate.
  - Entry signatures use a key derived from the passphrase by PBKDF2 (600,000 iterations) and HKDF.
    Before, the key was one SHA-256 of the passphrase, so a known value and its signature let anyone
    test passphrase guesses about 51,000 times faster than PBKDF2 allows (measured on one core).
  - A wrong passphrase is refused when the vault opens; before, only SQLCipher refused it.
- Python: a vault written by 0.1.0a5 or earlier is upgraded on its first open with the passphrase, in
  one transaction: entries are re-sealed and re-signed, digests keyed, journal hashes recomputed, and a
  `migrate` event records the old chain head; then the file is vacuumed so the old digests are gone. It
  refuses to run under a wrong passphrase. Older versions cannot read an upgraded vault.

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
- Writes that name no state go through `MemoryAdmissionGate` in the Python vault: speculation and
  transient remarks are stored as candidates (transient ones valid for 24 hours), and other text is
  stored verified, as before. `SQLiteMemoryVault(auto_gate=False)` or `put(auto_gate=False)` turns
  the gate off.

### Added
- Supersession: `put` and `store` take `supersedes_key` (and `supersedes_category`), and
  `supersede()` writes a replacement in one call. The replaced entry is marked revoked, its validity
  ends, and the two are linked through `MemoryEntity.supersedes` and `superseded_by` (new columns,
  added when a vault is opened; 0.1.0a4 can still read and write such a file but does not keep the
  links). Each supersession is journaled.
- `search(active_only=True)`, the default, leaves out entries outside their validity window.
- `python -m kibisis.review` lists candidates and approves, disputes or rejects them, recording the
  operating-system user (or `--reviewer`) as the reviewer.
- `python -m kibisis.keys PATH` creates a key file with mode 0600.
- Console scripts `kibisis-mcp`, `kibisis-review` and `kibisis-keygen` for the three commands above.
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
