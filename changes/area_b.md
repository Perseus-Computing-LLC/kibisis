# Area B changes (crypto, journal integrity, opening order, leases, Rust bindings)

Entries for CHANGELOG.md, to be merged by the parent. No version bump.

## Security

- **Journal format downgrade (F2).** A keyed vault pins the lowest journal format its journal holds
  (`vault_meta.journal_format_floor`) and whether the journal has ever held a row (`journal_anchored`),
  both under the meta MAC. `verify_audit_chain` refuses rows below the floor and demands a signed head
  once the journal has held a row, even with every row removed, so rewriting rows in the unkeyed
  format 1 layout and dropping the head no longer verifies. The verifier streams the journal in pages
  (the 1,000,000-row cap is gone) and sets `vault.last_chain_error`. Its rules are those of
  `kibisis::journal::verify_chain` (now also `verify_chain_with(.., head_required)`), which
  `kibisis_native.verify_chain` exports; `tests/test_review_b_journal.py` feeds the same rows (written
  with whole-second timestamps, the crate's type) to both.
- **Signed tombstone table (F4).** Integrity format 3: every `rejected_value_tombstones` row carries
  `tombstone_mac`, an HMAC under the signing key over scope, category, key and both digests, verified at
  open and on every `_find_tombstone` hit (`VaultIntegrityError` on an edited, planted or unsigned row).
  At open, every journaled `tombstone` event not undone by a `tombstone_lifted` event (an unknown action
  is a no-op) must still have its row, else the open is refused: deleting the row no longer readmits the
  value. Existing rows are signed during the upgrade to format 3.
- **Key check before anything is written (F13, F9, L4).** `vault_meta.key_check` is compared before any
  migration. For a plain SQLite file about to be converted to SQLCipher, the check runs against the plain
  file with stdlib `sqlite3` first; a wrong passphrase raises `Failed to authenticate` and leaves the file
  byte for byte as it was. The conversion writes a sibling temp file, opens it with the key, and only then
  replaces the original. A keyed vault (integrity format >= 2) without a key check is refused (Round 2
  extends this to any vault with a `kdf_salt`, below). `integrity_format`, `kdf_salt`, `key_check`, the journal floor and anchoring and
  `term_index_format` are bound under one HMAC (`vault_meta.meta_mac`); a keyed vault whose MAC is missing
  or wrong refuses to open (`VaultIntegrityError`). A vault claiming integrity format 1 while carrying a key
  check or meta MAC (records only format 2+ writes) is refused instead of re-migrated. A migration whose
  previous chain fails verification refuses instead of re-signing; the format 1 head is verified under the
  legacy key it was signed with.
- **Envelope salt and iteration count (L5).** A provider bound to a vault derives keys from the vault's
  `kdf_salt` at the fixed iteration count only; an envelope naming another salt is refused before any key
  derivation (an integrity failure for that row), and its iteration count is ignored. Every envelope a vault
  has written since 0.1.0a5 carries the vault salt, so stored rows still open. Tombstone digests imported
  from a snapshot of another vault go through `decrypt_foreign`, which honours the envelope's salt
  (that is the one legitimate foreign-salt case).
- **Silent drops are not silent (F14).** A row that fails its integrity check is left out of search,
  listing and snapshot export with a WARNING naming category and key, counted in
  `vault.integrity_failures` (`count` and the last ten `(category, key)`), and raises
  `EntryIntegrityError` when the vault was opened with `strict=True` (new constructor flag).
- **Plaintext fallback is opt-in (F15).** With a passphrase but no `sqlcipher3`, an on-disk vault is
  refused with `EncryptionRequiredError` (the message names what would lie in plain text) unless
  `allow_plaintext=True` or `KIBISIS_ALLOW_PLAINTEXT=1` (`config.open_vault` relays the flag). In-memory
  vaults are unaffected. `vault.encrypted_at_rest` reports whether SQLCipher is active; area C's
  `aml` log line should use it rather than passphrase presence.
- **Fencing tokens only go up (L7).** `FileLeaseCoordinator` keeps a per-resource `<digest>.highest` file,
  written atomically before the lease that carries the token; a grant is one above both the state file's
  token and that record, so deleting the state file or restoring an older copy cannot reissue a token. A
  damaged highest-token file is a `lease store:` error, never a reset. Deleting the `.highest` or `.lock`
  files is documented as out of scope.
- **Bindings (L6).** `kibisis_native.FileLeaseCoordinator` methods take `&self` over a mutex, so
  concurrent calls from several threads wait their turn instead of raising `RuntimeError: Already
  borrowed`; a `ttl_seconds` past `Duration`'s range is a `ValueError`, not a `PanicException`. No other
  PyO3-reachable panic was found (`sequence` out of u64 was already `OverflowError`).
- **Renew and validate agree.** A lease whose deadline second has arrived can neither be renewed nor fence a
  write (`renew` used `>=`, `validate_fencing_token` and `acquire` used `>`; all three now use `>`), in
  the in-memory and the file coordinator.

## Changed

- `INTEGRITY_FORMAT` is 3. The first open of a format 2 vault with its passphrase upgrades it in one
  transaction (journal verified under its old rule first; a journal that verified but has no head gets one
  for its last row). The `integrity_upgrade` report of a vault that held data adds `tombstones_signed` and
  `journal_format_floor`. Older versions cannot open an upgraded vault.
- New: `kibisis.VaultIntegrityError` (a `PermissionError`), `SQLiteMemoryVault(strict=...)`,
  `vault.integrity_failures`, `vault.last_chain_error`, `vault.encrypted_at_rest`,
  `kibisis._vault_audit.ChainVerifier` / `verify_journal_rows`, `kibisis_native.verify_chain`,
  `kibisis::journal::verify_chain_with`.
- `bindings/python/Cargo.toml`: `extension-module` is a default feature so `cargo test --no-default-features`
  (with `PYO3_PYTHON` and `LD_LIBRARY_PATH` pointing at an interpreter with a shared libpython) runs the
  crate's own tests; one test covers the TTL error path.
- Tests: `tests/review_b_*.py` became `tests/test_review_b_*.py` asserting the fixed behaviour; fallback-mode
  tests opt into plaintext; the legacy-row journal test verifies only under a floor of 2; deleting journal
  and head together is now asserted caught.

## Round 2

### Security

- **Format 1 migration no longer reachable on a keyed vault (R2-B1).** A vault with a `kdf_salt` is keyed
  whatever `integrity_format` says (edited to 1 or deleted). With the key check gone it is refused
  (`VaultIntegrityError`) unless it is a genuine 0.1.0a5 file: one holding none of what integrity format 2
  and later write (`_format_2_artefacts`: `meta_mac`, `journal_format_floor`, `journal_anchored`, a signed
  journal head, a tombstone MAC, a format 3 journal row, an entry sealed with its binding). The journal
  floor and anchoring are read whenever the vault is keyed, not only at integrity format 3, so a reset
  file is still held to the floor it recorded. Resetting `vault_meta`, blanking signatures, deleting the
  tombstone and re-chaining the journal as format 1 no longer launders through a re-migration.
- **Plain file authenticated before conversion, conversion adopted only after the upgrade (R2-B2).** A plain
  SQLite file with a salt but no key check (0.1.0a5) is authenticated against the plain file with stdlib
  `sqlite3` before anything is written: one of its sealed entries must open under the passphrase (or,
  with none sealed, a format 1 signature must verify). A wrong passphrase raises `Failed to authenticate`
  and leaves the file byte for byte as it was; the right one still opens it afterwards. The SQLCipher copy
  (`<path>.tmp_enc`) is now opened, authenticated and upgraded first and replaces the plain file only
  then (`os.replace`); any failure removes the copy and leaves the plain file.
- **Imported tombstones are journaled (R2-B3).** `import_snapshot` records a `tombstone` event
  (`metadata.path = "import_snapshot"`, `origin_class`) for every row it inserts, in the same
  transaction, so `_check_tombstones` reconciles it and a deleted row refuses the next open.
- **`verification_quorum` under the meta MAC (R2-B4).** `VAULT_META_BOUND_KEYS` gains `verification_quorum`;
  the MAC is rewritten whenever the stored quorum changes. A vault whose MAC was written over the legacy
  key set (`VAULT_META_BOUND_KEYS_V1`) opens once and is re-signed at the first writable open (read-only
  accepts it as it is); until then the stored quorum is not covered.
- **Salt removal refused (R2-B5).** A file whose `vault_meta` carries `key_check`, `meta_mac` or an
  `integrity_format` of 2 or more but no `kdf_salt` is refused by the read-only open (it was read as a
  plaintext vault with a path-derived signing key) and by the writable open (it was given a fresh salt
  before the key check failed); no salt is written.
- **`forget_requests` honours strict and counts (R2-B6).** An entry that fails its integrity check is
  counted in `integrity_failures` and raises under `strict=True`, as on the other read paths.
- **`strict=True` and the open (R2-B7).** Building or catching up the entry index at open no longer
  raises for a failing row: it is logged, counted, kept out of the index and left queued, and the first
  read through the index raises. `_index_queued(at_open=True)`, `_unindex_entry(keep_queued=True)`.
- **Verifier agreement (R2-B8, R2-B9).** The Python verifier refuses a journal row whose format is above
  `JOURNAL_FORMAT`, as the crate does (`UnsupportedFormat`), instead of hashing it as format 3; a row
  whose `metadata_json` is not JSON makes `verify_audit_chain` return False with `last_chain_error` set
  instead of raising.
- SECURITY.md no longer says the two verifiers agree on every row (whole-second, compact-metadata rows),
  that imported tombstones are reconciled (they are now), that the key check gates every conversion (the
  a5 path authenticates through an entry), or that `strict` only affects reads.

### Tests

- `tests/review2_b_*.py` became `tests/test_review2_b_*.py` asserting the fixed behaviour; the
  fixture-based test opens `vault-0.1.0a5-fallback.sqlite` with a wrong passphrase and checks the bytes.

## Not fixed

- `kibisis_native.verify_chain` takes whole-second timestamps only (the crate's `AuditEvent.timestamp` is
  `u64`, a pre-existing crate type), so a Python vault's journal (fractional timestamps) is verified by the
  Python `ChainVerifier`, which hashes through the crate's `event_hash_v3` and applies the same rules; the
  agreement test writes whole-second rows. Changing the crate type is an API change left to a release.
- Lock-file deletion (a second process locking a new inode while the first holds the old one) is documented
  as out of scope rather than detected.
