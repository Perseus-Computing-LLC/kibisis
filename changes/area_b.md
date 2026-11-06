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
  `kibisis_native.verify_chain` exports; `tests/test_review_b_journal.py` feeds the same rows to both.
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
  replaces the original. A keyed vault (integrity format >= 2 or `kdf_salt` present) without a key check
  is refused. `integrity_format`, `kdf_salt`, `key_check`, the journal floor and anchoring and
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

## Not fixed

- `kibisis_native.verify_chain` takes whole-second timestamps only (the crate's `AuditEvent.timestamp` is
  `u64`, a pre-existing crate type), so a Python vault's journal (fractional timestamps) is verified by the
  Python `ChainVerifier`, which hashes through the crate's `event_hash_v3` and applies the same rules; the
  agreement test writes whole-second rows. Changing the crate type is an API change left to a release.
- Lock-file deletion (a second process locking a new inode while the first holds the old one) is documented
  as out of scope rather than detected.
