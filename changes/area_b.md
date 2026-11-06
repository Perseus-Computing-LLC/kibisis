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
  journal head, a tombstone MAC, a format 3 journal row, an entry sealed with its binding; round 3: the
  binding is read from the envelope text whatever `is_encrypted` says; round 4: replaced by
  `_refuse_unless_genuine_a5`, see Round 4). The journal
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

## Round 3

Third-pass A+B seam findings in `review_notes/R3_AB.md`; regression tests in
`tests/test_review3_ab_migration.py` (the `test_attack_*` names are kept; each now asserts the fixed
behaviour; the R3-AB4 one is skipped until `fix/round3-entry` merges).

### Security

- **R3-AB2 (high): the a5 discriminator's entry witness no longer depends on `is_encrypted`.**
  `_format_2_artefacts` tests `encrypted_envelope_json LIKE '%"binding":…%'` on every row, so flipping
  the integer column to 0 (envelope untouched) no longer removes the witness; the R2-B1 reset is refused
  and nothing is written (no head, key check or meta MAC). `_migrate_integrity` itself also refuses
  (`VaultIntegrityError`): any row marked plaintext that carries an envelope (an a5 file wrote the two
  together); a keyed vault (salt present) whose journal records entries put and never purged / tombstoned
  while the entity table is empty (the `DELETE FROM entities` variant); and, when a salt is present, a
  format 1 chain head that verifies only under the path-derived key (the passphrase's legacy key alone is
  tried; the path key stays for a vault that never had a passphrase). The genuine a5 fixture still
  migrates, read-only and writable, idempotently.

### Round 6

Review `review_notes/R6.md`. Repro suite `tests/review6_keyless.py` → `tests/test_review6_keyless.py`
(collected; the seven `test_attack_*` are now `test_fixed_r6_*` asserting the fix; 42 tests).

### Fixed

- **R6-1 / R6-1b (low)** the salt-absent gate is on any content, not on rows alone.
  `_refuse_unadopted_keyless_rows` (via `_keyless_content()`) counts entity rows, tombstone rows,
  `audit_journal` events and `vault_meta` keys a first keyed open does not write itself
  (`_INIT_META_KEYS`: `kdf_salt`, `integrity_format`, `key_check`, `meta_mac`). A keyless file with a
  journal and no entries is refused with or without the opt-in ("a keyless file with a journal and no
  entries is not adoptable"), bytes unchanged, both modes; `_migrate_integrity` repeats the rule so no
  caller order chains such a journal under the signed head. A keyless file with only `vault_meta`
  records (a planted `verification_quorum`, say) is refused without the opt-in; with it the `migrate`
  event records `empty_keyless_file: true` and `vault_meta_keys_adopted`. When rows are adopted the
  file's journal is chained under the signed head and the `migrate` event (and `keyless_adoption()`,
  key `events`) records `journal_events_adopted_from_keyless_vault`. A SQLite file that holds tables
  but no `entities` table (another program's database, or a vault whose table was dropped beside a
  planted journal) is refused by the writable keyed open too (`_refuse_foreign_database` in `_connect`,
  before `PRAGMA journal_mode` touches the header; `ValueError` "not a kibisis vault"); an empty file
  (no tables) is still a fresh vault.
- **R6-2 / R6-2b (low)** `_demote_adopted_row` re-derives an adopted row as `_put` stores a
  model-origin write: `epistemic_state = candidate`, `origin_class = agent`, `act_class = inform`,
  `origin = model`, every key `_put` refuses from a payload dropped through the same
  `vault._reserved_metadata_keys` (the module's `RESERVED_METADATA_KEYS` plus the `lineage_*` prefix),
  every `PRINCIPAL_METADATA_KEYS` key (`author_id`, `supersession`, `proposed_supersedes`, `slot`,
  `last_verified_at`) moved under `agent_metadata` as `_put` moves it for an agent, the
  `supersedes`/`superseded_by` columns and their metadata mirrors (`_SUPERSESSION_METADATA_KEYS`)
  cleared. The stamp `adopted_from_keyless_file` records `stored_state`, `stored_origin`,
  `dropped_metadata_keys`, `moved_under_agent_metadata` and `supersession_cleared`. A forged
  principal-class row no longer refuses an agent's later write (K-R1) nor a forged `superseded_by`
  (K-R2), and a person's verdict on it yields an agent-class `inform` entry, never `principal`/`act`.
- **R6-3 (low)** a read-only open with `adopt_keyless=True` on a keyless file serves the rows demoted
  exactly as the writable adoption stores them: `_adopt_keyless_in_memory` copies the file into a
  private in-memory connection (`Connection.backup`) and runs `_demote_adopted_row` on every row; the
  file is byte for byte unchanged and `keyless_adoption()` reports the in-memory adoption with
  `sequence: None`. The forged `verified` state is never served.
- **Docs** SECURITY.md ("the second door" and the salt-removal bullet), the constructor docstring, the
  `_refuse_unadopted_keyless_rows` and `_demote_adopted_row` docstrings and `config.open_vault` now
  say what the code does: any content gates the open; the demotion is the model-origin `put` shape;
  read-only demotes in memory; a journal with no rows is not adoptable.

### Changed behaviour callers may notice

- `keyless_adoption()` carries `events` (journal events chained on the file's word) and, for a
  read-only in-memory adoption, `sequence: None`. `kibisis_health.keyless_adoption` adds
  `journal_events`.
- Adopted rows come back with `origin == "model"`, `origin_class == "agent"` and their `author_id`
  under `agent_metadata`, as an agent's own write would.

### Round 5

Review `review_notes/R5.md` (091c218). Repro suite `tests/review5_discriminator.py` →
`tests/test_review5_discriminator.py` (collected; the four `test_attack_*` are now `test_fixed_r5_*`
asserting the fix; 99 tests).

### Fixed

- **R5-1 (high)** the salt-absent door. A keyed vault whose whole `vault_meta` (salt included) was
  deleted and whose rows were flattened to plaintext read as "never keyed" and the first keyed open
  adopted every row as a signed entry in the writer's `epistemic_state`. Now (a) adoption is never
  silent or trusting: `_migrate_integrity` makes every adopted row a `candidate` via
  `_demote_adopted_row` (drops `human_reviews`, `attestations`, `verification_pending`,
  `act_class_capped_from`, `trust_inherited_from`, `last_verified_at`; stamps
  `adopted_from_keyless_file`), a tombstone row in a keyless file refuses the open outright, the
  `migrate` event keeps `entries_adopted_from_keyless_vault`, and `SQLiteMemoryVault.keyless_adoption()`
  reports the latest migration's count/date for `health` (MCP `kibisis_health.keyless_adoption`) and
  `review list` ("N entries adopted from a keyless file on <date> …"); (b) the keyed open of a
  salt-less file WITH rows needs the constructor kwarg `adopt_keyless=True` (default False; also on
  `config.open_vault`), read-only or writable, else `VaultIntegrityError` "this file has N plaintext
  entries and no salt; a keyed vault whose records were removed looks the same; pass adopt_keyless=True
  to adopt them as candidates" — checked by `_refuse_unadopted_keyless_rows` before `_init_schema`, so
  the refused file is untouched. A salt-less file with no rows and no tombstones is a fresh vault. The
  CLI flag is in area C. (c) `_refuse_unless_genuine_a5` docstring, `_migrate_integrity` docstring and
  SECURITY.md ("the second door", and the salt-removal bullet) now describe both doors.
- **R5-2 (low-med)** "empty vault" means empty: with no entity row and `kdf_salt` present the a5
  discriminator refuses when `rejected_value_tombstones` has any row or the journal any event
  (witnesses "an entity table that is empty beside N tombstone rows" / "… beside a journal of N events,
  first '<action>' on …"). The admitted empty reset's migration writes a `migrate` event with
  `empty_keyed_file: true` and zero counts, so it is told from a vault created fresh.
- **R5-3 (low)** `_refuse_keyed_records_without_salt` also refuses when any entity row has
  `is_encrypted != 0` or a non-empty envelope ("N sealed entries … but vault_meta holds no kdf_salt; the
  vault's salt was removed"), and runs before `_init_schema` in the writable open: no fresh salt, no
  schema upgrade, bytes and mtime unchanged on the refused file (asserted).
- **Minor** `integrity_format` is read through `_integrity_format_record()`: a non-integer value is a
  `VaultIntegrityError` naming it, not a `ValueError` from `int()`. `_A5_FOREIGN_META` now lists every
  `vault_meta` key the current code writes that a5 never wrote: `term_index_format`,
  `search_index_format`, `quorum_dropped_from` added.

### Changed behaviour callers may notice

- Giving a passphrase to a plaintext vault that holds entries now needs `adopt_keyless=True`, and the
  adopted entries come back as `candidate` (not served by `list_entities()` by default) until a person
  reviews them. Existing tests that did this were updated accordingly.
- A keyed a5-era file carrying `term_index_format` (a key a5 never wrote) is refused by the a5
  discriminator; genuine a5 files do not carry it.
- The empty keyed reset now leaves one `migrate` event in the journal.

## Not fixed

- A reset that also rewrites the journal headless **and** removes every entry and every `put` row is
  indistinguishable from an empty a5 file; that is the file writer deleting the vault (out of scope).
- **R3-AB4** is fixed on `fix/round3-entry` (`_verify_meta_mac`, `_persist_verification_quorum`).

## Round 4

Fourth-pass findings in `review_notes/R4.md`; regression tests in `tests/test_review4_r3fixes.py`
(the `test_attack_*` names are kept; each asserts the fixed behaviour; the controls are unchanged).

### Security

- **R4-1 (high): the format 1 migration class is closed by one discriminator, not one more witness.**
  R2-B1 → R3-AB2 → R4-1 were one attack: scrub whichever witness the last fix added and re-enter
  `_migrate_integrity`, which authenticates nothing and signs what it finds. `_format_2_artefacts` and the
  two checks inside `_migrate_integrity` are replaced by `_refuse_unless_genuine_a5` (`_vault_crypto.py`),
  run in every writable open with a passphrase on the connection BEFORE `_init_schema` (which used to add
  the `audit_head` table and the `format` / `tombstone_mac` columns before anything looked). With
  `kdf_salt` present and no `key_check`, the migration is allowed only when
  every witness is absent: table `audit_head`; column `audit_journal.format`; column
  `rejected_value_tombstones.tombstone_mac`; `vault_meta` `key_check` / `meta_mac` / `journal_format_floor`
  / `journal_anchored` / `verification_quorum`, or `integrity_format` ≥ 2; an entity row with
  `is_encrypted != 1`; a NULL, empty or malformed envelope; an envelope with the format 2 binding (in its
  text, or one whose ciphertext opens only under the binding's associated data); a sealed envelope that
  does not open under the passphrase the way a5 sealed it (no sealed row opening at all is `ValueError`,
  a wrong passphrase); an
  empty entity table while the journal holds unpurged `put`/`update` events. Any one witness is a
  `VaultIntegrityError` naming all of them, nothing written. `_upgrade_integrity` refuses the migration
  outright when the discriminator did not run. The migration's chain check is kept as necessary, never
  sufficient (a headless format 1 chain has no keyed element). Table-driven test
  (`test_attack_every_single_witness_scrub_and_the_full_scrub_are_refused`) enumerates every single-witness
  scrub and the all-witnesses scrub on a vault that was keyed; the genuine a5 fixture still migrates,
  re-opens read-only, and its chain verifies (`test_control_a5_fixture_full_lifecycle`). SECURITY.md now
  states the one reset the discriminator cannot tell from an a5 file ("headless journal + no entry event
  + no sealed entry" = an empty vault) and what the operator sees.
- **R4-3 (low)** `_check_tombstones`: a legacy `tombstone_lifted` event whose `metadata.tombstone_scope`
  differs from the event's scope also pops `(category, key, digest, tombstone_scope)` regardless of the
  `metadata.tombstone` name test, so a pre-fix lift of a global `'*'` row by a write under the same
  `category:key` reconciles instead of wedging both open modes.

### Recorded

- **R4-4** `import_snapshot(origin=None)` is principal; docstring and SECURITY.md say a library caller
  relaying a file from an agent must pass the agent's `origin`.

### Changed behaviour callers may notice

- A keyed format 1 file with any row left plaintext, undecryptable or malformed is now refused as a
  whole (`VaultIntegrityError`) instead of migrated with `entries_undecryptable > 0`; a5 sealed every
  entry, so no genuine a5 file changes behaviour.
- Error texts: "marked plaintext but carry a sealed envelope" → "marked plaintext (is_encrypted != 1)";
  "the entity table is empty" → "an entity table that is empty while the journal records …".

## Not fixed

- `kibisis_native.verify_chain` takes whole-second timestamps only (the crate's `AuditEvent.timestamp` is
  `u64`, a pre-existing crate type), so a Python vault's journal (fractional timestamps) is verified by the
  Python `ChainVerifier`, which hashes through the crate's `event_hash_v3` and applies the same rules; the
  agreement test writes whole-second rows. Changing the crate type is an API change left to a release.
- Lock-file deletion (a second process locking a new inode while the first holds the old one) is documented
  as out of scope rather than detected.

## Round 7

### Security

- **Journal wipe laundered by the next append (R7-4, medium).** `_append` continued the chain from the
  journal's last ROW, never from the signed head, so a writer who emptied `audit_journal` (or dropped the
  table) and left the head was caught by `verify_audit_chain()` only until the next routine write, which
  started a fresh chain at sequence 1 and re-signed the head over it. Fixed: a keyed vault records the
  highest sequence it has signed a head for in `vault_meta.journal_high_water`, under the full-set meta
  MAC (`VAULT_META_BOUND_OPTIONAL`, so a vault written before this round keeps its MAC and gets the mark
  from its signed head at the next writable open; a read-only open verifies without writing; the legacy
  V1 key set never bound it, so under a legacy MAC it is unknown and set at the re-sign). Every
  `_write_audit_head` raises the mark. Before writing, `_append` requires the journal's last row to be
  the one the signed head names (sequence and hash) and the journal to reach the mark
  (`_refuse_discontinued_journal`); otherwise `VaultIntegrityError`, nothing written, head untouched.
  `verify_audit_chain()` (and so the open-time check) reports False when the journal ends below the
  mark, which also catches the rows-and-head wipe and a journal and head put back from an older copy,
  where no head contradicts the rows. The a5 fixture migration and the format-3 upgrade set the mark
  from the verified journal; a fresh vault sets it at its first append. `tests/test_threat_model_claims.py`
  now asserts the wipe-with-head-removed case refuses the next write and stays False on reopen;
  `tests/test_review7_final.py` (the round-7 review's `review7_final.py`, converted) pins all four wipe
  variants plus the mark's lifecycle. `tests/test_review_b_journal.py`'s two next-append tests now expect
  the refusal instead of a head re-signed over rewritten rows.
- **Adopted rows stayed plain on disk (R7-1, low).** Keyless adoption re-signed each adopted row with
  `encrypt=is_encrypted==1`, so in the no-SQLCipher mode the adopted text and its FTS words stayed in
  the clear inside a vault that now had a passphrase until `migrate_plaintext()` ran. The adoption
  transaction now seals every adopted row through the same `_write_sealed` a model-origin put uses
  (which also drops the plaintext's FTS words); the plaintext is absent from the raw file bytes
  afterwards, `migrate_plaintext()` finds nothing left, and the rows read and search back through the
  keyed path.
- **Planted policy records signed by the adoption (R7-3, low).** A `verification_quorum` or
  `quorum_dropped_from` row in a salt-less file was read as the vault's stored policy: above the default
  it was MAC-signed by the opt-in open with no notice; below it the open was refused by a `ConfigError`
  whose remedy was to set the env to the planted value, and the adoption had already committed the
  planted quorum under the MAC. Both are now dropped inside the adoption transaction (and, for the
  read-only in-memory adoption, in the private copy), logged at WARNING by name and value, exactly as
  the legacy-MAC re-sign path does (`_drop_keyless_policy_records`); a planted `journal_high_water` goes
  with them, since the head the adoption signs is the first anyone signed. SECURITY.md's adoption
  item, the quorum paragraph, the journal items and the "Without SQLCipher" table, and README's fencing
  line, now say what the code does, including that `tenant_id` is dropped on adoption so tenant-filtered
  recall sees adopted rows as tenant-less.
