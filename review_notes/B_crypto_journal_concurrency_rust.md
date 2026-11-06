# AREA B review — crypto, journal integrity, concurrency/leases, Rust crate + PyO3 bindings

kibisis v0.1.0-alpha.16, worktree `/opt/data/cache/scratch/kib-review` at `1299c2859eb96c54bba7e34455a8ce9640ba1f2a`.
Rust at this tag is byte-identical to alpha.15; the venv's `kibisis_native` 0.1.0a15 is code-equivalent.

## 1. Restatement

Review the project's own crypto (entry sealing, key derivation, key check), audit-journal integrity (hash chain + head MAC, format-3 via `kibisis_native`), concurrency (`_write_tx`, fencing, `file_lease.rs`) and the Rust crate / PyO3 boundary for correctness defects, at the maintainers' request.
Evidence is three existing test files (`tests/review_b_crypto.py`, `review_b_journal.py`, `review_b_native.py`, 54 tests) plus one new file (`tests/review_b2_misc.py`, 4 tests) and code reading of the remaining checklist.
Nothing in `src/` was modified; every demonstration is reproducible with the commands in §6.

Threat-model vocabulary used below (SECURITY.md:33-38): **file writer** = read/write access to `vault.sqlite` (and `-wal/-shm`) *without* the passphrase; **passphrase holder** = someone who can open the vault legitimately. All Python demonstrations run the vault **without SQLCipher** (`_sqlcipher_available()` monkeypatched to False), which is the deployment SECURITY.md:63-65 says "everything below assumes".

## 2. Findings (most severe first)

### F1 — HIGH: opening a plain-SQLite vault with a *wrong* passphrase on a host that has `sqlcipher3` re-encrypts the file under the wrong passphrase before the key check runs; the right passphrase can no longer open it
- **Precondition:** none adversarial. A vault created where `sqlcipher3` was absent (plain file, sealed content) is later opened where it is present, with a typo'd passphrase. Also reachable by a file writer who cannot read the vault but can trigger an open (e.g. by swapping in a plain-SQLite file).
- **Where:** `src/kibisis/vault.py:311-323` (`_migrate_file_to_sqlcipher` runs at construction, keyed by the supplied passphrase, and `os.replace`s the original at `vault.py:481`); the passphrase is only checked afterwards in `_upgrade_integrity` → `_vault_crypto.py:283-285` (`key_check`). Order: convert (311-323) → connect (331) → `_upgrade_integrity` (362) → raise (348/285) with the file already replaced.
- **Problem:** one wrong passphrase converts the whole file to SQLCipher under that wrong passphrase, then raises "Failed to authenticate". Every later open fails: SQLCipher wants the wrong passphrase, `key_check` wants the right one. Recovery needs the wrong passphrase *and* a manual `sqlcipher_export` back to plain SQLite.
- **Repro:** `tests/review_b2_misc.py::test_attack_wrong_passphrase_with_sqlcipher_reencrypts_plain_vault_and_bricks_it`
  ```
  cd /opt/data/cache/scratch/kib-review && ARGUS_LEDGER_PATH=$TMPDIR/argus_b2.jsonl PYTHONPATH=src \
    /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider -s tests/review_b2_misc.py
  ```
  ACTUAL (excerpt):
  ```
  header after wrong-passphrase open: b'\x01\xfa/\xa0\x98m\xd1\xa6u\xd3j\xe6\xa3\x85\x90\xa8'
  2026-11-06 01:23:31.331: ERROR CORE sqlcipher_page_cipher: hmac check failed for pgno=1
  2026-11-06 01:23:31.331: ERROR CORE sqlite3Codec: error decrypting page 1 data: 1
  .
  4 passed in 1.17s
  ```
  (the header is no longer `SQLite format 3`; the subsequent open with the correct passphrase raises `ValueError: Failed to authenticate`).
- **Fix:** verify `vault_meta.key_check` against the plain file (open it read-only with stdlib `sqlite3`, derive keys from its `kdf_salt`) *before* converting; or convert to a sibling file and only `os.replace` after the first successful keyed open; keep the plain original until then.

### F2 — HIGH: a file writer without the passphrase can delete or edit journal rows undetectably by rewriting the remaining rows as journal format 1 and dropping `audit_head`; the next legitimate write signs the forged history
- **Precondition:** file writer (no passphrase). Vault without SQLCipher.
- **Where:** `src/kibisis/_vault_audit.py:222-236`. Rows are recomputed "under the layout they were written with" (`fmt=ev.format`, 225-228); format 1/2 hashes are unkeyed SHA-256 and the `format` column itself is not covered by any hash. `anchored = any(ev.format >= 3)` (234) and `if head is None: return not anchored` (235-236) mean a journal with no format-3 rows needs no head. Contrast `src/journal.rs:265-269`, where the Rust verifier refuses any row with `format != 3` — but Python never calls it (bindings expose only the hash functions, `bindings/python/src/lib.rs:222-232`).
- **Problem:** delete the `tombstone` event (or edit `author_id`, swap keys), re-chain with `_event_hash(..., fmt=1)`, set `format = 1`, delete `audit_head` → `verify_audit_chain()` is True. The next `remember()` appends a format-3 row and `_write_audit_head` (139, 155-160) signs a head over the forged chain, so it stays "verified" forever.
- **Repro:** `tests/review_b_journal.py::test_attack_format_downgrade_launders_middle_deletion` (line 119) and `::test_attack_format_downgrade_launders_payload_edit_and_reorder` (138).
  ```
  cd /opt/data/cache/scratch/kib-review && ARGUS_LEDGER_PATH=$TMPDIR/argus_b2.jsonl PYTHONPATH=src \
    /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/review_b_crypto.py tests/review_b_journal.py tests/review_b_native.py
  ```
  ACTUAL: `54 passed in 4.77s` (both attack tests pass = tampering undetected; with `-s` the first prints `verify_audit_chain after downgrade+deletion: True [...]` with no `tombstone` action and every `format == 1`, the second prints `head re-signed at sequence 5`).
- **Fix:** once `vault_meta.integrity_format >= 2` (or `_keyed`), refuse any row with `format < JOURNAL_FORMAT` and require a head regardless of row formats (mirror `journal.rs:265-269,284-286`); record the journal format floor in signed `vault_meta`.

### F3 — HIGH: deleting a `rejected_value_tombstones` row re-admits the forgotten value; `verify_audit_chain()` stays True
- **Precondition:** file writer (no passphrase). Vault without SQLCipher.
- **Where:** `_find_tombstone` (`src/kibisis/_vault_tombstone.py:55`) reads only the tombstone table; the table is unsigned and never reconciled with the journal's `tombstone` events (`_vault_audit.py:209-241` checks the journal against itself only, as SECURITY.md:78 admits for the entities table but not for tombstones).
- **Problem:** `DELETE FROM rejected_value_tombstones` and the exact value that was "forgotten" is accepted again by `remember()`.
- **Repro:** `tests/review_b_journal.py::test_attack_tombstone_row_deletion_readmits_value` (line 166); command as F2. ACTUAL: passes (value accepted; `verify_audit_chain() is True`).
- **Fix:** derive the active tombstone set from the (headed) journal at open, or HMAC each tombstone row under the signing key and refuse to open/put when a journaled tombstone has no row.

### F4 — MEDIUM: a one-cell edit of `vault_meta.integrity_format` makes the vault unopenable; with signatures blanked too, the forced re-migration launders a tampered journal and double-keys tombstone digests
- **Precondition:** file writer (no passphrase). Vault without SQLCipher.
- **Where:** `src/kibisis/_vault_crypto.py:281-283` runs `_migrate_integrity()` *before* the key check whenever `integrity_format < 2`; the migration checks `v2:` signatures as format 1 (`_vault_crypto.py:354-367`) and keys already-keyed digests again (`379-380`); `previous_chain_valid=False` is only logged.
- **Problem:** (a) `UPDATE vault_meta SET value='1' WHERE key='integrity_format'` → every open raises "Failed to authenticate" with the correct passphrase (DoS until hand-restored). (b) Additionally `UPDATE entities SET tenant_sig=NULL` → the open succeeds, rewrites the journal (minus whatever the attacker deleted), signs a fresh head, and the re-keyed tombstone digest no longer matches the value it protected, so the forgotten value is accepted.
- **Repro:** `tests/review_b_journal.py::test_attack_meta_integrity_format_edit_bricks_open` (186) and `::test_attack_meta_integrity_format_edit_plus_blank_sigs_resigns_journal` (199); command as F2. ACTUAL: both pass (`integrity_upgrade: {... 'journal_events_rekeyed': 4 ...}`, `verify_audit_chain() is True`, `remember("decision","k3c","fact number 3")` accepted).
- **Fix:** check `key_check` before any migration; bind `integrity_format` (and `kdf_salt`, `key_check`) in one HMAC under the signing key; make a migration whose previous chain fails verification refuse rather than re-sign.

### F5 — MEDIUM: a row whose signature fails is silently dropped from `search()`, `list_entities()` and the snapshot export — no exception, no log line
- **Precondition:** file writer (no passphrase), or any on-disk corruption.
- **Where:** `src/kibisis/_vault_crypto.py:217-225` (`_readable_content` returns None on `EntryIntegrityError`), consumed by `_vault_search.py:194-196`, `vault.py:1644-1646` and `_vault_search.py:842-844` (`continue`); `_vault_snapshot.py:68-71` counts it only as `unreadable_entity_count` (122). Only `get()` raises (`vault.py:1530`).
- **Problem:** one byte changed in `entities.tenant_sig` makes a memory vanish from recall with nothing reported anywhere: a targeted "forget this" by a file writer, indistinguishable from the entry never existing. (Behaviour matches SECURITY.md:47-48 "search leaves a failing row out", but silently.)
- **Repro:** `tests/review_b2_misc.py::test_attack_bad_signature_row_vanishes_silently_from_search_and_list`; command as F1. ACTUAL: `search -> ['a'] | list -> ['a'] | snapshot unreadable -> 1` / `log records mentioning integrity: []`.
- **Fix:** log at WARNING with category/key on every dropped row and expose a counter (`integrity_failures`) on the vault; optionally raise when `strict=True`.

### F6 — MEDIUM: with a passphrase but no `sqlcipher3`, the vault opens and writes a plain-SQLite file after a `logger.warning`; `allow_plaintext` is never consulted on this path
- **Precondition:** deployment detail (missing optional dependency), not an attacker.
- **Where:** `src/kibisis/vault.py:12-15` (`import sqlite3 as sqlcipher3` fallback), `:118-120`, `:305-310` (warning only), `:335-348` (`PRAGMA key`/`cipher_version` are no-ops on stdlib sqlite3; `_sqlcipher_active=False`). `config.plaintext_allowed()` (`config.py:130-133`) and `allow_plaintext` (`vault.py:279-283`) only gate the *no-passphrase* case.
- **Problem / what is plain on disk (confirmed by reading the file with stdlib `sqlite3`):** tables `audit_head, audit_journal, entities, entities_fts(+config/data/docsize/idx), entities_search_dirty, entities_terms, entities_terms_docs, rejected_value_tombstones, sqlite_sequence, vault_meta`. In `entities`: `category, key, scope, metadata_json, origin, epistemic_state, created_at/updated_at, version, archived, is_encrypted, encrypted_envelope_json (ciphertext+nonce+salt+iterations), tenant_sig`; `content` is empty for sealed rows. Whole `audit_journal` (`action, category, key, scope, author_id, metadata_json, timestamps, hashes`) and `audit_head` (incl. the MAC). Tombstone keyed digests, reason, author, scope, timestamp. `vault_meta` (`kdf_salt`, `key_check`, `integrity_format`, `term_index_format`). HMAC term tokens with positions (`entities_terms`: 14 tokens for two short entries). This matches SECURITY.md:92-95,174-177 — the finding is that the only signal is a log line a library user will not see, and the vault silently stays in that mode on every later open.
- **Repro:** `tests/review_b2_misc.py::test_attack_passphrase_without_sqlcipher_opens_plain_sqlite_with_only_a_log_warning`; command as F1. ACTUAL: `tables: [...14 tables...]`, `entity row (plain columns): {'category': 'decision', 'key': 'a', 'scope': 'default', 'metadata_json': '{"act_class": "inform", "origin_class": "principal"}', 'origin': 'user', 'epistemic_state': 'candidate', 'created_at': 1793928210.69, 'is_encrypted': 1, 'content': ''}`, `journal rows: [('put','decision','a','default',None), ('put','decision','b','default',None)]`, `term tokens: 14`.
- **Fix:** require an explicit opt-in (`allow_plaintext_metadata=True` or `KIBISIS_ALLOW_PLAINTEXT=1`) to open an on-disk vault with a passphrase when `_sqlcipher_available()` is False; or raise `EncryptionRequiredError` and let `config.open_vault` relay the env flag.

### F7 — LOW: removing `vault_meta.key_check` lets a wrong passphrase open the vault silently; writes under the wrong key then mix two key sets in one file
- **Precondition:** file writer (no passphrase). Vault without SQLCipher.
- **Where:** `_vault_crypto.py:283-285` (`if stored is not None and ...`): a missing key check is treated as "nothing to check".
- **Repro:** `tests/review_b_crypto.py::test_attack_key_check_deletion_lets_wrong_passphrase_open_silently` (140); command as F2. ACTUAL: passes (open succeeds; every read raises `EntryIntegrityError`; a write under the wrong key is stored; the real passphrase then refuses that row).
- **Fix:** when `integrity_format >= 2` (or `kdf_salt` exists) and `key_check` is absent, refuse to open.

### F8 — LOW (observation): per-row envelope salt/iterations are trusted before the GCM tag, so a file writer can make each read of a row cost a full PBKDF2
- **Where:** `src/kibisis/crypto.py:106-112` (salt and `iterations` read from the envelope, `_derive_key` before `AESGCM(...).decrypt`), bounded by `MAX_ITERATIONS`; 64-entry key cache (`crypto.py:63-64`) is defeated by > 64 distinct salts.
- **Repro:** `tests/review_b_crypto.py::test_attack_per_row_salt_forces_pbkdf2_per_read` (105). ACTUAL (`-s`): cold read of the salt-edited row is > 10× a warm read (hundreds of ms per row).
- **Fix:** ignore the envelope's salt/iterations and use the vault's `kdf_salt`/fixed iteration count (the control test at `review_b_crypto.py:72` shows every envelope already carries the vault salt).

### F9 — LOW: `kibisis_native.FileLeaseCoordinator.acquire/renew(ttl ≥ ~1.8e19)` panics across PyO3 (`PanicException`, a `BaseException`)
- **Where:** `bindings/python/src/lib.rs:31-38` (`Duration::from_secs_f64` after a finite/positive check only). The Python wrapper caps TTL at 86 400 s (`lease.py:34-43`), so only direct `kibisis_native` users reach it.
- **Repro:** `tests/review_b_native.py::test_attack_native_ttl_overflow_panics_across_pyo3` (102). ACTUAL: `native acquire(ttl=1e300) -> ('BaseException', 'PanicException', 'cannot convert float seconds to Duration: value is either too big or NaN')` (passes).
- **Fix:** `Duration::try_from_secs_f64(seconds).map_err(|e| PyValueError::new_err(e.to_string()))`.

### F10 — LOW: concurrent calls on one `kibisis_native.FileLeaseCoordinator` raise `RuntimeError: Already borrowed` instead of waiting
- **Where:** `bindings/python/src/lib.rs:124-148` (`&mut self` + `py.detach` while blocking on the OS lock). `kibisis.lease.FileLeaseCoordinator` serialises with an `RLock` (`lease.py:64-89`), so only direct native users see it.
- **Repro:** `tests/review_b_native.py::test_attack_native_coordinator_concurrent_mut_borrow_raises` (120). ACTUAL: `thread A: 1 | main B: RuntimeError: Already borrowed` (passes).
- **Fix:** take `&self` (the inner coordinator needs no `&mut`: every method locks a file) or wrap `inner` in a `Mutex`.

### F11 — LOW (documented in the crate, not in README): deleting a resource's `.lease` state file resets its fencing token to 1
- **Precondition:** write access to the lease directory (created `0o700`, files `0o600`: `file_lease.rs:73-86, 245-251`).
- **Where:** `src/file_lease.rs:171-183` (`None => 1`); disclosed at `file_lease.rs:34-39`. README.md:23 ("fencing tokens that only go up") and `src/lib.rs:10-12` carry no caveat.
- **Repro:** `tests/review_b2_misc.py::test_attack_deleting_lease_state_file_resets_fencing_token`; command as F1. ACTUAL: `tokens: 1 2 1`.
- **Fix:** keep a per-directory monotonic counter file (or embed the last token in the lock file, which "is never deleted") and refuse to go below it.

## 3. Suspected, unconfirmed

- **Lock-file deletion breaks mutual exclusion** (`file_lease.rs:117-127`): `lock()` opens-or-creates `<digest>.lock` on every call; if a non-holder unlinks it while A holds the flock on the old inode, B creates a fresh inode, locks it independently and both run the read-decide-write. `file_lease.rs:31` says "Lock files are never deleted" (by the crate). Not tested (needs a second process timed against the unlink); same owner-only precondition as F11.
- **`verify_audit_chain` silently caps at 1 000 000 rows** (`_vault_audit.py:219`): beyond that the head names a row outside the fetched slice and `head["sequence"] == events[-1].sequence` (241) is False forever — permanent "tampered" verdict for a large honest journal. Not exercised (cost).
- **Fencing without `holder_id` is token-only** (`vault.py:405-414`): any local process that reads the `.lease` file ("a lease is not a secret", `lease.py:59`) learns the current token and passes `_validate_fencing` without holding the lease. By design per README:131, but worth a line in SECURITY.md.
- **Clock skew** (`file_lease.rs:239-243`): all deadlines are wall-clock `SystemTime` seconds; a backward jump of N s extends every lease by N, a forward jump expires them early; `unwrap_or_default()` for a pre-1970 clock makes `now = 0` so every lease looks unexpired. Single-machine scope is documented (`file_lease.rs:8-9`), so only an NTP step on the one host matters. `renew` uses `>=` (`file_lease.rs:202`) while `validate_fencing_token` uses `>` (`:107`): at the exact expiry second a holder can renew a lease that validation already reports expired (one-second window, benign).
- **`lease.py:76-85` TOCTOU**: `renew` re-reads the lease via `get_lease` after dropping the Python lock; another process can only change it after expiry, so the stale `expires_at` copied back is at worst one second old.
- **Rust verifier unused from Python**: `journal::verify_chain` (strict about format, `journal.rs:252-310`) is not exported by the bindings, so the strict and lenient verifiers can disagree (root cause of F2). Not a defect in itself.

## 4. Documentation that overstates the code

| Quote | Where | Code fact |
|---|---|---|
| "`verify_audit_chain` … requires a head with a valid MAC that names the last row; a deleted tail, a deleted head with rows still present, or rows removed under a head fails." | SECURITY.md:52-54 | Rows removed under a head pass once the remaining rows are rewritten as format 1 and the head deleted (`_vault_audit.py:225-236`; F2). |
| "*Re-inserting a forgotten value.* Tombstones keep keyed digests … and `put`, restore and `import_snapshot` refuse a value whose digest matches" — listed under **In scope, caught** for the local file writer | SECURITY.md:42, 56-59 | The tombstone table is unsigned; deleting the row re-admits the value and the chain still verifies (F3). |
| "Every read checks the signature … and search leaves a failing row out" | SECURITY.md:47-48 | True, but the drop is silent: no log, no counter except the snapshot's `unreadable_entity_count` (F5). |
| "It refuses to run under a wrong passphrase." (the alpha.5 upgrade) | README.md:134 | The refusal comes from `key_check` *after* `_migrate_integrity` (`_vault_crypto.py:281-285`), and after the SQLCipher conversion (`vault.py:311-323`): a wrong passphrase first rewrites the file (F1, F4). |
| "Leases carry fencing tokens that only go up." | README.md:23; `src/lib.rs:10-12` | Deleting the state file resets to 1 (`file_lease.rs:171-183`, disclosed only at `file_lease.rs:34-39`; F11). |
| "An on-disk vault will not open without a passphrase unless you pass `allow_plaintext=True`." | SECURITY.md:19 | Accurate for *no* passphrase; with a passphrase and no `sqlcipher3` everything except content is plain and the only signal is a log warning (F6). SECURITY.md:171-177 does disclose the mode. |
| "A journal of every change … in the same transaction as the change." | README.md:22,116 | Confirmed for put/archive/tombstone/purge/review/import_snapshot (§5 below). `migrate_plaintext` (`_vault_crypto.py:127-146`) and `scrub` (`_vault_tombstone.py:287-320`) write no event, which README:131 acknowledges for the former only. |

## 5. Checklist items settled by code reading

**(4) Timing-safe comparisons.** All secret-bearing compares use `hmac.compare_digest`: entry signature `crypto.py:170` and `:196`; `key_check` `_vault_crypto.py:284`; journal row hash `_vault_audit.py:229`; head MAC `_vault_audit.py:237`; AML key `aml_adapter.py:497`; Rust head MAC and row hash `journal.rs:238-244, 276, 290-293` (`constant_time_eq`). Non-constant-time compares that are not secrets: `prev_hash`/`sequence` links (`_vault_audit.py:223, 241`; `journal.rs:259, 271, 305`), fencing token ints (`vault.py:409`; `file_lease.rs:105-107, 200-202, 216-218`). Term tokens are matched by SQL equality on an index (`_vault_search.py:573-589`) — inherent to an index lookup; the token is an HMAC, so equality leaks only "same word", which the index exists to reveal.

**(5) Journal atomicity.** `_record_audit_event` (`_vault_audit.py:99-139`) reads the head and inserts row + head inside the caller's transaction (it issues `BEGIN IMMEDIATE` itself if none is open, 117-118). Call sites inside a `_write_tx`: `_put` `vault.py:839` → events at `877, 1007, 1020, 1047, 1148` and state transitions `1058, 1159`; `record_refusal` `1373-1374`; `archive` `1544/1556`; `purge` `_vault_tombstone.py:35/43` and `_purge_value_copies:127`; `tombstone` `182/240`; `review_entity` → `_write_tx` at `_vault_review.py:395` → `_review_locked` (`416-465`, nested `_write_tx` at 454 yields the same transaction per `vault.py:449-451`), cascades at `235`; `admit` → `review_entity` (`302-343`); `set_persona_slot` → `put` (`vault.py:1650-1667`); `import_snapshot` `_vault_snapshot.py:197/237`; `_migrate_integrity` `_vault_crypto.py:313/411`; `adopt_unsigned_entries` `485/498`; OKF `import_bundle` → `vault.put` per concept (`okf/importer.py:405, 418`), each its own transaction (bundle not atomic; `put_batch` says so explicitly at `vault.py:1481-1483`). No mutation appends outside its row transaction. Not journaled at all: `migrate_plaintext`, `scrub` (both content-preserving).

**(6) Check-then-act.** `_put` performs no DB read before `_write_tx` (`vault.py:721-839`): tombstone gate, reviewed-entry check and fencing (`_fence`, 416-433) all run under `BEGIN IMMEDIATE`. `tombstone` reads the target under the lock (`_vault_tombstone.py:182-195`); quorum count is computed inside `_review_locked` (`_vault_review.py:474-483`). The remaining pre-checks outside a transaction are advisory and re-checked inside: OKF `is_tombstoned` / `_row_conflict` on a snapshot taken at `importer.py:~445` (`459-485`) before `vault.put`. No cross-connection race found cheaply; none demonstrated. **Fencing with the MCP server:** `mcp_server.py:354` opens the vault via `config.open_vault` (`config.py:136-149`) with no `coordinator` and `enforce_fencing=False`, and no MCP tool argument carries `fencing_token`; `_validate_fencing` returns at `vault.py:389-390` when both are None, so a stale (expired-lease) writer through the MCP server writes unconditionally — README.md:131 says so.

**(7) `file_lease.rs`.** TTL: `lease_deadline` (`lib.rs:1150-1153`) = `saturating_add` then round *up* to whole seconds (held ≥ ttl, ≤ ttl+1 s); tested by `an_expired_lease_goes_to_the_next_holder_with_a_higher_token` (`file_lease.rs:475-495`). Expiry recovery: a different holder may acquire once `expires_at <= now` (`:172`), token = old+1 with `checked_add` (`:178-181`, overflow → `Conflict`, never wrap). Release sets `expires_at = 0` and keeps the token (`:212-226`) so monotonicity survives restarts via the state file (`a_new_coordinator_on_the_same_directory_sees_the_same_leases`, `:497`); unreadable/foreign state files error rather than reset (`:286-337`, test `:520`). Deleted state file → token 1 (F11). Atomic replace via temp+rename+dir fsync (`:141-158`). Lock scope is one `.lock` per resource, held from read to rename (`:117-127, 168, 196, 213`). Clock: wall-clock seconds, see §3.

**(8) Rust panic/unsafe inventory (non-test code).** `src/lib.rs` (before `mod tests` at 1242), `src/journal.rs`, `src/file_lease.rs` (before 372) and `bindings/python/src/lib.rs`: **no `unsafe`, no `.unwrap()`, no `.expect(`, no `panic!`/`unreachable!`**. Every `.lock()` on a `Mutex` is followed by `.map_err(...)` or `if let Ok(...)` (`lib.rs:645, 654-660, 712-714, 726, 747, 778, 806, 834, 907, 921, 953, 984, 1016, 1045, 1115, 1164, 1205, 1227`); `file_lease.rs:125` is `File::lock` with `map_err`; `file_lease.rs:242` is `unwrap_or_default`. Test-only: `lib.rs:1761 .expect(...)`, `file_lease.rs:414, 633 panic!(...)`, and 130+ `.unwrap()` inside `#[cfg(test)]`. Reachable-from-Python panics: `Duration::from_secs_f64` at `bindings/python/src/lib.rs:37` (F9). `u64` arguments out of range raise `OverflowError` cleanly (`review_b_native.py:96-99`); lone surrogates raise `UnicodeEncodeError` (`:77-81`).

## 6. Test-suite gaps

- No test pins the journal-format floor (a format-3 vault should refuse format-1/2 rows) or that a headless journal fails once the vault is keyed (F2).
- No test reconciles `rejected_value_tombstones` with journal `tombstone` events (F3), nor covers `vault_meta` cells (`integrity_format`, `key_check`) against edits/deletion (F4, F7).
- No test asserts that `_readable_content` drops are reported (F5), nor that a passphrase-without-SQLCipher open is anything more than a warning (F6).
- No test of the SQLCipher conversion path with a wrong passphrase (F1); the repo's SQLCipher tests assume the right one.
- `tests/journal_vectors.rs` exercises the strict Rust verifier only; nothing checks Python `verify_audit_chain` and `journal::verify_chain` agree on the same rows.
- `bindings/python` crate has no Rust tests (TTL overflow, `&mut` borrow) — F9/F10 are only covered by the review tests.
- No test for lease state-file/lock-file deletion or clock steps (§3, F11).

## 7. Coverage

**Files read (line ranges):** `src/kibisis/vault.py` 12-15, 118-121, 211-500, 721-840 (grep), 1434-1500, 1533-1570, 1599-1683; `_vault_crypto.py` 180-240, 280-290 (+ grep of all `EntryIntegrityError`/`except` sites); `_vault_audit.py` 99-243; `_vault_search.py` 188-200, 838-860 (+ grep); `_vault_review.py` 200-245, 302-484; `_vault_tombstone.py` 160-200, 287-320; `_vault_snapshot.py` 60-78, 122; `okf/importer.py` 395-491; `config.py` 125-149; `lease.py` 20-94; `crypto.py` 104-113 (+ grep); `src/file_lease.rs` 1-375, 475-497; `src/lib.rs` 1-30, 640-730, 1144-1165 (+ full grep for panics/locks); `src/journal.rs` 236-310 (+ grep); `bindings/python/src/lib.rs` 1-233; `SECURITY.md` 1-183 (grep) and 42-95 in full; `README.md` and `CHANGELOG.md` by grep; `tests/review_b_crypto.py`, `review_b_journal.py`, `review_b_native.py` in full.

**Tests run:**
```
cd /opt/data/cache/scratch/kib-review && ARGUS_LEDGER_PATH=$TMPDIR/argus_b2.jsonl PYTHONPATH=src \
  /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/review_b_crypto.py tests/review_b_journal.py tests/review_b_native.py      -> 54 passed in 4.77s
same, tests/review_b2_misc.py (-s)                                                   -> 4 passed in 1.17s
cargo test (log $TMPDIR/cargo_test_b.log, EXIT=0, run by the previous reviewer):
  lib unit tests 23 passed; tests/journal_vectors.rs 8 passed; doc-tests 2 passed (33 total, 0 failed)
```
The `bindings/python` crate is not part of that cargo run (separate crate; not rebuilt — `maturin develop` was out of scope).

**Not reached:** SQLCipher-mode behaviour beyond F1 (all Python demonstrations deliberately disable `sqlcipher3`); multi-process lease contention and lock-file deletion (§3); `verify_audit_chain` at >1M rows (§3); `_vault_search.py` drain-queue correctness under SQLCipher; `lib.rs` Rust vault (`put/get/tombstone`, 640-1230) beyond its lock handling; `aml_adapter.py` and `mcp_server.py` beyond the fencing/open path.
