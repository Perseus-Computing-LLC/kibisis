# Review 2 — Area B (journal chain, meta MAC, signed tombstones, key-check ordering, crypto, leases, bindings)

Pin: worktree `/opt/data/cache/scratch/kib-review2`, detached at `6f96df3` (fix/review-integration). Nothing
under `src/` or existing tests changed. Repro tests: `tests/review2_b_*.py` (not collected by default).
Convention: `test_control_*` = secure behaviour (failing = bug); `test_attack_*` = defect demo (passing = bug).

```
cd /opt/data/cache/scratch/kib-review2 && ARGUS_LEDGER_PATH=$TMPDIR/argus_r2b.jsonl PYTHONPATH=src \
  /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/review2_b_*.py
21 passed in 5.75s
```

Threat model as in SECURITY.md:31-38: file writer with r/w on the plain-SQLite file, no passphrase, no
SQLCipher (`allow_plaintext`), unless stated otherwise.

## Findings (most severe first)

### R2-B1 — Full meta reset re-enters the format-1 migration, which launders a tampered journal and readmits tombstoned values — **high** (file writer)
*Where:* `_vault_crypto.py:372-394` (`_upgrade_integrity`). The refusal "format 1 claim carrying key_check or
meta_mac" (`:382`) and "keyed without key check" (`:377`, gated on `stored_format >= 2`) both assume the
attacker leaves one of those records behind. With `integrity_format` set to `1` (or the row deleted:
`int(None or 0) == 0`) **and** `key_check` and `meta_mac` deleted (`kdf_salt` kept), `stored is None` and
`stored_format < 2`, so `_migrate_integrity()` runs. Its own authentication is the entries' legacy signatures
(`:596-620`); with every `tenant_sig` blanked there are no `signed_rows`, `opened > 0` from the still-decryptable
envelopes, and nothing raises. The journal is verified under floor 1 / no anchoring (`_integrity_format` is
still 1 when `_chain_verifier` runs), so rows re-chained as format 1 with no head pass. The migration then
double-keys every tombstone and journal digest, appends a `migrate` event (`previous_chain_valid: True`), and
`_upgrade_to_format_3` signs a fresh head, tombstone MACs and meta MAC over the forged state.
*Effect:* (a) tombstone row + event deleted → value readmitted, journal shows no trace; (b) even with the
tombstone row left in place its digests are double-keyed, so `_find_tombstone` no longer matches the live
value (F13's "double-keys tombstone digests") while `_check_tombstones` still reconciles (both sides were
re-keyed together). Cost to the attacker: entries become "left unsigned" (WARNING, reads refuse until
`adopt_unsigned_entries()`), which reads like a legacy-vault condition, not an attack.
*Repro:* `tests/review2_b_journal.py::test_attack_full_meta_reset_launders_tombstone_and_journal_through_remigration`,
`::test_attack_meta_reset_without_tombstone_deletion_double_keys_the_digests`,
`::test_attack_same_reset_with_integrity_format_row_deleted` — all pass (open succeeds, `verify_audit_chain()`
True, `remember()` of the tombstoned value accepted, new head signed).
*Fix:* treat `kdf_salt` present as "keyed": refuse the format-1 migration whenever `kdf_salt` exists and
`key_check` is missing (the change note already claims this: "A keyed vault (integrity format >= 2 **or
`kdf_salt` present**) without a key check is refused" — the code checks only the format). For true a5
vaults (salt, no key check) require that at least one sealed entry *opens* under a signature... they have no
signatures either, so the better discriminator is: refuse when any `rejected_value_tombstones.tombstone_mac`
or `audit_head` row exists, or any journal row has `format >= 3`, or any entry envelope carries
`ENTRY_BINDING` (all are format-2+ artefacts a format-1 vault never wrote). Also pin the floor/anchoring
check to `kdf_salt` presence rather than `_integrity_format >= 3`.

### R2-B2 — Legacy a5 vault (salt, no key check) + wrong passphrase + sqlcipher3 present: file converted under the wrong passphrase, then refused — **high** (data loss, no attacker)
*Where:* `vault.py:519-525` (`_check_plain_file_passphrase`): `stored is None` and `integrity_format < 2` →
returns keys, no check; `:423` converts; `_migrate_integrity` then raises "Failed to authenticate" (sealed rows
did not open), but `os.replace` already happened. Exactly the file state of
`tests/fixtures/vault-0.1.0a5-fallback.sqlite` (`vault_meta` = `kdf_salt` only). F9 is closed for format-2+
files only.
*Repro:* `tests/review2_b_keycheck.py::test_attack_legacy_a5_vault_wrong_passphrase_is_converted_to_sqlcipher_before_any_check`
— passes: after the `ValueError`, the file no longer starts with `SQLite format 3` and the right passphrase
gets "Failed to authenticate".
*Fix:* for a salt-without-key-check file, authenticate against the plain file before converting: decrypt one
sealed entry (or verify one legacy signature) with stdlib sqlite3, as `_migrate_integrity` does later; or
convert to a sibling file and only `os.replace` after `_upgrade_integrity` succeeds (keep the plain file until
then).

### R2-B3 — Tombstones imported from a snapshot are not journaled, so deleting their row is not detected — **medium** (file writer)
*Where:* `_vault_snapshot.py:267-305`: `INSERT OR IGNORE INTO rejected_value_tombstones` with a MAC but no
`_record_audit_event(action="tombstone")`. `_check_tombstones` reconciles only journaled events.
*Repro:* `tests/review2_b_tombstone.py::test_attack_snapshot_imported_tombstone_row_deletion_readmits_value_unnoticed`
(passes: open succeeds, chain verifies, value accepted). Control
`::test_control_native_tombstone_row_deletion_is_caught` shows the native path is caught.
*Fix:* journal each imported tombstone (`tombstone`, metadata `{"path": "import_snapshot"}`) inside the same
transaction.

### R2-B4 — `vault_meta.verification_quorum` is outside the meta MAC; a file writer lowers the quorum to 1 — **medium** (file writer; undermines area A's F7 fix)
*Where:* `crypto.py:237` `VAULT_META_BOUND_KEYS` lacks `verification_quorum`; `vault.py:999-1008` adopts the
stored value when the process names none.
*Repro:* `tests/review2_b_journal.py::test_attack_verification_quorum_in_vault_meta_is_outside_the_meta_mac`
(passes: `v.verification_quorum == 1` after the edit, meta MAC verifies).
*Fix:* add it to `VAULT_META_BOUND_KEYS` (and `_write_meta_mac` after `_persist_verification_quorum`).

### R2-B5 — Read-only open of a keyed vault whose `kdf_salt` was removed silently degrades to the plaintext path — **low/medium** (file writer vs okf-export)
*Where:* `vault.py:583-611`: `elif passphrase:` branch ("a plain file never opened with a passphrase") when
`kdf_salt` is absent: no key check, no meta MAC, no tombstone reconciliation, path-derived signing key,
floor 1. A forged legacy-format chain with no head verifies; entries read as `[ENCRYPTED]`.
*Repro:* `tests/review2_b_tombstone.py::test_attack_read_only_open_treats_keyed_vault_with_salt_removed_as_plaintext`
(passes). The writable open fails closed (`ValueError` on key check) — but note it first **writes a fresh random
salt** into `vault_meta` (`_vault_salt`, `_vault_crypto.py:160-170`) before failing.
*Fix:* in read-only mode, when `key_check` or `meta_mac` exists without `kdf_salt`, raise `VaultIntegrityError`;
in writable mode, do not generate a salt when `key_check`/`meta_mac`/`integrity_format>=2` exist.

### R2-B6 — F14 residual: `forget_requests` drops a bad-signature row silently, ignores `strict=True`; `_value_copies` likewise — **low**
*Where:* `vault.py:1886-1890` (`except PermissionError: entity = None`, no `_note_integrity_failure`, no
strict); `_vault_tombstone.py:231-235` (`_value_copies`: a copy whose signature was blanked escapes the purge
of copies, silently).
*Repro:* `tests/review2_b_native.py::test_attack_forget_requests_drops_bad_signature_rows_silently_even_under_strict`.
*Fix:* route both through `_readable_content`.

### R2-B7 — `strict=True` makes the *open* raise when the term index touches a bad row — **low** (regression / doc)
*Where:* `vault.py:476` → `_vault_search.py:753,857,843` → `_readable_content` → raise under strict. Without
SQLCipher the term index is on by default, so `SQLiteMemoryVault(..., strict=True)` on a vault with one tampered
row raises `EntryIntegrityError` from the constructor; `integrity_failures` cannot be inspected. Docstring says
strict makes "every read" raise, not the open. Shown in the same test (first `pytest.raises`).
*Fix:* index building should drop-and-count (never raise) regardless of `strict`, or document.

### R2-B8 — Python verifier accepts `format` > 3 (hashes it as 3); the crate refuses it — **low** (Python/Rust disagreement, no forgery)
*Where:* `_vault_audit.py:78` (`if fmt < 3 ... else v3`) vs `journal.rs:281` (`!= JOURNAL_FORMAT`).
*Repro:* `tests/review2_b_native.py::test_attack_python_accepts_a_row_labelled_format_4_that_rust_refuses`,
`tests/review2_b_journal.py::test_attack_row_relabelled_format_4_is_accepted_by_python_refused_by_rust`.
*Fix:* `if ev.format > JOURNAL_FORMAT: error`.

### R2-B9 — `verify_audit_chain()` raises instead of returning False on non-JSON `metadata_json` — **low**
*Where:* `_vault_audit.py:324` `json.loads(r["metadata_json"])` (also `TypeError` on NULL). Callers that test
`is False` get an exception; `last_chain_error` unset.
*Repro:* `tests/review2_b_native.py::test_attack_verify_audit_chain_raises_instead_of_false_on_malformed_metadata_json`.

## Verified closed (evidence)

| Original | Status | Evidence |
|---|---|---|
| F2 format downgrade (keyed, format-3 vault with meta intact) | closed | `test_review_b_journal.py` attacks fail as expected; my re-chain attempts without the meta reset hit floor/anchoring (`test_attack_meta_mac_binds_the_integrity_records`). Only via R2-B1. |
| F4 tombstone row deletion/edit/plant | closed for native tombstones | `review2_b_tombstone.py::test_control_native_tombstone_row_deletion_is_caught`; MAC covers scope/category/key/both digests/origin_class so relabelling scope→`*` or class needs the key. Open for imported tombstones (R2-B3). |
| F9 wrong passphrase converts the file | closed for format-2+ files (`test_review_b2_misc.py::test_attack_wrong_passphrase_with_sqlcipher_leaves_plain_vault_untouched`) | open for a5 files (R2-B2). |
| F13 integrity_format edit | closed when key_check or meta_mac remain | open for the full reset (R2-B1). |
| F14 silent drops | closed for search/list/export (`test_review_b2_misc.py`) | residual in `forget_requests`, `_value_copies` (R2-B6), strict-at-open (R2-B7). |
| F15 plaintext fallback opt-in | closed | `test_review_b2_misc.py::test_attack_passphrase_without_sqlcipher_is_refused_unless_opted_in`; `config.open_vault` relays `plaintext_allowed(env)`; read-only never hits the check (never writes). |
| L4 key_check deletion | closed at format ≥ 2 | `test_review_b_crypto.py::test_attack_key_check_deletion_refuses_every_passphrase`; see R2-B1 for the combined reset. |
| L5 envelope salt/iterations | closed | `test_review_b_crypto.py::test_attack_per_row_salt_is_refused_before_any_key_derivation`; `decrypt_foreign` only on snapshot tombstones / trust seal. |
| L6 PyO3 panics / `&mut self` | closed | `review2_b_native.py::test_control_rust_binding_edge_inputs_raise_python_errors_not_panics` (format 256 → OverflowError, sequence 2^64 → OverflowError, NaN timestamp → ValueError, missing keys → KeyError/TypeError), `::test_control_ttl_out_of_range_is_value_error`, 12-thread concurrent acquire without `Already borrowed`. |
| L7 fencing token reset | closed | `::test_control_fencing_tokens_survive_state_deletion_and_two_coordinators` (state-file deletion, two coordinators on one dir, 12 concurrent holders → distinct increasing tokens). `.highest` deletion documented out of scope (README:23). |
| 1,000,000-row cap | closed | `verify_audit_chain` pages 10,000 rows (`_vault_audit.py:313-331`). |
| renew `>=` vs validate `>` | closed | `file_lease.rs:252,115,215` all `>`; crate test `a_lease_at_its_deadline_second_neither_renews_nor_fences`. |
| Clock skew | unchanged, not claimed fixed | `file_lease.rs:289-292` `unwrap_or_default`. Suspected only. |
| Lock-file deletion | documented out of scope (`file_lease.rs:44-46`, README:23) | not tested. |

## Regressions checked (none found)
- a5 fixture (format 1, salt only) with right passphrase upgrades to 3, floor 2, idempotent second open,
  journal verifies: `review2_b_keycheck.py::test_control_legacy_a5_vault_right_passphrase_upgrades_to_format_3`.
- Simulated integrity-format-2 vault (no meta MAC, unsigned tombstones), with head (a10-a15) and headless
  with format-2 rows (a6-a9): upgrades, signs 1 tombstone, floor 3/2, head written, tombstone still enforced,
  wrong passphrase refused before any write, read-only open afterwards fine:
  `::test_control_format_2_vault_upgrades_to_3_and_keeps_tombstones[False|True]`.
- In-memory vault with passphrase: `::test_control_in_memory_vault_with_passphrase_round_trips`.
- Note (not a regression, a design limit): a headless journal that already holds format-3 rows can never be
  upgraded (head required under the old rule) — only a tampered file is in that state.

## Suspected, unconfirmed
- **Per-open cost:** `_check_tombstones` scans `audit_journal WHERE action IN ('tombstone','tombstone_lifted')`
  on every open (writable and read-only); the only index is on `scope` (`vault.py:954`). O(journal) per open;
  not measured (no flooding).
- **Python ↔ Rust row-for-row agreement is only true for crafted rows:** the vault stores `metadata_json` with
  `json.dumps(sort_keys=True)` default separators (`{"epistemic_state": "candidate", ...}`) but hashes the
  compact canonical form; `journal.rs:112` digests the stored string verbatim, so `kibisis_native.verify_chain`
  on real rows reports HashMismatch even with whole-second timestamps. Consequently the Python verifier also
  accepts any re-serialisation of `metadata_json` (whitespace/key order) — benign.
- **Writable open with `kdf_salt` removed writes a new salt before failing** (R2-B5 note). Harmless for the
  attacker's goal but it means the "fails closed, writes nothing" claim is not literally true.

## Documentation that overstates the code
- changes/area_b.md:26 / SECURITY.md:76-80: "A keyed vault (integrity format >= 2 **or `kdf_salt` present**)
  without a key check is refused" — the code gates on the stored format only (R2-B1); "the key check is
  compared before any migration or file conversion" — not for a5 files (R2-B2).
- SECURITY.md:61-62 / changes/area_b.md:13-14: "`kibisis_native.verify_chain` gives the same verdict on the
  same rows" — only for whole-second, compact-metadata rows; and the two disagree on `format > 3` (R2-B8).
- SECURITY.md:69-75: "every `tombstone` event in the journal ... must still have its row, so a deleted row
  refuses the open" — true, but imported tombstones have no event (R2-B3).
- vault.py:292 docstring: "`strict=True` makes every read raise" — it also makes the open raise (R2-B7).
