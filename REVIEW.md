# kibisis v0.1.0-alpha.16 — adversarial code review

Pin: tag `v0.1.0-alpha.16` = `1299c2859eb96c54bba7e34455a8ce9640ba1f2a`, detached worktree `/opt/data/cache/scratch/kib-review`. Nothing under `src/` or the existing tests was changed; nothing pushed. All repro tests are `tests/review_*.py` in this worktree. Per-area working notes with full command transcripts: `review_notes/A1_trust_boundary.md`, `A2_review_doors_tombstones.md`, `B_crypto_journal_concurrency_rust.md`, `C_aml_okf_docs.md`.

Threat model used (SECURITY.md:31-38): **agent/MCP client** = untrusted; **same-uid shell** = what the agent's shell tool has; **file writer** = read/write on the DB file without the passphrase (the no-SQLCipher deployment SECURITY.md:63-65 "assumes"); **person at a terminal** = trusted.

Test convention: `review_a1_*` encode the *secure* behaviour and are marked `xfail(strict=True)` — they go RED when the defect is fixed. `review_a2_*`, `review_b*`, `review_c_*` use `test_control_*` for positive controls (failing = bug) and `test_attack_*` / `test_<name>` for demonstrations (passing = bug); each docstring says which.

---

## 1. Verdict on the five atlas fixes

| # | Atlas finding | Verdict | Evidence |
|---|---|---|---|
| 1 | MCP `kibisis_forget` could tombstone a person-verified entry | **Closed at the MCP layer; bypassable at the library layer; a new denial problem introduced** | MCP whitelists only `category/key/reason` (`mcp_server.py:60-66`), so the client cannot reach `content`/`origin` (4 controls pass). But `tombstone()`'s `protected()` guard (`_vault_tombstone.py:172-183`) only runs in the `content is None` branch (`:185-204`); any `content=` argument skips it and the row is deleted by category/key at `:236-240` regardless of match (**F1**). `purge()` has no `origin` at all (**F10**). And the fix's design lets an agent *deny* a value to a person forever (**F3**). |
| 2 | `kibisis-review approve/dispute/reject` had no terminal check | **Closed as stated; the stated thing is not a boundary** | `_operator.py:32-33` is `sys.stdin.isatty()`, called in `review.py:99-105` and `__main__.py:36-41`. A pipe is refused (exit 3). `pty.spawn(...)` or `script -qec` from a stdin=/dev/null shell passes it (`review_a2_review_doors.py`, 4 cases, rc 0 `is now verified (account hermes)`). `vault.review_entity`/`vault.admit` have no check at all. README.md:127 says so honestly; SECURITY.md:121-122 and CHANGELOG.md:256-257 claim the opposite (**F8**, §4). |
| 3 | Quorum counted free-text `--reviewer` names | **Closed for the CLI path only; every other attestation path still counts strings** | CLIs use `account_identity()` (`_operator.py:39-57`), `--reviewer` is a label (`_vault_review.py:430-431,474-476`). But principal `put(origin="user", epistemic_state="verified", author_id=X)` attests as `X`, or as the literal `"principal"` when absent (`vault.py:945-957`); `review_entity(reviewer_id=...)` counts any distinct string; snapshot import trusts `attestations` from the file (`_vault_snapshot.py:276-291`); the quorum itself is per-process env, not a vault property (**F5, F6, F7**). Pre-a15 typed name + post-a15 account from the same person = 2. |
| 4 | MCP recall bypassed `recall()` withholding | **Closed** | `mcp_server.py:600-606` calls `vault.recall()`; tool list is exactly `remember/recall/forget/health/verify_ledger`. Control: `search()` returns two conflicting verified entries, `kibisis_recall` returns `withheld="2"` with no content. Residual: `fence_recall` prints `author=` from caller-settable metadata (low). |
| 5 | `kibisis admit` opened a different DB/scope than the server | **Partially closed** | With `KIBISIS_SCOPE` set, server/admit/review agree. Without it, `resolve_scope` (`config.py:113-127`) derives the scope from the *caller's cwd* git checkout, so `admit` from another directory reports `not found in scope 'default'` while the server wrote to `project:checkout-<hash>` (`review_a1_paths.py`). `okf-export`/`okf-import` still default `--db` to `~/.hermes/kibisis/vault.sqlite` (`__main__.py:20`) while everything else uses `~/.local/share/kibisis/vault.sqlite`, and they ignore `XDG_DATA_HOME` and `KIBISIS_ALLOW_PLAINTEXT` (**F17, C-11**). |

---

## 2. Findings (most severe first)

Severity: **critical** = agent-reachable (MCP or same-uid shell) and defeats a core documented guarantee with no recovery; **high** = agent-reachable or file-writer-reachable and defeats a documented guarantee; **medium** = needs a library caller / passphrase holder / unlikely precondition, or partial defeat; **low** = hygiene, robustness, or documented-but-overstated.

Run everything with:
```
cd /opt/data/cache/scratch/kib-review && ARGUS_LEDGER_PATH=$TMPDIR/argus.jsonl PYTHONPATH=src \
  /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/review_*.py
```
(`--runxfail` turns the 21 A1 findings into visible assertion failures.)

### F1 — `tombstone(content=...)` skips the origin check entirely — **high**
*Reason:* the exact guard atlas fix #1 added is dead code whenever `content` is supplied, and `content` is the documented way to tombstone (README:115; every pre-a15 test uses it).
*Where:* `src/kibisis/_vault_tombstone.py:185-204` (`target` only assigned when `content is None`; `protected(target, …)` at `:199` never runs otherwise), `:211-213` (entry skipped in copy scan "checked above"), `:236-240` (`DELETE FROM entities WHERE category=? AND key=? AND scope=?` regardless of whether content matched).
*Problem:* a model-origin caller passing any `content` string — even one stored nowhere — deletes a person-verified entry by category/key, no `ReviewedEntryError`, journal records a successful `tombstone` by `author_id="mcp-agent"`. Reachable from any library embedder relaying an agent (not from the MCP whitelist).
*Repro:* `tests/review_a1_tombstone.py::test_model_tombstone_with_content_argument_must_not_delete_a_verified_entry[*]`, `::test_model_tombstone_with_content_must_not_delete_a_person_written_candidate` → `Failed: DID NOT RAISE ReviewedEntryError`. Control `::test_control_model_tombstone_without_content_is_refused` passes.
*Fix:* look the row up by category/key/scope and run `protected()` on it before any branch; when `content` is given and the stored digest doesn't match, delete nothing.

### F2 — File writer launders journal deletions/edits via format downgrade; the next honest write signs the forged history — **high**
*Reason:* defeats the one guarantee the journal exists for (SECURITY.md:52-54), with no passphrase.
*Where:* `src/kibisis/_vault_audit.py:222-236`. Rows are re-hashed under `fmt=ev.format` (unkeyed SHA-256 for 1/2); the `format` column is covered by nothing; `anchored = any(ev.format >= 3)` + `if head is None: return not anchored` means a journal with no format-3 rows needs no head. Rust `journal.rs:265-269` refuses `format != 3` but Python never calls it (bindings export only hash fns, `bindings/python/src/lib.rs:222-232`).
*Problem:* delete the `tombstone` event (or edit `author_id`, reorder), re-chain as format 1, drop `audit_head` → `verify_audit_chain()` is True. Next `remember()` appends a format-3 row and `_write_audit_head` (`:139,155-160`) signs the forged chain.
*Repro:* `tests/review_b_journal.py::test_attack_format_downgrade_launders_middle_deletion` (:119), `::test_attack_format_downgrade_launders_payload_edit_and_reorder` (:138) — both pass; `-s` prints `verify_audit_chain after downgrade+deletion: True`, `head re-signed at sequence 5`.
*Fix:* once `integrity_format >= 2`, refuse any row with `format < JOURNAL_FORMAT` and require a head regardless (mirror `journal.rs:265-269,284-286`); record the format floor in signed `vault_meta`.

### F3 — Through MCP, an agent can permanently deny a value to a person — **high**
*Reason:* reachable by the MCP client alone; there is no lift API.
*Where:* `_vault_tombstone.py:223-235` (scope-wide value tombstone on any origin), `vault.py:1066-1078` (`_put` refuses every later write incl. a person's verified write); `grep "DELETE FROM rejected_value_tombstones"` → none.
*Problem:* `kibisis_remember("Deploys go out on Tuesdays")` then `kibisis_forget` on the agent's own candidate blacklists that fact and all canonical look-alikes for the person forever. Person sees only `TombstonedValueError`.
*Repro:* `tests/review_a1_tombstone.py::test_mcp_remember_then_forget_must_not_block_a_persons_later_write_of_that_value`, `::test_mcp_forget_canonical_lookalike_also_denies_the_person` → `Failed: person's write refused by an agent-made tombstone: Write rejected by tombstone …`.
*Fix:* tag tombstones with origin class and let a higher-class writer override a lower-class tombstone; or give `kibisis-review` a `lift` verb; or make MCP forget `archive` rather than tombstone.

### F4 — File writer deletes a `rejected_value_tombstones` row and the forgotten value is re-admitted; chain still verifies — **high**
*Where:* `_vault_tombstone.py:55` (`_find_tombstone` reads only the unsigned table); `_vault_audit.py:209-241` never reconciles with journal `tombstone` events. SECURITY.md:42,56-59 lists this under "In scope, caught".
*Repro:* `tests/review_b_journal.py::test_attack_tombstone_row_deletion_readmits_value` (:166) passes (value accepted, `verify_audit_chain() is True`).
*Fix:* derive the active tombstone set from the headed journal at open, or HMAC each tombstone row and refuse to open/put when a journaled tombstone has no row.

### F5 — Tombstone canonical form misses `Mn` marks, Hangul fillers and homoglyphs; agent re-stores a rejected value via MCP — **high**
*Where:* `src/kibisis/_vault_crypto.py:45-71` (`canonicalize_text` strips only `Cf`/`Cc`, `P*`/`S*`, whitespace; NFKC+casefold).
*Problem:* one U+FE0F / U+034F / U+180B / U+3164, or one Cyrillic `а` / dotless `ı`, brings a person-rejected value back through `kibisis_remember`; recall returns it. README:20/55/125 promise look-alikes are refused.
*Repro:* `tests/review_a2_tombstones.py::test_invisible_nonspacing_marks_and_homoglyphs_bring_a_tombstoned_value_back[*]` (6), `::test_invisible_mark_variant_is_accepted_through_the_mcp_remember_tool`; controls (case, punctuation, ZWSP, fullwidth, NBSP) refused.
*Fix:* also drop `Mn`/`Me`/`Mc` after NFKC, drop Default_Ignorable code points and Hangul fillers, apply a UTS #39 confusables skeleton; state plainly that paraphrase is out of scope.

### F6 — An agent's supersession of its *own* note flips a person's verified entry to `disputed`, after which the reviewed-entry guard no longer covers it — **high**
*Where:* `_vault_review.py:205-241` (`_cascade_invalidate` marks every dependent `disputed`, no class or reviewed check); triggered from MCP `supersedes_key` (`vault.py:989-991,1062`). After the flip `_is_reviewed()` is False (no `human_reviews`, not verified).
*Repro:* `tests/review_a1_write_paths.py::test_agent_supersession_cascade_must_not_change_a_person_verified_entry` → `AssertionError: person's entry is now EpistemicState.DISPUTED via an agent cascade`; `::test_after_the_cascade_the_persons_entry_no_longer_counts_as_reviewed` documents.
*Fix:* in `_cascade_invalidate`, skip (or annotate only) dependents of a higher origin class or with `human_reviews` when the trigger is non-principal.

### F7 — Quorum of two is reachable by one same-uid process via free-text attestations, snapshot import, or a per-process quorum — **high** (library/same-uid shell; not via MCP)
*Where:* `vault.py:945-957` (`signer = author_id or principal_id or "principal"`), `_vault_review.py:474-479` (any distinct `reviewer_id` string counts; `reviewer_id=None` records a review with no attestation, `:421-432`), `_vault_snapshot.py:276-291` (`attestations`/`human_reviews` imported with `_trusted_metadata=True`; `manifest_sha256` optional, `:183-189`), `vault.py:267-271` (`KIBISIS_VERIFICATION_QUORUM` read at `__init__`, never persisted; bad values raise a bare `ValueError` that kills `review list` and the MCP server).
*Repro:* `tests/review_a2_quorum.py` — `test_b_two_user_writes_with_different_author_ids_reach_quorum` (`after bob: verified ['alice','bob']`), `test_b_user_write_with_no_author_id_signs_as_the_literal_principal`, `test_d_snapshot_import_trusts_forged_attestations_so_one_real_approval_mints_verified` (`['ghost','real-person']`), `test_f_quorum_is_a_per_process_setting_not_a_vault_property`, `test_f_env_quorum_values_that_crash_every_opener[*]`, `test_one_person_pre_a15_typed_name_plus_post_a15_account_reaches_quorum_two`, `test_g_review_entity_with_reviewer_id_none_records_a_review_but_no_attestation`.
*Fix:* make the vault resolve the attester (`account_identity()`) for `user`-origin writes and reviews; refuse `"principal"` and `None` as signers; drop attestations/`human_reviews` on import unless the snapshot's `digest_key_id` matches and the manifest verifies; persist the quorum in `vault_meta`, refuse to lower it, and validate the env var into a `ConfigError`.

### F8 — `review_entity(verdict="disputed"|"verified", reviewer_origin="model")` is accepted; `put()`/`put_batch()` expose `_review_verdict`/`_trusted_metadata` — **high** (library)
*Where:* `_vault_review.py:487-504` (only `revoked` routes through the origin-checked `tombstone`); `vault.py:749-750` (public kwargs), `:1503` (`put_batch` forwards dict items). With `_review_verdict=True`, `tool`/`unknown`/`None` origins write `verified` directly and keep a forged `human_reviews`; only `origin="model"` is still capped.
*Repro:* `tests/review_a1_write_paths.py::test_model_origin_review_verdict_disputed_must_not_change_a_person_verified_entry`, `::test_model_origin_review_verdict_must_not_make_an_agent_candidate_count_as_reviewed`, `::test_put_internal_flags_must_not_mint_verified_for_a_non_principal[tool|unknown|None]`, `::test_put_batch_forwards_internal_flags_from_dict_items` → `AssertionError: (<EpistemicState.VERIFIED>, 'external')`.
*Fix:* `review_entity` raises `PermissionError` for any non-principal `reviewer_origin`, every verdict; move the review write to a private `_put_reviewed` and strip the underscore kwargs from `put`/`put_batch`.

### F9 — Wrong passphrase on a plain-SQLite vault where `sqlcipher3` is present re-encrypts the file under the wrong passphrase before the key check — **high** (data loss, no attacker needed)
*Where:* `vault.py:311-323` (`_migrate_file_to_sqlcipher` keyed by the supplied passphrase, `os.replace` at `:481`) runs before `_upgrade_integrity` → `_vault_crypto.py:283-285` (`key_check`).
*Problem:* one typo converts the file; every later open fails (SQLCipher wants the wrong passphrase, `key_check` wants the right one). Recovery needs the wrong passphrase and a manual `sqlcipher_export`.
*Repro:* `tests/review_b2_misc.py::test_attack_wrong_passphrase_with_sqlcipher_reencrypts_plain_vault_and_bricks_it` → header no longer `SQLite format 3`; correct passphrase then raises `Failed to authenticate`.
*Fix:* verify `key_check` against the plain file (stdlib `sqlite3`, derive from `kdf_salt`) before converting; or convert to a sibling and `os.replace` only after a successful keyed open.

### F10 — `purge()` has no origin parameter and leaves no tombstone — **medium**
*Where:* `_vault_tombstone.py:25-52`. Deletes a verified principal entry outright with whatever `author_id` the caller passes; README:128 names `archive()` and origin-less `tombstone()` as unchecked but not `purge()`. Not reachable from MCP.
*Repro:* `tests/review_a1_tombstone.py::test_purge_has_no_origin_parameter_documents_insecure_behaviour`; `tests/review_a2_tombstones.py::test_purge_has_no_origin_check_and_leaves_no_tombstone`.
*Fix:* add `origin` and the same `protected()` check.

### F11 — Snapshot round-trip demotes a person's verified entry to external-class candidate, then agent-overwritable and agent-deletable — **medium**
*Where:* `_vault_snapshot.py:43-85` (no `origin` exported), `:276-291` (`put(origin=None, epistemic_state="verified")`), `vault.py:817-825,1111`. After restore: `origin=unknown`, class `external`, `candidate`, `trust_capped_from="verified"`, no `human_reviews`.
*Repro:* `tests/review_a1_write_paths.py::test_snapshot_round_trip_must_keep_a_person_verified_entry_verified_and_principal` → `('unknown','external',CANDIDATE,'verified')`; `::test_after_a_snapshot_restore_an_agent_can_overwrite_and_delete_the_persons_entry` → `DID NOT RAISE`; `tests/review_a2_quorum.py::test_d_snapshot_round_trip_demotes_a_legitimately_verified_entry`.
*Fix:* export `origin`/`author_id` per entity and pass them on import. Combined with F7's forged attestations, import currently loses real verification while keeping fake.

### F12 — Tombstoned value survives, and is re-storable, in `metadata` and in the `key` column; MCP recall prints keys — **medium**
*Where:* `_vault_tombstone.py:73-101` (`_value_copies` digests `content` only), `vault.py:1066-1079` (write check digests `content` only), `mcp_server.py:466-477,257-269`.
*Repro:* `tests/review_a2_tombstones.py::test_value_kept_in_agent_metadata_survives_the_tombstone_and_can_be_rewritten_after_it`, `::test_value_used_as_a_key_survives_and_is_shown_by_mcp_recall` → `recall shows forgotten value in key attr: True`.
*Fix:* digest `key` and string leaves of `agent_metadata` on write and in `_value_copies`; cap key charset/length on the MCP path.

### F13 — One-cell edit of `vault_meta.integrity_format` bricks the vault; with signatures blanked, the forced re-migration re-signs a tampered journal and double-keys tombstone digests — **medium** (file writer)
*Where:* `_vault_crypto.py:281-283` (migration before key check), `:354-367,379-380`; `previous_chain_valid=False` is only logged.
*Repro:* `tests/review_b_journal.py::test_attack_meta_integrity_format_edit_bricks_open` (:186), `::test_attack_meta_integrity_format_edit_plus_blank_sigs_resigns_journal` (:199).
*Fix:* key check before any migration; bind `integrity_format`, `kdf_salt`, `key_check` under one HMAC; a migration whose previous chain fails must refuse, not re-sign.

### F14 — Bad-signature rows vanish silently from `search()`, `list_entities()` and snapshot export — **medium**
*Where:* `_vault_crypto.py:217-225` (`_readable_content` → None), `_vault_search.py:194-196,842-844`, `vault.py:1644-1646`, `_vault_snapshot.py:68-71`. Only `get()` raises (`vault.py:1530`). No log line.
*Repro:* `tests/review_b2_misc.py::test_attack_bad_signature_row_vanishes_silently_from_search_and_list` → `log records mentioning integrity: []`.
*Fix:* WARNING with category/key per dropped row; `integrity_failures` counter; `strict=True` raises.

### F15 — With a passphrase but no `sqlcipher3`, the vault opens plain after one log warning; `allow_plaintext` never consulted — **medium**
*Where:* `vault.py:12-15,118-120,305-310,335-348`; `config.py:130-133` and `vault.py:279-283` gate only the *no-passphrase* case. Plain on disk: all of `audit_journal`/`audit_head`, `entities.{category,key,scope,metadata_json,origin,epistemic_state,timestamps}`, tombstone digests/reasons, `vault_meta`, HMAC term tokens with positions.
*Repro:* `tests/review_b2_misc.py::test_attack_passphrase_without_sqlcipher_opens_plain_sqlite_with_only_a_log_warning`.
*Fix:* require explicit opt-in to open on-disk with a passphrase when SQLCipher is absent; otherwise raise `EncryptionRequiredError`.

### F16 — AML adapter: input-driven 500s, chunked body-cap bypass, retention deletes arbitrary `*.kib`, resets on 401/404 — **medium** (network-facing, authenticated client except C-3/C-12)
*Where / repro (`tests/review_c_aml.py`):*
- C-1 `aml_adapter.py:140-153`: one Add with an out-of-range `timestamp` makes every later Search for that user a 500 (`::test_out_of_range_timestamp_poisons_search`).
- C-2 `:540-556`: chunked body with a negative chunk size bypasses `max_body_bytes` and reads to EOF (`::test_negative_chunk_size_bypasses_body_cap`, shown on a `BytesIO` reader).
- C-4 `:263-285`: `purge_idle` globs `*.kib` by mtime — deletes any decoy `*.kib` file, raises on a `*.kib` directory (aborting the sweep), and purges a read-only user's vault (`::test_retention_deletes_decoy_and_dies_on_directory`, `::test_read_only_user_is_purged`).
- C-3 `:570-577`: 401/404 are not drained, so a large body gets a reset instead of the reply (`::test_large_body_on_401_404_breaks_pipe`).
- C-7/C-8/C-10: `Infinity`/`NaN`/`1e400` and lone surrogates → 500 not 4xx; ms timestamps < 1973-03-03 reinterpreted as seconds.
- C-9 `:332`: reused `request_id` with a *different* payload is acknowledged and dropped.
*Fix:* validate timestamps into 422 at Add; reject negative/invalid chunk sizes with 400; have retention check the file is a regular SQLite/SQLCipher vault and skip/continue on errors; drain or `Connection: close` on 401/404; 409 on request_id payload mismatch.

### F17 — `okf-export`/`okf-import` default to a different vault than the server/admit/review, re-encrypt a plaintext vault in place, and ignore `KIBISIS_ALLOW_PLAINTEXT` — **medium**
*Where:* `__main__.py:20` (`~/.hermes/kibisis/vault.sqlite` vs `config.default_db_path()` → `~/.local/share/kibisis/vault.sqlite`, `XDG_DATA_HOME` ignored); `:99,:149` open with `SQLiteMemoryVault(args.db)` directly, so with a passphrase in the env the constructor migrates to SQLCipher in place and runs the integrity upgrade even for `okf-export` ("reads the vault only") and `okf-import --dry-run` ("writes nothing").
*Repro:* `tests/review_c_okf.py::test_okf_default_db_diverges_from_config`, `::test_export_and_dry_run_rewrite_a_plaintext_vault`, `::test_okf_cli_ignores_KIBISIS_ALLOW_PLAINTEXT_that_the_server_and_admit_honour`; `tests/review_a1_paths.py::test_okf_commands_default_to_a_different_vault_path_than_the_server`.
*Effect:* under default config `okf-import` silently creates and writes a vault the server never reads; `okf-export` of the server's vault exports an empty bundle.
*Fix:* open through `config.open_vault(args.db)`; add a read-only open mode for export/check/dry-run.

### F18 — MCP candidate's pending supersession of a verified entry is invisible in `kibisis-review list`; forget-request view is floodable — **medium**
*Where:* `review.py:68-100` prints author/version/content only; `_vault_review.py:484-501` applies `proposed_supersedes` on approve (verified target revoked, dependents disputed). `vault.py:1394-1397` reads the newest 5000 `refuse` events then filters; 5001 cheap refused MCP calls push a forget request out of view.
*Repro:* `tests/review_a1_review_surface.py::test_review_list_must_name_a_candidates_pending_supersession_of_a_verified_entry`, `::test_forget_requests_must_survive_a_flood_of_agent_refusals`.
*Fix:* print "approving retires X (verified)" in list and confirmation; filter `forget_request` in SQL or keep a dedicated table.

### F19 — Model-origin `tombstone(content=..., scope="*")` writes a global tombstone — **medium** (library)
*Where:* `_vault_tombstone.py:185-204,223-235`. *Repro:* `tests/review_a1_tombstone.py::test_model_origin_tombstone_with_content_and_wildcard_scope_must_not_write_a_global_tombstone`. *Fix:* refuse `scope="*"` for non-principal origins.

### Low
- **L1** `review_entity`/`_record_edges` (`_vault_review.py:164-203`): a model write's `conflicts_with` mutates a person's verified entry's metadata (`review_a1_write_paths.py::test_model_conflicts_with_must_not_modify_…`).
- **L2** `vault.py:808-812`: `remember(origin="model", epistemic_state="revoked")` stored as `revoked`; docs say any model write is capped to candidate (`::test_model_remember_must_not_store_revoked`).
- **L3** `vault.py:95-101`: `author_id`, `last_verified_at`, `supersession`, `proposed_supersedes`, `slot` are not reserved metadata keys; `archive()`/`set_persona_slot()` have no origin gate (`review_a1_*`, documenting).
- **L4** `_vault_crypto.py:283-285`: deleting `vault_meta.key_check` lets a wrong passphrase open silently; writes then mix key sets (`review_b_crypto.py:140`).
- **L5** `crypto.py:106-112`: per-row envelope salt/iterations trusted before the GCM tag; >64 distinct salts defeat the key cache and force PBKDF2 per read (`review_b_crypto.py:105`, >10× slowdown).
- **L6** `bindings/python/src/lib.rs:31-38`: `Duration::from_secs_f64` panics across PyO3 for ttl ≥ ~1.8e19 (`PanicException`, a `BaseException`); `:124-148` `&mut self` makes concurrent calls raise `RuntimeError: Already borrowed` (`review_b_native.py:102,120`). Python wrapper masks both.
- **L7** `file_lease.rs:171-183`: deleting a `.lease` state file resets the fencing token to 1 (`tokens: 1 2 1`, `review_b2_misc.py`); README:23 "only go up" has no caveat.
- **L8** `aml_adapter.py:570-577`: 404 answered before auth, so unauthenticated clients can enumerate POST paths. Error bodies otherwise leak nothing (control).
- **L9** `okf/export.py:870-871`: `--gate-cmd` stdout copied verbatim to stderr — a gate that echoes matches puts vault content on the terminal; "evaluation content is never logged" (deploy README:58) is scoped to AML only. Gate is fail-closed on timeout/non-zero/launch failure (control passes).

---

## 3. Suspected, unconfirmed

- **AML: no socket timeout / unbounded handler threads** — `AMLHandler.timeout` is `None`; `ThreadingHTTPServer` spawns a thread per connection; `--max-inflight` bounds processing, not connections. A stalled upload holds a slot indefinitely. Needs a deliberately stalled connection to show; not run by choice. *Would confirm:* a client that sends headers + Content-Length and nothing else, then a second client observing the thread count.
- **AML `purge_idle` stat-then-lock window** (`:267` vs `:272`): a write landing between the mtime read and the lock, finishing before deletion, loses its fresh vault. Microsecond window; needs instrumentation.
- **Lock-file deletion breaks lease mutual exclusion** (`file_lease.rs:117-127`): unlinking `<digest>.lock` while A holds the flock lets B lock a fresh inode. Same owner-only precondition as L7. Needs a second process timed against the unlink.
- **`verify_audit_chain` caps at 1 000 000 rows** (`_vault_audit.py:219`): beyond that the head names a row outside the fetched slice → permanent "tampered". Not exercised (cost).
- **Clock skew on leases** (`file_lease.rs:239-243`): wall-clock `SystemTime`; backward step extends every lease, pre-1970 clock makes all leases unexpired (`unwrap_or_default`). `renew` uses `>=` while `validate_fencing_token` uses `>` (one-second window).
- **uid/name drift**: container started once with numeric `--user` and later with a named user gives `uid-<n>` vs passwd name → two attestations from one person. Needs a controllable passwd DB.
- **Agent control of the operator's environment**: `KIBISIS_VERIFICATION_QUORUM=1` via shell rc / MCP launcher config is plausible under the same uid; not demonstrated.
- **Snapshot `tombstones` list as DoS**: a crafted snapshot with the vault's own keyed digests could tombstone a person's verified facts (`INSERT OR IGNORE`, `_vault_snapshot.py:216`). Requires the passphrase.
- **No-SQLCipher fallback invisible at the AML level**: `run_server` logs `encrypted=True` from `passphrase is not None` (`aml_adapter.py:634-635`); `sqlcipher3` is a hard dep so needs a broken install.
- **Atlas #5 exploitability**: scope mismatch confirmed as behaviour; a model cannot pick the server's cwd, so the risk is operational (admit lands on "not found" or a namesake in `default`).

---

## 4. Documentation that overstates the code

| Quote | Where | Code fact |
|---|---|---|
| "`tombstone()` takes `origin`: a non-principal origin may not delete a reviewed entry … raises `ReviewedEntryError` with nothing changed." | CHANGELOG.md:61-63 | False whenever `content` is passed (F1). |
| "`python -m kibisis admit` refuses when stdin is not a terminal … so the human path cannot be driven through an agent's shell tool or a pipe." | SECURITY.md:121-122; CHANGELOG.md:256-257 "cannot be replayed through an agent's shell tool, a pipe or cron" | `script -qec` / `pty.spawn` from an agent shell passes (F8/#2). SECURITY.md:129-131 then puts "an agent that controls the terminal" out of scope, contradicting :122. README.md:127 is the honest version. |
| "An entry becomes verified once two operating-system accounts have approved it" | README.md:94 | True for the two CLIs only; library `put`/`review_entity` and snapshot import count strings; quorum is per-process (F7). |
| "A tombstoned value is deleted everywhere in its scope. Writing it again is refused, even under another key …" / "including look-alike spellings" / "invisible characters and punctuation removed" | README.md:20, :55, :115, :125 | Survives in `metadata` and `key` (F12); `Mn` marks, Hangul fillers, homoglyphs are accepted (F5). `_vault_crypto.py:49` docstring "NFKC … replaces lookalikes" — NFKC does not fold script homoglyphs. |
| "`verify_audit_chain` … requires a head with a valid MAC that names the last row; … rows removed under a head fails." | SECURITY.md:52-54 | Rows removed under a head pass after a format-1 rewrite and head deletion (F2). |
| "*Re-inserting a forgotten value.* … `put`, restore and `import_snapshot` refuse a value whose digest matches" — under **In scope, caught** for the file writer | SECURITY.md:42, 56-59 | Tombstone table is unsigned; deleting the row re-admits (F4). |
| "A write with `origin="model"` is stored as `candidate` whatever `epistemic_state` it asks for." | SECURITY.md:111; CHANGELOG.md:247; `remember()` docstring | `revoked` is stored as asked (L2). |
| "A capped write cannot replace an entry a person verified or reviewed… it can only propose a replacement with `supersedes_key`." | SECURITY.md:113-114 | It can dispute it by cascade (F6) and mutate its metadata via back-edges (L1). |
| "a revocation recorded with a model or tool origin cannot delete a reviewed entry." | CHANGELOG.md:64-65 | Only `revoked` is gated; model-origin `disputed`/`verified` verdicts are applied (F8). |
| "It refuses to run under a wrong passphrase." (alpha.5 upgrade) | README.md:134 | Refusal comes after `_migrate_integrity` and after SQLCipher conversion; the wrong passphrase first rewrites the file (F9, F13). |
| "Every read checks the signature … and search leaves a failing row out" | SECURITY.md:47-48 | True, silently (F14). |
| "Leases carry fencing tokens that only go up." | README.md:23; `src/lib.rs:10-12` | State-file deletion resets to 1; disclosed only at `file_lease.rs:34-39` (L7). |
| "An on-disk vault will not open without a passphrase unless you pass `allow_plaintext=True`." | SECURITY.md:19; README.md:111 | Also under `KIBISIS_ALLOW_PLAINTEXT=1` and `aml-serve --plaintext`; and *with* a passphrase but no SQLCipher everything but content is plain after one log line (F15). |
| "`okf-export` and `okf-check` … read the vault and never change it." / "`--dry-run` writes nothing." | `__main__.py:3-5`; CHANGELOG.md:102; `okf/importer.py:54` | Direct `SQLiteMemoryVault(args.db)` open migrates/upgrades the file in place (F17). |
| "`--db` … (default: $KIBISIS_DB_PATH)" | `__main__.py:235, :250` | Fallback is `~/.hermes/kibisis/vault.sqlite`, not the per-user dir README:87 and `admit` use (F17). |
| "`kibisis admit` opens the vault, key and scope the way the MCP server and `kibisis-review` do" | CHANGELOG.md:52-55 | Same rules, but cwd-dependent scope (#5); and the OKF CLIs added in the same line still use the old path. |
| "a supersession of one waits as a proposal until a person approves." | README.md:118 | True, but the approver is never told what the approval retires (F18). |
| "… `archive()`, and library calls to `tombstone()` that do not pass an `origin`, are not checked." | README.md:128 | `purge()` is also unchecked (F10). |
| "There is one Kibisis vault per `user_id`, encrypted with SQLCipher." | deploy/aml/README.md:17 | `--plaintext` exists and the deploy README's Method section never mentions it. |
| "A retried request is acknowledged without being stored twice." | deploy/aml/README.md:20-21; CHANGELOG.md:27 | A reused `request_id` with a *different* payload is also acknowledged and dropped (C-9). |
| "`--retention-days`: vaults with no write for this long are deleted." | deploy/aml/README.md:56; CHANGELOG.md:34 | Deletes every `*.kib` path by mtime, vault or not; raises on a directory (F16/C-4). |
| "`--max-inflight`: requests served at once." | deploy/aml/README.md:54 | Bounds body-read+processing after auth, not connections or threads (C-2, S-1). |
| Threat-model table "Who can do what" | SECURITY.md:31-38 | No row for the `aml-serve` network client or an OKF bundle author. Gap, not a false claim. |
| "A journal of every change … in the same transaction as the change." | README.md:22, :116 | Confirmed for put/archive/tombstone/purge/review/import_snapshot; `migrate_plaintext` and `scrub` write no event (README:131 acknowledges only the former). |

---

## 5. Test-suite gaps that would have caught the findings

- `tests/test_atlas_limits_20261105.py:177-190` tests `tombstone(origin=…)` only *without* `content`; every pre-existing `content=` tombstone test passes no origin — F1 slipped through the fix's own test.
- `:192-196` tests only `verdict="revoked"` with `reviewer_origin="model"` — F8.
- `:340-353` (`test_admit_without_db_or_scope_opens_the_mcp_servers_vault_and_scope`) runs under `KIBISIS_SCOPE=proj-a` from the `on_disk` fixture, so the cwd-derived scope is never exercised — atlas #5.
- Quorum lowered to 1 in most fixtures/env (`test_atlas_limits:45,222,341`; `test_mcp_server:113,289`; `test_provenance:67-163`; `test_origin_bound_admission:66,98`; `test_atlas_acceptance:273`; `test_atlas_rubric_hardening:10,111`; persona/recall/supersession tests), so the two-account rule is tested in exactly two places and never on the terminal path (`test_review_cli_from_a_pipe_changes_nothing_and_at_a_terminal_approves` sets `KIBISIS_VERIFICATION_QUORUM=1`).
- Fake terminals: `_Terminal(io.StringIO)` with `isatty() -> True` (`test_atlas_limits:31-33`, `test_mcp_server:24-27`, `mock.patch("sys.stdin", …)` at :210,:262,:284, :303) test the `if`, not a terminal. The real-pty positive path (`test_atlas_limits:78-91`, `test_provenance:138-160`) *is* the bypass and no test says so.
- No test: writes a person's value after an agent `kibisis_forget` (F3); exercises `_cascade_invalidate` with a higher-class dependent (F6) or `_record_edges` onto a reviewed target (L1); round-trips a verified principal entry through snapshot and asserts origin/state (`test_cold_start_reload_integrity.py:25-56` asserts nothing after import — F11); imports a snapshot carrying `attestations`/`human_reviews` (F7); calls `put(…, _review_verdict=True)` from outside the review path (F8); covers `Mn` marks/fillers/homoglyphs, keys or metadata for tombstones (F5, F12); `purge()` on a verified entry (F10); quorum env validation or persistence across processes (F7).
- Journal: nothing pins a format floor or that a headless journal fails once keyed (F2); nothing reconciles `rejected_value_tombstones` with journal `tombstone` events (F4); nothing covers `vault_meta` cell edits (F13, L4); nothing asserts `_readable_content` drops are reported (F14); no wrong-passphrase SQLCipher-conversion test (F9); `tests/journal_vectors.rs` exercises only the strict Rust verifier and nothing checks it agrees with Python's.
- `bindings/python` crate has no Rust tests (L6). No lease state-file/lock-file deletion or clock-step tests (L7).
- AML: no out-of-range/non-finite timestamp, lone surrogate, malformed chunk-size, 401/404-with-body, decoy-file retention, or different-payload-retry tests; `assert AMLHandler.timeout` would pin a socket timeout. OKF: no test pins the default `--db` against `config.default_db_path()` or `KIBISIS_ALLOW_PLAINTEXT`; the dry-run test compares a logical snapshot, so the on-open migration is invisible.

---

## 6. Coverage

**Read (at 1299c28):** `vault.py` (constructor 211-500, `_put` 721-1172, review/snapshot/archive/persona 1200-1683), all six `_vault_*` mixins (`_vault_tombstone.py` full, `_vault_review.py` full, `_vault_crypto.py` 45-71/180-420, `_vault_audit.py` 99-243, `_vault_search.py` 188-200/573-589/838-860, `_vault_snapshot.py` 43-291), `crypto.py` 60-200, `config.py` full, `_operator.py` full, `review.py` full, `__main__.py` full, `mcp_server.py` (tool schema, dispatch, recall, forget, 60-66/208-225/257-269/354/466-477/600-606), `lease.py` full, `aml_adapter.py` full, `okf/export.py` (gate-cmd and bundle writer), `okf/importer.py` full, `src/lib.rs` 1-30/640-730/1144-1165 + full grep, `src/journal.rs` 236-310 + grep, `src/file_lease.rs` 1-375/475-520, `bindings/python/src/lib.rs` full, README.md, SECURITY.md, CHANGELOG.md (AML/OKF/trust entries), deploy/aml/README.md, Dockerfile, pyproject.toml.

**Not reached:** `okf/check.py`, `okf/frontmatter.py`, `okf/profile.py` (call sites only); `keys.py` (`_read_keyfile`, `resolve_passphrase`); `_vault_search.py` drain-queue correctness under SQLCipher; the Rust vault (`lib.rs` 640-1230 beyond lock handling); SQLCipher-mode behaviour beyond F9 (all Python demonstrations run without SQLCipher, the mode SECURITY.md:63-65 assumes); multi-process lease contention; macOS-only paths; Docker image build. Rust bindings were not rebuilt (`maturin develop` skipped: Rust is byte-identical to alpha.15 and the venv's `kibisis_native` 0.1.0a15 is code-equivalent).

**Ran:**
- Baseline, start: `ARGUS_LEDGER_PATH=$TMPDIR/argus.jsonl PYTHONPATH=src …/.venv/bin/python -m pytest -q -p no:cacheprovider` → **588 passed, 4 skipped** (matches the stated baseline).
- `cargo test` (`CARGO_TARGET_DIR=/opt/data/cache/scratch/kib-review-target`) → lib 23 passed, `tests/journal_vectors.rs` 8 passed, doc-tests 2 passed; 33 total, 0 failed. The `bindings/python` crate is a separate crate not covered.
- Review tests, per area (all re-run by the parent, not only by the writing subagent):
  - `tests/review_a1_*.py` → 24 passed, 21 xfailed (`--runxfail`: 21 failed, 24 passed — the raw findings).
  - `tests/review_a2_*.py` → 54 passed (`script(1)` present, no skips).
  - `tests/review_b_*.py` + `review_b2_misc.py` → 58 passed.
  - `tests/review_c_aml.py` + `review_c_okf.py` → 28 passed.
- Final full suite with review tests added (`-o 'python_files=test_*.py review_*.py' tests`, because `testpaths`/default `python_files` do not collect `review_*.py`): **752 passed, 4 skipped, 21 xfailed, 60 subtests passed in 164 s** — 588 baseline unchanged + 164 review tests (21 strict xfails = the A1 findings). Run without the override the suite still reports exactly 588 passed, 4 skipped, confirming nothing existing was touched.

**Method note:** four parallel reviewers (A1 write boundary, A2 review doors/quorum/tombstones, B crypto/journal/concurrency/Rust, C AML/OKF/docs); the parent re-ran every cited test and independently verified F1, F2, F5, F6, F8 and C-4 against the source lines cited before accepting them.

---

## The five things to fix before the next release, in order

1. **Run the origin guard on every `tombstone()` path and on `purge()`** (F1, F10, F19): look the target up first, run `protected()` before any branch, refuse wildcard scope for non-principal origins. The atlas #1 fix is otherwise dead code for the documented call form.
2. **Make the journal reject a format downgrade and bind the tombstone table to it** (F2, F4, F13): once keyed, refuse rows with `format < 3`, always require a head, HMAC tombstone rows (or rebuild them from the journal at open), and run the key check *before* any migration or SQLCipher conversion (also fixes the F9 data-loss path).
3. **Close the non-MCP routes to `verified` and `disputed`** (F7, F8, F6): the vault, not the caller, resolves the attester; refuse `"principal"`/`None` signers; `review_entity` refuses any non-principal origin for every verdict; make `_review_verdict`/`_trusted_metadata` private; cascades and back-edges never change a higher-class or reviewed row; persist the quorum in `vault_meta`.
4. **Give tombstones an origin class and a lift verb, and widen the canonical fold** (F3, F5, F12): an agent must not be able to permanently blacklist a fact for a person; fold `Mn`/default-ignorables/confusables; check `key` and metadata leaves against tombstones.
5. **Route every CLI through `config.open_vault`, add a read-only open, and harden `aml-serve` input handling** (F17, F16, F15): one default vault path everywhere; `okf-export`/`--dry-run`/`okf-check` cannot rewrite the file; timestamps/chunk sizes/surrogates → 4xx; retention verifies it is deleting a vault; socket timeout on the handler; explicit opt-in before opening a passphrase-protected vault without SQLCipher. Then rewrite SECURITY.md:121-122 and CHANGELOG:256-257 to say what README:127 already says about the TTY check.
