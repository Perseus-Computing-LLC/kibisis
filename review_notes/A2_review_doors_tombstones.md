# A2 — Review doors (TTY, uid identity, quorum) and tombstones — kibisis v0.1.0-alpha.16 @ 1299c28

## 1. Restatement

- Task: adversarially review the person-only doors (`kibisis-review` verdicts, `kibisis admit`): what the TTY check and the uid-derived identity stop, every route by which one account reaches `KIBISIS_VERIFICATION_QUORUM`, and whether a tombstoned value can come back or survive the purge. Nothing under `src/` or existing tests was changed; only `tests/review_a2_*.py` and this file were added in the worktree.
- Assumptions (from the brief): the agent (possibly with a shell as the same OS user, possibly MCP-only) and the MCP client are untrusted; the person at a terminal is trusted. Every claim below is backed by a test that passed at this commit; the docstring of each test says whether a pass means "gap present" (INSECURE) or "closed" (SECURE / control).
- Evidence basis: 54 new tests (3 files, all passing), 28 existing tests in `tests/test_atlas_limits_20261105.py` (passing), 4 scratch probes whose output is quoted below.

Commands (worktree root; `VENV=/opt/data/work/telarch-suite/.venv/bin/python`):
```
ARGUS_LEDGER_PATH=$TMPDIR/argus_a2.jsonl PYTHONPATH=src $VENV -m pytest -q -p no:cacheprovider \
  tests/review_a2_review_doors.py tests/review_a2_quorum.py tests/review_a2_tombstones.py
# -> 54 passed in 10.57s
ARGUS_LEDGER_PATH=$TMPDIR/argus_a2.jsonl PYTHONPATH=src $VENV -m pytest -q -p no:cacheprovider tests/test_atlas_limits_20261105.py
# -> 28 passed (82 passed when run together, 16.97s)
```

## 2. Verdict on atlas fixes #2 and #3

### #2 "kibisis-review approve/dispute/reject need a TTY on stdin" — **closed as stated, but the stated thing is a speed bump, not a door**

- The check is real and is in the right place in the CLI: `review.py:99-105` calls `require_terminal` before `open_vault()`; `__main__.py:36-41` does the same for `admit`. A plain pipe / `stdin=/dev/null` run exits 3 and writes nothing (`review_a2_review_doors.py::test_control_plain_pipe_is_refused[*]`).
- It is a `sys.stdin.isatty()` test (`_operator.py:32-33`). Any shell, including an agent's shell tool with stdin on `/dev/null`, allocates a pseudo-terminal in one line and the verdict lands, verified by the OS account the agent runs as:
  - `python -c 'import pty,sys; sys.exit(pty.spawn(sys.argv[1:]))' python -m kibisis.review approve c k` → rc 0, `c:k is now verified (account hermes)` (`test_pty_spawn_from_a_non_tty_shell_drives_the_verdict[review-approve|admit]`)
  - `script -qec '<cmd>' /dev/null` → rc 0, same result (`test_script_qec_from_a_non_tty_shell_drives_the_verdict[*]`)
  - The project's own tests use exactly this technique as the "happy path" (`tests/test_atlas_limits_20261105.py:78-91 _run(..., tty=True)`, `tests/test_provenance.py:138-145`), i.e. the suite demonstrates the bypass every run.
- The check exists only in the two CLI wrappers. `vault.review_entity` and `vault.admit` (`_vault_review.py:302-342, 365-399`) have no terminal or account check; a Python process with stdin on `/dev/null` calls `admit(reviewer='not-an-account', reviewer_origin='user')` and mints `verified` (`test_review_entity_and_admit_have_no_terminal_check_at_all`).
- README.md:127 states this honestly ("Neither is an authentication boundary … an agent with such a terminal included"). SECURITY.md:121-122 and CHANGELOG.md:256-257 do not (see §5).

### #3 "quorum identity is the OS account from os.getuid(); --reviewer is a label" — **closed for the CLI path only; the quorum itself still counts strings**

- In the CLIs: `account_identity()` (`_operator.py:39-57`) ignores `USER`/`LOGNAME` (confirmed, existing test `test_account_identity_ignores_user_and_logname`); `--reviewer` is stored as `reviewer_label` and never attests (`_vault_review.py:430-431, 474-476`; `review_a2_quorum.py::test_c_reviewer_label_never_counts`, and the existing `test_one_account_with_two_reviewer_names_is_one_approval`).
- Everywhere else the quorum is a count of distinct strings supplied by the caller: `reviewer_id` in `review_entity` (`_vault_review.py:474-479`), `author_id`/`principal_id`/literal `"principal"` in a principal-class `put` asking for `verified` (`vault.py:945-957`), and `attestations` carried in a snapshot (`_vault_snapshot.py:276-291`, `_trusted_metadata=True`). All reachable from any Python process holding the passphrase — which is the same OS user the agent's shell runs as. See findings F2–F5.
- Pre-a15 records: `login_name()` (`config.py:60-67`, `getpass.getuser()`) honours `LOGNAME/USER/LNAME/USERNAME`; `account_identity()` does not. The two therefore disagree whenever such a variable is set, and an a14 approval stored under a typed name plus one a16 approval by the same person's account is two attestations → verified by one person (`test_one_person_pre_a15_typed_name_plus_post_a15_account_reaches_quorum_two`, `test_login_name_follows_env_while_account_identity_does_not`). README.md:127 half-documents this ("still count as that name") without saying the sum crosses the quorum.
- Via MCP only: no route. The tool list is `remember/recall/forget/verify_ledger/health`; writes are `origin="model"`, authority arguments are refused, reserved metadata keys are dropped into `agent_metadata` (`test_g_control_mcp_exposes_no_review_admit_or_put_with_origin_user`).

## 3. Findings (most severe first)

Severity scale: **High** = reachable by the threat model's agent and defeats a documented guarantee; **Medium** = reachable with Python/shell as the same user, or defeats a documented guarantee partially; **Low** = hygiene / documentation / needs a precondition outside the threat model.

### F1 — Tombstone canonical form misses invisible nonspacing marks and homoglyphs — **High**
- Where: `src/kibisis/_vault_crypto.py:45-71` (`canonicalize_text`: strips only `Cf`/`Cc`, `P*`/`S*`, whitespace; NFKC+casefold).
- Problem: a value a person rejected comes back, through the agent's own MCP `remember`, by inserting one invisible character of category `Mn` (U+FE0F variation selector, U+034F combining grapheme joiner, U+180B Mongolian FVS) or the Hangul filler U+3164 (`Lo`, renders as nothing), or by one script homoglyph (Cyrillic `а`, dotless `ı`). Recall then returns it. README.md:20/55/125 promise that look-alikes are refused.
- Repro: `tests/review_a2_tombstones.py::test_invisible_nonspacing_marks_and_homoglyphs_bring_a_tombstoned_value_back[*]` (6 cases) and `::test_invisible_mark_variant_is_accepted_through_the_mcp_remember_tool`; controls `::test_control_case_punctuation_cf_and_compatibility_variants_are_refused[*]` (4 cases) show case, punctuation, ZWSP (`Cf`), fullwidth and NBSP *are* folded.
- Actual output (probe `a2_probe1.py`):
  ```
  refused     upper+punct (control)            refused     zero-width space U+200B (Cf, control)
  ACCEPTED    variation selector U+FE0F (Mn)    ACCEPTED    combining grapheme joiner U+034F (Mn)
  ACCEPTED    combining tilde overlay U+0334    ACCEPTED    Hangul filler U+3164 (Lo -> NFKC U+1160)
  ACCEPTED    Mongolian FVS1 U+180B (Mn)        ACCEPTED    Cyrillic a U+0430 homoglyph
  ACCEPTED    Latin small dotless i U+0131      refused     fullwidth (control)
  ```
- Fix: in `canonicalize_text` also drop categories `Mn`/`Me` (and `Mc`) after NFKC, drop the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) and other default-ignorable code points (`Default_Ignorable_Code_Point`), and apply a confusables fold (UTS #39 skeleton) for the Latin/Cyrillic/Greek block before hashing. State plainly in README that paraphrase and arbitrary homoglyph evasion remain out of scope.

### F2 — Snapshot import trusts `attestations`/`human_reviews` from the file; one real approval then mints `verified` — **Medium**
- Where: `src/kibisis/_vault_snapshot.py:276-291` (`put(..., _trusted_metadata=True)`), `_vault_review.py:474-479` (attestations accumulate), `vault.py:188-196` (`_is_reviewed` trusts `human_reviews`), `_vault_snapshot.py:183-189` (manifest is optional: a file without `manifest_sha256` is accepted).
- Problem: anyone who can get a snapshot imported (the operator restoring a backup the agent could write to, or a Python caller) can pre-load `attestations: ["ghost"]`; the next single real approval reaches quorum 2. A forged `human_reviews` list makes `_is_reviewed` true, which locks the entry against model rewrites and makes MCP recall print `reviewed_by="ghost"`.
- Repro: `tests/review_a2_quorum.py::test_d_snapshot_import_trusts_forged_attestations_so_one_real_approval_mints_verified`, `::test_d_snapshot_import_trusts_forged_human_reviews_which_lock_the_entry_against_the_agent`; control `::test_d_control_one_approval_on_an_unforged_import_stays_candidate`.
- Actual output (probe `a2_probe4.py`): `imported attestations: ['ghost'] state candidate` → `one real approval -> verified ['ghost', 'real-person']`; `control, no forged attestation, one approval -> candidate`.
- Fix: on import, drop `attestations`, `verification_pending` and `human_reviews` unless the snapshot's HMAC `digest_key_id` matches this vault *and* the manifest verifies; or re-derive `epistemic_state` from the imported review history under the current quorum instead of trusting the stored lists.

### F3 — Principal `put` attests as free-text `author_id`; two strings from one process reach quorum — **Medium**
- Where: `src/kibisis/vault.py:945-957` (`signer = author_id or principal_id or "principal"`), `vault.py:894-895` (origin-less rewrite inherits the stored principal class).
- Problem: atlas fix #3 bound only the CLI's reviewer to the uid. `put(origin="user", epistemic_state="verified", author_id=X)` is one attestation per distinct `X`; a write with no `author_id` attests as the literal string `"principal"`, which then counts as a person distinct from every real account. An origin-less rewrite of a principal row with a new `author_id` also attests, and leaves the entry both `verified` and `trust_capped_from="verified"`.
- Repro: `tests/review_a2_quorum.py::test_b_two_user_writes_with_different_author_ids_reach_quorum`, `::test_b_user_write_with_no_author_id_signs_as_the_literal_principal`, `::test_b_origin_less_rewrite_of_a_principal_row_adds_an_attestation_and_keeps_a_cap_marker`; control `::test_b_control_model_and_tool_writes_never_attest`. Same for `review_entity`: `::test_g_review_entity_counts_any_two_strings`.
- Actual output (probe `a2_probe2.py`): `after alice: candidate ['alice'] {'have': 1, 'need': 2}` → `after bob: verified ['alice', 'bob']`; `candidate ['principal']` → `+ alice review: verified ['principal', 'alice']`; origin-less rewrite: `verified ['alice', 'mallory'] verified` (last token = `trust_capped_from`).
- Fix: make the vault, not the caller, the source of the attestation identity: have `put`/`review_entity` take an `attester` that the library resolves (e.g. `account_identity()`) when `reviewer_origin`/`origin` is `user`, and refuse `"principal"` as a signer. At minimum, do not count an attestation when `author_id` is absent, and clear `trust_capped_from` when the quorum is met.

### F4 — `KIBISIS_VERIFICATION_QUORUM` is a per-process setting, not a property of the vault — **Medium**
- Where: `src/kibisis/vault.py:267-271` (read from env at `__init__`, never persisted); `review.py:106-111` and `__main__.py:44-49` catch only `ConfigError`/`EncryptionRequiredError`.
- Problem: (a) a process that opens the vault with quorum 1 mints `verified` with one approval, and a quorum-2 process reads it back as verified with nothing recording which quorum applied; (b) a value of `0`, `-1`, `abc`, `2.0` or empty raises `ValueError` out of the constructor, so the review CLI (`list` included, no TTY needed) and the MCP server die with a traceback until the variable is unset — whoever can set the operator's environment (shell rc files, MCP launcher config) denies review; (c) `" 1 "` and `"1_0"` are accepted silently.
- Repro: `tests/review_a2_quorum.py::test_f_quorum_is_a_per_process_setting_not_a_vault_property`, `::test_f_env_quorum_values_that_crash_every_opener[*]` (5), `::test_f_review_cli_list_crashes_with_a_traceback_on_a_bad_quorum_value`, `::test_f_env_quorum_values_that_lower_or_change_the_quorum[*]` (3).
- Actual output: `quorum=1 process: verified ['solo']` / `read back in quorum=2 process: verified`; `'abc' -> ValueError: invalid literal for int() with base 10: 'abc'`; CLI `list` → `rc 1 ... ValueError: invalid literal for int() with base 10: 'abc'`.
- Fix: store the quorum in `vault_meta` on first open and refuse (or require an explicit person-run command) to lower it; record `quorum_at_verification` in the entry; validate the variable in `config.py` and raise `ConfigError` with a message, not a traceback.

### F5 — The TTY guard is bypassed by any shell that can open a pty; the guarded functions have no guard — **Medium** (documented in README, overstated in SECURITY/CHANGELOG)
- Where: `src/kibisis/_operator.py:25-36`, `review.py:99-105`, `__main__.py:36-41`; `_vault_review.py:302-342, 365-399` (no check).
- Problem / repro / output: see §2 (#2). `pty rc 0 c:k is now verified (account hermes)`, `script rc 0 c:k is now verified (account hermes)`; direct `admit(reviewer='not-an-account')` → `verified`, `attestations == ['not-an-account']`.
- Fix: do not present `isatty` as a control against "an agent's shell tool"; if a real boundary is wanted, require something the agent's uid cannot produce (a second uid via `sudo -u reviewer`, a passphrase-file the agent cannot read, or an out-of-band confirmation), and say so.

### F6 — A tombstoned value survives, and can be re-stored, in `metadata` and in the `key` column; MCP recall prints keys — **Medium**
- Where: `src/kibisis/_vault_tombstone.py:73-101` (`_value_copies` digests `content` only), `vault.py:1066-1079` (write-time check digests `content` only), `mcp_server.py:466-477` (agent metadata stored under `agent_metadata`), `mcp_server.py:257-269` (recall prints `key=`).
- Problem: the agent stores the sentence as `metadata.note` or as the entry `key`; after the person rejects the content entry, both copies stay, and new copies are accepted. The key copy is shown to the model by `kibisis_recall`. README.md:20 says "deleted everywhere in its scope".
- Repro: `tests/review_a2_tombstones.py::test_value_kept_in_agent_metadata_survives_the_tombstone_and_can_be_rewritten_after_it`, `::test_value_used_as_a_key_survives_and_is_shown_by_mcp_recall`; controls `::test_control_copies_in_other_categories_and_archived_rows_are_purged`, `::test_control_other_scopes_keep_the_value_unless_the_tombstone_is_global`.
- Actual output (probe `a2_probe4.py`): `metadata copy still present: {'note': 'Use tabs for indentation'}`; `key copy still present: ['Use tabs for indentation', 'side']`; `recall shows forgotten value in key attr: True`; `post-tombstone write of value in metadata accepted: True`; `positive control, value as content refused: True`.
- Fix: digest and check `key` and every string leaf of `metadata` (at least `agent_metadata`) against tombstones on write and in `_value_copies`; or cap key length/charset on the MCP path and strip `agent_metadata` on purge.

### F7 — `purge()` has no origin check and leaves no tombstone — **Low** (library only)
- Where: `src/kibisis/_vault_tombstone.py:25-52`.
- Problem: `tombstone(origin="model")` refuses a verified entry; `purge()` takes no `origin` and deletes it outright, journaled as `purge` with whatever `author_id` the caller passes. README.md:128 lists `archive()` and origin-less `tombstone()` as unchecked but not `purge()`. Not exposed over MCP.
- Repro: `tests/review_a2_tombstones.py::test_purge_has_no_origin_check_and_leaves_no_tombstone`. Output: `tombstone(model) refused (control)` / `purge() returned True -> entry now None` / `tombstones after purge: []`.
- Fix: give `purge` the same `origin` parameter and `protected()` check as `tombstone`, and name it in README's limits.

### F8 — Snapshot round-trip demotes a legitimately verified entry — **Low** (functional, fail-safe direction)
- Where: `src/kibisis/_vault_snapshot.py:276-291` (no `origin` in the snapshot or the `put`), `vault.py:816-825`.
- Problem: a verified `origin="user"` entry exported and imported comes back `candidate`, origin `unknown`, class `external`, `trust_capped_from="verified"`. The one round-trip test (`tests/test_cold_start_reload_integrity.py:25-56`) never asserts the state after import. Combined with F2 this means the import both *loses* real verification and *keeps* forged attestations.
- Repro: `tests/review_a2_quorum.py::test_d_snapshot_round_trip_demotes_a_legitimately_verified_entry`. Output: `before export: verified user` → `after import: candidate origin unknown class external capped verified`.
- Fix: export `origin` and pass it (as `import`) on restore, or re-derive the state from the review history.

### F9 — `review_entity(reviewer_id=None)` records a review without an attestation and locks the entry — **Low**
- Where: `_vault_review.py:421-432, 475`. A `None` reviewer appends to `human_reviews` (so `_is_reviewed` is true and model rewrites are refused) while attesting nothing (`{'have': 0, 'need': 2}`).
- Repro: `tests/review_a2_quorum.py::test_g_review_entity_with_reviewer_id_none_records_a_review_but_no_attestation`.
- Fix: require a non-empty `reviewer_id` for `reviewer_origin="user"`.

Closed routes (with the test that shows it):
- (a) same account admit + review = one attestation: `test_a_same_reviewer_id_twice_is_one_attestation`.
- (c) `--reviewer` label never counts: `test_c_reviewer_label_never_counts` + existing atlas tests.
- (e) OKF import: model origin, reserved keys dropped, tombstone check applies: `test_e_okf_importer_writes_are_model_origin_and_drop_reserved_keys`, `test_control_okf_style_model_import_write_is_refused`.
- MCP-only agent has no quorum route: `test_g_control_mcp_exposes_no_review_admit_or_put_with_origin_user`.
- Snapshot import re-checks tombstones and keeps existing ones: `test_control_snapshot_import_refuses_a_tombstoned_value_and_import_keeps_tombstones`.
- No public method removes a tombstone row (scrub, purge, re-tombstone under the same key, `clear_existing` import): `test_no_public_method_removes_a_tombstone_row`. `INSERT OR REPLACE` keys on `(category, key, value_sha256, scope)` (`vault.py:630`), so a second tombstone under the same key does not replace the first.
- Search does not surface a revoked entry before `scrub()` (row delete cascades through triggers): `test_control_search_does_not_surface_a_revoked_entry_even_before_scrub`.
- Copies in other categories and archived rows are purged; scope-bound tombstones stay in scope; `'*'` applies everywhere.

## 4. Suspected, unconfirmed

- (h) uid/name drift: if the operator's account is renamed, or a container is started with a numeric `--user` once and a named user later, `account_identity()` returns `uid-<n>` on one run and the passwd name on another; two attestations from one person. Not reproduced (would need a controllable passwd database); `test_account_identity_falls_back_to_uid_string_without_passwd` only pins the fallback string.
- Agent control of the operator's environment: F4(b)/(a) and the `KIBISIS_VERIFICATION_QUORUM=1` lowering depend on the agent writing to the person's shell rc or MCP launcher config. Same OS user makes this plausible; not demonstrated here.
- Tombstone file-level residue: `scrub()` is run by the review CLI's `reject` but not by `review_entity(verdict="revoked")` callers; FTS segments and WAL may keep the plaintext tokens of a passphrase-less vault until scrub. Not examined at the byte level.
- Snapshot `tombstones` list as a denial-of-service: a crafted snapshot with the vault's own keyed digests could add tombstones for a person's verified facts (`INSERT OR IGNORE`, `_vault_snapshot.py:216`). Requires the passphrase; not reproduced.

## 5. Documentation that overstates the code

- SECURITY.md:121-122 — "`python -m kibisis admit` refuses when stdin is not a terminal (`__main__.py` , exit 3), so the human path cannot be driven through an agent's shell tool or a pipe." — An agent's shell tool drives it with `script -qec` or `pty.spawn` (F5). SECURITY.md:129-131 later puts "an agent … that controls the terminal" out of scope, which contradicts line 122.
- CHANGELOG.md:256-257 — "so the human path cannot be replayed through an agent's shell tool, a pipe or cron." — same overstatement.
- README.md:20 — "A tombstoned value is deleted everywhere in its scope. Writing it again is refused, even under another key …" — survives in `metadata` and in the `key` column (F6); `Mn`/homoglyph variants are written (F1).
- README.md:55 — "# Refused under any category or key in the scope, including look-alike spellings:" and README.md:125 "They stop exact and look-alike repeats of a value" — invisible marks and homoglyphs are not stopped (F1).
- README.md:115 — "(… invisible characters and punctuation removed …)" — only `Cf`/`Cc` invisibles; `Mn` invisibles and the Hangul filler are kept (F1).
- README.md:94 — "An entry becomes verified once two operating-system accounts have approved it" — true only for the two CLIs; library and snapshot paths count strings (F2, F3), and the quorum is whatever the opening process says (F4).
- README.md:127 — "Approvals recorded before 0.1.0a15 under a typed `--reviewer` name still count as that name." — accurate but incomplete: one person's old typed name plus their account today reaches the quorum of two.
- README.md:128 — "… but `archive()`, and library calls to `tombstone()` that do not pass an `origin`, are not checked." — `purge()` is also unchecked (F7).
- `_vault_crypto.py:49` docstring — "NFKC normalization (replaces lookalikes …)" — NFKC does not fold script homoglyphs.

## 6. Test-suite gaps (tests that pass for the wrong reason, or do not test the claim)

- Quorum lowered to 1 in fixtures/env, so one approval "verifies" and the two-account rule is never exercised except in two tests: `tests/test_atlas_limits_20261105.py:45` (fixture), `:222`, `:341`; `tests/test_mcp_server.py:113, :289`; `tests/test_provenance.py:67, :88, :109, :163`; `tests/test_origin_bound_admission.py:66, :98`; `tests/test_atlas_acceptance.py:273`; `tests/test_atlas_rubric_hardening.py:10, :111`; `tests/test_persona_slot.py`, `test_recall_layer_kr345.py`, `test_supersession_kr2.py`, `test_temporal_supersession.py`, `test_ranked_search.py`, `test_term_index_kd.py`, `test_fallback_integrity.py`, `test_review_2026_10_28.py:130-132`, `test_negative_probe_abstention.py` (all `verification_quorum=1`).
- Fake terminals: `_Terminal(io.StringIO)` with `isatty() -> True` in `tests/test_atlas_limits_20261105.py:31-33` and `tests/test_mcp_server.py:24-27`; `mock.patch("sys.stdin", _Terminal(""))` at `test_atlas_limits_20261105.py:210, :262, :284`, `test_mcp_server.py:303`. These test the `if`, not a terminal.
- Real pty used as the *positive* path, which is the bypass: `tests/test_atlas_limits_20261105.py:78-91`, `tests/test_provenance.py:138-160`. No test states that this is an agent-reachable path.
- `test_review_cli_from_a_pipe_changes_nothing_and_at_a_terminal_approves` (`:221-236`) sets `KIBISIS_VERIFICATION_QUORUM=1`, so it cannot see whether the terminal path respects the quorum.
- `tests/test_cold_start_reload_integrity.py:25-56` never asserts `epistemic_state`/`origin` after `import_snapshot` (F8 is invisible to it); no test imports a snapshot carrying `attestations` or `human_reviews` (F2).
- Tombstone look-alike tests cover case/punctuation/whitespace only (e.g. `test_atlas_limits_20261105.py:139-146` lower-case copy); nothing covers `Mn` marks, fillers, homoglyphs, keys or metadata (F1, F6).
- `test_account_identity_ignores_user_and_logname` is a positive control for `account_identity` but there is no test that `login_name()` (still used by `aml_adapter`, `test_aml_adapter.py:439`) *does* follow env, or that the two agree for the records both write.
- No test for `purge()` on a verified entry, for `KIBISIS_VERIFICATION_QUORUM` non-integer handling, or for quorum persistence across processes.

## 7. Coverage

Files read (line ranges) at 1299c28:
- `src/kibisis/_operator.py` 1-57 (all); `src/kibisis/review.py` 1-150 (all); `src/kibisis/config.py` 1-149 (all); `src/kibisis/__main__.py` 1-100.
- `src/kibisis/_vault_review.py` 1-120, 280-505 (admit, review_entity, _review_locked); not 121-279, 506-670 (remember/admit_candidate/evaluate_abstention/cascade internals — `_cascade_invalidate` 205 not read).
- `src/kibisis/vault.py` 72-130 (reserved keys, quorum default), 186-200 (`_is_reviewed`), 215-274 (`__init__`), 615-655 (tombstone schema), 721-975 (`_put` head through supersession start), 1060-1080 (tombstone check), 1200-1270 (`put` wrapper); `archive` 1533 signature only.
- `src/kibisis/_vault_tombstone.py` 1-304 (all); `src/kibisis/_vault_crypto.py` 40-84 (`canonicalize_text`, `value_digests`); `src/kibisis/_vault_snapshot.py` 156-200, 256-303; `src/kibisis/okf/importer.py` 388-427; `src/kibisis/_vault_search.py` grep only (index tables, triggers 703-830); `src/kibisis/mcp_server.py` 239-283 (`fence_recall`) + grep of tool names and write path.
- Tests: `tests/test_atlas_limits_20261105.py` 1-358 (all); `tests/conftest.py` (all); `tests/test_cold_start_reload_integrity.py` 22-56; `tests/test_provenance.py` 138-200 (excerpt); `tests/test_mcp_server.py` 283-310 (excerpt); grep over `tests/` for `verification_quorum=1`, `isatty`, `getuid`, `import_snapshot`.
- Docs: README.md 20, 55, 91-94, 111-134 (grep + excerpts); SECURITY.md 50-62, 115-150; CHANGELOG.md 44-51, 81, 219-220, 255-258, 289 (grep).

Tests run:
- `tests/review_a2_review_doors.py` — 10 passed; `tests/review_a2_quorum.py` — 24 passed; `tests/review_a2_tombstones.py` — 20 passed (54 total, 10.57s).
- `tests/test_atlas_limits_20261105.py` — 28 passed (with the three above: 82 passed, 16.97s).
- Scratch probes (outside the worktree, `$TMPDIR/a2_probe{1,2,3,4}.py`), output quoted in §3.

Not reached: Rust crate canonical fold (README's "narrower than Python" claim not measured); `_cascade_invalidate`; `aml_adapter` use of `login_name`; `okf-import` CLI end-to-end (importer `_write` path covered by equivalent `put` calls only); byte-level residue after `revoked` without `scrub`; uid-rename scenario (§4).
