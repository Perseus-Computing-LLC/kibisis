# Area A: write trust boundary, review doors and quorum, tombstones

Entries for the parent to merge into CHANGELOG.md (no version bump here).

## Fixed

- **F1** `tombstone(content=...)` looked up nothing and skipped the origin check. It now fetches the
  row by category/key/scope first and runs the protected-entry check before any branch; when `content`
  is given and does not match the stored value, nothing is deleted (a tombstone of the given value is
  still recorded for the scope).
- **F19** A non-principal origin may not tombstone with `scope="*"` (`PermissionError`, journaled).
- **F10** `purge()` takes `origin=` (default `None` keeps the library contract) and runs the same
  protected-entry check as `tombstone`; refusals are journaled as `refuse` events.
- **F3** Tombstones carry `origin_class` (new column; rows from before the column are `principal`).
  A write of a higher class than a tombstone's class lifts it (journaled `tombstone_lifted`) and
  succeeds; a principal-class tombstone blocks everyone. `kibisis-review lift CATEGORY KEY
  [--digest PREFIX]` (terminal-gated, journaled) is the person's way past a principal-class
  tombstone (round 2: the library method behind it takes an origin and refuses agents).
  `kibisis_forget` through MCP stays a tombstone, now model-class, so an agent cannot permanently
  deny a value a person wants to keep.
- **F5** `canonicalize_text` also drops `Mn`/`Me` marks and Default_Ignorable code points (round 2:
  `Mc` kept, Hangul fillers become spaces)
  (U+FE0F, U+034F, U+180B-D, Hangul fillers U+115F/U+1160/U+3164/U+FFA0, zero-width joiners) and
  folds a built-in table of Latin/Cyrillic/Greek homoglyphs (Cyrillic а е о р с у х і ј ѕ, Greek α ο ν,
  dotless ı). The Rust fold is unchanged (README says so). Paraphrase remains out of scope.
- **F12** The entry key and every string leaf of the metadata (`agent_metadata` included) are
  digested against tombstones on write and in `_value_copies` (purge/scrub remove such rows).
  The MCP `kibisis_remember` tool caps keys at 128 characters.
- **F6** `_cascade_invalidate` triggered by a non-principal write no longer changes the state of a
  dependent of a higher origin class or one with `human_reviews`; it appends an
  `invalidation_notice` to its metadata and the cascade does not continue through it.
- **L1** `_record_edges` stores a back-edge on the target only when the target is of the writer's
  class or below; otherwise the edge lives on the writer's row alone.
- **F8** `review_entity` raises `PermissionError` for any non-principal `reviewer_origin`, every
  verdict, and records nothing. `_review_verdict` / `_trusted_metadata` are gone from the public
  `put()` / `put_batch()`; the review write goes through the private `_write_review`, and
  `put_batch` raises `TypeError` for dict items carrying arguments `put()` does not take.
- **F9** `review_entity(reviewer_id=None)` raises `ValueError` and records no review.
- **F7** Attester resolution: a user-origin write or review attests as the operating-system
  account running the process (`kibisis._operator.account_identity()`), never as `author_id` /
  `reviewer_id`. `attester=` is honoured only on a vault opened with `trust_caller_identity=True`
  (embedder-only, documented); the literal `principal` and an empty name are never signers.
  `verification_quorum` is persisted in `vault_meta` on first open: a lower request raises
  `ConfigError`, a higher one is stored, a process that names no quorum adopts the vault's;
  verified entries record `quorum_at_verification`. `KIBISIS_VERIFICATION_QUORUM` is validated in
  `config.py` (`parse_verification_quorum`: strip, positive ASCII decimal only; `1_0`, `2.0`, `abc`,
  `''`, `0` raise `ConfigError`), and `kibisis.review` / `kibisis admit` print it in one line
  (exit 2) instead of a traceback. `import_snapshot` drops `attestations`, `verification_pending`
  and `human_reviews` unless the snapshot is this vault's (same `digest_key_id`, or its new
  passphrase-sealed `trust_seal` opens here) AND `manifest_sha256` is present and verifies; the
  drop is journaled and `epistemic_state` is re-derived from what survives (round 3: the seal alone
  proves it; `digest_key_id` is a public label).
- **F11** Snapshots export `origin` and `author_id` per entity and the import passes them on, so a
  verified principal entry restored into its own vault stays verified and principal (round 2: an
  agent's entry a person verified too).
- **L2** `_put` caps every non-candidate `epistemic_state` (including `revoked`) to `candidate` for
  non-principal origins, recording `trust_capped_from`.
- **L3** `author_id`, `last_verified_at`, `supersession`, `proposed_supersedes` and `slot` are
  principal-only top-level metadata keys (`PRINCIPAL_METADATA_KEYS`); non-principal writes have
  them moved under `agent_metadata`. `archive()` and `set_persona_slot()` take `origin` and run the
  protected-entry check.
- **F18** `kibisis-review list` prints `approving retires <cat>:<key> (<state>)` beside a candidate
  that carries `proposed_supersedes`, and `approve` repeats it. Forget requests are recorded as
  their own journal action (`forget_request`) and listed by an SQL filter on it, so a flood of
  other `refuse` events cannot hide them.
- **Atlas #5 residual** `kibisis admit` and `kibisis-review` print the resolved vault path and
  scope on every run; when the entry is not in that scope they list the scopes that hold
  `category:key` so the person can pass `--scope` / set `KIBISIS_SCOPE`.
- Docs: README (review/quorum, tombstone fold limits, forget/lift, archive/purge/persona checks)
  and SECURITY.md (agent-side writer section, TTY-check wording, attester and quorum rules, snapshot
  import rule) updated to match.

## Changed behaviour callers may notice

- `put(..., _review_verdict=..., _trusted_metadata=...)` is a `TypeError`.
- `review_entity` without `reviewer_id`, or with a non-user `reviewer_origin`, raises.
- Library `put(origin="user", epistemic_state="verified")` from one process is one attestation
  whatever `author_id` says; two accounts (or `trust_caller_identity=True` + `attester=`) reach a
  quorum of 2.
- Opening an existing vault with a smaller `verification_quorum` than it stored raises `ConfigError`.
- A model write that sets `last_verified_at` no longer moves recall's TTL clock.
- A snapshot restored into a vault with another passphrase keeps its entries' origin and author
  but not their verdicts.

## Tests

- `tests/review_a*.py` renamed to `tests/test_review_a*.py` and converted to regression tests of the
  fixed behaviour (no xfail left). `test_okf_commands_default_to_a_different_vault_path_than_the_server`
  is skipped: it is area C's `__main__.py` okf wiring.
- Existing tests updated to the new contract: `test_origin_bound_admission.py` (account attester),
  `test_persona_slot.py`, `test_enforce_fencing.py` (`reviewer_id`), `test_atlas_rubric_hardening.py`,
  `test_atlas_limits_20261105.py` (F8 raises `PermissionError`), `test_negative_probe_abstention.py`
  (a revoked store names a user origin), `test_recall_layer_kr345.py` (stale entry via write time),
  `test_review_2026_10_28.py` (race test pauses on `_tombstones_matching`).

## Not fixed / known gaps

- The homoglyph table is small by design (UTS #39 skeleton is not implemented).
- `trust_seal` lets any vault opened with the same passphrase keep a snapshot's trust facts; a
  snapshot made by a plaintext vault has no seal and no key id, so a plaintext vault keeps trust
  facts from any plaintext snapshot with a verifying manifest (manifest is unkeyed). Treat snapshot
  files like the database file (SECURITY.md).

## Round 2

Second-pass findings in `review_notes/R2_A.md`; regression tests in `tests/test_review2_a_tombstones.py`
and `tests/test_review2_a_trust.py` (the `test_attack_*` names are kept; each now asserts the fixed
behaviour).

### Fixed

- **R2-A1** (high) A tombstone row's class never goes down. `_tombstone_locked` no longer writes
  `INSERT OR REPLACE`: a request for a value that already has a row of the same or a higher class
  leaves the row, its class and its MAC untouched and journals `tombstone_reaffirmed` (with
  `origin_class` = the stored class, `requester_class`, `stored_class`); a higher-class request raises
  the row's class and re-signs it (journaled `tombstone`). The `tombstone` journal event now carries
  `origin_class` of the row as written. A person's rejection can no longer be replaced by an agent's
  re-tombstone and then lifted by an ordinary write.
- **R2-A7** (medium) `import_snapshot` of a vault's own snapshot (same vault, manifest verified)
  passes `_review_verdict=True` for every entity, and `_put` no longer applies the model trust ceiling
  under a verdict: an agent entry a person verified comes back `verified`, `origin='model'`,
  `human_reviews` and `attestations` intact, and restoring over the live reviewed row raises no
  `ReviewedEntryError`. The whole restore (tombstones, clearing, entities, refusal records) is one
  transaction: an error part-way rolls everything back. A foreign snapshot restored over a live vault
  leaves a person's reviewed / higher-class row in place (journaled `protected entry` refusal, not
  counted) instead of aborting.
- **R2-A2** (low-medium) `_entry_digests` matches the content, the key and the caller's own metadata
  (`agent_metadata`) only; the vault's bookkeeping strings (`origin_class`, `act_class`, the MCP
  server's `origin`, `attestations`, `human_reviews`, ...) are no longer digested, so one forget of
  a word such as `agent` or `mcp` no longer refuses every later agent write in the scope.
- **R2-A5** The Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) fold to a space, not to nothing
  (`_BLANK_CODE_POINTS`): a rejected sentence with its spaces replaced by fillers is refused.
- **R2-A4** The canonical fold keeps spacing combining marks (`Mc`): distinct Devanagari/Tamil words
  no longer share a digest. `Mn`/`Me` are still dropped (the evasion marks), so words that differ
  only in a nonspacing vowel sign still fold alike; documented in the docstring and README.
- **R2-A3** `string_leaves` yields dict keys as well as values at any depth: a tombstoned value is
  refused as a metadata key and a stored copy filed as a key is purged with the rest.
- **R2-A9** A principal's write of different content over an attested entry drops `attestations`,
  `verification_pending` and `quorum_at_verification` (journaled `attestations_reset` with the
  names), and the state is re-derived for the new content: the writer's own attestation counts
  alone and the quorum starts over. The same content written again keeps what it has.
- **R2-A6** `lift_tombstone()` takes `origin`; a `model`, `tool` or `unknown` origin is refused with
  `PermissionError` (journaled `refuse`, path `lift_tombstone`) whatever class the tombstone carries.
  `None` keeps the library contract (the caller vouches for a person; the review CLI's `lift` verb
  after its terminal check). README/SECURITY no longer call the CLI "the only way".
- Docs: README tombstone fold description and forget/lift paragraph, SECURITY forget paragraph, the
  `import_snapshot` docstring, and the F3/F5/F11 lines above.

### Not fixed here

- **R2-A8** (`verification_quorum` outside the vault meta MAC) is R2-B4 and lands in area B
  (`VAULT_META_BOUND_KEYS`); `test_attack_stored_quorum_is_not_under_the_vault_meta_mac` asserts the
  fixed behaviour and is skipped until the merge. `_persist_verification_quorum` runs before the
  signing key is derived in `__init__`, so a `_write_meta_mac` call there would be a no-op; area B's
  open-time MAC write must cover the key instead.

## Round 3

Third-pass A+B seam findings in `review_notes/R3_AB.md`; regression tests in
`tests/test_review3_ab_tombstones.py` and `tests/test_review3_ab_snapshot.py` (the `test_attack_*` names
are kept; each now asserts the fixed behaviour).

### Fixed

- **R3-AB1** (high) `_lift_lower_class_tombstones` journals `tombstone_lifted` under the **row's**
  category, key, scope and digest (as `_lift_tombstone_locked` does); the writer's entry goes in
  `metadata.entry` / `entry_scope` (`metadata.tombstone` / `tombstone_scope` are kept). An agent's forget
  of `c:k1` followed by a person's write of the same value under `c:k2`, or under another key in another
  scope, no longer leaves a `tombstone` expectation the next open cannot reconcile; writable and
  read-only opens succeed and the chain verifies. `_check_tombstones` also matches a `tombstone_lifted`
  event written before the fix through `metadata.tombstone` / `tombstone_scope`, so a vault already
  holding the mismatched events opens.
- **R3-AB3** (medium) `import_snapshot`: `same_vault` is the trust seal alone (`_trust_seal_level`);
  `digest_key_id` only routes the keyed digests. A vault without a passphrase has no seal and never keeps
  trust facts from a file, its own exports included. The seal now names the entities **and** the
  tombstones of the export; a seal that names the entities only (written before this round) still
  vouches for the entities' trust facts but not for tombstone classes. A tombstone's `origin_class` is
  taken from the file only under a full seal; otherwise it is capped at the importer's class (new
  `origin` keyword, as on `put`; `None` = the caller vouches for a person), journaled as a
  `tombstone classes capped` refusal. The `trust facts dropped` refusal reason now names the seal.
- **R3-AB5** (low–medium) `_check_tombstones` carries the latest `tombstone` event's
  `metadata.origin_class` per row identity and refuses (`VaultIntegrityError`, writable and read-only)
  a row whose stored class is lower: a file writer's replay of an older agent-class copy of a row over a
  person's raised one is caught at open instead of being lifted by the agent's next write.
- **R3-AB6** (docs) `import_snapshot` docstring and SECURITY.md say that an own-snapshot restore is a
  point-in-time replay of the reviews too (an older own snapshot puts back older verdicts; a later
  rejection still wins).
- Docs: SECURITY.md's tombstone-reconciliation and snapshot paragraphs rewritten (what a snapshot can and
  cannot carry).

### Changed behaviour callers may notice

- `import_snapshot(..., origin=None)`: new keyword. A keyless vault's own export now restores `verified`
  / `disputed` entries as `candidate` (`trust_capped_from`); `tests/test_review2_a_trust.py` gives its
  in-memory fixture a passphrase for the round-trip tests and adds the keyless case.
- The `tombstone_lifted` event from a write names the row, not the writer's entry (`metadata.entry`).

### Not fixed

- Nothing in this area. R3-AB4 (V1 meta MAC re-sign) is area B's entry-point branch.

## Round 3 — quorum pinning

### Fixed

- **R3-E1** (high) The stored `verification_quorum` was written by whichever process opened the file
  first, `review list` (no terminal needed, writable open) included, so a same-uid shell running
  `KIBISIS_VERIFICATION_QUORUM=1 python -m kibisis.review list` before the operator's first open pinned
  the vault at one account, every later open adopted it in silence, and one pty-driven approve minted
  `verified`. Now only a pinning open stores the quorum: `SQLiteMemoryVault(pin_quorum=True)` /
  `open_vault(pin_quorum=True)`, passed by the review verdicts and `admit` behind their terminal
  check. Every other open (`review list`, the MCP and AML servers, the OKF commands, a plain library
  open) adopts the stored quorum or runs with its own and writes nothing; a stored quorum below the
  default (2) is adopted only by a process whose own argument or `KIBISIS_VERIFICATION_QUORUM` names
  it, otherwise `ConfigError` saying so (`pinned at 1 ... set KIBISIS_VERIFICATION_QUORUM=1 to accept
  that`). `review list` opens the vault read-only (nothing created, converted, re-signed or pinned; a
  missing vault is "nothing to review"). `verification_quorum_stored` (None until pinned) is the
  file's value; `review list`, every verdict, `admit`, the MCP server banner and `kibisis_health`
  (`verification_quorum: {accounts, pinned, note}`) say the quorum in force, `quorum 1 — one account
  verifies` when it is one. The default of two is documented as a default until a person's first
  verdict pins it (README, SECURITY.md, `review.py` help, `SQLiteMemoryVault` docstring).
- **R3-AB4** (medium) When only the V1 meta MAC verified (the legacy key set, which never covered the
  quorum) the stored `verification_quorum` was adopted as it stood and re-signed under the full set,
  so a pre-R2-B4 `meta_mac` plus `verification_quorum = 1` became a signed downgrade. Under a legacy
  MAC the stored quorum is now not trusted: a value below the default is ignored (the process runs
  with its own / the default), deleted before the re-sign, and logged at WARNING; a value at or above
  the default was kept and covered in round 3 (round 4, R4-2: no value is kept any more; see below).
  `_verify_meta_mac` logs the legacy MAC at
  WARNING in both read-only and writable opens.
- **R3-E4** (low) `open_vault(env=...)` reads `KIBISIS_VERIFICATION_QUORUM` from its mapping
  (`parse_verification_quorum`) and passes `verification_quorum=` explicitly, like the path, key and
  plaintext opt-in; a mapping that names none isolates the vault from `os.environ`'s value.

### Tests

- `tests/review3_entry_cli.py` → `tests/test_review3_entry_cli.py`, `tests/review3_entry_r2closed.py`
  → `tests/test_review3_entry_r2closed.py`: collected; the `test_attack_*` cases assert the fixed
  behaviour; new `test_control_a_pinned_quorum_of_one_is_not_adopted_in_silence`.
- `tests/review3_ab_migration.py::test_attack_r2b4_legacy_v1_meta_mac_re_signs_an_attacker_quorum`
  rewritten in place to the fixed behaviour (the forged 1 is ignored, dropped, and the re-signed MAC
  covers a file with no stored quorum); `test_control_r2b4_quorum_edit_under_a_full_set_mac_is_refused`
  there now pins (`pin_quorum=True`) so it has a stored quorum to edit — one-token change in area B's
  file, for the merge. `test_control_r3ab4_legacy_meta_mac_keeps_a_stored_quorum_at_or_above_the_default`
  (test_review2_b_journal.py) covers the other half.
- Existing tests that relied on a plain open pinning the quorum now pin explicitly
  (`test_review_a2_quorum.py`, `test_review2_a_trust.py`, `test_review2_b_journal.py::_seeded`).

### Changed behaviour callers may notice

- A library open never stores the quorum; an embedder that wants the file to remember one passes
  `pin_quorum=True` from a path it trusts as a person's act.
- A vault pinned at 1 refuses every open that does not name 1 itself (`ConfigError`); run with
  `KIBISIS_VERIFICATION_QUORUM=1`, or raise it with a verdict under `KIBISIS_VERIFICATION_QUORUM=2`.

## Round 4

### Fixed

- **R4-2** (low–medium) Under a legacy (V1) meta MAC, round 3 kept a stored quorum at or above the
  default ("can only raise the bar" was measured against the default, not against what the person
  pinned), so a file writer could lower a pinned 3 to 2 and the re-sign made it permanent. No stored
  quorum is trusted under a legacy MAC now, whatever its value: `_stored_quorum` returns None and logs
  the value at WARNING ("not covered by the meta MAC … ignored and dropped"), `_drop_untrusted_stored_quorum`
  deletes it before the full-set re-sign, and the next TTY-gated verdict run under the person's
  `KIBISIS_VERIFICATION_QUORUM` re-pins it. Nothing that was not under a MAC is ever re-signed.
  `tests/test_review4_r3fixes.py::test_attack_legacy_meta_mac_keeps_a_lowered_quorum_that_is_still_at_the_default`
  asserts the fixed behaviour (process runs with the default, `verification_quorum_stored` None, two
  accounts do not mint `verified`, the full-set MAC covers no quorum, a pinning verdict restores 3).

### Changed behaviour callers may notice

- A pre-R2-B4 file whose person pinned a quorum above the default loses the pin at its first open under
  this release (logged at WARNING with the value) until the next review verdict re-pins it.
