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
  [--digest PREFIX]` (terminal-gated, journaled) is the only way past a principal-class tombstone.
  `kibisis_forget` through MCP stays a tombstone, now model-class, so an agent cannot permanently
  deny a value a person wants to keep.
- **F5** `canonicalize_text` also drops `Mn`/`Me`/`Mc` marks and Default_Ignorable code points
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
  drop is journaled and `epistemic_state` is re-derived from what survives.
- **F11** Snapshots export `origin` and `author_id` per entity and the import passes them on, so a
  verified principal entry restored into its own vault stays verified and principal.
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
