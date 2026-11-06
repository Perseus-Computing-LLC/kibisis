# R2 — second-pass adversarial review, AREA A (fix commit 6f96df3)

Worktree `/opt/data/cache/scratch/kib-review2`, detached at `6f96df3` (branch `fix/review-integration`).
Nothing under `src/` or the existing tests was changed. Repro tests: `tests/review2_a_tombstones.py`,
`tests/review2_a_trust.py` (not collected by default; run by path). Convention: `test_control_*` asserts
the secure behaviour (failing = bug); `test_attack_*` demonstrates a defect (passing = bug).

```
cd /opt/data/cache/scratch/kib-review2 && ARGUS_LEDGER_PATH=$TMPDIR/argus_r2a.jsonl PYTHONPATH=src \
  /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/review2_a_*.py
59 passed in 5.89s
```
(All controls pass = the fixes hold on those paths; all attacks pass = the defects below exist.)

Severity scale as in REVIEW.md: critical = agent-reachable, defeats a core guarantee, no recovery; high =
agent/file-writer reachable, defeats a documented guarantee; medium = needs a library caller /
passphrase holder / unlikely precondition, or partial defeat; low = hygiene or overstated docs.

---

## Findings (most severe first)

### R2-A1 — A non-principal `tombstone(content=V)` REPLACES a person's principal-class tombstone row — **high (library; embedder relaying an agent)**
*Where:* `src/kibisis/_vault_tombstone.py:391-404` (`INSERT OR REPLACE INTO rejected_value_tombstones`) against
`UNIQUE(category, key, value_sha256, scope)` (`vault.py:886`); the class is simply `requester` and the MAC is
recomputed for the new row (`:402`).
*Problem:* the F3 fix makes `origin_class` the thing that decides whether a tombstone can be lifted, but the
row's identity does not include it, and a lower-class request may rewrite the row. After a person rejects
value V under `c:k` (review CLI `reject`, or `tombstone(origin="user")`), any library caller relaying an
agent does `tombstone("c","k", content=V, origin="tool")`. The origin check passes (the entry is gone, no
protected copies exist), and the row becomes **external-class** with a fresh valid `tombstone_mac`. The
agent's next `put(origin="model")` / MCP `kibisis_remember` of V outranks it and **lifts it** (journaled as a
routine `tombstone_lifted` by an "agent-class write"). With `origin="model"` the row becomes agent-class and
the *person's own* next write of V silently undoes their rejection. SECURITY.md:150 / README:128 "a
principal-class tombstone blocks everyone until a person runs `kibisis-review lift`" no longer holds.
Not reachable through MCP alone (`kibisis_forget` has no `content`, so it records a row for the *stored*
value — `test_control_mcp_alone_cannot_replace_a_principal_tombstone_row`).
*Repro:* `review2_a_tombstones.py::test_attack_retombstone_downgrades_principal_tombstone_class[tool-model]`,
`[model-user]`, `::test_attack_retombstone_downgrade_also_works_after_person_reject_via_review`.
*Fix:* never let a lower class overwrite a row: `INSERT ... ON CONFLICT DO UPDATE SET origin_class = max-class`
(or `INSERT OR IGNORE` + keep the higher class), and refuse (or no-op) a non-principal re-tombstone of a value
that already has a higher-class row. Add `origin_class` to what the journal `tombstone` event is checked
against on open (area B's row/journal reconciliation).

### R2-A7 — F11 only closed for user-origin rows: an agent entry a person verified is demoted by its own vault's snapshot, and a restore over the live vault aborts — **medium** (legitimate flow broken; the common MCP case)
*Where:* `_vault_snapshot.py:371-391` passes `origin=ent_data["origin"]` (now `"model"`); `vault.py:1135-1137`
sets `trust_ceiling = candidate` for every model-origin write before `_review_verdict` is considered, and
`:1191-1195` caps `verified` → `candidate`; `:1368-1374` raises `ReviewedEntryError` when the live row is
reviewed.
*Problem:* in the MCP deployment almost every verified entry is model-origin + a person's approval. With
`clear_existing=True` such entries come back `candidate` with `trust_capped_from="verified"` *while keeping*
`human_reviews` and `attestations` (inconsistent: `_is_reviewed` is true, `list_entities`/recall treat it as
a candidate; the person must re-approve everything). Without `clear_existing`, `import_snapshot` raises
`ReviewedEntryError` on the first such entry and stops part-way (tombstones and earlier entities already
committed, each `_put_journaled` is its own transaction). The docstring (`:230-231`) and area_a.md ("a
verified principal entry restored into its own vault stays verified") are accurate only for principal rows.
*Repro:* `review2_a_trust.py::test_attack_f11_person_verified_agent_entry_is_demoted_by_its_own_vaults_snapshot`,
`::test_attack_f11_restoring_own_snapshot_over_the_live_vault_aborts_on_a_person_verified_agent_entry`
(control `::test_control_f11_user_verified_entry_round_trips_verified_and_principal` passes).
*Fix:* in `_put`, skip the model `trust_ceiling` (and the `_is_reviewed(existing)` refusal) when
`_review_verdict` is set (the state was decided by `review_entity`/a same-vault import); or have
`import_snapshot` write the restored row with `origin=None` + `_trusted_metadata` and set the `origin`
column afterwards. Make `import_snapshot` all-or-nothing.

### R2-A2 — Metadata-leaf digests include the vault's own bookkeeping strings: one forget wedges every later agent write in the scope — **low–medium (MCP-reachable self-denial; needs `kibisis-review lift` to recover)**
*Where:* `vault.py:1482` digests `meta` *after* `origin_class`, `act_class`, the MCP server's `origin: "mcp"`
(`mcp_server.py:475`), `author_id`, `trust_capped_from`, … were added; `_vault_tombstone.py:205-217`.
*Problem:* `kibisis_remember(content="agent")` + `kibisis_forget` tombstones canonical `agent` (agent class).
Every later `kibisis_remember` in the scope carries `origin_class: "agent"` → `TombstonedValueError (… in its
key or metadata)`. A person's write does not lift it (their rows say `principal`), so the agent's memory stays
wedged until someone runs `kibisis-review lift c k` — and nothing in `kibisis-review list` points at it (the
refusals are `refuse` journal rows). The same happens with `mcp` (every MCP write carries it); if a *person*
rejects an agent candidate whose content is "MCP", the resulting principal tombstone blocks every MCP write
permanently. `inform` (act_class) is also matched but a person's write lifts it (their rows carry it too).
*Repro:* `review2_a_tombstones.py::test_attack_tombstone_of_a_bookkeeping_word_blocks_every_agent_write_until_a_person_lifts[agent|mcp]`,
`::test_attack_person_reject_of_a_bookkeeping_word_blocks_the_agent_permanently`.
*Fix:* digest only caller-supplied leaves (`agent_metadata`, `source_ref`, and the caller's own keys) — build
the digest list from the metadata *as received*, before the vault adds its own fields; or exclude
`RESERVED_METADATA_KEYS` and `PRINCIPAL_METADATA_KEYS` from the walk. Have the MCP forget refuse to tombstone
a value shorter than N characters, or at least name the lift command in the refusal text.

### R2-A5 — F5 residual: Hangul fillers are visible blanks but are *dropped*, so a rejected sentence comes back with its spaces replaced — **low–medium (MCP-reachable)**
*Where:* `_vault_crypto.py:117-118` (`_IGNORABLE_CODE_POINTS` → `continue`), the fixer's list includes
U+115F/U+1160/U+3164/U+FFA0.
*Problem:* those code points render as a blank the width of a Hangul syllable, so
`DeploysㅤgoㅤoutㅤonㅤTuesdays.` reads as the rejected sentence; the fold removes them instead of mapping to a
space, the words fuse (`deploysgooutontuesdays`), the canonical digest differs and `kibisis_remember` stores
it (`get` returns it; FTS recall by a single word does not find it because the words are fused, recall by the
fused text does). Braille blank U+2800 and NBSP in place of spaces are refused (controls).
*Repro:* `review2_a_tombstones.py::test_attack_hangul_filler_in_place_of_spaces_brings_a_rejected_value_back_through_mcp[*]` (4).
*Fix:* map U+115F/U+1160/U+3164/U+FFA0 (and other visible-blank ignorables) to a space, not to nothing.

### R2-A4 — Canonical fold drops `Mc` (spacing vowel signs): distinct words in abugida scripts collapse to one digest — **low (false refusals in Hindi/Tamil/…; over-matching)**
*Where:* `_vault_crypto.py:120` (`"Mc"` in the dropped categories).
*Problem:* `कल` (tomorrow), `काल` (time) and `कील` (nail) all fold to `कल`; `நமஸ்தே`-style words lose every
vowel sign. A person's rejection of one Hindi word refuses every word with the same consonant skeleton in
the scope (any class, since the fold is symmetric); `is_tombstoned` reports them rejected. Latin accents are
unaffected (NFKC recomposes before the drop — `test_control_fold_keeps_latin_accents_distinct_from_their_base`).
*Repro:* `review2_a_tombstones.py::test_attack_canonical_fold_collapses_distinct_words_in_abugida_scripts[*]` (4),
`::test_attack_tombstone_of_one_hindi_word_refuses_a_different_hindi_word`.
*Fix:* drop `Mn`/`Me` only for the evasion code points (variation selectors, CGJ, FVS) and keep `Mc`; or keep
marks that have no precomposed form.

### R2-A8 — The persisted `verification_quorum` is not under the `vault_meta` MAC — **low (file writer, plain-file vaults)**
*Where:* `vault.py:1015-1017` stores it with `_set_meta`; `crypto.py:237-238` `VAULT_META_BOUND_KEYS` lists
`integrity_format, kdf_salt, key_check, journal_format_floor, journal_anchored, term_index_format` only.
*Problem:* F7's "persist the quorum" fix stores the one value that defines what `verified` means next to the
values area B deliberately bound under `meta_mac`, but outside the MAC. On a vault whose file is plain SQLite
(no passphrase, or passphrase without SQLCipher) a file writer sets it to `1`; the next process that names
no quorum adopts it and a single attestation mints `verified`. With SQLCipher active the file is encrypted and
this needs the passphrase (then the holder can do anything anyway).
*Repro:* `review2_a_trust.py::test_attack_stored_quorum_is_not_under_the_vault_meta_mac`.
*Fix:* add `verification_quorum` to `VAULT_META_BOUND_KEYS` and re-sign in `_persist_verification_quorum`.

### R2-A9 — Attestations carry over a content change — **low (library, principals only)**
*Where:* `vault.py:1347` seeds `attested` from the stored row regardless of content.
*Problem:* alice attests X (1 of 2); bob writes a different content Y with `verified` → Y is `verified` with
`['alice','bob']` though alice never saw Y. Reachable with `trust_caller_identity=True` or two OS accounts.
*Repro:* `review2_a_trust.py::test_attack_attestations_carry_over_a_content_change`.
*Fix:* reset `attestations` when the exact digest changes (keep them in `human_reviews` history).

### R2-A3 — F12 residual: a tombstoned value stored as a metadata dict *key* survives — **low**
*Where:* `_vault_tombstone.py:59-68` (`string_leaves` yields dict values only).
*Problem:* `kibisis_remember(..., metadata={"<rejected value>": 1})` is accepted after a person's rejection;
`get()`/`list_entities()` return it under `agent_metadata`; `_value_copies` does not purge it. MCP recall does
not print metadata, so it is not shown there (the F12 "recall prints keys" half is closed).
*Repro:* `review2_a_tombstones.py::test_attack_tombstoned_value_stored_as_a_metadata_dict_key_survives`.
*Fix:* yield dict keys in `string_leaves`.

### R2-A6 — `lift_tombstone` is an un-gated public library method; docs say the CLI's lift is "the only way" — **low (docs overstate)**
*Where:* `_vault_tombstone.py:426-473` (no `origin`, no check); README:128, SECURITY.md:150-151, area_a.md F3.
*Repro:* `review2_a_tombstones.py::test_attack_lift_tombstone_has_no_origin_and_no_terminal_check` (documents).
*Fix:* say "library callers that relay an agent must not expose `lift_tombstone`", as README:128 already does
for origin-less `tombstone()`/`purge()`; or give it an `origin` that refuses non-principals.

---

## Verified closed (evidence)

| Orig. | Evidence |
|---|---|
| F1 `tombstone(content=…)` skipped the origin check | `_vault_tombstone.py:356-376` runs `_refuse_if_protected(target)` before any branch, deletes only on digest match (`:406-407`). `review2_a_tombstones.py::test_control_model_tombstone_with_content_cannot_delete_verified_entry` (matching and non-matching content). Fixer: `test_review_a1_tombstone.py`. Residual: R2-A1 (the row write itself). |
| F3 agent's forget denies a value forever | agent-class tombstone; a person's write lifts it (`::test_control_mcp_forget_is_agent_class_and_a_person_lifts_by_writing`, journal `tombstone_lifted`). Residual: R2-A1 (downgrade), R2-A2 (self-denial), R2-A6 (lift ungated in the library). |
| F5 marks/homoglyphs | `::test_control_f5_variants_are_refused_through_mcp` (U+FE0F, U+034F, U+180B, trailing U+3164, Cyrillic а, dotless ı). Residual: R2-A5 (fillers in place of spaces), R2-A4 (over-match). |
| F6 agent supersession cascade flips a person's verified entry | `_vault_review.py:253-271` notice-only for higher class / reviewed; `review2_a_trust.py::test_control_f6_agent_supersession_cascade_leaves_person_verified_dependent_alone`. Every `_cascade_invalidate` caller passes `writer_class` (`vault.py:1470,1584,2061`; `review_entity` passes None = person). |
| F7 free-text attesters / snapshot / per-process quorum | `_resolve_attester` (`vault.py:1019-1045`): only `user` attests, as `account_identity()`; `attester=` needs `trust_caller_identity`; `"principal"`/empty refused. `::test_control_f7_user_writes_with_different_author_ids_are_one_attestation`, `::test_control_f7_quorum_cannot_be_lowered_and_is_adopted_when_unnamed`, `::test_control_f7d_foreign_snapshot_attestations_are_dropped` (other passphrase, no manifest → dropped). `parse_verification_quorum` covered by fixer `test_review_a1_config.py`. Residual: R2-A8 (stored quorum unsigned), R2-A9. |
| F8 `review_entity` non-user origins; `_review_verdict`/`_trusted_metadata` public | `_vault_review.py:440-447` raises before any write; `::test_control_f8_non_user_reviewer_origin_raises_and_records_nothing` (3 origins × 3 verdicts); `::test_control_f8_private_flags_are_not_reachable_through_put_or_put_batch` (`_review_verdict`, `_trusted_metadata`, `_attest` → `TypeError` on `put` and `put_batch`). `_write_review` is the only caller with the flags (`vault.py:1047-1081`); `_put_journaled`'s `**kwargs` is private. |
| F9 `reviewer_id=None` | `::test_control_f9_review_without_reviewer_id_raises`. |
| F10 `purge()` origin | `_vault_tombstone.py:119-157`; `::test_control_f10…` via `test_control_model_purge_of_verified_entry_refused`. `origin=None` still unchecked (documented, README:128). |
| F11 snapshot demotes verified | user-origin rows round-trip (`::test_control_f11_user_verified_entry_round_trips_verified_and_principal`). **Partially closed** — R2-A7 for model-origin rows a person verified. |
| F12 value in key / metadata | `_entry_digests` on write (`vault.py:1482`) and in `_value_copies`; MCP key cap 128 (`mcp_server.py:467`). `review2_a_tombstones.py::test_attack_tombstoned_value_stored_as_a_metadata_dict_key_survives` control half (dict value refused). Residual: R2-A3 (dict keys), R2-A2 (over-reach into vault fields). |
| F18 pending supersession invisible; forget-request flood | `record_refusal` writes a dedicated `forget_request` action (`vault.py:1843-1856`), `forget_requests` filters on it in SQL (`:1868-1872`); `::test_control_f18_forget_request_for_a_verified_entry_is_queued`. `review.py:189,214-219` prints the retire notice (code reading; fixer test). |
| F19 model `scope="*"` tombstone | `_vault_tombstone.py:328-331`; `::test_control_model_tombstone_wildcard_scope_refused` (journaled `PermissionError`). |
| L1 back-edge on a person's row | `_record_edges` `may_write_back` (`_vault_review.py:202`); `::test_control_l1_model_conflicts_with_leaves_no_back_edge_on_a_person_row`. |
| L2 model `revoked` stored | `vault.py:1200-1211`; `::test_control_l2_model_states_are_capped[verified|disputed|revoked]`. |
| L3 principal-only metadata keys; `archive`/`set_persona_slot` origin | `PRINCIPAL_METADATA_KEYS` moved under `agent_metadata` (`vault.py:1148-1162`); `::test_control_l3_principal_metadata_keys_are_moved_for_model_writes`, `::test_control_l3_archive_and_persona_slot_take_origin`. |
| Atlas #1 MCP forget of a reviewed entry | `mcp_server.py:567-568` passes `origin="model"`; `::test_control_f1_f10_mcp_forget_of_person_candidate_is_refused_and_journaled_as_forget_request`, `::test_control_f18_…`. |
| Atlas #2 review doors | `require_terminal` on `approve/dispute/reject/lift` before the vault opens (`review.py:156-162`); `::test_control_review_lift_refuses_without_a_tty` (rc 3). pty still passes by design (documented in `_operator.py` and README). |
| Atlas #3 quorum counted names | see F7. |
| Atlas #5 admit scope/path | `review.py:170` prints vault path and scope; `_not_found` lists holding scopes (code reading; fixer test). |

## Suspected, unconfirmed

- `forget_requests()` runs `SELECT … WHERE action='forget_request'` with no SQL `LIMIT`; an agent that
  repeats `kibisis_forget` on reviewed entries grows the scan linearly (dedup is in Python). Not tested (no
  flooding per the brief); bounded by the number of reviewed entries × repeats.
- `_entry_digests` issues one SQL query + one keyed digest per string leaf of the metadata; the MCP
  `metadata` object has no size/leaf cap (only `key` is capped). A large nested `metadata` makes every write
  cost O(leaves) queries. Not measured (no large payloads per the brief). Suggest a leaf/byte cap on
  `agent_metadata` in `_remember`.
- Quorum lock-in: once any process opens a vault with a larger quorum (e.g. a stray
  `KIBISIS_VERIFICATION_QUORUM=5`), nothing in the CLIs can lower it; recovery is a manual `vault_meta` edit
  with the passphrase. Behaves as documented; no recovery path is documented.
- `put(origin="import", epistemic_state="verified")` now yields `candidate` with
  `verification_pending {have: 0}` (no attester for `import`). Intended per `_resolve_attester`'s docstring,
  but not listed under "Changed behaviour callers may notice" in area_a.md.

## Docs sentences that overstate the code

- README.md:128 / SECURITY.md:150-151 / area_a.md F3: "a principal-class tombstone … is lifted **only** by
  `python -m kibisis.review lift`" — R2-A1 (a lower-class re-tombstone replaces the row, then an ordinary
  write lifts it) and R2-A6 (`lift_tombstone()` is public and ungated).
- `_vault_snapshot.py:230-231` / area_a.md F11: "a person's verified entry stays verified and principal when
  the trust facts are kept" — true for user-origin rows only; a model-origin row a person verified is
  demoted (R2-A7).
- SECURITY.md:151 / README:20,55,125 "look-alikes are refused": Hangul-filler-for-space variants are not
  (R2-A5); and the fold refuses more than look-alikes in abugida scripts (R2-A4).
- area_a.md F7 "`verification_quorum` is persisted in `vault_meta`" reads as a trust property; it is stored
  outside the `meta_mac` that the same release introduced for trust-deciding meta values (R2-A8).
