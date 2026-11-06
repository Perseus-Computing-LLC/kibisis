# A1 — Write trust boundary (kibisis v0.1.0-alpha.16, commit 1299c28)

## 1. Restatement
Task: find any way an untrusted writer (model/tool origin, MCP client, or a library caller relaying one) can reach `verified`, overwrite/retire/delete a person-reviewed entry, or be raised to a higher origin class; and verify atlas fixes #1 (forget), #4 (recall gating) and #5 (admit db/scope).
Assumptions: the vault API is reachable by untrusted code *with the origin argument honestly set* (library embedders relay the agent's origin); the MCP server is the only path where kibisis itself fixes the origin; the person at the terminal is trusted; snapshot files are declared trusted input by SECURITY.md:145 and I treat forging one as out of scope except where a round-trip of an honest snapshot loses trust.
Method: read `_put`, `tombstone`, `_vault_review`, `_vault_snapshot`, `okf/importer`, `mcp_server`, `config`, `__main__`, `review`; wrote 45 tests in three files that assert the secure behaviour (so the assertion fails while the defect exists) or explicitly document insecure behaviour (passes). The 21 finding tests carry `@finding("Fn")` = `xfail(strict=True)`: the suite is green today (`24 passed, 21 xfailed`) and a finding test turns RED the moment the defect is fixed, so the marker must then be removed. `pytest --runxfail` shows the raw assertion failures quoted below.

Repro command (all three files, ~9 s):
```
cd /opt/data/cache/scratch/kib-review && ARGUS_LEDGER_PATH=$TMPDIR/argus_a1.jsonl PYTHONPATH=src \
  /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/review_a1_tombstone.py tests/review_a1_write_paths.py tests/review_a1_config.py
# -> 24 passed, 21 xfailed in 8.65s        (add --runxfail -> 21 failed, 24 passed; the E lines below)
```

## 2. Verdict on atlas fixes

| Fix | Verdict | Evidence |
|---|---|---|
| #1 `kibisis_forget` of a person-verified entry | **Bypassable at the library layer; closed at the MCP layer** | The `protected()` closure (`_vault_tombstone.py:172-183`) is only evaluated when `content is None` (`:185-204`). Passing any `content=` skips the origin check on the target: `vault.tombstone("ops","deploy_day", content="anything", origin="model")` deletes a verified principal entry (F1, 3 failing tests). `purge()` (`:25`) takes no `origin` at all (F2). MCP `kibisis_forget` whitelists only `category/key/reason` (`mcp_server.py:60-66`), so the client cannot reach `content`, `origin`, `author_id` or `scope` (4 positive-control tests pass). Through MCP the agent cannot delete a person's entry, but it *can* permanently deny a person a value (F3) and the new refusal journal is floodable (F11). |
| #4 MCP recall calls `recall()` | **Closed** | `mcp_server.py:600-606` calls `self.vault.recall(...)`; `tools/list` exposes exactly `kibisis_remember/recall/forget/health/verify_ledger` — no list/get/search tool. Control test `test_control_mcp_exposes_only_five_tools_and_recall_withholds` passes: `search()` returns both conflicting verified entries, `kibisis_recall` returns `withheld="2"` with no content. Residual (not a leak): `fence_recall` prints `author=` from caller-settable metadata (F13). |
| #5 `kibisis admit` db/scope | **Partially closed** | With `KIBISIS_SCOPE` set, server/admit/review agree (`test_server_admit_and_review_agree_when_scope_env_is_set` passes). Without it, `resolve_scope` (`config.py:113-127`) derives the scope from the *caller's cwd* git checkout; the MCP server runs in the MCP client's cwd, the person's `admit` in their shell cwd. Same env, different directory ⇒ different scope: `test_admit_from_another_directory_misses_the_servers_entry` fails with `kibisis admit: c:k not found in scope 'default'` while the server wrote to `project:checkout-<hash>`. And `okf-export`/`okf-import` still default to `~/.hermes/kibisis/vault.sqlite` (`__main__.py:20`) while everything else uses `~/.local/share/kibisis/vault.sqlite` (`test_okf_commands_default_to_a_different_vault_path_than_the_server` fails with those two paths). |

## 3. Findings (most severe first)

### F1 — `tombstone(content=...)` skips the origin check on the target — **high**
Reason: the exact K-R1/reviewed guard the atlas fix added is dead code whenever `content` is supplied, and `content` is the documented way to tombstone (README:115, every older test uses it).
Where: `src/kibisis/_vault_tombstone.py:185-204` (`target` only assigned in the `content is None` branch; `protected(target, ...)` at :199 never runs otherwise), `:211-213` (the entry itself is skipped in the copy scan as "checked above"), `:236-240` (`DELETE FROM entities WHERE category=? AND key=? AND scope=?` regardless of whether the content matched).
Plain language: a model-origin caller that passes *any* `content` string — even one that is stored nowhere — deletes a person-verified entry (and a person-written candidate) by category/key, with no `ReviewedEntryError`, and the journal records a successful `tombstone` by `author_id="mcp-agent"`.
Repro: `tests/review_a1_tombstone.py::test_model_tombstone_with_content_argument_must_not_delete_a_verified_entry` (both params) and `::test_model_tombstone_with_content_must_not_delete_a_person_written_candidate`. Actual:
```
tests/review_a1_tombstone.py:66: in test_model_tombstone_with_content_argument_must_not_delete_a_verified_entry
E   Failed: DID NOT RAISE ReviewedEntryError
```
(the positive control `test_control_model_tombstone_without_content_is_refused` passes).
Fix: look up the row by category/key/scope first and run `protected()` on it before any branch; when `content` is given and the stored digest does not match, do not delete the row at all.

### F2 — `purge()` has no origin parameter — **medium**
Where: `_vault_tombstone.py:25`. A library embedder relaying an agent has no way to express the agent's origin; `purge("ops","deploy_day", author_id="mcp-agent")` deletes a verified principal entry. Not reachable from MCP. Repro: `::test_purge_has_no_origin_parameter_documents_insecure_behaviour` (passes, documents). Fix: add `origin` to `purge` and apply the same `protected()` check; default `None` keeps compatibility.

### F3 — Through MCP, an agent can permanently deny a value to a person — **high**
Reason: `kibisis_remember` + `kibisis_forget` on the agent's own unreviewed candidate writes a scope-wide value tombstone (`_vault_tombstone.py:223-235`). `_put` refuses every later write of that value or any canonical look-alike (`vault.py:1066-1078`), *including a person's verified write*, and there is no API to lift a tombstone (`grep "DELETE FROM rejected_value_tombstones"` → none). A model can thus pre-emptively blacklist facts ("Deploys go out on Tuesdays") so the person can never record them; the person sees only `TombstonedValueError`.
Repro: `tests/review_a1_tombstone.py::test_mcp_remember_then_forget_must_not_block_a_persons_later_write_of_that_value` and `::test_mcp_forget_canonical_lookalike_also_denies_the_person`. Actual:
```
E   Failed: person's write refused by an agent-made tombstone: Write rejected by tombstone: entity 'ops:deploy_day' [scope=default] matches rejected tombstone (digest: bdf7f2a87b94..., reason: forgotten through MCP)
E   Failed: person's write refused by an agent-made tombstone on a look-alike: Write rejected by tombstone: entity 'ops:deploy_day' [scope=default] matches rejected tombstone (digest: aeafa2a13f3a..., reason: forgotten through MCP)
```
Fix: a non-principal `tombstone` should delete the entry but record the tombstone tagged with its origin class, and `_put` should let a higher-class writer override a lower-class tombstone (or give `kibisis-review` a `lift` verb); alternatively MCP forget should `archive` rather than tombstone.

### F4 — model-origin `tombstone(content=..., scope="*")` writes a global tombstone — **medium**
Where: `_vault_tombstone.py:185-204, 223-235`. With `content` and `scope="*"` nothing is looked up, nothing is protected, and a `*` tombstone is inserted that refuses the value in *every* scope. Library-only (MCP fixes scope). Repro: `::test_model_origin_tombstone_with_content_and_wildcard_scope_must_not_write_a_global_tombstone`:
```
E   AssertionError: a model-origin request wrote a wildcard tombstone that binds every scope
```
Fix: refuse `scope="*"` for non-principal origins.

### F5 — An agent's supersession of its *own* entry flips a person's verified entry to `disputed` — **high**
Reason: `_cascade_invalidate` (`_vault_review.py:205-241`) marks every dependent `disputed` with no class or reviewed check; a person's verified entry that lists `derived_from=["notes:summary"]` (an agent note) is retroactively disputed when the agent supersedes its note through MCP (`supersedes_key`, `vault.py:989-991, 1062`). After that, `_is_reviewed()` is False for the person's row (no `human_reviews`, not verified), so the reviewed-entry guard no longer covers it; only the class check remains.
Repro: `tests/review_a1_write_paths.py::test_agent_supersession_cascade_must_not_change_a_person_verified_entry`:
```
E   AssertionError: person's entry is now EpistemicState.DISPUTED via an agent cascade
```
and `::test_after_the_cascade_the_persons_entry_no_longer_counts_as_reviewed` (passes, documents `_is_reviewed is False`).
Fix: in `_cascade_invalidate`, skip (or only annotate, never change state of) dependents of a higher origin class or with `human_reviews`, when the cascade is triggered by a non-principal write.

### F6 — `review_entity(verdict="disputed"|"verified", reviewer_origin="model")` is accepted — **high** (library), not reachable via MCP
Reason: the a16 fix routed only `revoked` through `tombstone(origin=reviewer_origin)`. `disputed`/`verified` go to `put(origin=None, _review_verdict=True, _trusted_metadata=True)` (`_vault_review.py:487-504`). A model-origin verdict changes a person's verified entry to disputed, and a model-origin `disputed` on the agent's own candidate records a `human_reviews` entry so `_is_reviewed()` is True and `list_entities()` shows the agent's entry next to the person's.
Repro: `::test_model_origin_review_verdict_disputed_must_not_change_a_person_verified_entry` → `AssertionError: a model-origin verdict made it EpistemicState.DISPUTED`; `::test_model_origin_review_verdict_must_not_make_an_agent_candidate_count_as_reviewed` → `AssertionError: [{'reviewer_id': 'bot', 'verdict': 'disputed', ... 'reviewer_origin': 'model'}]`.
Fix: `review_entity` should raise `PermissionError` when `origin_class_of(reviewer_origin)` is not `principal`, for every verdict.

### F7 — `put()`/`put_batch()` expose `_review_verdict` and `_trusted_metadata` to every caller — **high** (library)
Where: `vault.py:1200-1201` (public signature), `:1503` (put_batch forwards dict items as kwargs). With `_review_verdict=True` a `tool`/`unknown`/`None` origin writes `verified` directly and keeps a forged `human_reviews`; only `origin="model"` is still capped by `trust_ceiling`. The underscore is the only protection; `put_batch` even accepts them from plain dicts.
Repro: `::test_put_internal_flags_must_not_mint_verified_for_a_non_principal[tool|unknown|None]` and `::test_put_batch_forwards_internal_flags_from_dict_items`:
```
E   AssertionError: (<EpistemicState.VERIFIED: 'verified'>, 'external')
```
Fix: move the review path to a private method on the vault (`_put_reviewed`) and strip `_review_verdict`/`_trusted_metadata` from `put`/`put_batch` kwargs.

### F8 — Snapshot round-trip downgrades a person's verified entry to external-class candidate — **medium** (integrity), then agent-overwritable
Where: `_vault_snapshot.py:43-85` exports no `origin`; `:276-291` imports with `put(origin=None, epistemic_state="verified")`; `_put` caps non-principal to candidate (`vault.py:817-825`) and stores origin `unknown` (`:1111`). After restore, the row has `origin_class="external"`, state `candidate`, `trust_capped_from="verified"`, no `human_reviews`, so both guards admit a model write and a model tombstone.
Repro: `::test_snapshot_round_trip_must_keep_a_person_verified_entry_verified_and_principal` → `('unknown', 'external', <EpistemicState.CANDIDATE>, 'verified')`; `::test_after_a_snapshot_restore_an_agent_can_overwrite_and_delete_the_persons_entry` → `DID NOT RAISE`. Fix: export `origin` and `author_id` per entity and pass them on import.
Also documented (`::test_snapshot_import_trusts_file_metadata_documents_insecure_behaviour`, passes): a hand-made snapshot plants `human_reviews` and tombstones — consistent with SECURITY.md:145's "trusted input" declaration, but note `manifest_sha256` is optional, so a tampered file with the key removed imports silently.

### F9 — An MCP candidate's pending supersession of a verified entry is invisible in `kibisis-review list`; approving it retires the verified entry — **medium**
Where: proposal stored at `vault.py:992-1013`; `review.py:_list` (:68-100) prints author/version/content only; `_review_locked` applies the stored `proposed_supersedes` on a `verified` verdict (`_vault_review.py:484-501`): the verified target is revoked, `valid_until` closed, its dependents disputed.
Repro: `::test_review_list_must_name_a_candidates_pending_supersession_of_a_verified_entry` fails; output shows only `ops:deploy_day_v2  by mcp-agent ...  Deploys go out on Fridays.`; `::test_approving_the_proposal_retires_the_verified_entry_documents_behaviour` passes (old entry `REVOKED`, `superseded_by == "ops:v2"`). Fix: print "approving retires ops:deploy_day (verified)" in the list and in the approve confirmation.

### F10 — A model write's `conflicts_with` edits a person's verified entry's metadata — **low**
Where: `_record_edges` (`_vault_review.py:164-203`) writes the back-edge into the target row without class/reviewed checks. Agents can tag a verified entry as `conflicts_with` their own candidate (recall filters consider conflicts among *verified* entries only, so no withholding results, but the person's row is mutated and journaled). Repro: `::test_model_conflicts_with_must_not_modify_a_person_verified_entrys_metadata` → `AssertionError: ['notes:claim']`. Fix: skip back-edges onto higher-class rows, or store them on the writer only.

### F11 — The forget-request journal view is floodable from MCP — **medium**
Where: `vault.py:1394-1397` reads the newest 5000 `refuse` events of the scope, then filters for `forget_request`. Every refused MCP call (unknown argument, scope, trust argument) adds a `refuse` row (`mcp_server.py:208-225`). 5001 cheap `kibisis_health {"bogus":1}` calls push the agent's own forget request out of what `kibisis-review list` shows. Not forgeable (origin is server-fixed) but replay/flood hides them. Repro: `::test_forget_requests_must_survive_a_flood_of_agent_refusals` → `AssertionError: the forget request vanished behind agent refusals`. Fix: filter on `event_type='refuse' AND payload reason='forget_request'` in SQL, or keep a `forget_requests` table.

### F12 — `remember(origin="model", epistemic_state="revoked")` is stored as `revoked` — **low**
`remember()` docstring and SECURITY.md:111 say a model write is stored as candidate *whatever* `epistemic_state` says; `_put` caps only `verified`/`disputed` (`vault.py:808-812`). Repro: `::test_model_remember_must_not_store_revoked` → `EpistemicState.REVOKED`. Not reachable via MCP. Fix: cap any non-candidate state.

### F13 — `author_id`, `last_verified_at`, `supersession`, `proposed_supersedes`, `slot` are not reserved metadata keys — **low**
`vault.py:111-121` reserves `human_reviews`, `attestations`, `origin_class`, `review_outcome`… but a model write can set `metadata.author_id="alice"` (which `fence_recall` prints as `author="alice"`, `mcp_server.py` fence) and a far-future `last_verified_at` (recall's TTL clock). Repro: `::test_unreserved_trust_adjacent_keys_are_caller_settable_documents_behaviour` (passes, documents). Nested/cased/Unicode look-alike reserved keys are inert (`::test_nested_and_cased_reserved_keys_are_inert` passes).

### F14 — `archive()` and `set_persona_slot()` have no origin gate — **low**
`archive` (`vault.py:1533`) takes no origin and hides a verified entry from `list_entities`/recall; `set_persona_slot` (`:1650`) defaults `origin="user"`, so a relaying embedder that omits origin writes a principal-class verified entry. Not reachable via MCP. Repro: `::test_archive_and_persona_slot_have_no_origin_gate_documents_behaviour` (passes).

## 4. Suspected, unconfirmed
- **Scope mismatch between the person and the server (atlas #5)** — confirmed as behaviour (test fails) but I could not confirm it is *exploitable*: a model cannot pick the server's cwd. The risk is operational (admit lands on "not found" or on a namesake in `default`). Would confirm exploitability: a client that starts the server from a chosen directory.
- **OKF import** — reads at `okf/importer.py:368-500` show every put uses `origin="external-okf"`/`trust_ceiling=candidate` and strips reserved keys; a direct bypass was not found in two reading passes; not tested end-to-end. Would confirm: a test that imports a bundle with `human_reviews`/`verified` and asserts the stored row.
- **Snapshot `tombstones` list with a model-origin caller** — `import_snapshot` has no origin; writing tombstones through it is "trusted input" by SECURITY.md. Flagged only in F8's documenting test.

## 5. Documentation that overstates the code
- CHANGELOG.md:61-63 — "`tombstone()` takes `origin`: a non-principal origin may not delete a reviewed entry, or one of a higher origin class … and raises `ReviewedEntryError` with nothing changed." False whenever `content` is passed (F1).
- SECURITY.md:111 / CHANGELOG.md:247 / `remember()` docstring — "A write with `origin="model"` is stored as `candidate` whatever `epistemic_state` it asks for." `revoked` is stored as asked (F12).
- CHANGELOG.md:52-55 — "`kibisis admit` opens the vault, key and scope the way the MCP server and `kibisis-review` do." Same *rules*, but cwd-dependent; from another directory it opens a different scope (atlas #5, partial).
- SECURITY.md:113-114 — "A capped write cannot replace an entry a person verified or reviewed… it can only propose a replacement with `supersedes_key`." A capped write can also *dispute* it by cascade (F5) and mutate it via back-edges (F10).
- README.md:118 — "a supersession of one waits as a proposal until a person approves." True, but the person is never told what the approval applies (F9).
- CHANGELOG.md:64-65 — "a revocation recorded with a model or tool origin cannot delete a reviewed entry." Only `revoked` is gated; `disputed`/`verified` verdicts with a model origin are applied (F6).

## 6. Test-suite gaps
- `tests/test_atlas_limits_20261105.py:177-190` tests `tombstone(origin=...)` only *without* `content`; no test calls `tombstone(content=..., origin="model")` — F1 slipped through. Every pre-existing `content=` tombstone test (`test_contracts.py:237,310`, `test_cold_start_reload_integrity.py:36,76`, `test_okf_import.py:662`) passes no origin.
- `test_atlas_limits_20261105.py:192-196` tests only `verdict="revoked"` with `reviewer_origin="model"` — F6.
- `test_atlas_limits_20261105.py:340-353` (`test_admit_without_db_or_scope_opens_the_mcp_servers_vault_and_scope`) runs with `KIBISIS_SCOPE=proj-a` set by the `on_disk` fixture (:61), so the cwd-derived default scope is never exercised.
- No test exercises `_cascade_invalidate` with a dependent of a higher origin class (F5) or `_record_edges` onto a reviewed target (F10).
- No test writes a person's value after an agent `kibisis_forget` (F3); `test_mcp_forget_still_deletes_what_no_person_reviewed` stops at the delete.
- No test round-trips a verified principal entry through `export_snapshot`/`import_snapshot` and asserts origin/state (F8).
- No test calls `put(..., _review_verdict=True)` from outside the review path to show it is refused (F7).
- `verification_quorum=1` in most fixtures is fine for these findings (none depend on quorum).

## 7. Coverage
Files read (at 1299c28): `src/kibisis/vault.py` 56-210, 721-1172, 1172-1310, 1307-1437, 1437-1557, 1627-1726; `src/kibisis/_vault_review.py` 1-100, 101-195, 195-305, 302-402, 402-527; `src/kibisis/_vault_tombstone.py` 14-310; `src/kibisis/_vault_snapshot.py` 40-120, 140-305; `src/kibisis/okf/importer.py` 368-500 (+grep); `src/kibisis/mcp_server.py` 50-180, 200-270, 380-450, 447-522, 522-655; `src/kibisis/__main__.py` 1-110, 134-209; `src/kibisis/config.py` all; `src/kibisis/review.py` 68-150; `tests/test_atlas_limits_20261105.py` 1-360; CHANGELOG.md 50-69; SECURITY.md 106-148; README.md 115-118.
Tests created: `tests/review_a1_tombstone.py` (12 tests), `tests/review_a1_write_paths.py` (29 tests), `tests/review_a1_config.py` (4 tests). Run: command in §1 → **24 passed, 21 xfailed** (`--runxfail`: 21 failed, 24 passed; each xfail/failure maps to a finding above; each pass is a positive control or a documenting test). No existing test file was run beyond grep.
Not done: OKF importer end-to-end test; `_vault_search.py`/recall internals (A? other area); Rust bindings; `kibisis-review reject` under a pty for F9 end-to-end (approval path covered via `review_entity` instead).
