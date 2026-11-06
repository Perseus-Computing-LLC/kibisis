# R3 — entry points (MCP server, review CLI / admit, config / open_vault, AML adapter)

Third pass against `98c6f99`, from the outside in: what an MCP agent, a same-uid shell (the agent's
shell tool) or an HTTP client can still reach after rounds 1 and 2. Internals (tombstones, journal,
migration) are a sibling's area (`R3_AB.md`).

Evidence: `tests/review3_entry_{mcp,cli,aml,r2closed}.py` — not collected by default, run by path.
`test_control_*` = secure behaviour (failing = bug); `test_attack_*` = defect demonstrated (passing =
bug). Run: `ARGUS_LEDGER_PATH=$TMPDIR/argus_r3e.jsonl PYTHONPATH=src python -m pytest -q
-p no:cacheprovider tests/review3_entry_*.py` → **128 passed in 54 s** (6 attack tests pass = 6 defects
below, two of them the same root cause).

Threat model used (SECURITY.md:31-38): the MCP client is untrusted; a same-uid shell is the agent's
shell tool; a file writer has r/w on the DB without the passphrase; the person at the terminal is
trusted. SECURITY.md/README already concede that a pty defeats the terminal check and that one uid
cannot be told apart from itself — so the stored quorum is the control that is supposed to hold
against the shell tool. R3-E1 is about that control.

---

## Findings

### R3-E1 — A no-TTY `review list` by the agent's shell pins the vault's quorum to 1 before the operator ever opens it; one pty `approve` then mints `verified` — **high (same-uid shell; new installs and every pre-quorum vault)**

*Where:* `vault.py:337-349` (`_quorum_requested`, env read from `os.environ`), `vault.py:1091-1121`
`_persist_verification_quorum` (first open with no stored value stores the opener's quorum; later
opens that name none adopt it silently), `review.py:166` (`list` opens via `open_vault` read-write),
`config.py:165-192` (`open_vault` passes no quorum → the env decides).

*Problem:* The quorum is "pinned by whoever opens the file first". Nothing restricts *who* that is:
`kibisis.review list` needs no terminal, needs only the passphrase the agent's shell already has
(`KIBISIS_PASSPHRASE` / the key file, by the threat model), and opens the vault writable. Run with
`KIBISIS_VERIFICATION_QUORUM=1` in its own environment it (a) creates the file if absent and stores
`verification_quorum=1` under the meta MAC, or (b) on a vault that predates the stored quorum (every
alpha.16 file, or any file whose meta row was dropped and re-signed — the legacy re-sign path is
allowed) stores 1. The operator's later processes name no quorum, adopt 1, and nothing prints it:
`review list`, `health`, the MCP `kibisis_health` output and the fence all stay silent about the
quorum. Then one pty-driven `approve` (the documented pty limit) by the same uid yields `verified`.
The "raise but never lower" rule (R2-A/F7) holds; the gap is that the *floor* is set by the first
writer, not by a person, and that reaching the floor-setting write needs no terminal.

*Repro:* `review3_entry_cli.py::test_attack_first_open_by_a_no_tty_list_pins_quorum_one_and_a_single_pty_approve_verifies`
(new file: list → pinned 1 → silent adoption → `approve` → verified);
`::test_attack_pre_quorum_vault_is_pinned_by_whoever_opens_it_first` (existing vault without the meta
row); `::test_attack_review_list_opens_the_vault_writable` (a no-TTY `list` persists a *raised* quorum
too — proof the read path writes).

*Fix (suggestion, not applied):* treat the stored quorum like the terminal check — only a process
that passed the TTY gate (the verdict verbs / admit) may *store* a quorum; `list`/`health`/MCP/AML
opens should adopt or fail, never pin. Refuse to adopt a stored quorum of 1 without an explicit
`KIBISIS_VERIFICATION_QUORUM=1` in the operator's own environment (or print it loudly on every
verdict: "quorum 1 — one account verifies"). Open `review list` and the MCP server read-only w.r.t.
`vault_meta` (`open_vault(read_only=True)` already exists for okf-export). Document that the default
quorum of 2 is only a default until the first open.

### R3-E2 — MCP: refusing an agent write over a principal's unreviewed entry (or a superseded key) is reported as "Internal error" with a traceback in the server log — **low (hygiene; the refusal is correct)**

*Where:* `mcp_server.py:389-411` `_call_tool` maps `TombstonedValueError`, `KeyError/ValueError/TypeError`
and (in the tool bodies) `ReviewedEntryError`; `OriginClassError` and `SupersededEntryError` are
`PermissionError` subclasses and fall through to the catch-all → `"Internal error in kibisis_remember;
the details are in the server log."` + `traceback.print_exc()` to stderr.

*Problem:* The agent cannot tell a policy refusal (don't retry) from a server bug (retry / report),
and every routine refusal spams the operator's log with a traceback; an agent that loops on "internal
error" produces a traceback per attempt. The vault journals `refuse/origin_class_refused` so the audit
trail is intact. `kibisis_forget` on the same entry *is* mapped (`ReviewedEntryError` branch at
`:572`), which shows the intent.

*Repro:* `review3_entry_mcp.py::test_attack_refusal_of_a_principal_candidate_overwrite_is_an_internal_error`,
`::test_attack_refusal_of_a_superseded_key_rewrite_is_an_internal_error`.

*Fix:* add `except PermissionError as exc: return _result(..., f"Refused: {exc}", is_error=True)` to
`_call_tool` (after the more specific branches), journal a `refuse` with reason, no traceback.

### R3-E3 — MCP: `tools/call` with non-object `params` raises out of `handle_request` — **low (hygiene)**

*Where:* `mcp_server.py:383` `params.get("name")` on whatever `params` is.

*Problem:* `{"method":"tools/call","params":["kibisis_health"]}` raises `AttributeError`; the stdio
loop converts it to JSON-RPC `-32603 Internal error` plus a traceback (`:652`), where `-32602 Invalid
params` is the right answer; an embedder calling `handle_request` directly gets the exception. No
state is touched. `arguments` that are not an object *are* handled (`:419`).

*Repro:* `review3_entry_mcp.py::test_attack_tools_call_with_non_object_params_raises_out_of_handle_request`.
*Fix:* `if not isinstance(params, dict): return _error(req_id, -32602, "params must be an object")`.

### R3-E4 — `open_vault(env=...)` honours the mapping for path/key/plaintext but the quorum is read from `os.environ` only — **low (library API)**

*Where:* `config.py:165-192` vs `vault.py:338-346`.
*Problem:* An embedder that passes a scrubbed `env` mapping (the documented way to isolate the vault
from the process environment) still gets the process's `KIBISIS_VERIFICATION_QUORUM`, and a quorum
named in the mapping is ignored. Same root as R3-E1's "the env decides": the quorum is the one
setting that bypasses the config layer.
*Repro:* `review3_entry_cli.py::test_attack_open_vault_env_mapping_is_ignored_for_the_quorum`.
*Fix:* `open_vault` parses `KIBISIS_VERIFICATION_QUORUM` from its mapping via
`parse_verification_quorum` and passes `verification_quorum=` explicitly.

---

## Verified closed (entry-point view, with evidence)

| Item | Claim (changes/area_*.md) | Evidence at the entry point |
|---|---|---|
| R2-C-1 (AML: oversized ints / non-numeric `top_k` / deep nesting → 500) | 4xx via `_validating` | `review3_entry_aml.py::test_control_r2c1_shapes_are_4xx_and_the_server_keeps_serving` (422/422/422, nested → 400/422, server still serves). `::test_control_validating_does_not_swallow_storage_bugs_as_4xx`: a bug in the storage half is still 500, so the catch-all did not hide server bugs. `::test_control_storage_failure_is_500_without_a_traceback_and_the_permits_come_back`: 500 body is `"internal error"`, no traceback, no passphrase in body or log, `connections`/`inflight` permits back to max, next request 200. |
| R2-C-2 (AML started plaintext silently when sqlcipher missing) | refuse at startup unless `KIBISIS_ALLOW_PLAINTEXT` | `review3_entry_r2closed.py::test_control_r2c2_...` (`EncryptionRequiredError` from `storage_mode`; opt-in → plaintext). |
| R2-C-3 (auth after body / 100-continue) | auth and route before `Expect` | `review3_entry_aml.py::test_control_unauthenticated_post_is_401_on_every_path_without_100` (7 paths × with/without `Expect`: exactly one status, 401, never 100); `::test_control_bad_key_is_401_and_a_known_path_with_the_key_is_404_before_the_body`. |
| R2-C-4 (max-connections accounting) | permit released on every path | `::test_control_handler_exception_releases_the_connection_permit` (handler raising on 6 > max connections; `connections._value` back to max); storage-failure test above covers `inflight`. |
| R2-C-5 (retention purge boundaries) | only idle `.kib` vaults of its own | `::test_control_retention_only_deletes_its_own_idle_vault_files`: in-use vault skipped, non-vault files (wrong name; right name but not page-sized) and a symlink untouched, idle vault + sidecars removed, busy one removed once idle. |
| AML user_id → path | hashed names | `::test_control_user_id_cannot_choose_a_path` (11 shapes incl. `../`, absolute, NUL, 2000 chars: only `[0-9a-f]{32}.kib(-wal|-shm)?` under `data_dir`, 200 or 422, never 500). `::test_control_search_of_an_unknown_user_creates_nothing`. |
| AML methods | `HEAD`/`GET` touch nothing; others 501 | `::test_control_unknown_methods_never_reach_storage_or_leak`, `::test_control_head_and_get_read_no_body_and_touch_nothing`. |
| AML add cannot carry trust | import-origin candidates | `::test_control_add_rows_cannot_carry_trust` (`epistemic_state`, `origin`, `attester`, `metadata.human_reviews/attestations` in request and message: all rows `candidate`/`import`, no trust keys). |
| R2-A1 (lower-class re-tombstone downgrades a principal tombstone) | class never lowered | `review3_entry_r2closed.py::test_control_r2a1_...` (tool/model re-tombstone attempts, then MCP `remember` of the value still refused; a person's `put` does not silently lift). |
| R2-A2 (agent `forget` of a bookkeeping word wedges later writes) | key/metadata digests, canonical fold | `::test_control_r2a2_...` (`agent`, `mcp`, `inform`, `model`, `candidate`, `mcp-agent` forgotten; next `remember` with and without metadata succeeds). |
| R2-A6 (`lift_tombstone` by any origin) | principal only | `::test_control_r2a6_...` (model/tool/unknown raise; user lifts). Not exposed over MCP (`test_control_tool_surface_is_the_five_documented_tools`). |
| R2-A7 (own-snapshot restore caps a person-verified agent entry) | `trust_capped_from` not applied to own snapshot | `::test_control_r2a7_...` (verified after `import_snapshot(clear_existing=True)` and after a second import over the live vault; no `trust_capped_from`). |
| R2-A8 (stored quorum not under the meta MAC) | bound | The A-side placeholder was dropped in `98c6f99`; `tests/test_review2_b_journal.py:187-225` carries it (attack-turned-regression + two controls). R3-E1 is the remaining quorum issue and is orthogonal to the MAC. |

MCP server, re-verified against the fixed code (all controls in `review3_entry_mcp.py`):
`tools/list` is exactly `remember/recall/forget/verify_ledger/health`; no admit/lift/review/import/
purge/restore name resolves; every schema is `additionalProperties: false`. All 18 kwargs in
`_AUTHORITY_ARGS` plus `origin`, `origin_class`, `_review_verdict`, `_trusted_metadata`, `attester`,
`act_class`, `derived_from`, `revive`, `conflicts_with`, `fencing_token`, `reviewer_*` → `Refused:` and
a journaled `refuse` (`authority_claim` / `unknown_argument`), nothing stored. `scope` `*`, `''`,
`global`, `'default '`, `other`, `None`, `1` → refused. Every `RESERVED_METADATA_KEYS` member plus
`author_id`, `last_verified_at`, `supersession`, `proposed_supersedes`, `trust_capped_from`,
`quorum_at_verification`, `origin`, `epistemic_state`, `human_reviews` in `metadata` → entry is
`candidate`/`model`/`author mcp-agent`, `origin_class=agent`, the payload nested under
`agent_metadata`; recall fence shows `state="candidate" author="mcp-agent"`, no `reviewed_by`. Odd
category names (`''`, `*`, `__kibisis__`, `aml_message`-like, 5000 chars, SQL, NUL) and 17 FTS/SQL
query shapes never reach "Internal error". A principal's unreviewed entry cannot be overwritten or
forgotten over MCP; supersession of it is a proposal only. `health`/`verify_ledger` leak no passphrase,
path or quorum. The stdio server exits 2 ("No key") with no file created when no key is configured.

CLI, re-verified: `approve/dispute/reject/lift` and `admit` exit 3 without a terminal;
`KIBISIS_ADMIT_ALLOW_NOTTY` is gone (no match in `src/`, and the test proves it has no effect).
On a pty, three `--reviewer` labels, `admit`, and `USER`/`LOGNAME` spoofing from one uid count as
one attestation (`verification_pending {have:1, need:2}`) — F7 holds for the CLI. A stored quorum of 2
cannot be lowered by env (`exit 2`, "may be raised but not lowered"). `KIBISIS_SCOPE=*` and
`--scope '*'` are refused (exit 2). `open_vault` refuses plaintext without the opt-in (`0/no/false/
' '/'yes please'` are not opt-ins, no file is created); the passphrase file wins over the env and a
0644 key file is refused rather than skipped.

## Weakened tests

`git diff dd38c50..98c6f99 -- tests/`: 63 removed `assert`/`pytest.raises` lines, 1 added skip.
All 63 are in the `review2_*` → `test_review2_*` conversions (attack tests inverted into regressions
with the opposite assertion) or in two pre-existing tests whose expectations moved *with* a fix and
got stricter: `test_provenance.py` (R2-A9: an origin-less rewrite is now `candidate` with
`verification_pending {0,1}`, then the person's rewrite is `verified` — two assertions added) and
`test_review_b2_misc.py` (R2-B7: strict open no longer raises; `integrity_failures["count"] == 1` is
asserted and the raise moved to the first read). The one skip is
`kibisis_native was built before verify_chain was exported` (native-extension availability, not a
behaviour). The R2-A8 placeholder removal in `98c6f99` is backed by `test_review2_b_journal.py:187-225`.
**Verdict: no assertion in the entry-point areas was weakened.**

## Suspected (not demonstrated)

- `review list` / MCP / AML opens run the full open path (legacy meta re-sign, integrity upgrade,
  journal conversion) writable. R3-E1 is the one consequence proven here; a sibling covers the
  internals. If anything else in the open path is "first writer wins", the same no-TTY route reaches it.
- `kibisis_health` over MCP returns `integrity_failures` counts; harmless now, but any future key
  added to `health()` (path, quorum, attester) would flow to the agent unfiltered — the tool copies
  the dict as is.

## Docs overstating

- README.md:94 "An entry becomes verified once two operating-system accounts have approved it" — true
  only once the stored quorum is 2; until the first open (and for every pre-quorum file) the number is
  whatever the first opener's environment said (R3-E1). Say "by default two; the vault remembers the
  quorum of its first open — check it with …" (there is nothing to check it with today).
- SECURITY.md:182 "The attestation that counts toward the quorum is the operating-system account" —
  holds; add "the quorum itself is a file property set on first open, not a per-process setting".

## Scope / method notes

Only `tests/review3_entry_*.py` and this file were written; nothing in `src/` or existing tests
changed. AML servers bind `127.0.0.1:0` and shut down in `finally`; CLI tests drive a pty via
`pty.openpty()` the way `test_provenance.py` does; every attack test is < 5 s. Two hypotheses tried
and dropped: `scope` list-vs-string confusion in `recall` (handled), and `Expect: 100-continue` on
`HEAD` (no body read, 404 once).
