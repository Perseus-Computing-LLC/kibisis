# R2 — second-pass review of the area C fixes (commit 6f96df3)

Scope: F16 (C-1..C-12), F17, L8, L9, S-1/S-2/S-4 and the §4 doc sentences for AML/OKF, as fixed on
`fix/review-integration`. Method: read the fixed code, then probe each fix in-process. Evidence lives in
`tests/review2_c_aml.py` and `tests/review2_c_okf.py` (not collected by default; run by explicit path).
`test_control_*` = correct behaviour asserted (failing = bug); `test_attack_*` = defect demonstrated
(passing = bug). Nothing in `src/` or the existing tests was changed.

Run: `PYTHONPATH=src python -m pytest -q -p no:cacheprovider tests/review2_c_*.py` → **24 passed in 12.99s**.
Regression check of the fixed suites (`test_review_c_aml.py`, `test_review_c_okf.py`, `test_aml_adapter.py`,
`test_okf_*.py`) → 282 passed.

Environment note: this host exports `KIBISIS_PASSPHRASE`/`KIBISIS_PASSPHRASE_FILE`; `resolve_passphrase(None)`
reads them, so an "allow_plaintext" vault built without clearing them is SQLCipher. Every R2 test clears both.

## New findings

### R2-C-1 — Three input shapes still answer `500` — **low** (authenticated client; no crash, no data effect)
*Where:* `aml_adapter.py` `_timestamp_ms` (`float(value)`), `AMLService.search` (`int(top_k.strip())`),
`parse_json_body` (`except (UnicodeDecodeError, ValueError)` only); all reach `do_POST`'s `except Exception`
→ `500 internal error`, `Connection: close`.
*Problem:* C-1/C-7/C-8 closed the shapes the first review listed, not the class. (a) `timestamp` as a JSON
integer of 310–4300 digits (`10**400`): `float()` raises `OverflowError` before the `>= MS_FLOOR` test.
(b) `top_k` as a digit string longer than 4300 characters: `isdigit()` passes, `int()` raises `ValueError`
(CPython int/str limit). (c) a body nested ~100 000 deep (`[[[[…`, 200 KB, far under the 64 MiB cap):
`json.loads` raises `RecursionError`, which is not a `ValueError`.
*Repro:* `review2_c_aml.py::test_attack_integer_timestamp_too_large_for_float_is_500[_over_http]`,
`::test_attack_top_k_digit_string_over_4300_digits_is_500`, `::test_attack_deeply_nested_json_is_500`.
*Fix:* in `_timestamp_ms` compare the int directly (`value > MS_CEILING` before `float()`), or catch
`OverflowError`; in `search` bound the digit-string length (or `len(top_k) <= 4`) before `int()`; in
`parse_json_body` add `RecursionError` to the except tuple (400). SECURITY.md "timestamps must convert to a
datetime at Add" is true; "input-driven 500s" is not fully closed.

### R2-C-2 — Retention is a no-op in the no-`sqlcipher3` fallback; the S-4 warning describes a server that cannot serve — **low** (misconfigured host only; privacy promise silently void)
*Where:* `aml_adapter.py` `purge_idle` → `is_vault_file(path, self.passphrase is not None)`; `run_server`
S-4 warning text; `VaultPool._open`.
*Problem:* with a passphrase and no `sqlcipher3`, (1) without `KIBISIS_ALLOW_PLAINTEXT` the area B
constructor raises `EncryptionRequiredError` on the first open, so every Add/Search is `500` — the startup
line warns "entry content is sealed, but roles, timestamps and request markers are stored in the clear",
i.e. describes a degraded server, not a dead one; (2) with `KIBISIS_ALLOW_PLAINTEXT=1` the server runs and
writes plain-SQLite `.kib` files, but `is_vault_file(…, encrypted=True)` rejects any file with the SQLite
header, so `purge_idle` returns 0 forever and `--retention-days` deletes nothing. No log line says so.
*Repro:* `review2_c_aml.py::test_attack_retention_never_deletes_in_the_no_sqlcipher_fallback`,
`::test_attack_no_sqlcipher_without_opt_in_makes_every_request_500` (both monkeypatch
`kibisis.vault.sqlcipher3 = sqlite3`, which is exactly what the import fallback produces).
*Fix:* pass `encrypted = self.passphrase is not None and _sqlcipher_available()` (or the vault's
`encrypted_at_rest`) to `is_vault_file`; have `run_server` refuse to start (or say "every request will fail")
when a passphrase is set, `sqlcipher3` is missing and plaintext is not allowed.

### R2-C-3 — Read-only open leaves `-wal` and `-shm` files behind — **low** (docs overstate; no data change)
*Where:* `vault.py` `_open_read_only` (`?mode=ro` on a WAL-mode vault); SECURITY.md §"OKF bundle author"
("changes none of its bytes"), `__main__.py` docstring ("never changes it"), `config.open_vault` docstring
("without changing a byte of it").
*Problem:* SQLite needs the shared-memory index for a WAL database even read-only, so the open creates
`<vault>-wal` (0 bytes) and `<vault>-shm` (32 KiB, mode 0600 via umask, not `_restrict_permissions`) when
none existed and does not remove them on close. The main file's bytes and mtime are unchanged (control in
the same test). A later writable open cleans them up. Harmless, but "none of its bytes" is a claim about
the file, and an operator diffing the vault directory after `okf-export` sees two new files.
*Repro:* `review2_c_okf.py::test_attack_read_only_open_leaves_wal_and_shm_sidecars_behind[plain|keyed]`.
*Fix:* say so in the three sentences (or open with `immutable=1` only when no `-wal` exists and no writer
can be running — not recommended, it disables locking).

### R2-C-4 — `Expect: 100-continue` is answered before the credential check — **low** (L8 residue)
*Where:* `http.server.BaseHTTPRequestHandler.parse_request` → `handle_expect_100` runs before `do_POST`.
*Problem:* an unauthenticated `POST` with `Expect: 100-continue` and a `Content-Length` gets `100 Continue`
(the server commits to reading a body), then `401` and a `DRAIN_SECONDS` (2 s) wait for a body that never
has to come; that holds a handler thread and a `max_connections` permit for 2 s per connection at zero
cost to the client. Not enumeration (every path behaves the same), so L8 stays closed; it is the cheapest
way to occupy connection slots without a key.
*Repro:* `review2_c_aml.py::test_attack_expect_100_continue_is_honoured_before_the_credential_check`.
*Fix:* override `handle_expect_100` to check `_authorized()` and route first (send `401`/`404` instead of
`100`), and skip the drain when nothing has been sent (`Expect` present, no body bytes buffered).

### R2-C-5 — Read-only refusal of an edited-down `integrity_format` tells the operator to open writable — **info**
*Where:* `vault.py:_open_read_only` (format check before key check and before `_verify_meta_mac`).
*Problem:* a keyed vault whose `vault_meta.integrity_format` was edited to 1 (F13) is refused read-only
with "needs an integrity upgrade: open it writable once first"; the writable open then refuses with the
real reason ("the integrity record was edited"). Correct refusal, misleading advice. Also, on a genuinely
old-format keyed vault a wrong passphrase reports "needs an upgrade" rather than a key failure (SQLCipher
catches it first for encrypted files, so this only shows on the plain-file keyed fallback).
*Repro:* `review2_c_okf.py::test_attack_read_only_refusal_of_an_edited_down_integrity_format_tells_the_operator_to_open_writable`.
*Fix:* run the key check and the "format says 1 but carries key_check/meta_mac" test before the upgrade
check in the read-only path (same order as `_vault_crypto.py:372-389`).

## Verified closed (evidence)

| Original | Verdict | Evidence |
|---|---|---|
| C-1 timestamp poisons Search | closed | `_timestamp_ms` 422 at Add for every non-convertible value (`MS_CEILING+1`, negatives, 0, `[1e11-1]`, bools, lists, ISO out of 1970..9999); `_iso`/`_stamp` never raise. `review2_c_aml.py::test_control_ordinary_bad_inputs_are_4xx`; fixed suite `test_out_of_range_timestamp_is_422_at_add_and_never_poisons_search`. Residue: R2-C-1(a). |
| C-2 chunked cap bypass | closed | `_CHUNK_SIZE` is digits-only (1–16 hex), cap checked before every chunk, size exactly at cap accepted, one over → 413 before the read; `-1`, `+5`, `0x10`, 17 digits, missing CRLF → 400 + close; TE wins over CL; `identity` falls back to CL; `TE: gzip` with no CL → 411. `::test_control_chunked_edge_shapes`, `::test_control_duplicate_and_conflicting_length_headers_do_not_500`. |
| C-3 / L8 401, 404 reset; 404 before auth | closed | auth checked before routing; `/add`, `/search`, `/nope`, `/v1/memories/add` all `401` + `Connection: close` + drain; GET on POST paths is `404` from `_health`; PUT/OPTIONS `501`. `::test_control_unauthenticated_requests_are_401_and_other_methods_do_not_route`; fixed suite `test_a_large_body_refused_with_401_or_404_reaches_the_client`. Residue: R2-C-4 (chunked bodies are not drained, documented). |
| C-4 / S-2 retention | closed | symlink skipped, future mtime skipped, unreadable file logged and skipped, held slot skipped, directory/decoy/hex-named non-vault skipped (fixed suite). `::test_control_retention_edge_cases`; the stat-then-lock window (§3 suspected) is gone: mtime check, slot removal and unlink are under `_lock`, `use()` cannot create a slot meanwhile. Residue: R2-C-2. |
| C-7/C-8/C-10 NaN/Infinity/1e400, surrogates, ms floor | closed | `parse_json_body` 400 for `NaN`, `1e400`, lone surrogate in key or value, 5000-digit int, invalid UTF-8; `_encodable` 422 on every stored string; ms/seconds rule bounded and documented. Residue: R2-C-1(b,c). |
| C-9 request_id reuse | closed | 409 for a different text, timestamp, session_id or role; identical retry (and the same instant sent in seconds) is a no-op; per-user scoping; `""`, `None`, `5`, `"  "` → 422; a 20 000-char id is accepted and echoed. `::test_control_request_id_reuse_rules`. Markers written before this fix carry no payload digest and stay idempotent (by design, worth one changelog line). |
| S-1 socket timeout / max-connections | closed | permits are returned after `500`s and after idle closes (`connections._value == max_connections`), the (N+1)th idle connection gets `503` synchronously, `408` on a stalled body (fixed suite). `::test_control_connection_permits_are_returned_after_500_and_idle_close`. `process_request` releases on thread-start failure; `process_request_thread` releases in `finally`. |
| S-4 encrypted_at_rest log | closed as written | `_encrypted_at_rest` = passphrase set and `sqlcipher3` loads. Residue: R2-C-2 (the warning's description of the fallback). |
| F17 / C-5 / C-6 / C-11 one vault path, read-only opens | closed | `--db` > `KIBISIS_DB_PATH` > XDG (`::test_control_db_flag_beats_env_beats_data_dir`, lazy `DEFAULT_DB_PATH` matches); missing vault → `error: no vault at <path>`, rc 1, nothing created; `okf-import` (writing) refuses without a key or `KIBISIS_ALLOW_PLAINTEXT`, `--dry-run` too; scope outside the profile is skipped; imported rows are model-origin candidates. Read-only: `ReadOnlyVaultError` from `put`/`put_batch`/`tombstone`/`archive`; reads see a concurrent writer's WAL frames; plain file + passphrase read as plain (`passphrase=None`, `encrypted_at_rest=False`), bytes unchanged; wrong passphrase refused; missing/empty/directory/`:memory:` → `FileNotFoundError`, nothing created. `::test_control_read_only_*`. Residue: R2-C-3, R2-C-5. |
| L9 gate stdout | closed | `command_gate` summarises (verdict, exit, files, lines); `--gate-verbose` copies; argv via `shlex.split` (a quoted path with a space works), no shell; timeout/non-zero/launch failure refuse (fixed suite). `::test_control_export_round_trip_and_gate_cmd_argv`. |

## Regressions

None found: add/search/health round trip over HTTP (`created_at` rendered, Paris found), keep-alive
survives `422` and `400` (pipelined second request answered), identical retries, OKF export → check →
import `--dry-run` round trip on an encrypted vault with unchanged bytes. The four fixed suites pass (282).

## Suspected, not shown

- `AMLConfig` does not validate `max_body_bytes` (≤ 0 makes every body `413`/`400`) or `retry_after_s`
  (negative → `Retry-After: -1`). Operator flags, not client input; one `ValueError` in `__post_init__`.
- A `413` on a chunked body (`_body_unread` stays False) and a `401`/`404` on a chunked body close with
  unread data → RST on some stacks. Documented in `_drain_body`'s docstring; not in `deploy/aml/README.md`
  line 73-74, which says refusals "drain the declared body".
- `_send` raising (client gone) inside the `except Exception` branch propagates out of `do_POST`;
  `socketserver.handle_error` then prints a traceback to stderr. No content in it; two attempts, not
  reproduced deterministically without a flaky half-close.
- `purge_idle` runs `is_vault_file` (header read) outside the pool lock, then re-stats under it; a file
  swapped between the two (same name, different kind) would be unlinked only if the second stat still
  succeeds — the unlink is by name, so a decoy renamed into place in that window is deleted. Microsecond
  window, local attacker with write access to the data dir, who can delete the file anyway.

## Documentation that still overstates

| Sentence | Where | Reality |
|---|---|---|
| "`okf-export`, `okf-check` and `okf-import --dry-run` open the vault read-only" | SECURITY.md §OKF bundle author | `okf-check` never opens a vault (`check_bundle(args.bundle)` only). |
| "running them against a vault changes none of its bytes" / "never changes it" / "without changing a byte of it" | SECURITY.md, `__main__.py:3-5`, `config.open_vault` docstring | True for the file; the open creates and leaves `-wal`/`-shm` beside it (R2-C-3). |
| "refusals sent before the body is read (`401`, `404`, `413`, `429`) drain the declared body" | deploy/aml/README.md:73-74 | Content-Length bodies only; chunked bodies are not drained (close → possible RST). |
| S-4 warning "vault files are not encrypted as a whole; entry content is sealed, but roles … in the clear" | `aml_adapter.run_server` | Without `KIBISIS_ALLOW_PLAINTEXT` the server answers `500` to everything in that state; with it, retention is dead (R2-C-2). |
| "timestamps must convert to a datetime at Add, so a stored row can never make a later Search fail" | SECURITY.md §aml-serve | True; but "input-driven 500s" are not gone (R2-C-1). |
| "A retried request … is acknowledged without being stored twice; the same `request_id` with a different payload is refused with `409`" | deploy/aml/README.md:22-24 | True for markers written by this version; markers from alpha.16 have no payload digest and any payload under their id is acknowledged. |
