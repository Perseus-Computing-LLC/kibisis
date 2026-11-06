# Review C — AML HTTP adapter, OKF CLIs, docs-vs-code (kibisis v0.1.0-alpha.16, commit 1299c28)

## 1. Restatement

Task: read `src/kibisis/aml_adapter.py`, the `okf-*`/`aml-serve` wiring in `src/kibisis/__main__.py`, `okf/export.py` (`--gate-cmd`) and `okf/importer.py`; find correctness/robustness defects; demonstrate each with a small in-process pytest; audit README/SECURITY/CHANGELOG/deploy-README sentences against the code.
Assumptions: worktree `/opt/data/cache/scratch/kib-review` at 1299c28; nothing under `src/` or existing tests changed; only ordinary `http.client` requests to an in-process server on 127.0.0.1:0; no raw-socket framing, no flooding, no long stalls (those are listed under "Suspected, unconfirmed" from code reading only).
Deliverables: this file, `tests/review_c_aml.py` (21 tests), `tests/review_c_okf.py` (7 tests); all 28 pass, every "passing = bug" test demonstrates a defect, every "failing = bug" test is a positive control.

Run: `cd /opt/data/cache/scratch/kib-review && ARGUS_LEDGER_PATH=$TMPDIR/argus_c.jsonl PYTHONPATH=src /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/review_c_aml.py tests/review_c_okf.py` → `28 passed in 11.13s`.

## 2. Findings (most severe first)

### C-1 · medium · One Add with an out-of-range timestamp makes every later Search for that user a 500
- **Where:** `aml_adapter.py:133-153` (`_timestamp_ms`, no range check), `:165-174` (`_utc/_iso/_stamp` → `datetime.fromtimestamp`), `:389` and `:405` (called during Search rendering), `:600-603` (generic `except Exception` → 500).
- **Problem:** Add accepts any numeric timestamp (`10**17` ms, `-1e15`, anything whose year is outside 1..9999), stores it, returns 200. Search later calls `datetime.fromtimestamp` on it and raises `ValueError: year 3170843 is out of range` (or `OverflowError`), which is not a `ContractError`, so the client gets `500 {"error":"internal error"}` and the connection is closed. The row stays in the vault, so the user's vault is permanently poisoned for any query that hits that group — a single malformed message in a benchmark conversation turns all of that conversation's searches into errors. Normal messages for other users are unaffected.
- **Repro:** `tests/review_c_aml.py::test_add_accepts_an_out_of_range_timestamp_then_every_search_for_that_user_is_500` (passing = bug). Probe output: `1. add huge ts: {'success': True, ...}` / `1. search raised: ValueError year 3170843 is out of range`.
- **Fix:** bound the timestamp in `_timestamp_ms` (e.g. refuse |ms| outside the `datetime` range with 422), and have `_iso/_stamp` tolerate an unrenderable `t` (omit `created_at`) so stored rows can never break Search.

### C-2 · medium · Chunked body with a negative chunk size bypasses `max_body_bytes` and reads until EOF
- **Where:** `aml_adapter.py:504-517` — `size = int(size_line..., 16)` accepts `-1`; the cap test `len(out) + size > limit` is then false; `self.rfile.read(size)` with a negative size reads to EOF.
- **Problem:** The chunked path is meant to honour the same cap as Content-Length. A chunk-size line `-1` passes the cap check and turns the read into `read(-1)`: on a socket this blocks the handler thread (and its `max_inflight` slot, held since `:578`) until the client closes, and buffers everything the client sends into `out` in memory with no bound. Only after EOF does the next size line fail and produce 400. The handler has no socket timeout (`AMLHandler.timeout` is `None`, see S-1), so there is no upper bound on the wait.
- **Repro:** `tests/review_c_aml.py::test_chunked_body_with_a_negative_chunk_size_reads_unbounded_past_the_cap` (passing = bug) — drives `_read_body` in-process on a recording `BytesIO` with `max_body_bytes=16`: the handler calls `read(-1)`, consumes 64+ bytes, then raises 400. No sockets used.
- **Fix:** reject `size < 0` (and non-hex prefixes) with 400 before the cap check; also cap the size-line length check on the trailer loop.

### C-3 · medium · 401/404 with a body larger than the socket buffers reaches the client as a reset, not a reply
- **Where:** `aml_adapter.py:570-577` (404 and 401 set `close_connection=True` and return without draining), vs `:582` and `:598-599` where 413/429 call `_drain_body()`.
- **Problem:** CHANGELOG alpha.15 (l.74-76) fixed exactly this for 413/429 after it failed a macOS runner; the same close-with-unread-body happens on 401 and 404. With a body larger than the kernel buffers (the default cap is 64 MiB) the client gets `BrokenPipeError`/`ECONNRESET` instead of the 401, so a client whose Memory System Key rotated cannot distinguish an auth failure from an outage, and retries blindly.
- **Repro:** `tests/review_c_aml.py::test_a_large_body_refused_with_401_or_404_reaches_the_client_as_a_broken_pipe` (passing = bug; one ordinary 8 MiB request). Probe: `4194304 wrong key -> client error: BrokenPipeError [Errno 32] Broken pipe`; `65536 wrong key -> 401`.
- **Fix:** call `_drain_body()` (bounded, 2 s) after sending 401/404 as for 413/429, or check auth before the body cap but drain uniformly in a `finally`.

### C-4 · medium · Retention deletes any `*.kib` file and crashes on a `*.kib` directory
- **Where:** `aml_adapter.py:264` (`glob("*.kib")`), `:279-283` (only `FileNotFoundError` is caught), `:622-633` (retention thread), `:629-632` (purge at startup).
- **Problem:** Selection is by suffix and mtime only. (a) Any `.kib` file in the data dir that is not a 32-hex-digit vault (an operator's `notes.kib`, a backup) is unlinked once it is 28 days old. (b) A directory named `*.kib` makes `f.unlink()` raise `IsADirectoryError`, which propagates out of `purge_idle`: at startup that aborts `run_server`; later it kills the daemon `aml-retention` thread silently, after which no vault is ever purged again (the server keeps serving). (c) mtime counts writes only, so a user whose vault is only searched for 28 days is deleted (CLI help says "no write", the module docstring l.29 says "idle").
- **Repro:** `tests/review_c_aml.py::test_retention_deletes_any_kib_file_in_the_data_dir_and_dies_on_a_kib_directory`, `::test_retention_counts_writes_only_so_a_read_only_user_is_purged` (both passing = bug). Probe: `4. purge decoy -> 1 decoy exists: False`; `4. purge dir raised: IsADirectoryError [Errno 21] Is a directory`.
- **Fix:** match `^[0-9a-f]{32}\.kib$` and `is_file()`; catch `OSError` per file and log; decide whether reads should refresh the idle clock (touch the file on Search, or document "no write").

### C-5 · medium · `okf-export` / `okf-import --dry-run` re-encrypt a plaintext vault in place ("reads the vault only" / "writes nothing")
- **Where:** `__main__.py:99` and `:149` (`SQLiteMemoryVault(args.db)` with no explicit passphrase), `vault.py:276` (passphrase from env), `:311-323` (plain SQLite header → `_migrate_file_to_sqlcipher`), plus the integrity upgrade on open. Docs: `__main__.py:3-5`, CHANGELOG l.102 "reads the vault only", importer docstring l.54 "writes nothing".
- **Problem:** Both "read-only" commands open through the constructor's migration path. If `KIBISIS_PASSPHRASE[_FILE]` is set in the shell and `--db` points at a vault created with `allow_plaintext=True`, the first `okf-export` or `okf-import --dry-run` rewrites the whole file as SQLCipher and runs the integrity upgrade; the process that created it (plaintext opener) then fails with "file is not a database". The report still says `written: 0`.
- **Repro:** `tests/review_c_okf.py::test_okf_export_and_import_dry_run_rewrite_a_plaintext_vault_when_a_passphrase_is_in_the_env` (passing = bug). Probe: `rc 0 | header before b'SQLite format 3\x00' | after b'/\xbbHk^\xb0 ...' | bytes changed: True`.
- **Fix:** open the vault read-only for export/dry-run (a `read_only=True` constructor flag that skips migration/upgrade, or `mode=ro` URI), or at least refuse to migrate under `okf-*` and print why.

### C-6 · medium · `okf-export`/`okf-import` default `--db` is a different vault than the server, `admit` and `review` use
- **Where:** `__main__.py:20` (`~/.hermes/kibisis/vault.sqlite`), `:235`/`:250` (help says only "default: $KIBISIS_DB_PATH"); `config.py:37-57` (`default_db_path` → `$XDG_DATA_HOME/kibisis/vault.sqlite` or `~/.local/share/kibisis/vault.sqlite`); CHANGELOG l.52-54 (alpha.15 moved `admit` off the `~/.hermes` path).
- **Problem:** Under identical env the two defaults differ unless `KIBISIS_DB_PATH` is set; `XDG_DATA_HOME` is ignored by the okf commands. Both commands refuse a missing file (`:95`, `:145`), so the usual symptom is `error: no vault at ~/.hermes/kibisis/vault.sqlite` for a user who has the documented vault; but if a stale pre-alpha.15 vault still exists there, `okf-import` silently writes rows into it that the MCP server never reads, and `okf-export` exports stale data.
  | env | okf default | `config.default_db_path` |
  |---|---|---|
  | `HOME=$T/h` | `$T/h/.hermes/kibisis/vault.sqlite` | `$T/h/.local/share/kibisis/vault.sqlite` |
  | + `XDG_DATA_HOME=$T/xdg` | `$T/h/.hermes/kibisis/vault.sqlite` | `$T/xdg/kibisis/vault.sqlite` |
  | + `KIBISIS_DB_PATH=$T/explicit.sqlite` | `$T/explicit.sqlite` | `$T/explicit.sqlite` |
- **Repro:** `tests/review_c_okf.py::test_okf_cli_default_db_differs_from_the_vault_the_server_and_admit_use` (passing = bug).
- **Fix:** default `--db` to `config.default_db_path()` (lazily, at parse time) like `admit`; say the fallback in `--help`.

### C-7 · low · Non-finite JSON numbers (`Infinity`, `NaN`, `1e400`) in `timestamp` are 500, not 422
- **Where:** `aml_adapter.py:587` (`json.loads` default `allow_nan`/overflow → `float('inf')`), `:139-143` (`int(inf)` → `OverflowError`, `int(nan)` → `ValueError`).
- **Repro:** `tests/review_c_aml.py::test_json_infinity_or_nan_timestamp_is_500_not_422` (passing = bug; the string `"yesterday"` correctly gets 422 as control).
- **Fix:** `json.loads(..., parse_constant=...)` that raises, and `math.isfinite` in `_timestamp_ms`.

### C-8 · low · A lone-surrogate JSON escape in content is 500, not 4xx
- **Where:** `aml_adapter.py:587-589` accept `"\udc80"` (valid JSON, invalid Unicode); SQLite's UTF-8 encoding of the bound parameter raises `UnicodeEncodeError` inside `_write_tx` → 500.
- **Repro:** `tests/review_c_aml.py::test_a_lone_surrogate_escape_in_content_is_500` (passing = bug). Probe: `UnicodeEncodeError: 'utf-8' codec can't encode character '\udc80'`.
- **Fix:** after `json.loads`, re-encode text fields with `errors="strict"` and answer 422 (or `surrogatepass`/replace, documented).

### C-9 · low · Reused `request_id` with a different payload is acknowledged and silently dropped
- **Where:** `aml_adapter.py:322-334` — the marker row carries no payload digest.
- **Problem:** Per the contract a retry has the same payload; a client bug (or a request_id generator collision) that reuses an id loses the second request with `success: true`. Scoping per user is correct (`::test_request_ids_are_scoped_per_user`, control).
- **Repro:** `tests/review_c_aml.py::test_reused_request_id_with_a_different_payload_is_acknowledged_and_silently_dropped` (passing = bug).
- **Fix:** store a sha256 of the canonical message list in the marker's metadata and answer 409 when it differs.

### C-10 · low · Millisecond timestamps before 1973-03-03 are reinterpreted as seconds
- **Where:** `aml_adapter.py:141-142` (`abs(ms) < 1e11` → `*1000`).
- **Repro:** `tests/review_c_aml.py::test_small_millisecond_timestamps_are_silently_read_as_seconds` (passing = bug): `5_000_000_000` ms (1970-02-27) is rendered as `2128-06-11`.
- **Fix:** take the contract's unit as given (ms) and accept seconds only as an explicitly typed/string form, or document the heuristic.

### C-11 · low · `okf-*` ignore `KIBISIS_ALLOW_PLAINTEXT`, unlike the server/`admit`
- **Where:** `__main__.py:99`, `:149` vs `config.py:136-149`.
- **Repro:** `tests/review_c_okf.py::test_okf_cli_ignores_KIBISIS_ALLOW_PLAINTEXT_that_the_server_and_admit_honour` (passing = bug): `config.open_vault` opens the plaintext vault; `okf-export` exits 1 `cannot open the vault ... EncryptionRequiredError`.
- **Fix:** open through `config.open_vault(args.db)` (also fixes C-6 and, if a read-only mode is added, C-5).

### C-12 · low · 404 is answered before the credential is checked
- **Where:** `aml_adapter.py:570-577`. Unauthenticated clients can tell which POST paths exist. Documented by `::test_error_bodies_carry_no_traceback_or_path_and_unknown_routes_answer_before_auth`. Error bodies otherwise carry no traceback or path (control, same test).

## 3. Suspected, unconfirmed (from code reading; not exercised per the constraints)

- **S-1 · No socket timeout, unbounded handler threads.** `AMLHandler` sets no `timeout` (inherited `None`, verified: `AMLHandler.timeout = None`); `ThreadingHTTPServer` starts one daemon thread per accepted connection (`:417-420`, `request_queue_size=128`). A client that connects and sends nothing, or sends headers and a Content-Length but no body (`:532 rfile.read(size)`), holds a thread forever; a slow body upload holds a `max_inflight` slot (`:578`) for its whole duration — `--max-inflight` bounds request processing, not connections or threads. `DRAIN_SECONDS` applies only to the drain. Only `_drain_body` ever calls `settimeout` (`:556`). Demonstrating this needs a deliberately stalled connection, so not run. Fix: `timeout = 30` on the handler class (Python's `StreamRequestHandler` applies it to the socket) and ideally a connection cap.
- **S-2 · `purge_idle` stat-then-lock window.** mtime is read (`:267`) before `self._lock` is taken (`:272`); a request that writes between the two and finishes (refs back to 0) has its fresh vault deleted. Window is microseconds per file; not reproducible deterministically without instrumentation.
- **S-3 · Eviction while another thread opens the same vault.** `_evict_locked` only removes slots with `refs == 0` and `_close` takes `slot.lock`, so a vault in use cannot be closed under a handler — code looks correct; `test_lru_eviction_keeps_data_searchable` and `test_concurrent_adds_and_searches` in the existing suite exercise it. Two `SQLiteMemoryVault` objects on one file can briefly coexist (evicted one closing, new slot opening); SQLite file locking covers that.
- **S-4 · No-SQLCipher fallback is silent at the AML level.** If `sqlcipher3` fails to import, `vault.py:305-310` logs one warning per open and stores metadata (timestamps, roles, request digests) in the clear; `run_server` logs `encrypted=True` purely from `passphrase is not None` (`:634-635`). `sqlcipher3` is a hard dependency (pyproject l.29) so this needs a broken install; not exercised.
- **S-5 · Content-Length leniency.** `int(length)` (`:524`) accepts `"+5"`, `" 5 "`, `"1_0"`; harmless (the value is still bounded) but non-RFC; chunk-size lines likewise accept `0x10`. Not exercised.
- **S-6 · `--gate-cmd` output buffering.** `subprocess.run(stdout=PIPE)` (`export.py:865`) buffers the gate's entire output in memory before copying it to stderr; a chatty gate over a large bundle costs memory, not correctness. Timeout (900 s) kills the child; grandchildren of a shell-wrapper gate survive. Fail-closed on timeout/non-zero/launch failure is confirmed by `::test_gate_cmd_timeout_and_non_zero_exit_refuse_the_bundle_and_leave_nothing`.
- **S-7 · Key in environment.** `KIBISIS_AML_KEY` (raw key) is readable from `/proc/<pid>/environ` by the same uid; `--key-sha256` on argv is a digest only, so `ps` shows nothing secret. Same posture SECURITY.md l.165-167 states for `KIBISIS_PASSPHRASE`; not a defect, noted for completeness.

Not exercised by choice: raw-socket malformed framing (C-2 is shown on a `BytesIO` instead), stalled connections (S-1), concurrent eviction races (S-2/S-3), a broken `sqlcipher3` install (S-4).

## 4. Documentation that overstates the code

| Exact quote | file:line | Code fact |
|---|---|---|
| "`okf-export` and `okf-check` (P13.1) project the vault into an OKF v0.2 bundle and check one; they read the vault and never change it." | `src/kibisis/__main__.py:3-4`; same claim CHANGELOG.md:102 "reads the vault only" | `_okf_export` opens with `SQLiteMemoryVault(args.db)` (`__main__.py:99`); with a passphrase in the env the constructor migrates a plain SQLite file to SQLCipher in place and runs the integrity upgrade (`vault.py:311-323`). C-5 test shows the file's bytes and header change. |
| "`okf-import` (P13.2) diffs a bundle into the vault as model-origin candidates; `--dry-run` writes nothing." / "``dry_run=True`` reads the bundle and the vault and writes nothing." | `src/kibisis/__main__.py:5`; `src/kibisis/okf/importer.py:54`; `--dry-run` help `__main__.py:253` | Same open path (`__main__.py:149`); dry-run writes no rows but the open can rewrite the whole file (C-5). True for an already-encrypted, already-upgraded vault. |
| "`--db` … vault path (default: $KIBISIS_DB_PATH)" | `src/kibisis/__main__.py:235`, `:250` | The fallback is `~/.hermes/kibisis/vault.sqlite` (`:20`), not the per-user data directory the README (l.87) and `admit` (`:216`) use; `XDG_DATA_HOME` is ignored (C-6). |
| "`kibisis admit` opens the vault, key and scope the way the MCP server and `kibisis-review` do … instead of `~/.hermes/kibisis/vault.sqlite`" | CHANGELOG.md:52-54 | True for `admit`; the reader is not told that `okf-export`/`okf-import` (added in the same alpha.14/15 line) still default to the old path. Incomplete rather than false. |
| "There is one Kibisis vault per `user_id`, encrypted with SQLCipher." | deploy/aml/README.md:17; aml_adapter docstring l.11-12 says "unless `--plaintext`" | `--plaintext` (`__main__.py:266`, `aml_adapter.py:205-206`) stores vaults unencrypted; the deploy README's Method section never mentions it. Without `sqlcipher3` the vault falls back with only a log warning and `run_server` still logs `encrypted=True` (`aml_adapter.py:634-635`) — S-4. |
| "A retried request is acknowledged without being stored twice." | deploy/aml/README.md:20-21; CHANGELOG.md:27; aml_adapter docstring l.15-16 | True for an identical retry; a reused `request_id` with a *different* payload is also acknowledged and dropped (C-9, `aml_adapter.py:332`). The docstring's parenthetical "(same id, same payload, per the contract)" is the only hint. |
| "`--retention-days`: vaults with no write for this long are deleted." / "vaults idle for ``retention_days`` are deleted" | deploy/aml/README.md:56; CHANGELOG.md:34; `aml_adapter.py:29` | `purge_idle` deletes every `*.kib` path in the data dir by mtime, vault or not, and raises on a directory (C-4). "idle" (docstring) and "no write" (help) disagree: reads do not count. |
| "`aml-serve` reads and drops the body of a request it refuses unread (413 over the size limit, 429 when busy) for up to 2 s before closing. Closing with the body still arriving made the kernel reset the connection, so a client still sending got a reset instead of the reply" | CHANGELOG.md:74-76 | Accurate as stated, but 401 and 404 are also refused unread and are *not* drained (`aml_adapter.py:570-577`), so the reset the entry describes still happens for them (C-3). |
| "`--max-inflight`: requests served at once. Further requests get `429` with `Retry-After`." | deploy/aml/README.md:54; CHANGELOG.md:33 | The semaphore (`:578`) is taken after auth and before the body read, so it bounds body-reading+processing, not connections/threads; a negative chunk size or a stalled upload holds a slot indefinitely (C-2, S-1). |
| "An on-disk vault will not open without a passphrase unless you pass `allow_plaintext=True`." | SECURITY.md:19; README.md:111 (last sentence) | Also opens without a passphrase under `KIBISIS_ALLOW_PLAINTEXT=1` (`config.py:130-149`, MCP server/`admit`) and `aml-serve --plaintext` (`aml_adapter.py:206`). Incomplete. |
| Threat-model table "Who can do what" lists: local file writer, agent-side writer, forged review, passphrase holder. | SECURITY.md:31-38 (and Scope l.18-23) | No row for the `aml-serve` network client (bearer-key auth over plain HTTP, 64 MiB bodies, no socket timeout, retention deletion) or for an OKF bundle author (importer caps origin/state — verified by `::test_imported_rows_cannot_declare_origin_state_identity_or_reserved_metadata` — but the policy does not say so). Gap, not a false claim. |
| "Evaluation content is never logged; each request logs one line with its operation, status and latency." | deploy/aml/README.md:58 | Supported for the adapter's own logging (`:454-455`, `:600-605`). Caveat: `--gate-cmd` (OKF, not AML) copies whatever the gate prints to stderr verbatim (`export.py:870-871`, shown by `::test_gate_cmd_stdout_is_copied_to_stderr_verbatim`); a gate that echoes matches puts vault content on the terminal. Documented in the function docstring only. |

Checked and found supported by code: README l.25 "listens on `127.0.0.1` unless given `--host`" (`__main__.py:260-261`, `run_server` default); CHANGELOG l.13-15; deploy README l.44-45 "never needs the Memory System Key itself, only its SHA-256 digest" (`__main__.py:164-174`, `aml_adapter.py:495-497` constant-time compare of digests); aml docstring l.27 "a vault is used by one request at a time" (`_Slot.lock`); CHANGELOG l.26-27 "A failed write leaves nothing behind" (`_write_tx`, existing `test_failed_request_leaves_nothing_and_retry_stores_it_whole`); `user_id` → path is a sha256 digest (`:201-202`; control test, 8 hostile names).

## 5. Test-suite gaps (existing `tests/test_aml_adapter.py`, `test_okf_export.py`, `test_okf_import.py`)

- No test feeds a timestamp outside the `datetime` range, a non-finite JSON number, or a lone surrogate (C-1, C-7, C-8).
- `test_chunked_request_body` sends only well-formed chunks; no malformed chunk-size line (C-2).
- `test_a_refused_body_is_read_and_dropped_so_the_connection_closes_cleanly` covers 413/429 only, not 401/404 (C-3).
- `test_retention_purges_idle_vaults_only` has no decoy files, directories, or read-only users in the data dir (C-4).
- `test_retried_request_is_stored_once` retries the identical payload only (C-9).
- `test_cli_dry_run_reports_and_writes_nothing_then_a_real_run_writes` compares a logical snapshot of an already-encrypted vault, not file bytes, so the migration-on-open (C-5) is invisible.
- No test pins the `okf-*` default `--db` against `config.default_db_path()` (C-6) or `KIBISIS_ALLOW_PLAINTEXT` (C-11).
- No test asserts a socket/handler timeout exists (S-1) — a one-line `assert AMLHandler.timeout` would pin a fix.
- `--gate-cmd` tests cover a hit and a pass; no timeout, launch-failure, or non-zero-exit case (now covered by `review_c_okf.py` as a control).

## 6. Coverage

**Files read (line ranges at 1299c28):** `src/kibisis/aml_adapter.py` 1-643 (all); `src/kibisis/__main__.py` 1-281 (all); `src/kibisis/config.py` 1-149 (all); `src/kibisis/vault.py` 95-101, 118-120, 211-335, 462-470 (constructor, reserved keys, sqlcipher detection); `src/kibisis/okf/export.py` 85-118, 264-275, 361-373, 540-660, 756-874; `src/kibisis/okf/importer.py` 1-497 (all); `README.md` 1-152 (all); `SECURITY.md` 1-183 (all); `CHANGELOG.md` 10-36, 50-58, 70-80, 99-112, 416-424 (AML/OKF/path entries); `deploy/aml/README.md` 1-58, `deploy/aml/Dockerfile` 1-26; `pyproject.toml` 25-30; `tests/test_aml_adapter.py` 1-60, 195-314 and test names; `tests/test_okf_import.py` 1-60, 705-760 and test names; `tests/test_okf_export.py` 384-452 and test names; `tests/_okf_fixtures.py` 40-60 and function names.

**Not reached:** `okf/check.py`, `okf/frontmatter.py`, `okf/profile.py` (only their call sites); `keys.py` (`_read_keyfile`, `resolve_passphrase` — trusted from SECURITY.md l.152-155 and other reviewers' areas); `_vault_crypto.py` integrity upgrade internals; `mcp_server.py`; the Rust crate; Docker image build.

**Tests run (commands + counts):**
- `cd /opt/data/cache/scratch/kib-review && ARGUS_LEDGER_PATH=$TMPDIR/argus_c.jsonl PYTHONPATH=src /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/review_c_aml.py tests/review_c_okf.py` → `28 passed in 11.13s` (21 + 7).
- Same command with `tests/test_aml_adapter.py` (existing, single file) → `41 passed in 11.90s` (unchanged baseline for this file).
- Probe scripts (not deliverables, under `$TMPDIR/kib-review-probe/probe{1,2,3}.py`) produced the ACTUAL outputs quoted above.

**Test inventory (`passing = bug` unless marked control):**
`review_c_aml.py`: out-of-range timestamp → Search 500 (C-1); Infinity/NaN/1e400 → 500 (C-7); small ms read as seconds (C-10); lone surrogate → 500 (C-8); reused request_id dropped (C-9); request_id scoped per user (control); retention deletes decoy + dies on directory (C-4); read-only user purged (C-4c); negative chunk size bypasses cap (C-2); one byte over cap → 413 (control); user_id → path inside data dir ×8 (control); large body on 401/404 → broken pipe (C-3); error bodies leak nothing + 404 before auth (control / C-12); auth header forms (control).
`review_c_okf.py`: default `--db` divergence (C-6); `KIBISIS_ALLOW_PLAINTEXT` ignored (C-11); export/dry-run re-encrypt plaintext vault (C-5); gate timeout/non-zero/launch-failure refuse and leave nothing (control); gate stdout copied to stderr (caveat); symlinks never followed out of the bundle (control); imported rows cannot declare origin/state/identity/reserved keys (control).
