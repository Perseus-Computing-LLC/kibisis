# Review C (alpha.16): AML adapter, OKF/CLI vault paths, docs

Unreleased. To be folded into CHANGELOG.md by the merge; no version bump.

## Fixed

### `kibisis aml-serve` (`src/kibisis/aml_adapter.py`)

- **C-1** A message timestamp must convert to a datetime at Add; otherwise `422` naming the field. A stored
  row whose timestamp cannot be rendered is returned without `created_at`, and a row with unusable metadata is
  skipped and logged; Search never answers `500` because of a stored row.
- **C-2** Chunked bodies: the chunk-size line must be 1–16 hex digits (no sign, no `0x`); anything else is
  `400 malformed chunked body` and the connection closes. The body cap is checked before every chunk and a
  short read is `400`. `Content-Length` must be plain digits.
- **C-3** `401` and `404` drain the declared body (same `DRAIN_SECONDS` logic as `413`/`429`) and send
  `Connection: close`, so a client with a large body reads the reply instead of a reset.
- **C-4 / S-2** Retention deletes only regular, non-symlink `<32 hex>.kib` files whose first page matches the
  pool's mode (SQLite header for `--plaintext`, no header for SQLCipher); directories and decoys are skipped;
  per-file errors are logged and the sweep continues; the mtime check and the unlink happen under the pool
  lock, and a vault whose slot is in use is skipped. Reads count as activity: a Search touches the vault's
  mtime. The retention thread survives a failed sweep.
- **C-7 / C-8 / C-10** JSON is parsed with `parse_constant`/`parse_float` that refuse `NaN`, `Infinity` and
  overflowing floats (`400`); a lone surrogate anywhere in the body is `400`, and every stored string is
  checked for UTF-8 encodability (`422`). The ms-vs-seconds rule is documented and bounded: `>= MS_FLOOR`
  (1e11) is milliseconds, `[SECONDS_FLOOR, SECONDS_CEILING)` = `[1e9, 4e9)` is seconds, every other number is
  `422` instead of a silent reinterpretation.
- **C-9** A reused `request_id` with a different payload is `409 request_id was already used with a different
  payload` (the marker stores a payload digest); identical retries stay idempotent.
- **C-12 / L8** The credential is checked before routing: every unauthenticated `POST` is `401`, so routes
  are not enumerable without the key.
- **S-1** `AMLHandler.timeout` / `--socket-timeout` (default 30 s) close idle and stalled connections (`408`
  when the headers were complete); `--max-connections` (default 256) caps handler threads with `503` +
  `Retry-After`; `server_bind` no longer does a reverse-DNS lookup. `--max-inflight` is documented as bounding
  processing, not connections.
- **S-4** The startup line logs `encrypted_at_rest=` computed from the passphrase and `sqlcipher3`
  availability, and warns when a passphrase is set but the files are not SQLCipher. (After the area B merge
  this should read the vault's `encrypted_at_rest` property instead; the value is the same.)

### `kibisis okf-export | okf-check | okf-import` (`src/kibisis/__main__.py`, `okf/export.py`)

- **F17 / C-5 / C-6 / C-11** The okf commands resolve the vault exactly like every other subcommand:
  `--db`, else `KIBISIS_DB_PATH`, else `config.default_db_path()`; they open it through `config.open_vault`,
  so `KIBISIS_ALLOW_PLAINTEXT` and the key rules apply and the refusal messages match. The import-time
  `DEFAULT_DB_PATH` (`~/.hermes/kibisis/vault.sqlite`, used by nothing else) is gone; the name remains as a
  lazy module attribute returning `default_db_path()`. `--db` help says what the default is. A missing vault
  is `error: no vault at <path>` (rc 1), never created.
- **C-6** `okf-export` and `okf-import --dry-run` open the vault read-only: `SQLiteMemoryVault(read_only=True)`
  connects with `mode=ro`, derives keys from the stored salt, builds no index, refuses (rather than performs)
  an integrity upgrade, reads a plain-SQLite file as the plaintext vault it is even when a passphrase is set
  (no in-place SQLCipher conversion), and raises `ReadOnlyVaultError` from `_write_tx`. A test asserts the
  file's bytes are unchanged. `config.open_vault(..., read_only=True)` wraps it. The module docstring's
  "reads the vault and never changes it" is now true.
- **L9** `--gate-cmd` output is summarised on stderr (verdict, exit status, file and line counts);
  `--gate-verbose` copies it. Launch failures log the exception type, not its text.

### Docs

- `deploy/aml/README.md`: `--plaintext` in Method, retried-request and `409` semantics, timestamp rule,
  `--max-inflight` vs `--max-connections` / `--socket-timeout`, the retention rule (Add or Search counts;
  only real vault files), `401` before `404`, draining.
- `SECURITY.md`: threat-model rows and sections for the `aml-serve` network client and the OKF bundle
  author. `README.md` points at them.

## Tests

- `tests/review_c_aml.py` → `tests/test_review_c_aml.py`, `tests/review_c_okf.py` → `tests/test_review_c_okf.py`;
  every "passing = bug" demonstration now asserts the fixed behaviour; the positive controls are kept.
- New: stalled-header and stalled-body connections are closed within `socket_timeout + 2 s` and the handler
  thread exits (1 s timeout, under 5 s total); `max_connections` → `503`; retention with a decoy file, a
  hex-named non-vault, a directory, a symlink and an open slot; reads count as activity; `is_vault_file`
  follows the pool's mode; read-only okf commands leave the vault bytes unchanged (plaintext file with a
  passphrase in the environment, and an encrypted file); `ReadOnlyVaultError`; `--gate-verbose`.

## Not fixed

- Nothing in area C is left open. `S-4` reads the encryption state from the config until area B's
  `encrypted_at_rest` property lands; swap `_encrypted_at_rest(config)` for the property at merge.

## Round 2

Second-pass findings R2-C-1..R2-C-5 (`review_notes/R2_C.md`), plus the "suspected" and "overstates" lists.

### Fixed

- **R2-C-1** input-driven `500`s, the class and the three instances. `_timestamp_ms` bounds a JSON integer
  against `MS_CEILING` before `float()` (a 400-digit integer is `422`, not `OverflowError`); `top_k` as a
  string must be 1–9 ASCII digits before `int()` (a 5000-digit string, or `"²"`, which `isdigit` accepts and
  `int` refuses, is `422`); `parse_json_body` catches `RecursionError` (`400`). The class: the field-reading
  halves of Add and Search (`_read_add`, `_read_search`) and the handler's body read + parse run under
  `_validating(...)`, which turns any exception other than `ContractError` and the socket's own errors into
  `422` (fields) or `400` (body) with a stable message, logging the exception type and the traceback frames
  once — never the exception's text, which could quote the request. The `500` branch is now reserved for
  the storage side.
- **R2-C-2** retention and the S-4 warning in the no-`sqlcipher3` fallback. `VaultPool.encrypted_at_rest`
  (passphrase set *and* driver loaded) is what `purge_idle` passes to `is_vault_file`, so plain-SQLite
  vaults written under a passphrase without the driver are recognised and deleted when idle. `storage_mode`
  (called by `run_server` before binding) raises `EncryptionRequiredError` for a passphrase without
  `sqlcipher3` and without `KIBISIS_ALLOW_PLAINTEXT`: `aml-serve` exits 2 with the reason instead of
  answering `500` to everything. The warning for the opted-in fallback now says what is in the clear and
  that retention treats the files as plaintext vaults. `_encrypted_at_rest` is kept as an alias.
- **R2-C-3** documented, not changed: SECURITY.md §OKF bundle author, the `__main__` docstring and
  `config.open_vault` now say a read-only open may create and leave an empty `-wal` and a `-shm` beside a
  WAL-mode vault (the vault file's bytes are unchanged; the next writable open removes them). `immutable=1`
  was not used: it disables locking against a concurrent writer.
- **R2-C-4** `AMLHandler.handle_expect_100` checks the credential and the route before answering
  `Expect: 100-continue`: an unauthenticated `POST` gets `401`, an unknown path with the key gets `404`,
  neither sends `100` nor drains (no body was invited), and the connection closes. Authorised requests on a
  real route keep the stdlib behaviour.
- **R2-C-5** `vault.py:_open_read_only` runs the key check and the edited-down `integrity_format` test
  before the upgrade refusal (the writable open's order): an edited record is refused as "the integrity
  record was edited" (`VaultIntegrityError`) instead of "open it writable once first", and a wrong passphrase
  on a vault that carries a key check is a key failure.
- Suspected list: `AMLConfig` rejects `max_body_bytes < 1` and `retry_after_s < 0`; `is_vault_file` now runs
  under the pool lock in `purge_idle`, so the file checked is the file unlinked; the error branches of
  `do_POST` reply through `_reply`, which swallows an `OSError` from a client that is already gone (no
  `socketserver.handle_error` traceback on stderr). The chunked-body drain note moved into
  `deploy/aml/README.md`.
- Overstates table: SECURITY.md no longer says `okf-check` opens a vault; the `aml-serve` section says
  unexpected failures while reading a request are `4xx` and that `Expect: 100-continue` is answered after
  the credential check; `deploy/aml/README.md` says `Content-Length` bodies are drained and chunked bodies
  are not, that markers written before the payload digest existed accept any payload under their id, and
  what happens without `sqlcipher3`.

### Tests

- `tests/review2_c_aml.py` → `tests/test_review2_c_aml.py`, `tests/review2_c_okf.py` →
  `tests/test_review2_c_okf.py`; every `test_attack_*` is now `test_fixed_*` asserting the fixed behaviour;
  controls kept. The connection-permit control produces its `500`s from a patched storage call, since the
  input shape it used is `422` now. New: unexpected validation errors are `422` and logged once without the
  request's text (`caplog`); a patched parser raising `RecursionError` is `400` and keep-alive survives;
  `AMLConfig` bounds; `storage_mode` refuses / `run_server` raises before binding; the no-driver fallback's
  retention deletes an idle vault; `Expect: 100-continue` → `401`/`404`/`100` by case; read-only open leaves
  the vault file's bytes and mtime unchanged and at most an empty `-wal`, which the next writable open
  removes; the plain-file keyed fallback reports a wrong passphrase as such. Every test < 2.1 s.

### Not fixed

- Nothing from R2-C is left open. R2-C-3 is settled by documentation (the sidecars are SQLite's, and the
  vault file is unchanged). On a genuinely format-1 keyed vault with no key check, a read-only open still
  cannot tell a wrong passphrase from a vault that needs the upgrade (there is nothing to check against);
  the message says to open it writable once, which is the right advice there.

## Round 3 — MCP/config

### Fixed

- **R3-E2** (low) `_call_tool` maps `PermissionError` (`OriginClassError`, `SupersededEntryError`, any
  subclass a tool body did not map) to the tool result `Refused: <msg>` with `isError`, no traceback on
  the server log. The vault's own journal entry stands for an origin-class refusal; a supersession
  refusal is journaled by the server (`path=mcp`, `reason=superseded_refused`), any other
  `PermissionError` as `permission_refused`.
- **R3-E3** (low) `tools/call` with `params` that is not an object answers JSON-RPC `-32602`
  `params must be an object` from `handle_request` (no `AttributeError` for an embedder, no `-32603`
  plus traceback over stdio).
- `kibisis_health` reports `verification_quorum` (`accounts`, `pinned`, `note`); the stdio banner says
  `quorum 1 — one account verifies` when the vault runs with one (R3-E1; the pinning change itself is in
  area A).

### Tests

- `tests/review3_entry_mcp.py` → `tests/test_review3_entry_mcp.py`, `tests/review3_entry_aml.py` →
  `tests/test_review3_entry_aml.py`: collected; the `test_attack_*` cases assert the fixed behaviour;
  `test_control_health_and_ledger_do_not_leak_secrets` now expects the quorum in the health report.

## Round 5

- **R5-1 (b)** `--adopt-keyless` on `kibisis-review <verdict>` / `lift` (the TTY-gated commands) and on
  the admit command in `kibisis` main: the one place an operator gives a passphrase to a plaintext
  vault that holds entries; passes `adopt_keyless=True` to `open_vault`. `review list`, the MCP and
  AML servers and the OKF commands never pass it (pinned by
  `test_fixed_r5_1_servers_and_okf_commands_never_pass_the_opt_in`). `review list` prints the
  adoption notice; `kibisis_health` reports `keyless_adoption` (`entries`, `at`, `note`) or null.

## Round 6

- **Minor** `config.cli_refusal_text` rewords a vault refusal for a person at a CLI: the library's
  "pass adopt_keyless=True" becomes "pass --adopt-keyless" in `kibisis-review` and the admit command
  (which now also catches `ValueError`/`PermissionError` from the open and exits 2 instead of
  tracing). The `--adopt-keyless` help text on both says the adoption happens at the open, before the
  verdict/admission, each row stored as a model-origin candidate, and is written even when the verdict
  itself is then refused. `review list` / verdicts print the adoption line with "in memory only: this
  read-only open wrote nothing" for a read-only in-memory adoption (R6-3) and the count of journal
  events chained on the file's word (R6-1).

## Round 7

- **Minor (R7-2)** `kibisis-review list` refused on a keyless file said "pass --adopt-keyless", a flag
  `list` does not accept (only the verdicts and `lift`, behind the terminal check, adopt), so following
  the message gave an argparse error. `list` stays read-only; its refusal now says "open it with a
  verdict command (approve, dispute, reject or lift) and --adopt-keyless" (`review._refusal_text`). The
  verdicts' refusal is unchanged.
