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
