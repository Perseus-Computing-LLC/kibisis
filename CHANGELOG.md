# Changelog

All notable changes to `kibisis` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Write trust boundary.** A `model`, `tool` or `unknown` origin can only write `candidate` entries: any other
  `epistemic_state` (`revoked` included) is capped and recorded as `trust_capped_from`, and `author_id`,
  `last_verified_at`, `supersession`, `proposed_supersedes` and `slot` move under `agent_metadata`, so an agent's
  write no longer moves recall's TTL clock. A cascade started by such a write no longer changes a higher-class
  or person-reviewed dependent; it adds an `invalidation_notice` to that entry's metadata and stops there.
- **Review doors.** `review_entity` refuses any `reviewer_origin` other than `user` (`PermissionError`) and a
  verdict with no `reviewer_id` (`ValueError`); `put()` / `put_batch()` no longer accept the internal review
  arguments (`TypeError`). A user-origin write or review attests as the operating-system account running the
  process, never as `author_id` / `reviewer_id`; `attester=` is honoured only on a vault opened with
  `trust_caller_identity=True`, and `principal` or an empty name is never a signer. A principal's write of
  different content over an attested entry resets its attestations and the quorum starts over.
- **Tombstones carry a class.** Each tombstone records the `origin_class` of whoever made it (older rows count as
  `principal`). A higher-class write lifts a lower-class tombstone (journaled `tombstone_lifted`); a
  principal-class tombstone blocks everyone until a person lifts it with `kibisis-review lift CATEGORY KEY
  [--digest PREFIX]` or `lift_tombstone()`, which refuses a `model`, `tool` or `unknown` `origin`. A class never
  goes down (`tombstone_reaffirmed`). MCP `kibisis_forget` records a model-class tombstone.
- **Tombstone checks apply everywhere.** `tombstone(content=...)` runs the protected-entry check first and deletes
  nothing when `content` does not match the stored value; a non-principal origin cannot tombstone `scope="*"`;
  `purge()`, `archive()` and `set_persona_slot()` take `origin` and run the same check. The entry key and every
  string in the caller's metadata (keys and values) are digested against tombstones; the vault's bookkeeping
  strings are not. The canonical fold drops nonspacing marks and default-ignorable code points, folds a small
  table of Latin/Cyrillic/Greek homoglyphs and turns Hangul fillers into spaces; the Rust fold is unchanged.
- **Signed tombstones and journal continuity (integrity format 3).** Every tombstone row carries an HMAC verified
  at open and on every hit; a journaled tombstone whose row is missing, or whose stored class is lower than the
  journal says, refuses the open. A keyed vault pins the lowest journal format it has held, whether it ever held
  a row, and the highest sequence a signed head covers (`journal_high_water`): rows cannot be rewritten in the
  unkeyed format 1 layout, an append on a journal that no longer ends at the signed head is refused
  (`VaultIntegrityError`), and `verify_audit_chain()` is False when the journal ends below the mark, so a wipe is
  not laundered by the next write. The verifier streams the journal (no row cap), refuses rows above the
  supported format and reports unreadable metadata through `vault.last_chain_error` instead of raising.
- **Key check and meta MAC before anything is written.** `key_check` is compared before any migration or SQLCipher
  conversion; a wrong passphrase leaves a plain file byte for byte unchanged, and a converted copy replaces it
  only after it has opened, authenticated and upgraded. The vault's integrity records, journal marks and stored
  `verification_quorum` are bound under one MAC; a keyed vault whose MAC is missing or wrong refuses to open. A
  MAC over the legacy key set is re-signed at the first writable open, but no stored quorum under it is trusted:
  it is logged at WARNING, dropped, remembered as `quorum_dropped_from`, and the next verdict re-pins it. Removing
  `kdf_salt` while a key check, MAC, format 2+ record or sealed row remains is refused. A salted vault with no
  key check migrates only when it is a genuine 0.1.0a5 file; any witness of a later format, any plaintext or
  unopenable row, or an empty entity table beside unpurged `put` events refuses the open with nothing written.
  An envelope naming another salt is refused.
- **Keyless adoption is opt-in and never trusting.** A keyed open of a file with no salt that holds any content
  (entries, tombstones, journal events, or `vault_meta` records a first open does not write) is refused unless
  `adopt_keyless=True` / `--adopt-keyless` is passed. Adopted rows are stored as a model-origin write would be:
  `candidate`, agent class, principal-only keys under `agent_metadata`, supersession and `tenant_id` dropped,
  sealed on disk, stamped `adopted_from_keyless_file`. A keyless file with a tombstone row, or a journal and no
  entries, is never adoptable; a planted `verification_quorum`, `quorum_dropped_from` or `journal_high_water` is
  dropped with a WARNING; a file with no `entities` table is refused. A read-only open adopts in memory only.
- **Quorum pinning.** The stored `verification_quorum` is written only by a pinning open (`pin_quorum=True`: the
  `kibisis-review` verdicts and `kibisis admit`, behind their terminal check). Every other open adopts the stored
  value or runs with its own and writes nothing; a stored quorum below the default is adopted only by a process
  whose own argument or `KIBISIS_VERIFICATION_QUORUM` names it, otherwise `ConfigError` says what to set.
  `open_vault(env=...)` reads `KIBISIS_VERIFICATION_QUORUM` from its mapping, not from `os.environ`.
- **Snapshot trust.** `import_snapshot` keeps attestations, pending verifications and reviews only when the
  snapshot's passphrase-sealed `trust_seal` opens here and `manifest_sha256` verifies; otherwise they are dropped
  (journaled) and the state re-derived. A vault without a passphrase never keeps trust facts from a file. `origin`
  and `author_id` are exported and restored, so a verified entry round-trips intact in its own vault. The restore
  is one transaction, imported tombstones are journaled, a foreign snapshot leaves a reviewed or higher-class row
  in place, and a tombstone's class comes from the file only under a seal naming the tombstones, else it is
  capped at the importer's `origin`.
- **Integrity failures are not silent.** A row that fails its check is left out of search, listing, export and
  `forget_requests` with a WARNING, counted in `vault.integrity_failures`, and raises `EntryIntegrityError` on a
  vault opened with `strict=True`. With a passphrase but no `sqlcipher3`, an on-disk vault is refused with
  `EncryptionRequiredError` unless `allow_plaintext=True` or `KIBISIS_ALLOW_PLAINTEXT=1`.
- **Leases.** `FileLeaseCoordinator` keeps a per-resource highest-token file, so deleting or rolling back the state
  file cannot reissue a fencing token; a lease whose deadline has arrived can neither be renewed nor fence a write.
- **MCP, AML and CLI hardening.** The MCP server maps any `PermissionError` to a `Refused:` tool result with no
  traceback, answers non-object `params` with JSON-RPC `-32602`, and caps `kibisis_remember` keys at 128
  characters. `kibisis aml-serve` checks the credential before routing (every unauthenticated `POST`, and
  `Expect: 100-continue`, is `401`), closes idle connections after `--socket-timeout`, caps handler threads at
  `--max-connections` (`503`), refuses `NaN`/`Infinity`, lone surrogates and out-of-range timestamps, answers a
  reused `request_id` with a different payload `409`, and deletes only real vault files at retention. The OKF
  commands resolve the vault like every other subcommand (`--db`, `KIBISIS_DB_PATH`, default path) through
  `config.open_vault`; `okf-export` and `okf-import --dry-run` open it read-only and leave its bytes unchanged.

### Changed
- `INTEGRITY_FORMAT` is 3. The first writable open of a format 2 vault with its passphrase upgrades it in one
  transaction; older versions cannot open an upgraded vault. A keyed format 1 file with any plaintext,
  undecryptable or malformed row is refused as a whole instead of migrated with `entries_undecryptable > 0`.
- Giving a passphrase to a plaintext vault that holds entries needs `adopt_keyless=True` (library) or
  `--adopt-keyless` (`kibisis-review` verdicts and `lift`, `kibisis admit`); the adopted entries come back as
  `origin="model"` candidates until a person reviews them. `kibisis-review list`, the servers and the OKF
  commands never adopt.
- A library open never stores the quorum. Opening a vault with a smaller `verification_quorum` than it stored,
  or a vault pinned at 1 without naming 1, raises `ConfigError`; a file whose MAC predates quorum binding loses
  its pin until the next verdict re-pins it. `put(origin="user", epistemic_state="verified")` from one process is
  one attestation whatever `author_id` says; a quorum of two needs two accounts.
- A snapshot restored into a vault under another passphrase keeps its entries' origin and author but not their
  verdicts; a keyless vault's own export restores `verified` / `disputed` entries as `candidate`.
- `kibisis-review list` opens the vault read-only (a missing vault is "nothing to review") and prints the quorum
  in force and any keyless adoption; it and `kibisis admit` print the resolved vault path and scope and, when the
  entry is elsewhere, the scopes that hold it. A refused open prints one line and exits 2.
- `kibisis aml-serve` answers malformed or unexpected input with `400`/`422` instead of `500`, and exits 2 before
  binding when a passphrase is set without `sqlcipher3` and without `KIBISIS_ALLOW_PLAINTEXT`.
- `recall()` gates the whole matched set. `n_matched` and the withheld counts are those of every match and the
  z-score's mean and deviation are taken over all of them (with four or more matches, as before). The receipt's
  `hits` and the `withheld` list name the best `max(limit * 8, 64)` matches in BM25 order, plus any entry that
  was returned or withheld for a conflict; the counts say how many more there are, and the MCP envelope's
  `below_gate` count is the receipt's.
- Recall coverage is read from the search index: a query word is covered wherever the index matched it
  (category, key, content or scope, with the index's folding of case and accents, and as the start of a longer
  word where the index matches prefixes). A word that names a category is covered in every entry of that
  category, so a query that shares words with keys or categories passes more entries than before.
- Recall gates on what the vault keeps unsealed (scores, keys, metadata, times) and opens only the entries it
  returns, compares for a slot conflict or digests. An entry that fails its integrity check is still never
  returned; it can now be counted among the matches and named as withheld.

### Added
- `SQLiteMemoryVault` / `config.open_vault` keywords `strict`, `read_only`, `pin_quorum`, `adopt_keyless`,
  `allow_plaintext` and `trust_caller_identity`; `KIBISIS_ALLOW_PLAINTEXT`; `origin` on `purge()`, `archive()`,
  `set_persona_slot()`, `lift_tombstone()` and `import_snapshot()`.
- `kibisis.VaultIntegrityError`, `kibisis.EntryIntegrityError`, `kibisis.EncryptionRequiredError`,
  `kibisis.vault.ReadOnlyVaultError`; `vault.integrity_failures`, `vault.last_chain_error`,
  `vault.encrypted_at_rest`, `vault.verification_quorum_stored`, `vault.quorum_dropped_from`, `vault.keyless_adoption()`.
- `kibisis-review lift CATEGORY KEY [--digest PREFIX]`; `--adopt-keyless` on the verdicts, `lift` and `kibisis
  admit`; `kibisis-review list` marks a candidate that `approving retires <cat>:<key>`, and forget requests are
  journaled as their own `forget_request` action so other refusals cannot hide them.
- `kibisis_health` reports `verification_quorum` (`accounts`, `pinned`, `note`) and `keyless_adoption`.
- `recall(prefer_recent=True, recency_boost_bp=5000, recency_half_life_days=30)`: off by default. When on, a hit
  that passed the gate is ranked by its score times `1 + boost * 2^(-age / half_life)`, the age taken from
  `updated_at`; which hits pass does not change. The receipt carries the setting (`recency`) and each boosted
  hit's factor (`recency_bp`). For "what is the latest state" questions; leave it off for "what is the rule".
- Withheld rows below the gate carry `coverage_bp`, `rank` (position in BM25 order) and `updated_at`, and every
  receipt hit carries `rank` and `updated_at`, so a caller can pick a key to read. They carry no content unless
  the caller passes `recall(withheld_digest_chars=N)`: then rows below the gate, never rows withheld for a
  conflict or as stale, also carry the first N characters of the content on one line (`digest`).
- The `kibisis.memory_recall` Argus event and `recent_recalls()` carry `returned`: the refs of the entries a
  recall returned, in order, as one comma-separated string of at most 40 `category:key` refs.
- `kibisis aml-serve --socket-timeout` and `--max-connections`; `--gate-verbose` on the OKF commands.
- Rust: `kibisis::journal::verify_chain_with(.., head_required)` and `kibisis_native.verify_chain`, with the same
  rules in Python's `kibisis._vault_audit.ChainVerifier`. `extension-module` is a default feature of
  `bindings/python`, so `cargo test --no-default-features` runs the crate's own tests.

### Fixed
- `kibisis aml-serve`: a stored row with an unrenderable timestamp or unusable metadata no longer makes Search
  answer `500`; malformed chunk sizes are `400`; `401` and `404` drain the body and close the connection; the
  retention thread survives a failed sweep and a Search counts as activity; `server_bind` does no reverse DNS.
- `kibisis_native.FileLeaseCoordinator` no longer raises `RuntimeError: Already borrowed` under concurrent calls,
  and a `ttl_seconds` past the supported range is a `ValueError`, not a panic.
- A vault holding `tombstone_lifted` events written before this release, or a lift of a global `*` row,
  reconciles at open instead of refusing both open modes.
- A read-only open runs the key check before the upgrade refusal, so a wrong passphrase is reported as such; a
  non-integer `integrity_format` is a `VaultIntegrityError` naming it.
- `KIBISIS_VERIFICATION_QUORUM` is validated (positive decimal only) and a bad value prints one line (exit 2).
- `kibisis-review list` refused on a keyless file no longer suggests a flag it does not accept; the OKF commands'
  import-time `DEFAULT_DB_PATH` is gone (a lazy alias of `default_db_path()` remains).
- `recall()`: the verdict for a hit no longer depends on `limit`, and `n_matched` is no longer capped at
  `max(limit * 8, 64)`; the gate used to see only that many of the best matches.
- `recall()`: a hit found through its key or category, or through the index's folding of accents, is no longer
  withheld as `below_gate` with a coverage of 0.

### Documentation
- SECURITY.md and README state the residual limits: the terminal check stops pipes and cron jobs but not an agent
  that can allocate a pseudo-terminal in the operator's account, and a same-uid shell can run the review CLI; a
  reset to a salted file with no entry, tombstone or journal event is an empty vault the discriminator cannot tell
  from a fresh one (the operator sees a `migrate` event with `empty_keyed_file`); keyless adoption is an opt-in
  that stores agent-class candidates only; a restore of the vault's own snapshot is a point-in-time replay of the
  reviews too (a later rejection still wins); `import_snapshot(origin=None)` is principal, so a library caller
  relaying an agent's file must pass the agent's `origin`; treat snapshot files like the database file; deleting
  a lease's highest-token or lock file is out of scope.
- SECURITY.md gains threat-model rows for the `aml-serve` network client and the OKF bundle author, and says a
  read-only open may leave an empty `-wal`/`-shm` beside a WAL-mode vault. `deploy/aml/README.md` covers
  `--plaintext`, retries and `409`, the timestamp rule, `--max-inflight` vs `--max-connections`, retention and
  draining. README documents the tombstone fold limits, forget/lift, the fencing highest-token file and the
  quorum default.
- The `recall()` docstring no longer says each call is journaled as a `recall` event: a recall writes nothing to
  the vault or its journal. It is kept in `recent_recalls()` and, when `ARGUS_LEDGER_PATH` is set, in the Argus
  ledger.

## [0.1.0-alpha.16] - 2026-11-05

### Changed
- `kibisis aml-serve` and `kibisis.aml_adapter.run_server` now bind `127.0.0.1` by default instead of `0.0.0.0`,
  so a server started without `--host` is reachable from this machine only. Pass `--host 0.0.0.0` to listen on every
  interface; the `deploy/aml` Docker image already does, so containers are unaffected.
- README: the "Local only" line said Kibisis contains no network code, which stopped being true when alpha.15 added
  `aml-serve`. It now says Kibisis makes no outbound connections and names the opt-in server.

## [0.1.0-alpha.15] - 2026-11-05

### Added
- `kibisis aml-serve`: an HTTP adapter for the [Agent Memory Leaderboard](https://agentmemoryleaderboard.ai)
  Add/Search contract (Textual track), in `kibisis.aml_adapter`, using only the standard library. Each
  `user_id` gets its own vault, encrypted with SQLCipher unless `--plaintext` is passed. Each message is stored
  verbatim as its own entry, with its role and timestamp in the entry metadata.
  - **Add** writes the whole request in one transaction, together with a marker keyed on `request_id`. A failed
    write leaves nothing behind, and a retried request is acknowledged without being stored twice.
  - **Search** runs one BM25 query (`match="any"`) over the question and any answer options. It groups hits by
    the Add request they came from, shows each hit with the message before it, and returns up to `top_k` groups,
    best first, with stable ids and scores that never rise down the list.
  - **Auth** accepts `Token`, `Bearer` or `X-Api-Key`. The server needs only the key's SHA-256 digest
    (`--key-sha256`, `KIBISIS_AML_KEY_SHA256`), or reads the key from `KIBISIS_AML_KEY_FILE` or `KIBISIS_AML_KEY`.
  - **Limits:** above `--max-inflight` requests are refused with `429` and `Retry-After`. Per-user vaults are kept
    open up to `--max-open-vaults`, and vaults with no write for `--retention-days` are deleted.
  - **Deployment:** `deploy/aml/` has a Dockerfile and a README.
  - Tests are in `tests/test_aml_adapter.py`.

### Changed
These follow the [Agent Memory Atlas](https://neoneye.github.io/agent-memory-atlas/systems/kibisis/) reading
of e9ddf61, which named each as a limit (`tests/test_atlas_limits_20261105.py`).
- MCP `kibisis_recall` goes through the gated `recall()`, as the library's model-facing path does, instead of
  `search()`. Two verified entries that conflict are both held back and named on `<withheld>` lines; matches that
  contain under half of the query's words, or that do not stand out from four or more other matches, are left out
  and counted; and each call is recorded on the recall log and mirrored to Argus as `kibisis.memory_recall`.
- `kibisis-review approve`, `dispute` and `reject` need a terminal on stdin, as `kibisis admit` does, and refuse
  (exit 3) before opening the vault without one. `list` still runs anywhere, and now also shows the agent's
  refused requests to forget reviewed entries.
- `kibisis-review` and `kibisis admit` record the operating-system account they run as, read from the process's
  user id, as the reviewer. `--reviewer` is now a label stored beside it (`reviewer_label`), so one account
  approving twice under two names is one approval, and the default quorum of two needs two accounts. Set
  `KIBISIS_VERIFICATION_QUORUM=1` if you are the only reviewer. `review_entity` and `admit` take `reviewer_label`.
- `kibisis admit` opens the vault, key and scope the way the MCP server and `kibisis-review` do (`KIBISIS_DB_PATH`
  or the per-user vault; `KIBISIS_PASSPHRASE_FILE` or `KIBISIS_PASSPHRASE`; `KIBISIS_SCOPE`, else the git
  project's scope, else `default`), instead of `~/.hermes/kibisis/vault.sqlite` in scope `default`. It prints the
  vault and scope it used, and the approvals still needed.

### Security
- `kibisis_forget` no longer deletes an entry a person verified, reviewed or wrote, or a value such an entry holds
  under another key (its tombstone would have purged that copy too). The call is refused and journaled with the
  agent's reason, `kibisis-review list` shows it, and a person carries it out by rejecting the entry; a later
  review keeps the entry and settles the request. `tombstone()` takes `origin`: a non-principal origin may not
  delete a reviewed entry, or one of a higher origin class (K-R1's rule for writes, applied to deletes), and
  raises `ReviewedEntryError` with nothing changed. Without `origin`, library calls behave as before.
- `review_entity(verdict="revoked")` passes its `reviewer_origin` to the tombstone, so a revocation recorded with a
  model or tool origin cannot delete a reviewed entry.

### Fixed
- The CLI no longer crashes when its uid has no passwd entry, as under `docker run --user <uid>`.
  Building the parser called `getpass.getuser()` for the `admit --reviewer` default, which raises there, so
  every subcommand failed. The default reviewer is now `kibisis.config.login_name()`, which falls back to
  `uid-<n>`; `kibisis review` uses the same fallback.
- `aml-serve` no longer does a reverse DNS lookup of its bind address at startup. `HTTPServer.server_bind`
  calls `socket.getfqdn()`, which stalled startup for about 35 s on macOS runners.
- `aml-serve` reads and drops the body of a request it refuses unread (413 over the size limit, 429 when busy)
  for up to 2 s before closing. Closing with the body still arriving made the kernel reset the connection, so a
  client still sending got a reset instead of the reply and its `Retry-After`; this failed a macOS runner.
- Documentation that overstated what the code does: the README said search returns verified memories unless asked
  for more (search returns candidates too, labeled; only `list_entities` defaults to verified and disputed), and
  that the Rust vault matches tombstoned values the same way as the Python one (it does not apply NFKC, and
  lowercases rather than case-folds). `kibisis.review`'s docstring said approving stores an entry as verified,
  which holds only at a quorum of one. The README's limits now also cover tombstones that cannot be lifted,
  validity windows that a rewrite replaces, and BM25 statistics shared across scopes.

## [0.1.0-alpha.14] - 2026-11-03

### Added
- `kibisis.okf.export` naming helpers (telarch P14.3, roadmap 17.2 Pass 2): the rule that says when a turn's
  query names a vault row. `name_tokens(text)` is the one tokenizer (case-folded runs of letters and digits)
  for keys, titles and queries. `names_at(query, key, title=None)` is the earliest offset at which the query
  names the row, by its key (case-folded, not inside a longer word) or by its title's token sequence among
  the query's tokens; the title defaults to the key, which is the title okf-export writes.
  `named_rows(query, rows)` returns the indices of the named rows in request order, ties in row order, each
  row once; a row is its key or a `(key, title)` pair. Pure functions, no vault access
  (`tests/test_okf_names.py`).

## [0.1.0-alpha.13] - 2026-11-02

### Added
- `kibisis.okf` (telarch P13): Open Knowledge Format v0.2 bundles out of and back into the vault.
  - P13.4: the export profile `kibisis.okf_export_profile/1` (`kibisis.okf.profile`), loaded default-deny,
    with a canonical digest.
  - P13.1: `okf-export` writes allowlisted vault rows as an OKF v0.2 bundle and reads the vault only;
    `kibisis.okf.frontmatter` is the stdlib frontmatter subset it writes and parses; `okf-check` checks a
    bundle against the OKF v0.2 producer MUSTs. `log.md` carries counts only, and a bundle is replaced in
    one exchange. `export_bundle(index_profile_digest=False)` leaves the profile digest out of `index.md`.
    `kibisis.okf.export.first_sentence(content)` is the description an exported row carries.
  - P13.2: `okf-import` diffs an OKF v0.2 bundle into the vault as model-origin candidates.

### Changed
- README: the lease rows and scope describe the file coordinator; benchmark figures from
  telarch-benchmarks v0.1.0-alpha.11 (EC2 m8azn.metal, 2026-10-31).
- Tests: the K-C 8-holder contention test runs its holders as script subprocesses with bounded waits
  (`tests/_kc_hammer.py`); a spawned pool hung CI for over an hour.
- CI: the github-actions group bumped (#22).

## [0.1.0-alpha.12] - 2026-10-30

### Changed
- K-C (telarch P7.3): one lease coordinator. `kibisis.FileLeaseCoordinator` adapts the crate's
  `FileLeaseCoordinator` through the new `kibisis_native` extension (`bindings/python`, pyo3, abi3):
  one lock file and one state file per resource under a `0700` directory, fencing tokens that only go
  up. The Python SQLite lease table (`SQLiteLeaseCoordinator`) is gone, and the format-3 journal hash
  and head MAC are the crate's functions, so the Python vault and the Rust verifier share one
  implementation. The shared `expires_at` is a whole second rounded up (the crate's resolution).
  `kibisis` now requires `kibisis-native` (same version); there is no pure-Python fallback.
- Release workflow: `kibisis_native` wheels for manylinux x86_64 and macOS universal2 plus an sdist are
  built, attested and published alongside the `kibisis` wheel (abi3, CPython >= 3.11). The install check
  takes a file lease through the extension on both platforms.

## [0.1.0-alpha.11] - 2026-10-29

### Added
- K-R2: three-way supersession. `put(supersedes_key=...)` resolves to `applied` (the writer's origin class
  is at or above the target's and the target is not reviewed, or a person confirmed the proposal: the target
  is revoked and closed), `needs_confirmation` (the entry is stored as a proposal with
  `metadata["proposed_supersedes"]`, the target stays active and carries `pending_supersession_by`; a
  person's `verified` review applies it, any other verdict clears it), or `SupersessionRefused` (missing or
  already superseded target). The outcome is in `metadata["supersession"]` and journaled as a
  `supersession` event. Retiring an entry through an edge, a review or `archive()` marks every active entry
  that `derived_from` it `disputed` with `invalidated_by`, recursively (cycles terminate). A key closed by
  supersession refuses writes (`SupersededEntryError`, journaled as a `superseded_entry` refusal) unless a
  principal passes `revive=True`, which opens a new version at or after the closed interval's end and
  records `revived_from`; the old interval is never reopened. `state_transition` events carry a `cause`
  (`write`, `supersede`, `review`, `cascade`).
- K-R3/K-R4/K-R5: `recall()`, the model-facing read, returns a `RecallResult` of `results`, `withheld`
  (`WithheldEntry`: ref, reason, sources; never content) and a `receipt`. Two verified entries that conflict
  (an explicit `conflicts_with` edge, recorded on both sides and journaled as a `contradiction` before the
  write, or the same `slot` with different content) are both withheld as `conflict_unresolved` until a
  person resolves one. A hit is returned only if it covers at least `min_coverage_bp` of the query's words
  (default 50%) and, with four or more matches, its BM25 z-score among the matched set is at most `z_max_bp`
  (default -0.5): a crowd of tied scores carries no evidence and is dropped, so false accepts stay flat as
  the store grows. `ttl_seconds` per origin class withholds entries older than `last_verified_at` (a verified
  review refreshes it) as `stale`. The receipt carries `n_store`, `n_matched`, the counts withheld by reason,
  the gate, and each hit's coverage and z-score in basis points. `contrasts_with` names confusables: a
  symmetric edge, both sides returned, carried in the receipt. Every call is mirrored to Argus as
  `kibisis.memory_recall` (channel, counts, withheld refs, a 12-hex digest of the query) and kept in a
  bounded in-process log (`recent_recalls()`); a recall never writes to the vault.
- K-J: `resolve_scope(env, cwd)` derives the default scope from the git checkout the process runs in
  (`project:<name>-<8 hex of the real root path>`, the same for every subdirectory) and falls back to
  `default` outside one. `KIBISIS_SCOPE` wins when set and is the only way to reach `global`.
- K-B: the Rust crate's audit journal moves to format 3 and matches the Python vault byte for byte. New module
  `kibisis::journal`: `event_hash_v3` (SHA-256 of the canonical JSON array, metadata as the digest of its sorted-key
  JSON), `head_mac_v1` (HMAC-SHA256 over `kibisis audit head v1:` and `[sequence,"event_hash"]`, built on the crate's
  own SHA-256, so the crate still has no runtime dependencies) and `verify_chain`, which names the failure
  (`ChainError`: tail cut, mid-chain edit, missing head, bad MAC). `InMemoryMemoryVault` re-signs its head on every
  append; `new()` derives a fresh non-secret key per vault, `with_signing_key` takes the caller's key, and
  `verify_audit_journal` returns the `ChainError` behind `verify_audit_chain`. `AuditEvent` gains `metadata_json`
  (canonical JSON, `None` in the in-memory vault) and `format`; its `timestamp` stays whole seconds, so Rust rows
  hash as `<seconds>.000000`. The crate's former `:`-joined layout is gone (the in-memory journal is never persisted,
  so there are no legacy journals to read). One vector file, `tests/fixtures/journal_format3_vectors.json`, written
  by `tests/fixtures/make_journal_vectors.py` from the Python reference, is checked by both `tests/journal_vectors.rs`
  and `tests/test_journal_vectors.py`, including a five-event chain whose tail cut and mid-chain edits must fail in
  both languages. Vectors keep floats out of metadata: JSON writers print the same double differently, so a metadata
  float is not guaranteed to hash alike across implementations. `serde_json` is a dev-dependency for the fixture.
- `SQLiteMemoryVault.evaluate_abstention(probes, answerable=, unanswerable=, search_fn=, k=, scope=)` and
  `kibisis.Probe` (#20). Scores probes the vault must answer (query -> expected `category:key`) and probes it
  must refuse, through any caller-supplied `search_fn` (default: `search(query, match="any")`), and reports
  every outcome: `answered`, `false_block`, `wrong_entry`, `abstained`, `false_accept`, with
  `answerable_hit_rate`, `unanswerable_abstain_rate`, `false_accept_count`, `false_reject_count`, per-tag
  figures, the matched entries of each miss, `store_size` (N) and a `verdict`. The verdict is `perfect` only
  when the store holds entries, at least one probe is answerable, and nothing was missed or leaked: an empty
  vault or a retriever that returns nothing is `empty_store` / `false_rejects`, never perfect.
- `kibisis.mcp_server.recalled_refs(text)` lists the `category:key` of each entry in a `<kibisis-recall>`
  envelope, so the eval can score the MCP recall tool's own output. Tests run it through the MCP recall handler
  and through `search()` with the server's arguments and check the figures agree.
- SECURITY.md gains a threat model (in scope / out of scope for a local file-write attacker, an agent-side
  writer, a forged review, the passphrase, and a vault without SQLCipher), with the functions that enforce each
  point.
- K-D: a vault with a passphrase whose file is not SQLCipher-encrypted keeps a keyed term index
  (`entities_terms`, `entities_terms_docs`, `term_index_format` in `vault_meta`), so search looks the query's
  words up instead of opening every entry: it used to build an in-memory index of the decrypted vault after
  each write, at a cost linear in the vault. Each token is the first 16 hex characters of HMAC-SHA256, under a
  term key, of the entry's scope and the word as FTS5's tokenizer folds it; no word reaches the file in the
  clear, the same word has another token in another scope or vault, and a token cannot be tested against a
  guess without the passphrase. The term key is a third output of the key derivation the signing and digest
  keys come from: `derive_vault_keys(passphrase, salt)` returns `(signing, digest, term)`;
  `derive_integrity_keys` still returns the first two. Scores are the BM25 FTS5 computes, over whole-vault
  statistics, so they equal a plaintext vault's for whole-word queries, and `search_keys` opens no entry. In
  the test, a query that hits one entry takes 0.17 ms over 200 entries and 0.24 ms over 2000, against 3.5 ms
  and 30 ms before. An older vault gets the index on its first open; rows written by an older version are
  queued by triggers and indexed before the next search; a file later converted to SQLCipher drops it.

### Changed
- K-D: in a vault with a passphrase but without SQLCipher, a query word matches whole words only. In the other
  modes a word also matches longer words that start with it ("project" finds "projects"); a keyed token says
  nothing about the tokens of longer words, so this mode cannot. `SQLiteMemoryVault(..., term_index=False)`
  keeps no term index (and removes one the file has) and searches as before, by opening every entry, for a
  vault whose threat model cannot take what the index shows: word counts per entry, which entries in a scope
  share a word, token frequency and order (SECURITY.md, threat model, "Reading the shape of the text").
- K-A: `src/kibisis/vault.py` is split by concern. `SQLiteMemoryVault` is now composed from mixins in
  `_vault_audit.py` (journal and chain head), `_vault_crypto.py` (sealing, signing, digests, integrity
  upgrade), `_vault_review.py` (origins and trust classes, admission, review, state transitions, abstention),
  `_vault_search.py` (search, recall, the entry and term indexes), `_vault_tombstone.py` (tombstones, purge,
  scrub) and `_vault_snapshot.py` (export and import); `vault.py` keeps the constructor, schema, write lock
  and fencing, the put family, get, archive, list_entities, persona slots and the exceptions. The code is
  moved as it was, and every name that `kibisis.vault` had is still importable from it. No behaviour change.

### Changed
- K-E: a `put()` with no `epistemic_state` stores a `candidate`. `verified` needs `verification_quorum`
  independent principal attestations (constructor argument or `KIBISIS_VERIFICATION_QUORUM`, default 2): a
  user write with `author_id` counts as one, each `review_entity(verdict="verified")` by a different reviewer
  adds one; until then the entry is a candidate with `metadata["attestations"]` and `verification_pending`.
  `search()` returns candidates by default, labeled by state; only `revoked` entries are left out unless asked for.
- K-R1: the vault stamps every entry with an immutable `origin_class` (`principal` for user/human origins,
  `agent` for model origins, `external` for tool and other origins). A lower-class writer cannot overwrite a
  higher-class entry (`OriginClassError`, journaled as an `origin_class_refused` refusal); `act_class` is capped
  at `inform` unless the writer is a principal (`act_class_capped_from` records the request); an entry
  inherits the lowest class along `supersedes` / `derived_from` links (`trust_inherited_from`).
- `recall()` refuses `scope="*"`: a model-facing read is bound to one scope (the MCP server already was).

### Deprecated
- `evaluate_epistemic_abstention()` is a wrapper over `evaluate_abstention()` and warns (`DeprecationWarning`).
  It keeps its keys; `perfect_abstention` still means only that every probe returned nothing, which an empty
  vault also achieves. The report now also carries `store_size`, `verdict` and `perfect` from the new eval.


## [0.1.0-alpha.10] - 2026-10-28

Provenance columns plus the repair set from the 2026-10-28 review (finding ids K-01 to K-12 refer to that
review). The crate and the Python package move together to alpha.10; alpha.9 stays the last release without
provenance.

### Added
- Provenance on every entry: `entities.origin` (`user` | `model` | `tool` | `import` | `unknown`, NOT NULL,
  CHECK-constrained), `source_ref` and `confidence`. Rows that predate the column migrate as `unknown`; nothing
  claims they were a person's. `Vault.remember(..., origin=...)` requires an origin; `put()`/`store()` accept it.
- `origin="model"` writes are stored as `candidate` whatever `epistemic_state` says (the trust ceiling is implied by
  provenance, not by the caller) and cannot replace an entry a person verified (`ReviewedEntryError`).
- `Vault.admit(category, key, reviewer=, reviewer_origin=)` promotes to `verified` only for `reviewer_origin="user"`;
  a model or tool reviewer raises `AdmissionRefused` and the entry is left untouched. Human path:
  `python -m kibisis admit --category C --key K --by user` (new `__main__`).
- Every epistemic-state transition (review, admit, supersede, revoke) is journaled as a `state_transition` audit
  event and mirrored to the Argus ledger through the `argus_ledger` library (`ARGUS_LEDGER_PATH`; empty string
  disables), so the hash chain stays valid. `list_audit_events()` gains a `key` filter.
- The MCP server's `remember` path now carries `origin="model"`.
- `python -m kibisis admit` refuses when stdin is not a terminal (exit 3), so the human path cannot be replayed
  through an agent's shell tool, a pipe or cron. There is no environment-variable escape; the test suite drives
  the command through a pseudo-terminal.

### Changed
- CI: every action is pinned to a full commit SHA (the Rust toolchain action followed a branch) and runs on Node 24.
  Dependabot proposes weekly grouped updates for actions, Cargo and Python (uv) dependencies once a release is 7 days
  old, and an OpenSSF Scorecard workflow reports to code scanning.
- `Lease` gains `local_deadline` (a `time.monotonic()` deadline set by the coordinator that acquired or renewed it)
  and `is_locally_expired`; `renew` updates the caller's `Lease` in place. `SQLiteLeaseCoordinator`'s docstring
  states the wall-clock assumption behind `expires_at` (K-07).
- README: the lease throughput figure is labelled as lease decisions per second under contention on the Rust
  in-memory coordinator (about 95% of counted attempts were rejected); the Python vault's leases are SQLite
  transactions.

### Fixed
Findings from the 2026-10-28 review, by id:
- K-01: every mutating vault method takes the SQLite write lock (`BEGIN IMMEDIATE`) before its first read, through
  one `_write_tx()` context manager. The tombstone gate, the reviewed-entry check and the audit head read used to
  run unlocked, so a second connection could tombstone a value between the check and the insert and the rejected
  value stayed readable. `review_entity` runs its read and re-write in one transaction. Regression test with two
  connections on one file.
- K-02: `search()` and `list_entities()` reported `origin="unknown"` and dropped `source_ref` and `confidence` for
  every entry. One `_entity()` constructor now serves `get`, `search`, `list_entities` and the `put` return value.
- K-05: `export_snapshot(path)` creates its file with mode `0600` (`O_EXCL`), fsyncs and renames atomically, and
  removes the temp file on failure. It used to inherit the umask and write decrypted entries world-readable.
- K-06: `human_reviews`, `tenant_id`, `principal_id` and `lineage_*` are reserved metadata keys. `put()` drops them
  from caller-supplied `metadata` (and logs the drop); only `review_entity` and `import_snapshot` write them. A
  caller could previously forge a person's review and lock an entry against model correction.
- K-07: `acquire` and `renew` reject `ttl_seconds` outside `(0, 86400]`.
- K-09: `EncryptedEnvelope.iterations` is capped at 5,000,000, and `decrypt` refuses counts above
  `ITERATIONS * 2` before running PBKDF2, so a tampered row cannot dictate an unbounded KDF cost.
- K-10: the Rust `sha256_hex` has FIPS 180-4 known-answer tests (empty string, `abc`, 56-, 64- and 112-byte inputs).
- K-12: the `KIBISIS_ADMIT_ALLOW_NOTTY` escape from the admit TTY gate is removed; tests use a pseudo-terminal.

- K-03/K-04: journal format 3. Each audit event's hash is now a SHA-256 of a canonical JSON array (field boundaries are
  unambiguous: a `:` in a category or key can no longer alias another event) that includes a digest of the event's
  metadata, so a rewritten reviewer or verdict fails `verify_audit_chain()`. Every append also signs the chain head
  (sequence and hash, HMAC under the vault's signing key) into a one-row `audit_head` table, so deleting rows from
  the tail, or the head itself, fails verification. Rows carry their `format`; journals written by older versions
  keep verifying under their own layout and are anchored by their first new append. `AuditEvent` gains `format`.
  The Rust crate's journal (`src/lib.rs`) is a separate implementation and is unchanged.

## [0.1.0-alpha.9] - 2026-10-21

### Added
- Python: `SQLiteMemoryVault(..., cache_mb=N)` sets SQLite's page cache, in MiB. Under SQLCipher a page read from
  outside the cache is decrypted again, so ranked search over a vault larger than the cache slows down. On a
  97 MB SQLCipher vault (6,228 entries of one BEAM 10M conversation, `memory_security=False`), one-word
  `search_keys()` calls took 35.0 ms on average with the default cache, 10.8 ms with `cache_mb=64` and 2.6 ms
  with `cache_mb=512`; the same entries in a plaintext vault took 5.2 ms with the default cache. The default is
  unchanged.

## [0.1.0-alpha.8] - 2026-10-21

### Added
- Python: `search_keys()` returns the keys and BM25 scores of the entries that `search()` returns for the same
  arguments, filters and tenant, principal and lineage bounds, as `SearchHit` items, without opening any
  entry: nothing is decrypted and no snippet is built. Because it opens no entry, it checks no entry's
  integrity; `get()` still refuses an entry that fails its check. In a synthetic test (20,000 entries of 60
  words, one-word queries, 400 results each) it took 19.8 ms a query where `search()` took 35.3 ms under
  SQLCipher, and 2.7 ms against 7.4 ms in a plaintext vault.
- Python: `SQLiteMemoryVault(..., memory_security=False)` does not turn on SQLCipher's
  `cipher_memory_security`, which wipes the memory SQLite frees. The default stays `True`. The setting is
  process-wide in SQLCipher and slows ranked search over sealed entries: in the same test `search_keys()`
  took 9.2 ms a query with it off and `search()` 21.0 ms.

### Changed
- Python: `search()` checks the tenant, principal and lineage bounds on each entry's stored metadata before
  it opens the entry, so entries outside them are no longer decrypted. Results are unchanged.

## [0.1.0-alpha.7] - 2026-10-21

### Added
- Python: ranked search over sealed entries. With SQLCipher, a vault with a passphrase keeps a contentless
  FTS5 index (`entities_search`) of entry content inside the encrypted file, ranks sealed entries by BM25
  with the scores a plaintext vault gives the same entries, and decrypts only the results it returns.
  Without SQLCipher, search builds an FTS5 index of the opened entries in memory, never on disk, and builds
  it again after the vault changes.
- Python: `search(..., match="any")` finds entries with any of the query's words and leaves out common
  words, for questions in natural language. The MCP server's `kibisis_recall` takes `match` (`any`, the
  default, or `all`).

### Changed
- Python: search over sealed entries follows the word rules of plaintext search, where a word also matches
  longer words that start with it. It used to match substrings of entry text, in storage order, each with
  a score of -0.5. Results with equal scores now come in entry order.
- Python: the first open of a SQLCipher vault with its passphrase builds the index by opening each entry
  once. Older versions keep working on the vault: triggers queue the rows they write, and the next search
  indexes them. `scrub()` also rebuilds the index from the entries, leaving no words of deleted entries.

### Fixed
- Python: search no longer runs its full-text query once for every entry in the scope. With a scope filter,
  SQLite could start from the entities index on scope (added in 0.1.0-alpha.5) and evaluate the query row by
  row: an eight-word query over 2,000 entries took about 0.4 s, or 3.6 s under SQLCipher, against about 1 ms
  now. The full-text index now drives the join (`CROSS JOIN`).
- Python: under SQLCipher, a full-text query that SQLite rejects falls back to a substring match, as under
  SQLite (sqlcipher3 raises its own `OperationalError`, which search did not catch). Query words without a
  letter or digit are ignored.

## [0.1.0-alpha.6] - 2026-10-21

### Added
- Python: `SQLiteMemoryVault.integrity_status()` counts stored entries that reads refuse, `adopt_unsigned_entries()`
  signs entries that carry no signature after a person has checked them, `stored_digest()` gives the form in
  which the vault stores a value's digest, `integrity_upgrade` reports what an upgrade did, and
  `EntryIntegrityError` (a `PermissionError`) is raised for an entry that fails its integrity check.
- Rust: `FileLeaseCoordinator`, a lease coordinator for processes on one machine. Each resource's
  lease lives in a small state file in a shared directory, and every acquire, renew and release holds
  an operating-system lock on a companion lock file from reading the lease to writing its successor.
  New state is written to a temporary file and renamed into place. Fencing tokens never go backwards:
  a damaged state file, or one naming another resource, is an error rather than a fresh start. It
  follows the same rules as `InMemoryLeaseCoordinator` and adds `get_lease` and
  `validate_fencing_token`. Network filesystems are not supported.

### Changed
- Rust: the minimum supported Rust version is now 1.89 (was 1.85), for the standard library's file
  locks (`File::lock`). The crate still has no dependencies.
- Python: `CryptoEnvelopeProvider.encrypt` and `decrypt` take an `aad` keyword (associated data); a
  custom provider without it is refused when the vault opens. `EncryptedEnvelope` has a `binding` field.
- Python: snapshots are format 1.1. They record `digest_scheme`, `digest_key_id` and
  `unreadable_entity_count`, and each tombstone's `sealed_digests`.
- Python: the MCP forget response's `value_digest_prefix` is taken from the stored, keyed digest.
- Python: `migrate_plaintext` no longer seals an entry that fails its signature check.

### Security
- Python, when the `sqlcipher3` driver does not load (the file is plain SQLite; content stays sealed):
  - Sealed content is bound to its entry (AES-GCM associated data: scope, category and key), and a
    vault with a passphrase refuses an entry without a signature. Before, an entry whose signature was
    removed skipped the check, so sealed content copied under another entry's name was returned.
  - The journal and tombstones store value digests keyed with a key derived from the passphrase.
    Before, they stored plain SHA-256, so short values such as codes, PINs and yes/no answers could be
    recovered by hashing every candidate.
  - Entry signatures use a key derived from the passphrase by PBKDF2 (600,000 iterations) and HKDF.
    Before, the key was one SHA-256 of the passphrase, so a known value and its signature let anyone
    test passphrase guesses about 51,000 times faster than PBKDF2 allows (measured on one core).
  - A wrong passphrase is refused when the vault opens; before, only SQLCipher refused it.
- Python: a vault written by 0.1.0a5 or earlier is upgraded on its first open with the passphrase, in
  one transaction: entries are re-sealed and re-signed, digests keyed, journal hashes recomputed, and a
  `migrate` event records the old chain head; then the file is vacuumed so the old digests are gone. It
  refuses to run under a wrong passphrase. Older versions cannot read an upgraded vault.

## [0.1.0-alpha.5] - 2026-10-20

### Changed
- The MCP server serves one scope, fixed when it starts (`KIBISIS_SCOPE`, default `default`). Tools
  no longer take `scope`; a call that names another scope, `"*"` or an empty scope is refused, and the
  refusal is journaled.
- Writes through MCP are stored as `candidate` at most and recorded with author `mcp-agent`, whatever
  their content claims. `kibisis_remember` no longer takes `epistemic_state` or `auto_gate`; a call
  that sends them, or `author_id` or `reviewer_id`, is refused and journaled. Metadata from the model
  is stored under `agent_metadata`. An MCP write cannot replace an entry a person verified or
  reviewed, and a supersession of one is kept as a proposal that `review_entity` applies when a
  person approves the new entry.
- `kibisis_recall` returns entries inside a `<kibisis-recall>` envelope with their text escaped,
  instead of bare JSON. Each entry is labeled with its state and author. Candidates are included, so
  an agent's own writes still come back before review; `include_candidates=false` returns only
  reviewed entries.
- `kibisis_forget` deletes the entry and tombstones its value, then rebuilds the search index,
  truncates the write-ahead log and vacuums the file. Before, it only archived the entry, so the text
  stayed in the file and could be restated.
- The MCP server refuses to start without a key unless `KIBISIS_ALLOW_PLAINTEXT=1` is set. Before, it
  opened its vault unencrypted. Its default database moved from a fixed `/opt/data/...` path to the
  user data directory (`~/.local/share/kibisis/` on Linux, `~/Library/Application Support/kibisis/`
  on macOS, `%LOCALAPPDATA%\kibisis\` on Windows); `KIBISIS_DB_PATH` still overrides it.
- Tool errors no longer include a Python traceback.
- Writes that name no state go through `MemoryAdmissionGate` in the Python vault: speculation and
  transient remarks are stored as candidates (transient ones valid for 24 hours), and other text is
  stored verified, as before. `SQLiteMemoryVault(auto_gate=False)` or `put(auto_gate=False)` turns
  the gate off.

### Added
- Supersession: `put` and `store` take `supersedes_key` (and `supersedes_category`), and
  `supersede()` writes a replacement in one call. The replaced entry is marked revoked, its validity
  ends, and the two are linked through `MemoryEntity.supersedes` and `superseded_by` (new columns,
  added when a vault is opened; 0.1.0a4 can still read and write such a file but does not keep the
  links). Each supersession is journaled.
- `search(active_only=True)`, the default, leaves out entries outside their validity window.
- `python -m kibisis.review` lists candidates and approves, disputes or rejects them, recording the
  operating-system user (or `--reviewer`) as the reviewer.
- `python -m kibisis.keys PATH` creates a key file with mode 0600.
- Console scripts `kibisis-mcp`, `kibisis-review` and `kibisis-keygen` for the three commands above.
- `put(trust_ceiling="candidate")`, `record_refusal()`, `scrub()` and `ReviewedEntryError` in the
  Python vault; `kibisis.config` holds the settings the MCP server and review command share.
- A write refused because its value is tombstoned is journaled as a `refuse` event, from `put`,
  `store` and `import_snapshot`. Before, the refusal rolled back with the write and left no record.

### Removed
- The `kibisis_admit` MCP tool. It let an agent mark its own writes verified.
- The Rust crate's `CryptoEnvelope`, `EncryptedEnvelope`, `CryptoError` and `ZeroizingPassphrase`,
  and with them the `zeroize` dependency. The crate never implemented encryption; it keeps memory in
  RAM. Its description no longer says it is encrypted.

### Fixed
- The README said the vault does not run the admission gate on its own; it does, on writes that name
  no state, unless opened with `auto_gate=False`. Its measured table now matches telarch.ai/evidence:
  the kill test kills the lease holder with SIGKILL while it holds the lease (not mid-write), and the
  16-thread throughput is the v0.1.0-alpha.4 median.

## [0.1.0-alpha.4] - 2026-10-19

### Fixed
- `enforce_fencing=True` now takes effect. Before, the vault stored the flag and never checked a
  token. With it (it needs `coordinator=`), `put`, `store`, `put_batch`, `archive`, `purge`,
  `tombstone`, `admit_candidate`, `review_entity`, `set_persona_slot` and `import_snapshot` take
  `fencing_token`, `resource` and an optional `holder_id`. A missing, stale or expired token raises
  `LeaseConflictError` and changes nothing: no entry, tombstone or audit event. The vault checks the
  token after taking its write lock (`BEGIN IMMEDIATE`), so a write that passes is ordered before
  any write by a later lease holder. Without the flag, a token is checked only when a call passes
  one. `enforce_fencing=True` without a coordinator raises `ValueError`.
- `put_batch`'s docstring said it used one transaction. Each item is written in its own
  transaction; the batch stops at the first failure and keeps the items before it.
- Tombstones match a value by its exact and canonical SHA-256 digests under every category and key
  in the scope (or every scope for a `"*"` tombstone). Before, a forgotten value was refused only
  under the category and key it was rejected at, so it came back under a new key. Python and Rust.
- Tombstoning a value also deletes the other copies of it in the scope, each journaled as a purge.
- `import_snapshot()` imports tombstones first and never removes them, refuses entities whose value
  is tombstoned, restores archived entities archived, and journals the purges `clear_existing`
  makes. `clear_existing=True` failed outright before (it deleted from a table that does not exist).
- `kibisis_admit` over MCP records reviewer `mcp-agent` instead of a caller-supplied reviewer id, and
  its description says it is not a human review. The ledger tool's description now says what it
  checks: a linear SHA-256 hash chain.
- `cargo fmt` formatting (CI failed `cargo fmt --check` at v0.1.0-alpha.3).
- A vault opened with a passphrase on a system without `sqlcipher3` can be opened again. The second
  open tried to convert the plain SQLite file with `sqlcipher_export()`, which only SQLCipher has, and
  failed. Without `sqlcipher3`, entry content is still sealed but categories, keys and metadata are
  stored in plain text, and a warning says so. The first open with `sqlcipher3` converts the file.

### Added
- `TombstonedValueError`, a `ValueError` subclass raised when a write carries a tombstoned value.
- Tests named after the agent-memory-atlas acceptance tests they cover, in
  `tests/test_atlas_acceptance.py` and `src/lib.rs`, plus a test that every put, archive, tombstone
  and purge fails closed when the audit journal is unwritable.
- Release workflow: builds and attests the sdist, wheel and crate, installs the wheel with its
  dependencies on Ubuntu and macOS arm64, creates a GitHub release naming the commit, and publishes
  to PyPI and crates.io by trusted publishing from protected environments.

### Changed
- CI tests the Python package on Ubuntu and macOS arm64. Windows is no longer in the matrix: at
  v0.1.0-alpha.3 its job never got past the wheel step (a PowerShell glob), and once that was fixed,
  three tests failed there on POSIX file permissions and temporary-file locking. Windows is not tested.
- The Python dependency is `sqlcipher3>=0.5`, which ships wheels for macOS arm64. 0.1.0a2 on PyPI
  required `sqlcipher3-binary`, which has Linux wheels only.

## [0.1.0-alpha.3] - 2026-10-18

### Added
- Multi-process SQLiteLeaseCoordinator support with WAL mode and BEGIN IMMEDIATE atomic transactions.
- Zeroizing passphrase memory security via `zeroize`.
- SQLCipher full-page encryption with PBKDF2-HMAC-SHA256 (600,000 iterations).
- A TLA+ specification of the lease state machine and fencing tokens. Correction: it is in
  telarch-benchmarks (`spec/kibisis_lease_fencing.tla`), not in this repository.
- MSRV enforcement for `rust-version = "1.85"` in `Cargo.toml`.

### Changed
- Standardized clippy warnings with zero warnings under `-D warnings`.
- Documented whole-second TTL rounding in the in-process Rust coordinator.
- Corrected Python dependencies to include `pydantic`, `cryptography`, and `sqlcipher3-binary`.

## [0.1.0-alpha.2] - 2026-10-13

### Added
- Initial public release of Kibisis memory vault and atomic SWMR lease coordinator.
- Bi-temporal valid-time indexing and human review candidate admission lifecycle.
