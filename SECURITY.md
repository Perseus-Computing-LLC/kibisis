# Security Policy

Kibisis is part of the Telarch Suite by Perseus Computing LLC.

## Reporting a Vulnerability

Please do not report security vulnerabilities via public GitHub issues.

Send details directly to:
**`contact@perseuscomputing.com`**
Subject: `[SECURITY] Kibisis Vulnerability Report`

### SLA
- **Acknowledgement**: Within 48 hours.
- **Triage & Status**: Within 5 business days.
- **Fix & Advisory**: Within 14 calendar days for verified high/critical vulnerabilities.

## Scope
- **Python package:** each entry's content is sealed with AES-256-GCM under a key derived with PBKDF2-HMAC-SHA256 (600,000 iterations). An on-disk vault will not open without a passphrase unless you pass `allow_plaintext=True` (or set `KIBISIS_ALLOW_PLAINTEXT=1`; `aml-serve --plaintext` does the same). With `sqlcipher3` installed, SQLCipher also encrypts the whole database file, including categories, keys and metadata. Without it, an on-disk vault with a passphrase is refused as well (`EncryptionRequiredError`, naming what would be stored in plain text) unless the same opt-in is given, in which case those fields are stored in plain text and Kibisis logs a warning; `vault.encrypted_at_rest` reports which it is. With or without SQLCipher, each entry is signed with a key derived from the passphrase by PBKDF2 and its sealed content is bound to the entry, so entries cannot be swapped or altered without the passphrase, and the value digests kept in the journal and in tombstones are keyed, so they do not reveal short values.
- **Search index:** with SQLCipher, a vault with a passphrase keeps a full-text index of entry content in the database file so that search can rank sealed entries. It holds each entry's words and their positions, enough to rebuild the entry's text without case or punctuation, and SQLCipher's whole-file encryption protects it, not the entry's AES-256-GCM seal; both keys come from the passphrase. Without SQLCipher, entry words are never written to disk: search uses an index of keyed tokens of the words (HMAC under a passphrase-derived key), whose shape, not content, is readable from the file; see the threat model. Words of deleted or replaced entries stay in index pages until `scrub()` rebuilds the index (the MCP server's forget runs it).
- **Rust crate:** holds memory in RAM and does not encrypt it.
- **Leases:** Rust's `InMemoryLeaseCoordinator` coordinates threads in one process. Rust's `FileLeaseCoordinator` and Python's `SQLiteLeaseCoordinator` coordinate processes on one machine that share a directory or an SQLite file on a local filesystem. None of them is a distributed lock. A Python vault opened with `enforce_fencing=True` refuses writes that do not carry the current fencing token; otherwise it checks a token only when a call passes one. The MCP server and the Rust crate do not check tokens.
- **Not covered:** a running process that already holds the key, or a weak passphrase.

## Threat model

What Kibisis defends against, what it does not, and which code does the work. Line numbers refer to the
source at the commit that added this section; the function names are the stable reference. Nothing here is
a guarantee beyond what the named code does.

### Who can do what

| Attacker | Has | Does not have |
|---|---|---|
| Local file writer | Read and write access to `vault.sqlite`, its `-wal`/`-shm` files and the Argus ledger file | The passphrase; a process that holds the open vault |
| Agent-side writer | The MCP tools (`kibisis_remember`, `kibisis_recall`, `kibisis_forget`), or `Vault.remember(..., origin="model")` | A person's review; the right to choose its own trust level |
| Forged review | A write that carries review metadata, or a snapshot file | The vault's own write transaction |
| `aml-serve` network client | A TCP connection to the adapter, and (with the Memory System Key) the Add and Search endpoints for any `user_id` it names | The vault passphrase, the files, a path of its choosing (a `user_id` becomes `sha256(user_id)[:32].kib` inside the data dir), the ability to read another user's data except through the `user_id` it sends |
| OKF bundle author | The files `okf-import` reads: it can choose every body and most frontmatter fields | The vault's write transaction: imported rows are model-origin candidates and must be admitted by a person; `okf-export` and `okf-import --dry-run` open the vault read-only |
| Anyone with the passphrase, or in the process | Everything the vault can read and write | — |

### Local file writer on `vault.sqlite`

**In scope, caught:**

- *Changing an entry's text.* Each entry is signed over its scope, category, key and content
  (`crypto.sign_entry`, crypto.py; applied by `SQLiteMemoryVault._sign`, _vault_crypto.py). A vault with a
  passphrase derives the signing key from the passphrase (`crypto.derive_integrity_keys`: one PBKDF2
  stretch, split with HKDF). Every read checks the signature (`_open_entry`, _vault_crypto.py); `get` raises
  `EntryIntegrityError`, and search, listing and snapshot export leave a failing row out and say so: a WARNING
  naming the category and key, a count and the last few names in `vault.integrity_failures`, and under
  `strict=True` the same error instead (`_readable_content`, _vault_crypto.py). Sealed content is also bound to
  its entry by AES-GCM associated data (`crypto.entry_aad`), so a sealed value moved to another row fails to
  open, and an envelope that names another salt is refused before any key derivation (the vault's own
  `kdf_salt` and iteration count are the only ones used).
- *Removing the tail of the journal, or rows under its head.* Every write appends a row whose hash chains from
  the previous one (`_record_audit_event`, _vault_audit.py) and re-signs the chain head with an HMAC under the
  signing key (`_write_audit_head`, _vault_audit.py; `_head_mac`, _vault_audit.py). `verify_audit_chain` (_vault_audit.py) recomputes every
  row (streaming, so any journal size verifies), then requires a head with a valid MAC that names the last
  row; a deleted tail, a deleted head with rows still present, or rows removed under a head fails, and so
  does a row labelled with a journal format this version does not know, or whose metadata is not JSON
  (`verify_audit_chain` returns False with `last_chain_error` set; it does not raise). The rules
  are those of `kibisis::journal::verify_chain` in the crate: `kibisis_native.verify_chain` gives the same
  verdict on the same rows when the rows are what the crate's types hold (whole-second timestamps,
  compact canonical metadata JSON); a Python vault's journal is verified by the Python verifier, which
  hashes through the crate. A vault that has ever been keyed (`kdf_salt` present) pins the lowest
  journal format it holds, whether its journal has ever held a row, and the highest sequence it has
  signed a head for, in `vault_meta` (`journal_format_floor`, `journal_anchored`, `journal_high_water`),
  under the meta MAC below, so rows rewritten in an older, unkeyed hash layout are refused and deleting
  every row, with or without the head, or putting back an older journal, is caught too, whatever
  `integrity_format` was edited to say. The check holds across later writes: an append refuses
  (`VaultIntegrityError`, nothing written) unless the journal's last row is the one the signed head
  names and the journal reaches the high-water mark, so no routine write re-signs a head over the hole.
- *Re-inserting a forgotten value.* Tombstones keep keyed digests of forgotten values
  (`crypto.keyed_value_digest`, crypto.py; `_seal_digests`, _vault_crypto.py), and `put`, restore and
  `import_snapshot` refuse a value whose digest matches, as content, key or a metadata string
  (`_tombstones_matching`, _vault_tombstone.py). The digest is keyed, so
  it does not let the file reader test guesses of a short value without the passphrase.
  Each tombstone row
  carries an HMAC under the signing key (`crypto.tombstone_mac`), checked at open and on every hit, so an
  edited or planted row is refused rather than honoured; and at open every `tombstone` event in the journal
  (not undone by a `tombstone_lifted` event) must still have its row at no lower a class than the event
  journaled, so a deleted row, or an older lower-class copy of a row put back over a person's raised one,
  refuses the open (`VaultIntegrityError`) instead of readmitting the value. Every lift is journaled under
  the row's own identity, whichever entry's write lifted it, so a lift by a person's write under another
  key or scope reconciles at the next open. A tombstone imported from a snapshot is
  journaled in the import's transaction (`metadata.path = "import_snapshot"`), so it is reconciled too.
- *Editing the integrity record.* `vault_meta.integrity_format`, `kdf_salt`, `key_check`, the journal format
  floor and anchoring, `term_index_format` and `verification_quorum` are bound under one HMAC (`meta_mac`,
  `crypto.vault_meta_mac`). A keyed vault whose MAC is missing or does not verify, or whose `key_check` is
  missing, refuses to open: a vault with a `kdf_salt` is keyed whatever `integrity_format` says, and the
  format 1 migration (which re-signs the journal and re-keys tombstone digests) runs only for a file that
  one discriminator (`_refuse_unless_genuine_a5`, run on the plain file before the schema upgrade adds
  anything) proves to be a genuine 0.1.0a5 file: no `audit_head` table, no `format` column on the
  journal, no `tombstone_mac` column, no `key_check`, `meta_mac`, `journal_format_floor`,
  `journal_anchored` or `verification_quorum` key, no `integrity_format` of 2 or more, every entity row
  sealed (`is_encrypted = 1`) with an envelope that carries no format 2 binding (in its text or in the
  associated data its ciphertext opens under) and opens under the passphrase (a5 sealed every entry, and
  each a5 row is its own proof of the passphrase), and an entity table that is non-empty or a journal
  with no unpurged `put`/`update` event. Any one failure refuses the open (`VaultIntegrityError` naming
  every witness found); no sealed row opening at all is a wrong passphrase (`ValueError`). The
  migration's own chain check stays necessary (a chain that does not verify is never re-signed) but
  admits nothing by itself: a headless format 1 chain has no keyed element, so the opened rows are what
  authenticate the file; a keyed vault's format 1 chain head that verifies only under the path-derived
  key (one a file writer computes) is refused too. What the discriminator cannot tell from a genuine a5
  file is the reset that satisfies all of it: a salted file with no entry, no tombstone row and no
  journal event at all, which is an empty vault (a planted tombstone or any journal event on an empty
  entity table is a witness, round 5). The operator then sees a vault with no entries (`list_entities()`
  is empty in every scope) and a journal holding one `migrate` event with `empty_keyed_file`, which is
  the file writer deleting the vault (out of scope, SECURITY.md threat model), not a vault whose
  rejections were laundered; a vault created fresh has no such event. The key check (or, for a 0.1.0a5
  file, one of its sealed entries) is compared against the file before any migration or SQLCipher
  conversion, and a converted copy replaces the plain file only after it has opened, authenticated and
  upgraded. Removing `kdf_salt` while a key check, meta MAC, integrity format of 2 or more, or any
  sealed entry row remains is refused by both the read-only and the writable open before anything is
  written; no fresh salt and no schema upgrade is written over it.

  The second door is the file with no salt at all: `vault_meta` deleted whole, every row flattened to
  plaintext with whatever content and state the writer chose, tombstones dropped. That file is
  indistinguishable from a vault that was written without a passphrase, and the discriminator above
  does not see it. It is guarded on its own terms (round 5, R5-1; round 6, R6-1..R6-3): a keyed open
  (read-only or writable) of a salt-less file that holds any content (entry rows, tombstone rows,
  journal events, or a `vault_meta` record a first keyed open does not write itself) is refused
  (`VaultIntegrityError`: "this file has N plaintext entries and no salt; a keyed vault whose records
  were removed looks the same; pass adopt_keyless=True to adopt them as candidates"; the CLIs word it
  as `--adopt-keyless`) unless the caller opted in; only the operator commands behind the terminal
  check (`kibisis-review <verdict>|lift --adopt-keyless`, the admit command's `--adopt-keyless`) can,
  never the MCP or AML servers or the OKF commands. Only a salt-less file with none of these (tables
  and nothing else) is a fresh vault. A SQLite file that holds tables but no `entities` table is not
  a vault at all and is refused by every keyed open, writable included ("not a kibisis vault"), with
  nothing written. With the opt-in every adopted row is stored exactly as a model-origin `put` stores
  an agent's write, sealed included (its content is AES-GCM-sealed in the adoption transaction, and the
  plaintext's full-text words leave the file with it): a `candidate` with `origin_class: agent`,
  `act_class: inform`, origin `model`,
  every reserved metadata key (`human_reviews`, `attestations`, `origin_class`, `act_class`,
  `superseded_by`, `supersedes`, `trust_capped_from`, ...) dropped, every principal-only key
  (`author_id`, `supersession`, `proposed_supersedes`, ...) moved under `agent_metadata`, and its
  supersession links cleared (`_demote_adopted_row`); what the file said is kept as a label in
  `adopted_from_keyless_file`; a `tenant_id` the file carried is dropped with the rest, so a
  tenant-filtered recall sees every adopted row as tenant-less (the file's tenant labels were on
  nobody's word). The file's policy records go the same way: a `verification_quorum` or
  `quorum_dropped_from` planted in a salt-less file is dropped in the adoption transaction, logged at
  WARNING by name and value, exactly as the legacy-MAC re-sign drops them, so the signed meta MAC never
  binds a quorum nobody signed; the vault runs at the default until a verdict pins one. A forged
  principal-class row therefore neither blocks an agent's later
  write on the key nor outranks it, and a person's verdict on it yields what a verdict on an agent's
  candidate yields. A writable open writes that into the file; a read-only open with the opt-in
  applies the same demotion to a private in-memory copy and writes nothing, so the writer's rows are
  never served as verified by either. A tombstone row in such a file refuses the open outright (it
  would be MAC-signed on nobody's word; lift it in the keyless vault first), and so does a journal
  with no entries ("a keyless file with a journal and no entries is not adoptable"): the events would
  be chained under the signed head on nobody's word. When rows are adopted, the file's journal is
  chained under the signed head and the `migrate` event records both
  `entries_adopted_from_keyless_vault` and `journal_events_adopted_from_keyless_vault`; `health` (MCP
  `kibisis_health`), `review list` and `keyless_adoption()` show "N entries adopted from a keyless
  file on <date>" for as long as that is the latest migration. What the writer gets from this door is
  therefore a vault of agent-class candidates that a person must review one by one, and a notice that
  says where they came from.
- *Stalling reads with an absurd KDF cost.* A provider bound to a vault derives keys from the vault's own
  salt at the fixed iteration count only; the salt and count written in an envelope are not used, and a
  foreign salt is refused before any derivation (`AESGCMCryptoEnvelopeProvider.decrypt`, crypto.py). The cap
  (`MAX_ITERATIONS`) still applies to the unbound provider.

**In scope, caught only with SQLCipher:** when `sqlcipher3` is installed and the vault has a passphrase, the
whole file is encrypted (`PRAGMA key` in `__init__`, vault.py), so the file writer cannot read or usefully change any
table. Everything below assumes SQLCipher is absent.

**Not caught without a passphrase.** When the vault is opened with `allow_plaintext=True`, the signing key
is derived from the file path, not from a secret (`sig_seed = passphrase if passphrase else self.db_path`,
vault.py; see the note at `_head_mac`, _vault_audit.py). A file writer who knows the path recomputes it, so entry
signatures and the journal head MAC then catch accidental damage only, not a deliberate edit. Content is
also stored in plain text.

**Not caught even with a passphrase (no SQLCipher):**

- *Flipping trust.* The entry signature does not cover `epistemic_state`, `origin` or `metadata_json`. A
  file writer can set a candidate row to `verified`, set its origin to `user` and plant a `human_reviews`
  list; the signature still verifies, the row is returned by default recall, and `verify_audit_chain`
  stays true because the journal checks only itself, not the entities table. Pinned by
  `tests/test_threat_model_claims.py`; the fix would be to sign the state and review metadata or to
  reconcile the table against the journal. Until then, the honest statement is: without SQLCipher, trust
  labels on disk are integrity-protected only by file permissions (`_restrict_permissions`, lease.py,
  sets mode 0600).
- *Rolling back the whole file.* An older copy of the file carries an older but valid head MAC. Nothing in
  the vault detects that. The Argus mirror (`_argus_append`, _vault_audit.py) records state transitions, not
  the journal head, so it does not catch a rollback either; only a copy of the head's sequence and hash kept
  outside the file would.
- *Deleting the file.*
- *Deleting the whole journal together with its head, and the integrity record.* `journal_anchored` under
  the meta MAC records that the journal has held a row and `journal_high_water` the last sequence a head
  was signed for, so emptying the journal with the head kept is refused at open (`verify_audit_chain()`
  False) and again on every append, and emptying it together with the head, or putting back an older
  journal and head, is refused by the high-water mark the same way; nothing is written and the next open
  still reports it (pinned by `tests/test_threat_model_claims.py` and `tests/test_review7_final.py`). A
  writer who also removes `kdf_salt`, `key_check`,
  `integrity_format` and the MAC (and flattens every sealed row, since a sealed row without a salt is
  refused) turns the file into one that looks like it never had a passphrase, with whatever rows the
  writer left in it. One with rows is refused by every keyed open until an operator passes
  `adopt_keyless` at a terminal, and then holds only agent-class candidates with a standing notice of
  the adoption (above, "the second door"); the writer's rows are never served as verified, by a
  writable or a read-only open. One with no rows but a journal, a tombstone, or a `vault_meta` record a
  first open never writes is refused too (a journal with no rows with or without the opt-in). A file
  the writer emptied of everything but the tables is told apart from a new vault only by a copy of the
  head kept outside the file.
- *Reading everything that is not sealed content:* categories, keys, scopes, metadata, states, origins, the
  journal's categories, keys and author ids, and the `entities_fts` index of category, key and scope terms
  (created in `_init_schema`, vault.py). The content column of a sealed row is empty (`_seal`, _vault_crypto.py), so entry text and
  its terms are not in that index.
- *Reading the shape of the text from the keyed term index.* The index (`entities_terms`, K-D) holds, for
  each entry, the sequence of its words as tokens: 16 hex characters of HMAC-SHA256, under a key derived
  from the passphrase (`derive_vault_keys`, crypto.py), of the entry's scope and the folded word. Without the
  passphrase a token cannot be tested against a guessed word (each guess would cost the PBKDF2 stretch, as
  for sealed content), and the same word has another token in another scope and in another vault. What
  the file does show is structure: how many words each entry has, which entries in one scope share a word,
  how often each token occurs and in what order. Word-frequency and co-occurrence analysis, and a known
  entry's text, let a file reader tell which other entries mention the same words. This is the known
  cost of a searchable encrypted index; a vault that must not show it opens with `term_index=False`
  (search then opens every entry, as before K-D) or installs `sqlcipher3`.

### Agent-side writer (a model, through MCP or the library)

**In scope, enforced:**

- A write with any origin but `user` or `import` is stored as `candidate` whatever `epistemic_state` it
  asks for, `revoked` included (`_put`, vault.py; the request is kept as `trust_capped_from`). A capped
  write cannot replace an entry a person verified or reviewed (`ReviewedEntryError`, raised in the write
  transaction after `_is_reviewed`, vault.py); it can only propose a replacement with `supersedes_key`.
  When such a proposal is approved and the retired entry's dependents are invalidated, a dependent of a
  higher class or one a person reviewed keeps its state and gets an `invalidation_notice` instead
  (`_cascade_invalidate`, _vault_review.py), and a lower-class writer's `conflicts_with` /
  `contrasts_with` back-edges are stored on the writer only (`_record_edges`). The keys `author_id`,
  `last_verified_at`, `supersession`, `proposed_supersedes` and `slot` are a person's: a non-principal
  write that sets them has them moved under `agent_metadata`.
- `tombstone()`, `purge()`, `archive()` and `set_persona_slot()` take `origin` and refuse, with nothing
  changed and a `refuse` journal event, a model or tool request against an entry a person wrote or
  reviewed; `tombstone(content=...)` looks the row up and runs the same check before any branch, and
  deletes nothing when the stored value does not match. A non-principal may not tombstone with
  `scope="*"`. A tombstone records the class of its maker: a person's write lifts a model-class
  tombstone (journaled `tombstone_lifted`), a principal-class one blocks everyone until a person lifts
  it (`python -m kibisis.review lift`, or `lift_tombstone()` with a principal or vouched origin; a
  model, tool or unknown origin is refused). A later lower-class `tombstone()` of the same value
  never replaces the row (journaled `tombstone_reaffirmed`). A tombstoned value is refused as a key
  or as any string (key or value) of the caller's `agent_metadata` as well as content; the vault's
  bookkeeping metadata is not matched. Look-alikes are the canonical fold's: case, spacing,
  punctuation, invisible code points, Hangul fillers as blanks, a small homoglyph table; nonspacing
  marks are dropped, spacing marks kept. The MCP tools cap keys at 128 characters.
- The MCP server fixes the trust arguments itself: `_remember` (mcp_server.py ) always passes
  `trust_ceiling="candidate"` and `origin="model"` (mcp_server.py). A call that tries to send
  `epistemic_state`, `auto_gate`, `trust_ceiling`, `author_id`, `reviewer_id`, `tenant_id`, `principal_id`,
  `include_unverified` or `verdict` is refused and journaled as `authority_claim` (`_AUTHORITY_ARGS`, mcp_server.py;
  `_check_args`, mcp_server.py). A call that names another scope is refused as `scope_widening` ().
- Promotion to `verified` needs a person: `admit` (_vault_review.py) raises `AdmissionRefused` and
  `review_entity` raises `PermissionError` for any `reviewer_origin` other than `"user"`, every verdict,
  and a verdict with no `reviewer_id` is refused. `python -m kibisis admit` and the review verdicts refuse
  when stdin is not a terminal (`__main__.py`, exit 3). That check stops pipes and cron jobs; it does not
  stop an agent that can allocate a pseudo-terminal in the operator's account (see README, Limits).
- The attestation that counts toward the quorum is the operating-system account running the process
  (`_resolve_attester`, vault.py), for `put(origin="user")`, `review_entity` and `admit` alike;
  `author_id` / `reviewer_id` are labels. `attester=` is honoured only on a vault opened with
  `trust_caller_identity=True` (embedders that authenticate their users), and `"principal"` or an
  empty name is never a signer. The quorum itself is a property of the vault file, not a per-process
  setting: it is stored in `vault_meta` only by a pinning open (`pin_quorum=True`: the review verdicts
  and `admit`, behind the terminal check), two by default until that first verdict. Every other open
  adopts the stored value and never writes one; an open that asks for less is refused (`ConfigError`),
  a pinning open that asks for more stores it, a stored quorum below the default is adopted only by a
  process whose own `KIBISIS_VERIFICATION_QUORUM` names it, a quorum found in a salt-less file is not
  stored policy at all (dropped when the file is adopted, see the adoption item above), and while the
  meta MAC verifies only over
  the legacy key set no stored quorum is trusted, whatever its value (the MAC never covered it, so a
  file writer can lower a pinned 3 to 2 as easily as to 1): it is ignored, logged at WARNING with the
  value, and dropped before the re-sign; the next verdict run under the person's
  `KIBISIS_VERIFICATION_QUORUM` pins it again under the full-set MAC. Every verdict that can mint
  `verified` (`review_entity`, `admit`, `put(origin="user")` asking for `verified`) is settled against
  the larger of the process's quorum and the file's trusted stored one, read in the verdict's own write
  transaction (`_quorum_in_force`), so a vault opened before a pinning open raised the quorum applies the
  raised value to its next verdict. A verified entry carries `quorum_at_verification`, the quorum its
  verdict applied. `_review_verdict` / `_trusted_metadata` are not parameters of the public
  `put()`; `put_batch` rejects items that carry them.
- Recall returns entries inside a `<kibisis-recall>` envelope with text escaped (`fence_recall`,
  mcp_server.py ), so a stored instruction cannot close the envelope.

**Out of scope:**

- Code running in the same process as the vault. `review_entity` (_vault_review.py) is the person's API and
  takes `reviewer_origin` on trust; the library cannot tell who typed it, though it attests as the
  account the process runs as, so a library caller cannot add a second attestation by naming one. An
  agent that can run Python against the vault, or that controls the terminal `python -m kibisis admit`
  runs in, can admit anything that one account may. Keep the vault process and the agent's tool sandbox
  apart if that matters.
- What a candidate says. The admission gate (`MemoryAdmissionGate`) classifies text; it does not judge
  truth. A model can write a false candidate; it stays labelled `candidate` until a person reviews it.
- A recall that returns the wrong thing is a retrieval quality problem, not a trust bypass: measure it with
  `evaluate_abstention` through the search function the caller runs.

### Forged review metadata

`human_reviews` is what `_is_reviewed` (vault.py) consults, so it is a reserved metadata key
(`RESERVED_METADATA_KEYS`, vault.py, with `tenant_id`, `principal_id` and `lineage_*`). `_put` drops reserved keys
from any caller-supplied metadata unless the caller is one of the vault's own private paths
(`_write_review`, which appended the review inside the same write transaction, and `import_snapshot`
under the rule below); the public `put()` has no way to ask for that.

`import_snapshot` keeps a snapshot's `attestations`, `verification_pending` and `human_reviews` only when
the snapshot's `trust_seal` opens under this vault's passphrase and names the entities it carries, and its
`manifest_sha256` is present and verifies; otherwise they are dropped, the drop is journaled, and the
`epistemic_state` is re-derived from what survives (a `verified` claim with no attestations becomes
`candidate`). `digest_key_id` is a public label written in clear into every export; it routes the keyed
digests and proves nothing. A vault without a passphrase writes no seal and opens none, so it never keeps
trust facts from a file, its own exports included. Each entity's `origin` and `author_id` are exported and
restored, so a person's verified entry round-trips as verified and principal within the vault that made
it (or any vault under the same passphrase). A tombstone's `origin_class` is taken from the file only when
the seal also covers the file's tombstones (seals written since this rule name both); otherwise it is
capped at the importer's class (`origin`, as on `put`; no origin = the caller vouches for a person). That
default makes `origin=None` principal: a library caller relaying a file it did not make (one an agent
handed over) must pass the agent's `origin`, or an unsealed file's tombstones are planted at principal
class (`import_snapshot` has no MCP or CLI caller, so no agent reaches it without a library caller).

What a snapshot can and cannot carry: the manifest is a plain SHA-256 anyone computes, so a snapshot file
is a trusted input for **content**: it can carry any entity text and metadata, any `candidate`, any
tombstone (a rejection the importer then owns at its own class), and a replay of older content over
newer. Without a seal that opens here it cannot carry a `verified` or `disputed` state, attestations, a
review record, or a tombstone class above the importer's. A restore of the vault's own snapshot is a
point-in-time replay of the reviews too: an older own snapshot puts back verdicts and attestations as
they stood when it was taken, over any review made since (a later rejection still wins, because
tombstones are never removed). Treat snapshot files like the database file.

### `aml-serve` network client

The adapter (`kibisis.aml_adapter`) accepts connections only from the bind address (`127.0.0.1` unless
`--host` says otherwise) and checks the credential before anything else: an unauthenticated `POST` is `401`
on every path, so routes are not enumerable without the key. Bodies are bounded (`max_body_bytes`, checked
before every chunk of a chunked body; malformed chunk sizes are `400` and close the connection); JSON is
parsed without `NaN`/`Infinity` and refused when it holds a lone surrogate; timestamps must convert to a
datetime at Add, so a stored row can never make a later Search fail. Any other exception raised while a
request's body or fields are read is answered `400`/`422` (its traceback is logged once, without the
request's text), so a client's input never produces a `500`. Stalled connections are closed after
`--socket-timeout`, open connections are capped by `--max-connections`, and processing by `--max-inflight`.
An unauthenticated `POST` with `Expect: 100-continue` gets the `401` instead of `100 Continue`, so no body
is invited and nothing is drained.
A reused `request_id` with a different payload is `409`. Retention deletes only regular files that are
vaults of this server, under the pool lock, and never one with a request inside it.

**Out of scope:** the Memory System Key is a shared secret; whoever holds it can read and write every
`user_id`. TLS, rate limiting per client and authentication of individual users belong to the reverse proxy
in front of the adapter.

### OKF bundle author

`okf-import` reads a directory of Markdown files written by someone else. Every imported row is a
model-origin candidate; `human_reviews` and other reserved metadata in a bundle's frontmatter are dropped by
`_put` like any caller-supplied metadata, so a bundle cannot forge a review or a verified state. Bodies are
stored as text and never executed. A real `okf-import` judges each concept on its row as it is inside that
row's own write transaction (`SQLiteMemoryVault._judged_put`, vault.py: the row is re-read under the write
lock) and writes in the same transaction, so a row another connection archives, marks confidential, rewrites
as a person, disputes or tombstones after the importer's scan is reported as a conflict and left as it is;
nothing lands between the judgement and the write. `okf-export` and `okf-import --dry-run` open the vault read-only
(`SQLiteMemoryVault(read_only=True)`: `mode=ro`, no migration, no integrity upgrade, no index build), so
running them against a vault changes none of the vault file's bytes; `okf-check` reads only the bundle and
opens no vault. A read-only open of a WAL-mode vault still needs SQLite's shared-memory index, so it may
create and leave an empty `<vault>-wal` and a `<vault>-shm` (32 KiB) beside the file when none existed; the
next writable open removes them.

### Passphrase handling

- Resolution order (`keys.resolve_passphrase`, keys.py ): the `passphrase=` argument, then the file named
  by `KIBISIS_PASSPHRASE_FILE`, then `KIBISIS_PASSPHRASE`. A key file readable by group or others is refused
  (`_read_keyfile`, keys.py). `python -m kibisis.keys PATH` creates a 256-bit random key file with mode 0600
  and never prints it. Passphrases shorter than 12 characters are refused (`MIN_PASSPHRASE_LENGTH`, keys.py).
- Use: the content key is PBKDF2-HMAC-SHA256 at 600,000 iterations under a per-vault salt
  (`AESGCMCryptoEnvelopeProvider._derive_key`, crypto.py); each entry is sealed with AES-256-GCM under a
  fresh random nonce with the entry's identity as associated data (`encrypt`, protocols.py). The signing and digest
  keys come from a separate PBKDF2 stretch of the same passphrase (`derive_integrity_keys`, crypto.py), so a
  guess costs a full stretch against any of them.
- The passphrase is never written to a log: the only place it is interpolated is the `PRAGMA key` statement
  sent to SQLCipher (`__init__`, vault.py). The vault object keeps it in memory (`self.passphrase`) for the
  life of the process, and the derived keys are cached in the provider.

**Out of scope:** a process that holds the open vault, or that can read its memory; `KIBISIS_PASSPHRASE`
in an environment that other processes of the same user can read (`/proc/<pid>/environ`); a weak
passphrase; the operating system swapping process memory to disk.

### Without SQLCipher

Install `sqlcipher3` for whole-file encryption; without it Kibisis warns at open (`__init__`, vault.py) and runs
in one of two reduced modes. `_ranked_rows` () picks the search path:

| Mode | Entry text on disk | Entry terms on disk | Categories, keys, metadata, states, journal |
|---|---|---|---|
| No passphrase (`allow_plaintext=True`) | Plain, in `entities.content` | Plain, in `entities_fts` (`_plaintext_rows`, _vault_search.py) | Plain |
| Passphrase, no SQLCipher | Sealed (AES-GCM); rows written before the vault had a passphrase, or legacy rows an older release left plain, are re-sealed by `migrate_plaintext()` (`encryption_status()` counts them); rows adopted from a salt-less file are sealed by the adoption itself | Keyed tokens, in order, in `entities_terms` (`_ensure_term_index`): HMAC-SHA256 of scope and word under a passphrase-derived key, no word in the clear; see the term index item above for what their shape shows. With `term_index=False`: not written, the index is built in process memory from decrypted entries (`_scan_index`) and rebuilt when the vault changes | Plain |
| Passphrase + SQLCipher | Sealed, inside an encrypted file | Inside the encrypted file: a contentless FTS5 table of words and positions, enough to rebuild each entry's text without case or punctuation (`_ensure_search_index`, _vault_search.py) | Encrypted with the file |

In the middle row with `term_index=False`, the search index lives in a `:memory:` SQLite connection; it is
as exposed as the rest of the process's memory and no more. In every mode, words (or tokens) of deleted or
replaced entries stay in index pages and free pages until `scrub()` () rebuilds the index and vacuums;
the MCP server's `forget` runs it, the library does not run it for you.
