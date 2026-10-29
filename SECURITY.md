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
- **Python package:** each entry's content is sealed with AES-256-GCM under a key derived with PBKDF2-HMAC-SHA256 (600,000 iterations). An on-disk vault will not open without a passphrase unless you pass `allow_plaintext=True`. With `sqlcipher3` installed, SQLCipher also encrypts the whole database file, including categories, keys and metadata. Without it, those fields are stored in plain text and Kibisis logs a warning. With or without SQLCipher, each entry is signed with a key derived from the passphrase by PBKDF2 and its sealed content is bound to the entry, so entries cannot be swapped or altered without the passphrase, and the value digests kept in the journal and in tombstones are keyed, so they do not reveal short values.
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
| Anyone with the passphrase, or in the process | Everything the vault can read and write | — |

### Local file writer on `vault.sqlite`

**In scope, caught:**

- *Changing an entry's text.* Each entry is signed over its scope, category, key and content
  (`crypto.sign_entry`, crypto.py; applied by `SQLiteMemoryVault._sign`, _vault_crypto.py). A vault with a
  passphrase derives the signing key from the passphrase (`crypto.derive_integrity_keys`: one PBKDF2
  stretch, split with HKDF). Every read checks the signature (`_open_entry`, _vault_crypto.py) and search
  leaves a failing row out (`_readable_content`, _vault_crypto.py). Sealed content is also bound to its entry by
  AES-GCM associated data (`crypto.entry_aad`), so a sealed value moved to another row fails to open.
- *Removing the tail of the journal, or rows under its head.* Every write appends a row whose hash chains from
  the previous one (`_record_audit_event`, _vault_audit.py) and re-signs the chain head with an HMAC under the
  signing key (`_write_audit_head`, _vault_audit.py; `_head_mac`, _vault_audit.py). `verify_audit_chain` (_vault_audit.py) recomputes every
  row, then requires a head with a valid MAC that names the last row; a deleted tail, a deleted head with
  rows still present, or rows removed under a head fails. (Deleting rows and head together is not caught:
  see below.)
- *Re-inserting a forgotten value.* Tombstones keep keyed digests of forgotten values
  (`crypto.keyed_value_digest`, crypto.py; `_seal_digests`, _vault_crypto.py), and `put`, restore and
  `import_snapshot` refuse a value whose digest matches (`_find_tombstone`, _vault_tombstone.py). The digest is keyed, so
  it does not let the file reader test guesses of a short value without the passphrase.
- *Stalling reads with an absurd KDF cost.* The iteration count in an envelope is read before the tag is
  checked, so it is capped (`AESGCMCryptoEnvelopeProvider.MAX_ITERATIONS`, crypto.py, checked at ).

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
- *Deleting the whole journal together with its head.* With no rows and no head there is nothing left to
  check, and `verify_audit_chain` returns true (pinned by `tests/test_threat_model_claims.py`). The entries
  stay readable. A journal that was emptied this way can be told apart from a new vault only by a copy of
  the head kept outside the file.
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

- A write with `origin="model"` is stored as `candidate` whatever `epistemic_state` it asks for
  (`_put`, vault.py: `if origin == "model": trust_ceiling = CANDIDATE`). A capped write
  cannot replace an entry a person verified or reviewed (`ReviewedEntryError`, raised in the write
  transaction after `_is_reviewed`, vault.py); it can only propose a replacement with `supersedes_key`.
- The MCP server fixes the trust arguments itself: `_remember` (mcp_server.py ) always passes
  `trust_ceiling="candidate"` and `origin="model"` (mcp_server.py). A call that tries to send
  `epistemic_state`, `auto_gate`, `trust_ceiling`, `author_id`, `reviewer_id`, `tenant_id`, `principal_id`,
  `include_unverified` or `verdict` is refused and journaled as `authority_claim` (`_AUTHORITY_ARGS`, mcp_server.py;
  `_check_args`, mcp_server.py). A call that names another scope is refused as `scope_widening` ().
- Promotion to `verified` needs a person: `admit` (_vault_review.py) raises `AdmissionRefused` for any
  `reviewer_origin` other than `"user"`, and `python -m kibisis admit` refuses when stdin is not a terminal
  (`__main__.py` , exit 3), so the human path cannot be driven through an agent's shell tool or a pipe.
- Recall returns entries inside a `<kibisis-recall>` envelope with text escaped (`fence_recall`,
  mcp_server.py ), so a stored instruction cannot close the envelope.

**Out of scope:**

- Code running in the same process as the vault. `review_entity` (_vault_review.py) is the person's API and
  takes `reviewer_origin` on trust; the library cannot tell who typed it. An agent that can run Python
  against the vault, or that controls the terminal `python -m kibisis admit` runs in, can admit anything.
  Keep the vault process and the agent's tool sandbox apart if that matters.
- What a candidate says. The admission gate (`MemoryAdmissionGate`) classifies text; it does not judge
  truth. A model can write a false candidate; it stays labelled `candidate` until a person reviews it.
- A recall that returns the wrong thing is a retrieval quality problem, not a trust bypass: measure it with
  `evaluate_abstention` through the search function the caller runs.

### Forged review metadata

`human_reviews` is what `_is_reviewed` (vault.py) consults, so it is a reserved metadata key
(`RESERVED_METADATA_KEYS`, vault.py, with `tenant_id`, `principal_id` and `lineage_*`). `_put` drops reserved keys
from any caller-supplied metadata () unless the caller is one of the vault's own paths that sets
`_trusted_metadata=True`: `_review_locked` (), which appended the review inside the same write
transaction, and `import_snapshot` (), which restores a snapshot's review history as exported.

**Out of scope:** a snapshot file is a trusted input. A forged snapshot can carry `human_reviews` and
`verified` states; `import_snapshot` checks tombstones and, when the snapshot has one, its `manifest_sha256`
(vault.py), which is a plain SHA-256 anyone can recompute, not a signature. Treat snapshot files like
the database file.

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
| Passphrase, no SQLCipher | Sealed (AES-GCM) | Keyed tokens, in order, in `entities_terms` (`_ensure_term_index`): HMAC-SHA256 of scope and word under a passphrase-derived key, no word in the clear; see the term index item above for what their shape shows. With `term_index=False`: not written, the index is built in process memory from decrypted entries (`_scan_index`) and rebuilt when the vault changes | Plain |
| Passphrase + SQLCipher | Sealed, inside an encrypted file | Inside the encrypted file: a contentless FTS5 table of words and positions, enough to rebuild each entry's text without case or punctuation (`_ensure_search_index`, _vault_search.py) | Encrypted with the file |

In the middle row with `term_index=False`, the search index lives in a `:memory:` SQLite connection; it is
as exposed as the rest of the process's memory and no more. In every mode, words (or tokens) of deleted or
replaced entries stay in index pages and free pages until `scrub()` () rebuilds the index and vacuums;
the MCP server's `forget` runs it, the library does not run it for you.
