# Kibisis

**Local, encrypted memory for AI agents.** Kibisis keeps what an agent learns on your own machine, decides what comes back, makes forgetting stick and lets one writer in at a time.

[![CI](https://github.com/Perseus-Computing-LLC/kibisis/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Perseus-Computing-LLC/kibisis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV: 1.89](https://img.shields.io/badge/MSRV-1.89-informational.svg)](Cargo.toml)
[![M8ven Score](https://m8ven.ai/badge/mcp/perseus-computing-llc-kibisis-13szsu?v=c14fb7f48a3bfb2a15213c5988349ed2)](https://m8ven.ai/mcp/perseus-computing-llc-kibisis-13szsu?s=readme)

Kibisis is one of the three [Telarch](https://telarch.ai) libraries from [Perseus Computing LLC](https://perseuscomputing.com). [Harpe](https://github.com/Perseus-Computing-LLC/harpe) decides what goes into each model call, and [Argus](https://github.com/Perseus-Computing-LLC/argus) keeps a tamper-evident record of what the agent did. Each one works on its own.

## Why

An agent that runs for hours learns things worth keeping: decisions, preferences, facts about the code it works on. In a plain file, anyone who copies the file can read them. In a hosted service, they leave your machine. And with no rules for what comes back, a memory that was wrong, unreviewed or deliberately forgotten can return in the next prompt. Kibisis keeps agent memory local, encrypted and deliberate.

## What you get

- **Encrypted on disk.** The Python vault seals every entry with AES-256-GCM in one SQLite file. With SQLCipher it encrypts the whole file.
- **Recall you can reason about.** Every memory is a candidate, verified, disputed or revoked. Search returns candidate, verified and disputed memories, each labeled with its state, leaves out revoked ones, and can answer "what was true on this date". The model-facing `recall()`, which the MCP server uses, also holds back verified memories that conflict and matches that cover too little of the query, and says what it held back.
- **Forgetting that sticks.** A tombstoned value is deleted everywhere in its scope. Writing it again is refused, even as a key or inside metadata, or with different case, spacing, punctuation or common look-alike letters.
- **Scopes that hold.** Each memory is signed over its scope, category, key and content, and a row that fails the check is never returned.
- **A journal of every change.** Every write, archive, tombstone and purge is recorded in a hash chain, in the same transaction as the change.
- **One writer at a time.** Leases carry fencing tokens that only go up: each resource keeps its highest token in its own file, written before the lease that carries it, so a deleted or rolled-back state file cannot hand a token out twice (deleting that file too, or a lock file, is outside what the coordinator guards against). They coordinate processes on one machine through a shared directory (one lock file, one state file and one highest-token file per resource; the Python `FileLeaseCoordinator` is the Rust one, through the `kibisis_native` extension), and threads within one Rust process. A Python vault opened with `enforce_fencing=True` refuses writes that do not carry the current token.
- **Ready for agents.** An MCP server over stdio offers remember, recall, forget, verify-ledger and health tools. It serves one scope fixed at startup, stores what an agent writes as an unreviewed candidate, returns recall as escaped data, not instructions, and will not delete what a person wrote or reviewed.
- **Local by default.** Kibisis makes no outbound network connections. The one network feature is opt-in: `kibisis aml-serve`, the [Agent Memory Leaderboard adapter](deploy/aml/README.md), is an HTTP server that runs only when started and listens on `127.0.0.1` unless given `--host`. Its network client and the author of an OKF bundle fed to `kibisis okf-import` are the two outside parties in the [threat model](SECURITY.md#who-can-do-what).

## Install

This README describes 0.1.0-alpha.16 (0.1.0a16 on PyPI). It is a pre-release, so name the version.

```toml
# Rust: Cargo.toml
[dependencies]
kibisis = "0.1.0-alpha.16"
```

```bash
# Python
pip install kibisis==0.1.0a16
```

## Quickstart

### Python

```python
from kibisis import SQLiteMemoryVault

# The passphrase comes from KIBISIS_PASSPHRASE or KIBISIS_PASSPHRASE_FILE.
vault = SQLiteMemoryVault("memory.db")
vault.put("preferences", "indent", "Use tabs for indentation", scope="project-a")
print([hit.entity.content for hit in vault.search("indentation", scope="project-a")])

vault.tombstone("preferences", "indent", reason="user asked to forget", scope="project-a")
# Refused under any category or key in the scope, including look-alike spellings:
print(vault.is_tombstoned("notes", "style", "USE TABS FOR INDENTATION", scope="project-a"))  # True
```

### Rust

```rust
use kibisis::{InMemoryLeaseCoordinator, InMemoryMemoryVault, LeaseCoordinator, MemoryEntity, MemoryVault};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut vault = InMemoryMemoryVault::new();
    let mut coordinator = InMemoryLeaseCoordinator::new();
    let lease = coordinator.acquire("notes", "worker-a", Duration::from_secs(1))?;
    vault.put(&MemoryEntity::new("preferences", "indent", "Use tabs for indentation"))?;
    coordinator.release(&lease)?;
    println!("saved under fencing token {}", lease.fencing_token);
    Ok(())
}
```

### As an MCP server

```bash
python -m kibisis.keys ~/.config/kibisis/kibisis.key     # once: creates a key file with mode 0600
export KIBISIS_PASSPHRASE_FILE=~/.config/kibisis/kibisis.key
export KIBISIS_SCOPE=project-a                            # optional; unset, the scope is the git checkout's project scope, else "default"; "global" only when set here
python -m kibisis.mcp_server                              # remember, recall, forget, verify-ledger and health over stdio
```

The package also installs these as `kibisis-keygen`, `kibisis-mcp` and `kibisis-review`.

The server keeps its vault in your user data directory (`~/.local/share/kibisis/vault.sqlite` on Linux, `~/Library/Application Support/kibisis/` on macOS, `%LOCALAPPDATA%\kibisis\` on Windows) unless `KIBISIS_DB_PATH` names another file. It refuses to start without a key unless `KIBISIS_ALLOW_PLAINTEXT=1` is set. What an agent stores is a candidate written by `mcp-agent`; a person reviews candidates:

```bash
python -m kibisis.review list                     # candidates, and the agent's requests to forget reviewed entries
python -m kibisis.review approve CATEGORY KEY      # or: dispute, reject; needs a terminal
```

An entry becomes verified once the vault's verification quorum of operating-system accounts have approved it: two by default (`KIBISIS_VERIFICATION_QUORUM`; set it to 1 if you are the only reviewer). The attesting account is always the one running the process, read from its user id: the review commands, `python -m kibisis admit`, and library `put(origin="user")` / `review_entity` calls all record it, and `author_id`, `reviewer_id` and `--reviewer` are labels kept beside it that never count. An embedder that authenticates its own users can open the vault with `trust_caller_identity=True` and pass `attester=` on those calls; the literal `principal` and an empty name are never signers. The default of two is only a default until a person's first verdict pins it: the review verdicts and `admit` (the commands that need a terminal) store the quorum they run with in the vault, and may raise it later but never lower it. Nothing else pins: `review list`, the MCP and AML servers, the OKF commands and library opens adopt the stored quorum (or run with their own when none is stored), an open that asks for less than the vault remembers is refused with `ConfigError`, and a stored quorum below two is adopted only by a process whose own `KIBISIS_VERIFICATION_QUORUM` names it. Every command prints the quorum in force beside the vault path (`quorum 2 — 2 accounts verify (default until a verdict pins it)`, or `quorum 1 — one account verifies`), and `kibisis_health` reports it as `verification_quorum`. A verified entry records `quorum_at_verification`. A bad `KIBISIS_VERIFICATION_QUORUM` value (`0`, `abc`, `2.0`, `1_0`, empty) is a `ConfigError` the CLIs report in one line.

## Measured

Medians of five runs of [telarch-benchmarks](https://github.com/Perseus-Computing-LLC/telarch-benchmarks) v0.1.0-alpha.12 against kibisis 0.1.0-alpha.15 (the Rust crate, and the Python package 0.1.0a16 for the multi-process rows), with synthetic data on one EC2 m8azn.metal-12xl bare-metal server. Every run, its range and the command that reproduces it are on [telarch.ai/evidence](https://telarch.ai/evidence).

| Measurement | Result |
| --- | --- |
| Times two holders had the same lease, in 64,000 contended attempts from 16 and 32 threads | 0 |
| Fencing tokens that went backwards | 0 |
| Times two processes held the lease at once, 2 to 32 processes sharing one lease directory | 0 |
| Late write from a paused holder | rejected |
| Lease state after its holder is killed with SIGKILL while holding the lease | intact |
| Lease decisions per second under contention, 16 threads, in memory (Rust coordinator; counts every acquire attempt, about 95% of which were rejected, so this is not acquire-release cycles and not the Python package's file coordinator, which crosses processes) | 1,290,854 |

## How it works

- **Encryption (Python).** Entry content is sealed with AES-256-GCM under a key derived by PBKDF2-HMAC-SHA256 with 600,000 iterations (`src/kibisis/crypto.py`). When the `sqlcipher3` dependency loads, SQLCipher also encrypts every page of the database file. If it does not load, an on-disk vault with a passphrase is refused (`EncryptionRequiredError`) unless opened with `allow_plaintext=True` or `KIBISIS_ALLOW_PLAINTEXT=1`; with that opt-in the vault falls back to SQLite: content stays encrypted and bound to its entry, and the value digests in the journal and in tombstones are keyed, but categories, keys, metadata and the rest of the audit journal are stored in the clear, and a warning says so (`SQLiteMemoryVault.__init__` in `src/kibisis/vault.py`; `vault.encrypted_at_rest` reports the state). Either way, a wrong passphrase is refused when the vault opens, before anything is migrated or converted. An on-disk vault refuses to open without a passphrase under the same opt-in rule.
- **Scopes and integrity.** Every memory belongs to a scope and carries an HMAC-SHA256 signature over its scope, category, key and content. In a vault with a passphrase, the signing key comes from PBKDF2 (600,000 iterations), so a stored signature is no quicker to test passphrase guesses against than sealed content, and sealed content is bound to its entry as associated data, so it cannot be moved under another entry's name. `search`, `list_entities` and snapshot export skip (with a WARNING naming the entry, a count in `vault.integrity_failures`, or an `EntryIntegrityError` when the vault was opened with `strict=True`), and `get` refuses with `EntryIntegrityError`, a row whose signature is missing or does not verify, or whose sealed content was not sealed for it (`sign_entry`, `entry_aad` and `derive_integrity_keys` in `src/kibisis/crypto.py`, used in `src/kibisis/_vault_crypto.py`). A vault without a passphrase has no secret to sign with, so there signatures only catch accidental damage.
- **Trust states and validity windows.** Each memory is a candidate, verified, disputed or revoked, and can carry valid-from and valid-until times. Search leaves out revoked memories and memories outside their validity window unless asked, labels the rest with their state, and can return what was valid at a given time; `list_entities` lists verified and disputed memories unless asked for candidates (`src/kibisis/models.py`, `search` in `src/kibisis/_vault_search.py`). A write with `supersedes_key`, or `supersede()`, retires an earlier memory: it is marked revoked, its validity ends, and it links to its replacement. `review_entity` records a reviewer's verdict; a revocation tombstones the value. On writes that do not name a state, the vault runs `MemoryAdmissionGate` (`src/kibisis/admission.py`), a heuristic classifier that stores hedged or speculative text as a candidate; open the vault with `auto_gate=False` to turn it off.
- **Search.** `search` ranks results with BM25 (SQLite FTS5). By default it wants every word of the query; `match="any"` wants at least one and leaves out common words such as "what" and "the", for questions in natural language. With SQLCipher, a vault with a passphrase keeps a full-text index of entry content inside the encrypted file, so sealed entries rank as they would in a plaintext vault and only the top results are decrypted. Without SQLCipher no entry words are written to disk either: the vault keeps an index of keyed tokens of the words (HMAC-SHA256 under a key derived from the passphrase, one token per word and scope), looks the query's words up there and opens only the entries it returns, so a query costs its words' rows, not the vault; in this mode a word matches whole words only, not longer words that start with it, and the file shows the shape of the text (word counts, shared tokens, their order) though no word; `term_index=False` keeps no such index and searches by opening every entry (`search` in `src/kibisis/_vault_search.py`, SECURITY.md). `search_keys` takes the same arguments and returns only keys and scores, without opening (or decrypting) any entry, for callers that hold the text elsewhere; it does not check entry integrity, which `get` still does. Under SQLCipher, ranked search is several times slower with SQLCipher's `cipher_memory_security` on, which kibisis does by default (`memory_security=True`); it is a process-wide setting that wipes memory SQLite frees. Pages read from outside SQLite's page cache are decrypted again, so give a large SQLCipher vault a cache that holds it (`cache_mb`).
- **Tombstones.** `tombstone` records a value's SHA-256 digest and the digest of its canonical form (Unicode compatibility folding, case folding, invisible characters and punctuation removed, whitespace collapsed), then deletes every copy of the value in the scope. In a vault with a passphrase both digests are stored keyed (HMAC-SHA256 under a key derived from the passphrase), so they do not reveal short values such as codes or PINs. Afterwards the value is refused under any category or key in that scope, and `import_snapshot` will not restore it (`src/kibisis/_vault_tombstone.py`). The Rust vault in `src/lib.rs` uses a narrower canonical form: it folds only fullwidth ASCII and the ideographic space, not the rest of Unicode compatibility folding (NFKC), and lowercases rather than case-folds, so some look-alikes the Python vault refuses get through there. The Python canonical form also drops nonspacing and enclosing marks and the invisible Default_Ignorable code points (variation selectors, the combining grapheme joiner, zero-width joiners), turns the Hangul fillers (visible blanks) into spaces, keeps spacing combining marks (the side vowel signs of Devanagari, Tamil and other abugidas, so different words there keep different digests; words that differ only in a nonspacing sign fold alike), and folds a built-in table of Latin/Cyrillic/Greek homoglyphs and dotless i; a homoglyph outside that table, a paraphrase or a translation is not caught. An entry's key and every string of the caller's own metadata (`agent_metadata`, keys and values at any depth) are digested against tombstones as the content is, so a forgotten value cannot be stored as a name; the vault's own bookkeeping fields (`origin_class`, `attestations`, ...) are not matched. A snapshot carries each tombstone's digests sealed, so the tombstone also applies when the snapshot is imported into another vault opened with the same passphrase.
- **Audit journal.** Every put, archive, tombstone and purge appends a SHA-256 hash-chained event in the same database transaction as the change, so a change cannot land without its event; in a vault with a passphrase, the value digest it records is keyed, like a tombstone's. A write refused because its value is tombstoned, from the API or a snapshot import, is journaled as a `refuse` event, and so is an MCP call refused for its scope or trust arguments, or for asking to forget an entry a person wrote or reviewed. `verify_audit_chain` re-checks the chain (`_record_audit_event` in `src/kibisis/_vault_audit.py`).
- **Leases.** `FileLeaseCoordinator` (`src/kibisis/lease.py`, an adapter over the `kibisis_native` extension in `bindings/python`), the Rust `InMemoryLeaseCoordinator` (`src/lib.rs`) and the Rust `FileLeaseCoordinator` (`src/file_lease.rs`) grant time-limited leases with increasing fencing tokens, and `validate_fencing_token` on the SQLite and file coordinators checks a token. `FileLeaseCoordinator` keeps each resource's lease in a small file and holds an operating-system lock on a companion lock file for every read-decide-write, so processes that open the same directory share one lease table. A damaged state file is reported as an error; it never resets the token. A Python vault opened with `coordinator=` and `enforce_fencing=True` checks the caller's token on every write while it holds its write lock, and refuses a missing, stale or expired token with `LeaseConflictError` before anything changes (`_fence` in `src/kibisis/vault.py`).
- **MCP server.** `python -m kibisis.mcp_server` (`src/kibisis/mcp_server.py`, settings in `src/kibisis/config.py`) serves one scope, fixed at startup, and refuses and journals calls that name another scope or try to set a trust state or an identity. It stores writes as candidates by `mcp-agent`; they cannot replace a reviewed entry, and a supersession of one waits as a proposal until a person approves. Recall goes through the gated `recall()`: two verified entries that conflict are both held back and named on `<withheld>` lines, matches that contain under half of the query's words, or that do not stand out from four or more other matches, are only counted, and each call is recorded (counts and a digest of the query). Results come back inside a `<kibisis-recall>` envelope with stored text escaped, each entry labeled with its state and author; candidates are included unless `include_candidates` is false, and recall wants any of the query's words unless `match` is `all`. Forget deletes the entry, tombstones its value, and rebuilds the search index, truncates the write-ahead log and vacuums the file. It refuses an entry a person verified, reviewed or wrote, and a value such an entry holds, since the tombstone would purge that copy too; the refusal is journaled, `python -m kibisis.review list` shows it as a request, and a person carries it out by rejecting the entry. People review candidates with `python -m kibisis.review` (`src/kibisis/review.py`).

## Limits

- **Alpha release:** APIs will change before 1.0.
- **Platforms:** CI tests the Python package on Linux and macOS (arm64). Windows is not tested.
- **Encryption scope:** In the Python package, entry content is always encrypted unless the vault is opened with `allow_plaintext=True`; whole-file encryption needs SQLCipher (see above). With SQLCipher, the search index also holds each entry's words and their positions, protected by SQLCipher's encryption of the file rather than by the entry's own seal. The Rust crate keeps memories in RAM and neither encrypts nor persists them.
- **Tombstones:** They stop exact and look-alike repeats of a value (the canonical fold above), not paraphrases, translations or reorderings. A tombstone covers one scope; a person can tombstone with `scope="*"` to forget a value in every scope; a model or tool origin may not.
- **Scopes:** A library caller names the scope. Kibisis keeps scopes apart but does not decide which caller may use which scope. The MCP server serves only the scope it was started with.
- **Review:** `python -m kibisis.review` verdicts and `python -m kibisis admit` need a terminal on stdin and record the operating-system account they run as, read from the process's user id rather than `USER`, so the quorum counts accounts, not typed names. Neither is an authentication boundary: the terminal check stops pipes and cron jobs, and anything that can run commands as that account with a pseudo-terminal can run them, an agent with such a terminal included. `review_entity` records a person's verdict only: any other `reviewer_origin` is refused for every verdict, a verdict with no `reviewer_id` is refused, and the attester is the account, not the `reviewer_id` (see Review above). Approvals recorded before 0.1.0a15 under a typed `--reviewer` name still count as that name. Both commands print the vault path and scope they resolved, and a verdict on an entry that is in another scope names the scopes that hold it.
- **Forget:** A tombstone carries the class of whoever made it. One a person made (or one from before classes existed) blocks everyone until a person lifts it: `python -m kibisis.review lift CATEGORY KEY` needs a terminal and journals the lift, and the library method `lift_tombstone()` refuses a `model`, `tool` or `unknown` origin (a library caller that passes no `origin` vouches for a person, as everywhere else). A tombstone's class never goes down: a later agent `tombstone()` of a value a person already rejected leaves the person's row as it is (journaled `tombstone_reaffirmed`). One the agent made through `kibisis_forget` is model-class: it blocks the agent, and a person's later write of the value lifts it (journaled as `tombstone_lifted`), so an agent cannot permanently deny a value. An agent's forget through the MCP server never deletes what a person wrote or reviewed; `tombstone()`, `purge()`, `archive()` and `set_persona_slot()` run the same check when given a model or tool `origin`, and library calls that pass no `origin` vouch for themselves and are not checked.
- **Validity windows:** Rewriting a key replaces its validity window with the one the write gives, so a write without one clears it. Use `supersedes_key` to keep the earlier memory and its window.
- **Ranking across scopes:** BM25 counts how common a word is across the whole file, so memories in other scopes shift the scores in this one. They never appear in its results.
- **Fencing:** The Python vault checks fencing tokens only when it is opened with `enforce_fencing=True` or a call passes a token. `migrate_plaintext`, which seals rows written before the vault had a passphrase without changing them (rows adopted from a keyless file with `adopt_keyless` are sealed by the adoption itself; `encryption_status()` counts what is left plain), and `adopt_unsigned_entries` take no token. The MCP server opens its vault without a coordinator, and the Rust vault does not check tokens. Storage outside Kibisis must compare tokens itself.
- **Lease coordination scope:** Leases coordinate threads in one process, or processes on one machine that share a local filesystem: through operating-system file locks on a shared directory with `FileLeaseCoordinator` (the Rust one, which the Python package reaches through the `kibisis_native` extension). They are not a distributed consensus service, and network filesystems are not supported.
- **TTL resolution:** The coordinators track deadlines in whole seconds and round up, so a lease is held for at least its TTL and at most one second longer. The shared `expires_at` timestamp is synchronized through `kibisis_native`.
- **Upgrade from 0.1.0a5 or earlier:** The first open with the passphrase upgrades the vault in one transaction: entries are re-sealed, bound to their entry, and re-signed; digests in the journal and in tombstones are keyed; the journal's hashes are recomputed; and a `migrate` event records the counts and the old chain head. A wrong passphrase is refused before the upgrade, and before a plain SQLite file is converted to SQLCipher, so it changes nothing; a journal that does not verify under the old rule refuses the upgrade rather than being re-signed. A vault at integrity format 2 (0.1.0a6 to a15) is brought to format 3 the same way: tombstone rows get their MAC, the journal's format floor is pinned, and the integrity record is MACed. Older versions cannot read an upgraded vault, so upgrade every process that opens it at the same time. An entry without a signature, in a vault that was not already SQLCipher-encrypted, cannot be told apart from a tampered one, so it is refused until `adopt_unsigned_entries()` accepts it; `integrity_status()` counts such entries. Tombstones in a snapshot from a vault with a different passphrase are not applied, and the import journals that.
- **Upgrade from 0.1.0a6 or earlier (search index):** The first open of a SQLCipher vault with its passphrase builds the search index by opening each entry once. Older versions keep working on the vault: triggers queue the rows they write, and the next search indexes them. The same holds for the keyed term index of a vault without SQLCipher: the first open builds it, and rows written by an older version are indexed before the next search.
- **Not independently assessed:** No security review or certification has been completed. Designed for local and disconnected use.

## Security

Report a vulnerability to contact@perseuscomputing.com with `[SECURITY]` in the subject; please do not open a public issue. See the [security policy](https://github.com/Perseus-Computing-LLC/.github/blob/main/SECURITY.md) for response times.

## Links

- [telarch.ai/kibisis](https://telarch.ai/kibisis): overview and a live demo of the lease coordinator
- [telarch.ai/chatgpt](https://telarch.ai/chatgpt): Telarch as an app for ChatGPT and a plugin for Codex
- [Documentation (docs.rs)](https://docs.rs/kibisis)
- [Agent Memory Leaderboard adapter](deploy/aml/README.md): `kibisis aml-serve`, the AML Add/Search API over Kibisis vaults
- [Changelog](CHANGELOG.md)

## License

Released under the [MIT License](LICENSE) © 2026 Perseus Computing LLC.
