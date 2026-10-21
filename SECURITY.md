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
- **Search index:** with SQLCipher, a vault with a passphrase keeps a full-text index of entry content in the database file so that search can rank sealed entries. It holds each entry's words and their positions, enough to rebuild the entry's text without case or punctuation, and SQLCipher's whole-file encryption protects it, not the entry's AES-256-GCM seal; both keys come from the passphrase. Without SQLCipher, entry words are never written to disk: search builds its index in memory. Words of deleted or replaced entries stay in index pages until `scrub()` rebuilds the index (the MCP server's forget runs it).
- **Rust crate:** holds memory in RAM and does not encrypt it.
- **Leases:** Rust's `InMemoryLeaseCoordinator` coordinates threads in one process. Rust's `FileLeaseCoordinator` and Python's `SQLiteLeaseCoordinator` coordinate processes on one machine that share a directory or an SQLite file on a local filesystem. None of them is a distributed lock. A Python vault opened with `enforce_fencing=True` refuses writes that do not carry the current fencing token; otherwise it checks a token only when a call passes one. The MCP server and the Rust crate do not check tokens.
- **Not covered:** a running process that already holds the key, or a weak passphrase.
