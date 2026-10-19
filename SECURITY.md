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
- **Python package:** each entry's content is sealed with AES-256-GCM under a key derived with PBKDF2-HMAC-SHA256 (600,000 iterations). An on-disk vault will not open without a passphrase unless you pass `allow_plaintext=True`. With `sqlcipher3` installed, SQLCipher also encrypts the whole database file, including categories, keys and metadata. Without it, those fields are stored in plain text and Kibisis logs a warning.
- **Rust crate:** holds memory in RAM and does not encrypt it.
- **Leases:** Rust leases coordinate threads in one process. Python leases coordinate processes that share one SQLite file on one machine. Neither is a distributed lock. A Python vault opened with `enforce_fencing=True` refuses writes that do not carry the current fencing token; otherwise it checks a token only when a call passes one. The MCP server and the Rust crate do not check tokens.
- **Not covered:** a running process that already holds the key, or a weak passphrase.
