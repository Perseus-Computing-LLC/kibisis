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

## Scope & Cryptographic Boundaries
- **Python Package**: Employs SQLCipher full-page encryption and AES-256-GCM envelope encryption with keys derived via PBKDF2-HMAC-SHA256 (600,000 iterations). Raw disk scans reveal zero plaintext.
- **Rust Crate**: Provides high-throughput in-memory memory vault and concurrency lease coordination. It does not encrypt at rest.
- **Local Boundary**: Leases coordinate local threads and processes sharing access to an atomic SQLite transaction store. They are not a distributed consensus lock service.
