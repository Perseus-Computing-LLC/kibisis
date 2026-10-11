# Telarch Claims & Benchmark Audit Ledger

> In accordance with Telarch engineering principles and the Agent Memory Atlas methodology, all architectural claims and benchmark figures in Telarch documentation must correspond to committed, runnable code with deterministic verification paths. Unsubstantiated claims are formally retired.

---

## 1. Retired & Corrected Claims

The following claims previously present in documentation or legacy monolithic materials have been audited and formally retired or corrected:

| Component | Previous Claim | Disposition | Ground Truth & Correction |
| :--- | :--- | :--- | :--- |
| **External Evaluations** | LongMemEval-S 0.9111 MRR across 23,854 sessions | **RETIRED** | Standalone runner and multi-seed run reports are not yet committed to `telarch-benchmarks`. Historical monolithic runs achieved 73.8% (vanilla) and 79.0% (official-cot), but all headline metrics are withdrawn from READMEs until the modular harness and 3-seed artifacts are committed. |
| **Kibisis Crypto** | ChaCha20-Poly1305 with Argon2id | **CORRECTED** | Codebase implements AES-256-GCM authenticated encryption with PBKDF2HMAC-SHA256 (100,000 iterations). Documentation updated to reflect the actual cipher suite. |
| **Kibisis Storage** | Envelope encryption claimed in docs | **REMEDIATED** | Previous `SQLiteMemoryVault` stored plaintext in `entities` and `entities_fts` without calling `AESGCMCryptoEnvelopeProvider`. Wire-level envelope encryption has now been integrated directly into the `put()` / `get()` storage path with FTS cleartext suppression. |
| **Kibisis Tombstones**| Exact SHA-256 hash matching | **REMEDIATED** | Exact-match hashing allowed trivial bypass via casing/punctuation changes. Upgraded to canonicalized text normalization (Unicode NFKC, lowercase folding, punctuation removal, whitespace collapse). |
| **Argus Latency** | 4.12 µs append latency | **CORRECTED** | Measured bare-metal throughput is ~600,000 events/s (~1.67 µs/op) for in-memory SHA-256 event chaining. |
| **Argus Verification**| 2,170,000 events/s verification | **CORRECTED** | 2.17M was a copy-paste artifact from Kibisis in-memory ingestion. Measured full-chain validation traversal is ~839,000 events/s (~1.19 µs/event). |
| **Argus Tamper** | Scans 100,000 events in 46.00 µs | **CORRECTED** | The 46.50 µs metric represents immediate fail-closed abort upon detecting tampered block #42 in sequence, not a full 100,000-block traversal. |

---

## 2. Active Verified Claims Matrix

All metrics below are reproducible via `cargo run --release -p telarch-benchmarks` on bare-metal Linux x86_64:

| System | Metric | Target / Claim | Verification Command | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Harpe** | Small Context (10 items / 2k context) | p50: ~1.76 µs | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Harpe** | Large Context (200 items / 40k context) | p50: ~35.74 µs | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Harpe** | Multi-Turn Pruning Ceiling Reduction | ~69.51% reduction | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Harpe** | 100,000-Turn Production Cost Curve | 84.77% reduction, 0 overruns, 24.3 µs/turn | `cargo run --release -p telarch-benchmarks --bin knapsack_cost_curve` | **VERIFIED** |
| **Kibisis** | Sequential In-Memory Write Ingestion | >2,098,000 writes/s | `cargo run --release -p telarch-benchmarks` | **VERIFIED** |
| **Kibisis** | Multi-Agent SWMR Lease Concurrency (16 workers) | 1,696,000+ ops/s (0.59 µs latency) | `cargo run --release -p telarch-benchmarks --bin adversarial_contention` | **VERIFIED** |
| **Kibisis** | Multi-Agent SWMR Lease Concurrency (32 workers) | 1,776,000+ ops/s (0.56 µs latency) | `cargo run --release -p telarch-benchmarks --bin adversarial_contention` | **VERIFIED** |
| **Argus** | SHA-256 Continuous Hash Chaining (1M events) | 632,170 events/s (1.58 µs/op) | `cargo run --release -p telarch-benchmarks --bin argus_1m_scale` | **VERIFIED** |
| **Argus** | Full Chain Verification Traversal (1M events) | 770,758 events/s (1.30 µs/event) | `cargo run --release -p telarch-benchmarks --bin argus_1m_scale` | **VERIFIED** |
| **Argus** | Tamper Fail-Closed Detection (Sequence #500,000) | 640.48 ms across 1M events | `cargo run --release -p telarch-benchmarks --bin argus_1m_scale` | **VERIFIED** |
| **Swarm** | Network Partition Tolerance (50% drop) | 100% convergence, 0 split-brain (599,631 msgs/s) | `cargo run --release -p telarch-benchmarks --bin swarm_partition` | **VERIFIED** |
| **Payload** | Tier 0 / Tier 1 Restricted Payloads | 93.6% / 88.7% reduction (<41 µs) | `cargo run --release -p telarch-benchmarks --bin restricted_payload_test` | **VERIFIED** |

---

## 3. Cryptographic & Negative Memory Guarantees

1. **Storage-Engine Encryption**:
   * Algorithm: AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).
   * Key Derivation: PBKDF2HMAC with SHA-256, 100,000 iterations, 16-byte random salt.
   * SQLite Storage: Encrypted payloads stored as authenticated binary envelopes (`ciphertext`, `nonce`, `salt`, `algo`).
   * Plaintext Leakage Prevention: When encryption is active, raw content is never inserted into unencrypted FTS5 virtual tables.

2. **Negative Memory Tombstones**:
   * Normalization: Unicode NFKC normalization $\rightarrow$ lowercase fold $\rightarrow$ punctuation strip $\rightarrow$ whitespace collapse.
   * Matching: Content matches against normalized rejection digests and canonical tokens, preventing trivial prompt injection or typographical evasion.
