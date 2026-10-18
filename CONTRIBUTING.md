# Contributing to Kibisis

Thank you for contributing to Kibisis.

## Rules
1. All changes must be tested: `cargo test` for Rust and `pytest tests` for Python.
2. Code must pass `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`.
3. Do not add external network dependencies or telemetry.
4. Concurrency invariants (mutual exclusion, strictly monotonic fencing) must be preserved.
5. Contributions are licensed under the MIT License.
