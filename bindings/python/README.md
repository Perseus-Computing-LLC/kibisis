# kibisis-native

Python extension (pyo3, abi3) over the kibisis Rust crate. It carries the lease coordinator the Python
package uses (`kibisis.lease.FileLeaseCoordinator` is a thin adapter over `kibisis_native.FileLeaseCoordinator`)
and the format-3 journal hash functions, so there is one implementation of each.

Build: `cd bindings/python && maturin build --release --locked`. The `kibisis` Python package requires this
extension for leases; there is no Python fallback.
