//! `kibisis_native`: the kibisis Rust crate for Python.
//!
//! Leases: [`kibisis::file_lease::FileLeaseCoordinator`] behind a `#[pyclass]`, one lock file and one state
//! file per resource under a directory, so every process (and every language) that opens the directory
//! sees the same lease. Journal: the format-3 hash functions and the chain verifier, so the Python vault
//! and the Rust verifier hash and judge byte for byte alike without a second implementation.
//!
//! No call here can panic into Python: a bad `ttl_seconds` is a `ValueError`, and the coordinator sits
//! behind a mutex, so concurrent calls on one `FileLeaseCoordinator` from several threads wait their turn
//! instead of failing with "Already borrowed".
use std::sync::Mutex;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyOSError, PyValueError};
use pyo3::prelude::*;

use kibisis::journal::{self, EventFields, JournalHead};
use kibisis::FileLeaseCoordinator as Inner;
use kibisis::{AuditEvent, Lease as InnerLease, LeaseCoordinator, LeaseError};

create_exception!(
    kibisis_native,
    LeaseConflict,
    PyException,
    "The resource is held by another holder."
);

fn map_err(e: LeaseError) -> PyErr {
    match e {
        LeaseError::Conflict(m) => LeaseConflict::new_err(m),
        LeaseError::Expired(m) | LeaseError::InvalidToken(m) => PyValueError::new_err(m),
    }
}

fn ttl(seconds: f64) -> PyResult<Duration> {
    if !(seconds.is_finite() && seconds > 0.0) {
        return Err(PyValueError::new_err(
            "ttl_seconds must be a positive, finite number",
        ));
    }
    // `Duration::from_secs_f64` panics past u64::MAX seconds; the checked form reports it instead.
    Duration::try_from_secs_f64(seconds)
        .map_err(|e| PyValueError::new_err(format!("ttl_seconds {seconds} is out of range: {e}")))
}

/// A lease record: `resource`, `holder_id`, `fencing_token`, `acquired_at`, `expires_at` (whole seconds).
#[pyclass(name = "Lease", frozen, get_all)]
#[derive(Clone)]
pub struct PyLease {
    pub resource: String,
    pub holder_id: String,
    pub fencing_token: u64,
    pub acquired_at: u64,
    pub expires_at: u64,
}

impl From<InnerLease> for PyLease {
    fn from(l: InnerLease) -> Self {
        Self {
            resource: l.resource,
            holder_id: l.holder_id,
            fencing_token: l.fencing_token,
            acquired_at: l.acquired_at,
            expires_at: l.expires_at,
        }
    }
}

impl PyLease {
    fn inner(&self) -> InnerLease {
        InnerLease {
            resource: self.resource.clone(),
            holder_id: self.holder_id.clone(),
            fencing_token: self.fencing_token,
            acquired_at: self.acquired_at,
            expires_at: self.expires_at,
        }
    }
}

#[pymethods]
impl PyLease {
    #[new]
    fn new(
        resource: String,
        holder_id: String,
        fencing_token: u64,
        acquired_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            resource,
            holder_id,
            fencing_token,
            acquired_at,
            expires_at,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Lease(resource={:?}, holder_id={:?}, fencing_token={}, acquired_at={}, expires_at={})",
            self.resource, self.holder_id, self.fencing_token, self.acquired_at, self.expires_at
        )
    }
}

/// File-backed lease coordinator: `FileLeaseCoordinator(dir)`.
///
/// Every method takes `&self` and locks the inner coordinator for the call, outside the GIL, so threads
/// sharing one object block on each other rather than raising.
#[pyclass(name = "FileLeaseCoordinator")]
pub struct PyFileLeaseCoordinator {
    inner: Mutex<Inner>,
}

impl PyFileLeaseCoordinator {
    /// Run `f` on the inner coordinator under its mutex. A thread that panicked while holding the
    /// mutex (which no code path does) would poison it; the state is still usable, so recover it.
    fn with_inner<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }
}

#[pymethods]
impl PyFileLeaseCoordinator {
    #[new]
    fn new(dir: String) -> PyResult<Self> {
        Inner::new(&dir)
            .map(|inner| Self {
                inner: Mutex::new(inner),
            })
            .map_err(|e| PyOSError::new_err(e.to_string()))
    }

    /// The directory holding the lock and state files.
    fn dir(&self) -> String {
        self.with_inner(|inner| inner.dir().display().to_string())
    }

    /// Acquire `resource` for `holder_id` for `ttl_seconds`; raises `LeaseConflict` while another holder has it.
    /// The same holder re-acquiring gets the next fencing token.
    fn acquire(
        &self,
        py: Python<'_>,
        resource: &str,
        holder_id: &str,
        ttl_seconds: f64,
    ) -> PyResult<PyLease> {
        let ttl = ttl(ttl_seconds)?;
        py.detach(|| self.with_inner(|inner| inner.acquire(resource, holder_id, ttl)))
            .map(PyLease::from)
            .map_err(map_err)
    }

    /// Extend the lease if `holder_id` still holds it with the same fencing token; `False` otherwise.
    fn renew(&self, py: Python<'_>, lease: &PyLease, ttl_seconds: f64) -> PyResult<bool> {
        let ttl = ttl(ttl_seconds)?;
        let l = lease.inner();
        py.detach(|| self.with_inner(|inner| inner.renew(&l, ttl)))
            .map_err(map_err)
    }

    /// Release the lease if it is held with the same fencing token; `False` otherwise.
    fn release(&self, py: Python<'_>, lease: &PyLease) -> PyResult<bool> {
        let l = lease.inner();
        py.detach(|| self.with_inner(|inner| inner.release(&l)))
            .map_err(map_err)
    }

    /// The current record for `resource` (expired and released ones included), or `None`.
    fn get_lease(&self, py: Python<'_>, resource: &str) -> PyResult<Option<PyLease>> {
        py.detach(|| self.with_inner(|inner| inner.get_lease(resource)))
            .map(|o| o.map(PyLease::from))
            .map_err(map_err)
    }

    /// `True` if `holder_id` holds an unexpired lease on `resource` with exactly `fencing_token`.
    fn validate_fencing_token(
        &self,
        py: Python<'_>,
        resource: &str,
        holder_id: &str,
        fencing_token: u64,
    ) -> PyResult<bool> {
        py.detach(|| {
            self.with_inner(|inner| {
                inner.validate_fencing_token(resource, holder_id, fencing_token)
            })
        })
        .map_err(map_err)
    }
}

/// One journal row as `verify_chain` takes it: a dict with `sequence`, `timestamp` (a whole number of
/// seconds, int or float: the crate's `AuditEvent` keeps seconds as `u64`), `action`, `category`, `key`,
/// `scope`, `value_sha256`, `prev_hash`, `event_hash`, `author_id` (or None), `metadata_json` (canonical
/// JSON text, or None) and `format`.
fn audit_event_from_py(row: &Bound<'_, PyAny>) -> PyResult<AuditEvent> {
    let get = |name: &str| row.get_item(name);
    let timestamp = get("timestamp")?.extract::<f64>()?;
    if !(timestamp.is_finite() && timestamp >= 0.0 && timestamp.fract() == 0.0) {
        return Err(PyValueError::new_err(format!(
            "timestamp {timestamp} is not a whole number of seconds; the crate's journal rows keep \
             seconds as u64, so a row with a fractional timestamp cannot be verified natively"
        )));
    }
    let opt_str = |name: &str| -> PyResult<Option<String>> {
        let v = get(name)?;
        if v.is_none() {
            Ok(None)
        } else {
            v.extract::<String>().map(Some)
        }
    };
    Ok(AuditEvent {
        sequence: get("sequence")?.extract()?,
        timestamp: timestamp as u64,
        action: get("action")?.extract()?,
        category: get("category")?.extract()?,
        key: get("key")?.extract()?,
        scope: get("scope")?.extract()?,
        value_sha256: get("value_sha256")?.extract()?,
        prev_hash: get("prev_hash")?.extract()?,
        event_hash: get("event_hash")?.extract()?,
        author_id: opt_str("author_id")?,
        metadata_json: opt_str("metadata_json")?,
        format: get("format")?.extract()?,
    })
}

/// Verify a format 3 journal the way the crate does (`kibisis::journal::verify_chain_with`).
///
/// `events` is a list of row dicts (see `audit_event_from_py`), `head` a dict with `sequence`,
/// `event_hash` and `mac` or None. Returns None when the chain is sound, else the crate's reason as
/// text, so a Python verifier can be checked against it row for row. `head_required` is the rule for a
/// keyed vault whose journal has held a row: no head is a failure even with no rows left. Rows must
/// carry whole-second timestamps (ValueError otherwise); a Python vault's journal, whose timestamps
/// are fractional, is verified by `kibisis._vault_audit.ChainVerifier`, which hashes through this
/// module's `event_hash_v3` and applies the same rules.
#[pyfunction]
#[pyo3(signature = (events, head, signing_key, head_required=false))]
fn verify_chain(
    events: &Bound<'_, PyAny>,
    head: Option<&Bound<'_, PyAny>>,
    signing_key: &[u8],
    head_required: bool,
) -> PyResult<Option<String>> {
    let mut rows = Vec::new();
    for row in events.try_iter()? {
        rows.push(audit_event_from_py(&row?)?);
    }
    let head = match head {
        None => None,
        Some(h) if h.is_none() => None,
        Some(h) => Some(JournalHead {
            sequence: h.get_item("sequence")?.extract()?,
            event_hash: h.get_item("event_hash")?.extract()?,
            mac: h.get_item("mac")?.extract()?,
        }),
    };
    Ok(
        journal::verify_chain_with(&rows, head.as_ref(), signing_key, head_required)
            .err()
            .map(|e| e.to_string()),
    )
}

/// Format-3 event hash (see `kibisis::journal::event_hash_v3`).
#[pyfunction]
#[pyo3(signature = (sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, author_id=None, metadata_json=None))]
#[allow(clippy::too_many_arguments)]
fn event_hash_v3(
    sequence: u64,
    timestamp: f64,
    action: &str,
    category: &str,
    key: &str,
    scope: &str,
    value_sha256: &str,
    prev_hash: &str,
    author_id: Option<&str>,
    metadata_json: Option<&str>,
) -> String {
    journal::event_hash_v3(&EventFields {
        sequence,
        timestamp,
        action,
        category,
        key,
        scope,
        value_sha256,
        prev_hash,
        author_id,
        metadata_json,
    })
}

/// Version-1 head MAC (see `kibisis::journal::head_mac_v1`).
#[pyfunction]
fn head_mac_v1(signing_key: &[u8], sequence: u64, event_hash: &str) -> String {
    journal::head_mac_v1(signing_key, sequence, event_hash)
}

/// SHA-256 hex of the canonical metadata JSON (`{}` for none).
#[pyfunction]
#[pyo3(signature = (metadata_json=None))]
fn metadata_digest(metadata_json: Option<&str>) -> String {
    journal::metadata_digest(metadata_json)
}

/// Version of the kibisis crate this extension was built from.
#[pyfunction]
fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn kibisis_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyLease>()?;
    m.add_class::<PyFileLeaseCoordinator>()?;
    m.add("LeaseConflict", m.py().get_type::<LeaseConflict>())?;
    m.add_function(wrap_pyfunction!(event_hash_v3, m)?)?;
    m.add_function(wrap_pyfunction!(head_mac_v1, m)?)?;
    m.add_function(wrap_pyfunction!(metadata_digest, m)?)?;
    m.add_function(wrap_pyfunction!(verify_chain, m)?)?;
    m.add_function(wrap_pyfunction!(crate_version, m)?)?;
    m.add("JOURNAL_FORMAT", journal::JOURNAL_FORMAT)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ttl;
    use std::time::Duration;

    /// `ttl` must never reach `Duration::from_secs_f64`'s panic: every bad input is an `Err`.
    #[test]
    fn ttl_rejects_out_of_range_and_non_positive_values_without_panicking() {
        pyo3::Python::initialize();
        for bad in [
            0.0,
            -1.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            1e300,
            f64::MAX,
        ] {
            assert!(ttl(bad).is_err(), "{bad} must be refused");
        }
        assert_eq!(ttl(1.5).unwrap(), Duration::from_secs_f64(1.5));
        assert_eq!(ttl(3600.0).unwrap(), Duration::from_secs(3600));
    }
}
