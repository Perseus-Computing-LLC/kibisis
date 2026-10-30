//! `kibisis_native`: the kibisis Rust crate for Python.
//!
//! Leases: [`kibisis::file_lease::FileLeaseCoordinator`] behind a `#[pyclass]`, one lock file and one state
//! file per resource under a directory, so every process (and every language) that opens the directory
//! sees the same lease. Journal: the format-3 hash functions, so the Python vault and the Rust verifier hash
//! byte for byte alike without a second implementation.
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyOSError, PyValueError};
use pyo3::prelude::*;

use kibisis::journal::{self, EventFields};
use kibisis::FileLeaseCoordinator as Inner;
use kibisis::{Lease as InnerLease, LeaseCoordinator, LeaseError};

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
    Ok(Duration::from_secs_f64(seconds))
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
#[pyclass(name = "FileLeaseCoordinator")]
pub struct PyFileLeaseCoordinator {
    inner: Inner,
}

#[pymethods]
impl PyFileLeaseCoordinator {
    #[new]
    fn new(dir: String) -> PyResult<Self> {
        Inner::new(&dir)
            .map(|inner| Self { inner })
            .map_err(|e| PyOSError::new_err(e.to_string()))
    }

    /// The directory holding the lock and state files.
    fn dir(&self) -> String {
        self.inner.dir().display().to_string()
    }

    /// Acquire `resource` for `holder_id` for `ttl_seconds`; raises `LeaseConflict` while another holder has it.
    /// The same holder re-acquiring gets the next fencing token.
    fn acquire(
        &mut self,
        py: Python<'_>,
        resource: &str,
        holder_id: &str,
        ttl_seconds: f64,
    ) -> PyResult<PyLease> {
        let ttl = ttl(ttl_seconds)?;
        py.detach(|| self.inner.acquire(resource, holder_id, ttl))
            .map(PyLease::from)
            .map_err(map_err)
    }

    /// Extend the lease if `holder_id` still holds it with the same fencing token; `False` otherwise.
    fn renew(&mut self, py: Python<'_>, lease: &PyLease, ttl_seconds: f64) -> PyResult<bool> {
        let ttl = ttl(ttl_seconds)?;
        let l = lease.inner();
        py.detach(|| self.inner.renew(&l, ttl)).map_err(map_err)
    }

    /// Release the lease if it is held with the same fencing token; `False` otherwise.
    fn release(&mut self, py: Python<'_>, lease: &PyLease) -> PyResult<bool> {
        let l = lease.inner();
        py.detach(|| self.inner.release(&l)).map_err(map_err)
    }

    /// The current record for `resource` (expired and released ones included), or `None`.
    fn get_lease(&self, py: Python<'_>, resource: &str) -> PyResult<Option<PyLease>> {
        py.detach(|| self.inner.get_lease(resource))
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
            self.inner
                .validate_fencing_token(resource, holder_id, fencing_token)
        })
        .map_err(map_err)
    }
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
    m.add_function(wrap_pyfunction!(crate_version, m)?)?;
    m.add("JOURNAL_FORMAT", journal::JOURNAL_FORMAT)?;
    Ok(())
}
