//! File-backed lease coordination for processes on one machine.
//!
//! [`FileLeaseCoordinator`] follows the same rules as [`crate::InMemoryLeaseCoordinator`], but
//! keeps the lease table in files under one directory, so separate processes on the same machine
//! can share it. Each operation holds an operating-system lock on a per-resource lock file from
//! the moment it reads the current lease until its new state is on disk. New state is written to
//! a temporary file and renamed over the old one, so a crash leaves either the old state or the
//! new one. The directory must be on a local filesystem: this is not a distributed lock service,
//! and network filesystems are not supported.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{lease_deadline, sha256_hex, Lease, LeaseCoordinator, LeaseError};

/// First line of every state file: the format and its version.
const STATE_HEADER: &str = "kibisis-lease v1";

/// Field names of a state file, in the order they are written.
const FIELDS: [&str; 5] = ["resource", "holder", "token", "acquired", "expires"];

/// Lease coordinator shared by processes on one machine through files in one directory.
///
/// Each resource has two files, named by the SHA-256 hex digest of the resource name so that any
/// name is safe to use: `<digest>.lock`, which every operation locks for its whole
/// read-decide-write, and `<digest>.lease`, a small versioned text file with the current lease.
/// Lock files are never deleted. Leases follow the rules of [`crate::InMemoryLeaseCoordinator`],
/// including deadlines in whole seconds, rounded up.
///
/// Fencing tokens never go backwards. A resource with no state file starts at token 1. A state
/// file that cannot be read or parsed, or that names a different resource, makes every operation
/// on that resource fail with [`LeaseError::Conflict`] and a message starting `lease store:`; the
/// token is never silently reset. File and lock failures are reported the same way. Deleting a
/// state file resets that resource's token to 1, so do not delete files in the directory while
/// any process uses it.
///
/// On Unix the directory is created with mode `0o700` and its files with mode `0o600`.
///
/// # Examples
///
/// ```
/// use kibisis::{FileLeaseCoordinator, LeaseCoordinator};
/// use std::time::{Duration, SystemTime, UNIX_EPOCH};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
/// let dir = std::env::temp_dir().join(format!("kibisis-doc-{}-{nanos}", std::process::id()));
///
/// let mut coordinator = FileLeaseCoordinator::new(&dir)?;
/// let lease = coordinator.acquire("notes", "worker-a", Duration::from_secs(30))?;
/// assert_eq!(lease.fencing_token, 1);
///
/// // Any process that opens the same directory sees the same lease.
/// let other = FileLeaseCoordinator::new(&dir)?;
/// assert!(other.validate_fencing_token("notes", "worker-a", 1)?);
///
/// coordinator.release(&lease)?;
/// # std::fs::remove_dir_all(&dir)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct FileLeaseCoordinator {
    dir: PathBuf,
}

impl FileLeaseCoordinator {
    /// Open a coordinator on `dir`, creating the directory and any missing parents.
    pub fn new(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&dir)?;
        Ok(Self { dir })
    }

    /// The directory that holds this coordinator's lock and state files.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The current lease record for `resource`, expired and released ones included, or `None`
    /// if the resource has never been leased in this directory.
    pub fn get_lease(&self, resource: &str) -> Result<Option<Lease>, LeaseError> {
        let _lock = self.lock(resource)?;
        self.read_state(resource)
    }

    /// `true` if `holder_id` holds an unexpired lease on `resource` with exactly `fencing_token`.
    pub fn validate_fencing_token(
        &self,
        resource: &str,
        holder_id: &str,
        fencing_token: u64,
    ) -> Result<bool, LeaseError> {
        let _lock = self.lock(resource)?;
        let now = clock().as_secs();
        Ok(self.read_state(resource)?.is_some_and(|lease| {
            lease.holder_id == holder_id
                && lease.fencing_token == fencing_token
                && lease.expires_at > now
        }))
    }

    fn path(&self, resource: &str, extension: &str) -> PathBuf {
        let digest = sha256_hex(resource.as_bytes());
        self.dir.join(format!("{digest}.{extension}"))
    }

    /// Lock `resource` until the returned guard is dropped, creating its lock file if needed.
    fn lock(&self, resource: &str) -> Result<LockGuard, LeaseError> {
        let file = private_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.path(resource, "lock"))
            .map_err(|e| io_error(resource, "open lock file", e))?;
        file.lock().map_err(|e| io_error(resource, "lock", e))?;
        Ok(LockGuard(file))
    }

    /// Read the state of `resource`; the caller holds its lock. `None` means no state file.
    fn read_state(&self, resource: &str) -> Result<Option<Lease>, LeaseError> {
        match fs::read_to_string(self.path(resource, "lease")) {
            Ok(text) => decode_state(&text, resource).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(resource, "read state file", e)),
        }
    }

    /// Replace the state of `lease.resource`; the caller holds its lock. Only the lock holder
    /// writes, so one temporary name per resource is enough, and a temporary file left behind
    /// by a crash is simply overwritten.
    fn write_state(&self, lease: &Lease) -> Result<(), LeaseError> {
        let resource = lease.resource.as_str();
        let temp = self.path(resource, "lease.tmp");
        let mut file = private_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp)
            .map_err(|e| io_error(resource, "create temporary state file", e))?;
        file.write_all(encode_state(lease).as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error(resource, "write temporary state file", e))?;
        drop(file);
        fs::rename(&temp, self.path(resource, "lease"))
            .map_err(|e| io_error(resource, "replace state file", e))?;
        sync_dir(&self.dir);
        Ok(())
    }
}

impl LeaseCoordinator for FileLeaseCoordinator {
    fn acquire(
        &mut self,
        resource: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Lease, LeaseError> {
        let _lock = self.lock(resource)?;
        let since_epoch = clock();
        let now = since_epoch.as_secs();
        let fencing_token = match self.read_state(resource)? {
            Some(existing) if existing.expires_at > now && existing.holder_id != holder_id => {
                return Err(LeaseError::Conflict(format!(
                    "Resource '{}' already held by '{}'",
                    resource, existing.holder_id
                )));
            }
            Some(existing) => existing
                .fencing_token
                .checked_add(1)
                .ok_or_else(|| store_error(resource, "the fencing token cannot go any higher"))?,
            None => 1,
        };
        let lease = Lease {
            resource: resource.to_string(),
            holder_id: holder_id.to_string(),
            fencing_token,
            acquired_at: now,
            expires_at: lease_deadline(since_epoch, ttl),
        };
        self.write_state(&lease)?;
        Ok(lease)
    }

    fn renew(&mut self, lease: &Lease, ttl: Duration) -> Result<bool, LeaseError> {
        let _lock = self.lock(&lease.resource)?;
        let since_epoch = clock();
        match self.read_state(&lease.resource)? {
            Some(mut current)
                if current.holder_id == lease.holder_id
                    && current.fencing_token == lease.fencing_token
                    && current.expires_at >= since_epoch.as_secs() =>
            {
                current.expires_at = lease_deadline(since_epoch, ttl);
                self.write_state(&current)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn release(&mut self, lease: &Lease) -> Result<bool, LeaseError> {
        let _lock = self.lock(&lease.resource)?;
        match self.read_state(&lease.resource)? {
            Some(mut current)
                if current.holder_id == lease.holder_id
                    && current.fencing_token == lease.fencing_token
                    && current.expires_at > 0 =>
            {
                current.expires_at = 0;
                self.write_state(&current)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// Holds the OS lock on one lock file and unlocks it when dropped, panics included.
struct LockGuard(File);

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Closing the file releases the lock too; unlocking first releases it at once.
        let _ = self.0.unlock();
    }
}

fn clock() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// `OpenOptions` that create files readable and writable by the owner only (on Unix).
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    options.mode(0o600);
    options
}

/// Flush `dir` so a rename inside it survives a power cut. Best effort, as in SQLite: the
/// rename has already happened, and reporting a failure now would hide a change that took
/// effect. std has no way to flush a directory on Windows, so there this does nothing.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(handle) = File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn store_error(resource: &str, detail: &str) -> LeaseError {
    LeaseError::Conflict(format!("lease store: resource {resource:?}: {detail}"))
}

fn io_error(resource: &str, action: &str, error: io::Error) -> LeaseError {
    store_error(resource, &format!("{action}: {error}"))
}

fn encode_state(lease: &Lease) -> String {
    format!(
        "{STATE_HEADER}\nresource={}\nholder={}\ntoken={}\nacquired={}\nexpires={}\n",
        hex_encode(lease.resource.as_bytes()),
        hex_encode(lease.holder_id.as_bytes()),
        lease.fencing_token,
        lease.acquired_at,
        lease.expires_at,
    )
}

/// Parse a state file. Anything unexpected is an error, never a fresh lease.
fn decode_state(text: &str, resource: &str) -> Result<Lease, LeaseError> {
    let unreadable = |why: String| {
        store_error(
            resource,
            &format!("unreadable state file ({why}); its fencing token is not reset"),
        )
    };
    let mut lines = text.lines();
    if lines.next() != Some(STATE_HEADER) {
        return Err(unreadable(format!("first line is not {STATE_HEADER:?}")));
    }
    let mut values: [Option<&str>; 5] = [None; 5];
    for line in lines {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| unreadable(format!("line {line:?} is not name=value")))?;
        let slot = FIELDS
            .iter()
            .position(|field| *field == name)
            .ok_or_else(|| unreadable(format!("unknown field {name:?}")))?;
        if values[slot].replace(value).is_some() {
            return Err(unreadable(format!("field {name:?} appears twice")));
        }
    }
    let value = |slot: usize| {
        values[slot].ok_or_else(|| unreadable(format!("missing field {:?}", FIELDS[slot])))
    };
    let text_value = |slot: usize| -> Result<String, LeaseError> {
        hex_decode(value(slot)?)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| unreadable(format!("field {:?} is not hex UTF-8", FIELDS[slot])))
    };
    let number = |slot: usize| -> Result<u64, LeaseError> {
        parse_u64(value(slot)?)
            .ok_or_else(|| unreadable(format!("field {:?} is not a whole number", FIELDS[slot])))
    };
    let stored_resource = text_value(0)?;
    if stored_resource != resource {
        return Err(store_error(
            resource,
            "state file names a different resource; refusing to use it",
        ));
    }
    Ok(Lease {
        resource: stored_resource,
        holder_id: text_value(1)?,
        fencing_token: number(2)?,
        acquired_at: number(3)?,
        expires_at: number(4)?,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from((high << 4) | low).ok()
        })
        .collect()
}

/// A whole number written in ASCII digits only: no sign, spaces or other characters.
fn parse_u64(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod file_lease_tests {
    use super::*;
    use crate::InMemoryLeaseCoordinator;
    use std::collections::HashSet;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    const HOUR: Duration = Duration::from_secs(3600);
    /// Set for the child processes of `processes_share_one_grant_at_a_time`: their directory.
    const CHILD_ENV: &str = "KIBISIS_FILE_LEASE_TEST_CHILD";
    const CHILD_TEST: &str = "file_lease::file_lease_tests::processes_share_one_grant_at_a_time";

    /// A path for a new directory, unique per process, call and moment.
    fn scratch(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "kibisis-file-lease-{tag}-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            clock().as_nanos()
        ))
    }

    fn is_store_error<T>(result: &Result<T, LeaseError>) -> bool {
        matches!(result, Err(LeaseError::Conflict(msg)) if msg.starts_with("lease store: "))
    }

    /// One fixed sequence of lease operations with every outcome written down, so that two
    /// coordinators can be compared step by step.
    fn script(coordinator: &mut dyn LeaseCoordinator) -> Vec<String> {
        fn grant(result: Result<Lease, LeaseError>, log: &mut Vec<String>) -> Option<Lease> {
            match result {
                Ok(lease) => {
                    log.push(format!("granted {}", lease.fencing_token));
                    Some(lease)
                }
                Err(LeaseError::Conflict(msg)) if !msg.starts_with("lease store: ") => {
                    log.push("conflict".to_string());
                    None
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        let mut log = Vec::new();
        let first = grant(coordinator.acquire("doc", "a", HOUR), &mut log).unwrap();
        grant(coordinator.acquire("doc", "b", HOUR), &mut log);
        let second = grant(coordinator.acquire("doc", "a", HOUR), &mut log).unwrap();
        let mut stranger = second.clone();
        stranger.holder_id = "b".to_string();
        log.push(format!(
            "renew old token: {:?}",
            coordinator.renew(&first, HOUR)
        ));
        log.push(format!(
            "renew as another holder: {:?}",
            coordinator.renew(&stranger, HOUR)
        ));
        log.push(format!("renew: {:?}", coordinator.renew(&second, HOUR)));
        log.push(format!(
            "release as another holder: {:?}",
            coordinator.release(&stranger)
        ));
        log.push(format!("release: {:?}", coordinator.release(&second)));
        log.push(format!("release again: {:?}", coordinator.release(&second)));
        log.push(format!(
            "renew after release: {:?}",
            coordinator.renew(&second, HOUR)
        ));
        grant(coordinator.acquire("doc", "b", HOUR), &mut log).unwrap();
        grant(coordinator.acquire("other doc", "b", HOUR), &mut log).unwrap();
        log
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn follows_the_in_memory_rules_step_by_step() {
        let expected = [
            "granted 1",
            "conflict",
            "granted 2",
            "renew old token: Ok(false)",
            "renew as another holder: Ok(false)",
            "renew: Ok(true)",
            "release as another holder: Ok(false)",
            "release: Ok(true)",
            "release again: Ok(false)",
            "renew after release: Ok(false)",
            "granted 3",
            "granted 1",
        ];
        assert_eq!(script(&mut InMemoryLeaseCoordinator::new()), expected);
        let dir = scratch("rules");
        assert_eq!(
            script(&mut FileLeaseCoordinator::new(&dir).unwrap()),
            expected
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn an_expired_lease_goes_to_the_next_holder_with_a_higher_token() {
        let dir = scratch("expiry");
        let mut coordinator = FileLeaseCoordinator::new(&dir).unwrap();
        let first = coordinator
            .acquire("doc", "a", Duration::from_millis(2))
            .unwrap();
        // Deadlines are whole seconds rounded up, so a 2 ms lease lasts at most one more second.
        std::thread::sleep(Duration::from_millis(1100));
        let second = coordinator.acquire("doc", "b", HOUR).unwrap();
        assert_eq!(second.fencing_token, first.fencing_token + 1);
        assert!(!coordinator.renew(&first, HOUR).unwrap());
        assert!(!coordinator
            .validate_fencing_token("doc", "a", first.fencing_token)
            .unwrap());
        assert!(coordinator
            .validate_fencing_token("doc", "b", second.fencing_token)
            .unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_new_coordinator_on_the_same_directory_sees_the_same_leases() {
        let dir = scratch("reopen");
        let lease = FileLeaseCoordinator::new(&dir)
            .unwrap()
            .acquire("doc", "a", HOUR)
            .unwrap();
        let mut reopened = FileLeaseCoordinator::new(&dir).unwrap();
        assert_eq!(reopened.get_lease("doc").unwrap(), Some(lease.clone()));
        assert!(matches!(
            reopened.acquire("doc", "b", HOUR),
            Err(LeaseError::Conflict(msg)) if !msg.starts_with("lease store: ")
        ));
        assert!(reopened.release(&lease).unwrap());
        let next = FileLeaseCoordinator::new(&dir)
            .unwrap()
            .acquire("doc", "b", HOUR)
            .unwrap();
        assert_eq!(next.fencing_token, 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn an_unreadable_state_file_is_an_error_and_never_a_reset() {
        let dir = scratch("corrupt");
        let mut coordinator = FileLeaseCoordinator::new(&dir).unwrap();
        coordinator.acquire("doc", "a", HOUR).unwrap();
        coordinator.acquire("other doc", "a", HOUR).unwrap();
        let state = coordinator.path("doc", "lease");
        let good = fs::read_to_string(&state).unwrap();
        let damaged: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"not a lease file\n".to_vec(),
            format!("{STATE_HEADER}\n").into_bytes(),
            good.replace("token=1\n", "token=one\n").into_bytes(),
            good.replace("token=1\n", "token=1\ntoken=0\n").into_bytes(),
            good.replace("holder=", "holder=zz").into_bytes(),
            fs::read(coordinator.path("other doc", "lease")).unwrap(),
            vec![0xff, 0xfe, 0xfd],
        ];
        for bytes in damaged {
            fs::write(&state, &bytes).unwrap();
            let shown = String::from_utf8_lossy(&bytes).into_owned();
            assert!(
                is_store_error(&coordinator.acquire("doc", "b", HOUR)),
                "{shown:?}"
            );
            assert!(is_store_error(&coordinator.get_lease("doc")), "{shown:?}");
            assert!(
                is_store_error(&coordinator.validate_fencing_token("doc", "a", 1)),
                "{shown:?}"
            );
            assert_eq!(fs::read(&state).unwrap(), bytes, "state file was rewritten");
        }
        fs::write(&state, &good).unwrap();
        assert_eq!(
            coordinator.acquire("doc", "a", HOUR).unwrap().fencing_token,
            2
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn any_resource_or_holder_name_round_trips_through_its_own_files() {
        let dir = scratch("names");
        let mut coordinator = FileLeaseCoordinator::new(&dir).unwrap();
        let names = [
            "",
            "a/b/../c",
            "line\nbreak",
            "tab\tand=equals",
            "Ünïcödé 日本語",
            "A",
            "a",
        ];
        let mut state_files = HashSet::new();
        for name in names {
            let holder = format!("holder\n={name}");
            let lease = coordinator.acquire(name, &holder, HOUR).unwrap();
            assert_eq!(lease.fencing_token, 1, "{name:?}");
            let stored = coordinator.get_lease(name).unwrap().unwrap();
            assert_eq!(stored.resource, name);
            assert_eq!(stored.holder_id, holder);
            assert!(
                state_files.insert(coordinator.path(name, "lease")),
                "{name:?} shares a state file"
            );
        }
        // One lock file and one state file per resource, all directly in the directory.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2 * names.len());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_directory_and_its_files_are_private_to_the_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("modes");
        FileLeaseCoordinator::new(&dir)
            .unwrap()
            .acquire("doc", "a", HOUR)
            .unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            assert_eq!(mode(&path), 0o600, "{path:?}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Take the shared lease `rounds` times as `holder`, retrying while another holder has it.
    /// Inside each grant: create the `inside` marker, which fails if any other holder is inside
    /// as well; record the token in a file of its own; check the token through a second
    /// coordinator; then remove the marker and release.
    fn contend(dir: &Path, holder: &str, rounds: usize) {
        // Short enough that a holder dying inside its grant stalls the others for seconds, not an
        // hour; far longer than a grant is held here (a few milliseconds).
        let ttl = Duration::from_secs(10);
        let give_up = std::time::Instant::now() + Duration::from_secs(120);
        let mut coordinator = FileLeaseCoordinator::new(dir).unwrap();
        let checker = FileLeaseCoordinator::new(dir).unwrap();
        let marker = dir.join("inside");
        for round in 0..rounds {
            let lease = loop {
                match coordinator.acquire("shared", holder, ttl) {
                    Ok(lease) => break lease,
                    Err(LeaseError::Conflict(msg)) if !msg.starts_with("lease store: ") => {
                        assert!(
                            std::time::Instant::now() < give_up,
                            "{holder}: no grant in 120 s"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(other) => panic!("{holder}: {other:?}"),
                }
            };
            let inside = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker);
            assert!(
                inside.is_ok(),
                "{holder} got token {} while another holder was inside",
                lease.fencing_token
            );
            fs::write(
                dir.join(format!("token-{holder}-{round}")),
                lease.fencing_token.to_string(),
            )
            .unwrap();
            std::thread::sleep(Duration::from_millis(1));
            assert!(checker
                .validate_fencing_token("shared", holder, lease.fencing_token)
                .unwrap());
            drop(inside);
            fs::remove_file(&marker).unwrap();
            assert!(coordinator.release(&lease).unwrap(), "{holder}: release");
        }
    }

    /// Every grant recorded one token; together they must be exactly 1..=grants.
    fn assert_tokens(dir: &Path, grants: usize) {
        let mut tokens: Vec<u64> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("token-"))
            })
            .map(|path| fs::read_to_string(path).unwrap().parse().unwrap())
            .collect();
        tokens.sort_unstable();
        let expected: Vec<u64> = (1..=grants as u64).collect();
        assert_eq!(tokens, expected);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn threads_with_their_own_coordinators_take_turns() {
        const THREADS: usize = 16;
        const ROUNDS: usize = 8;
        let dir = scratch("threads");
        FileLeaseCoordinator::new(&dir).unwrap();
        let start = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|i| {
                let (dir, start) = (dir.clone(), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    contend(&dir, &format!("thread-{i}"), ROUNDS);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_tokens(&dir, THREADS * ROUNDS);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn processes_share_one_grant_at_a_time() {
        const PROCESSES: usize = 8;
        const ROUNDS: usize = 25;
        if let Some(dir) = std::env::var_os(CHILD_ENV) {
            // A child process started by the parent branch below.
            let holder = format!("process-{}", std::process::id());
            contend(Path::new(&dir), &holder, ROUNDS);
            return;
        }
        let dir = scratch("processes");
        FileLeaseCoordinator::new(&dir).unwrap();
        let exe = std::env::current_exe().unwrap();
        // Start every child before waiting for any, so they contend for the lease.
        let children: Vec<_> = (0..PROCESSES)
            .map(|_| {
                Command::new(&exe)
                    .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
                    .env(CHILD_ENV, &dir)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        // Wait for every child, failed ones included, so none is left running.
        let failures: Vec<String> = children
            .into_iter()
            .filter_map(|child| {
                let output = child.wait_with_output().unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                // With a wrong test path a child runs no tests and still exits 0.
                if output.status.success() && stdout.contains("1 passed") {
                    return None;
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                Some(format!("{}:\n{stdout}\n{stderr}", output.status))
            })
            .collect();
        assert!(
            failures.is_empty(),
            "child processes failed:\n{}",
            failures.join("\n")
        );
        assert_tokens(&dir, PROCESSES * ROUNDS);
        fs::remove_dir_all(&dir).unwrap();
    }
}
