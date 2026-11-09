use crate::F;
use ff::PrimeField;
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Mutex,
};

#[derive(Debug)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

pub trait ReplaySet {
    /// Atomically returns true and records a fresh pair, or returns false for
    /// an existing pair. Storage failure must return an error, never freshness.
    fn check_and_insert(&self, scope: F, nullifier: F) -> Result<bool, Error>;
}

#[derive(Default)]
pub struct InMemoryReplaySet {
    pairs: Mutex<HashSet<([u8; 32], [u8; 32])>>,
}

impl InMemoryReplaySet {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplaySet for InMemoryReplaySet {
    fn check_and_insert(&self, scope: F, nullifier: F) -> Result<bool, Error> {
        let mut pairs = self
            .pairs
            .lock()
            .map_err(|_| Error::new("in-memory replay lock is poisoned"))?;
        Ok(pairs.insert((field_bytes(scope), field_bytes(nullifier))))
    }
}

pub struct FileReplaySet {
    path: PathBuf,
}

impl FileReplaySet {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        Ok(Self { path })
    }
}

impl ReplaySet for FileReplaySet {
    fn check_and_insert(&self, scope: F, nullifier: F) -> Result<bool, Error> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        file.lock()
            .map_err(|error| Error::new(format!("cannot lock replay file: {error}")))?;
        let result = check_and_insert_locked(&mut file, scope, nullifier);
        let unlock = file.unlock();
        match (result, unlock) {
            (Ok(fresh), Ok(())) => Ok(fresh),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(Error::new(format!("cannot unlock replay file: {error}"))),
        }
    }
}

fn check_and_insert_locked(file: &mut File, scope: F, nullifier: F) -> Result<bool, Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| Error::new(format!("cannot read replay file: {error}")))?;
    if !contents.is_empty() && !contents.ends_with('\n') {
        return Err(Error::new("replay file has an incomplete final record"));
    }

    let scope_hex = hex(&field_bytes(scope));
    let nullifier_hex = hex(&field_bytes(nullifier));
    for line in contents.lines() {
        let mut parts = line.split(':');
        let stored_scope = parts.next().unwrap_or_default();
        let stored_nullifier = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || !is_lower_hex_64(stored_scope)
            || !is_lower_hex_64(stored_nullifier)
        {
            return Err(Error::new("replay file contains a corrupt record"));
        }
        if stored_scope == scope_hex && stored_nullifier == nullifier_hex {
            return Ok(false);
        }
    }

    writeln!(file, "{scope_hex}:{nullifier_hex}")?;
    file.sync_data()?;
    Ok(true)
}

fn field_bytes(value: F) -> [u8; 32] {
    let repr = value.to_repr();
    repr.as_ref()
        .try_into()
        .expect("Pallas base-field representations are 32 bytes")
}

fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };

    #[test]
    fn memory_admits_exactly_one_of_many_concurrent_presentations() {
        const THREADS: usize = 16;
        let replay = Arc::new(InMemoryReplaySet::new());
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let replay = Arc::clone(&replay);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    replay.check_and_insert(F::from(7), F::from(11)).unwrap()
                })
            })
            .collect();
        let fresh = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|fresh| *fresh)
            .count();
        assert_eq!(fresh, 1);
        assert!(!replay.check_and_insert(F::from(7), F::from(11)).unwrap());
        assert!(replay.check_and_insert(F::from(8), F::from(11)).unwrap());
        assert!(replay.check_and_insert(F::from(7), F::from(12)).unwrap());
    }

    #[test]
    fn independent_file_handles_admit_exactly_one_concurrent_presentation() {
        const THREADS: usize = 8;
        static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "zkar-replay-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let replay = FileReplaySet::new(path).unwrap();
                    barrier.wait();
                    replay.check_and_insert(F::from(7), F::from(11)).unwrap()
                })
            })
            .collect();
        let fresh = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|fresh| *fresh)
            .count();
        assert_eq!(fresh, 1);

        let replay = FileReplaySet::new(&path).unwrap();
        assert!(!replay.check_and_insert(F::from(7), F::from(11)).unwrap());
        drop(replay);
        std::fs::write(&path, "not a replay record\n").unwrap();
        let replay = FileReplaySet::new(&path).unwrap();
        assert!(replay.check_and_insert(F::from(7), F::from(11)).is_err());
        drop(replay);
        std::fs::remove_file(path).unwrap();
    }
}
