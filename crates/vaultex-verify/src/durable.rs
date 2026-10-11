//! Append-only local files, shared by the velocity store and the receipt log: created together
//! with a synced directory entry, locked exclusively while open, and synced after every append.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::Path;

use crate::velocity::StoreError;

/// Opens the file at `path` for reading and appending, creating it if absent, and takes its
/// exclusive lock ([`StoreError::Locked`] if another process holds it). A new file and its
/// directory entry are synced before the file is returned.
pub(crate) fn open_locked(path: &Path) -> Result<File, StoreError> {
    let mut opts = OpenOptions::new();
    opts.read(true).append(true);
    let (file, created) = match opts.clone().create_new(true).open(path) {
        Ok(file) => (file, true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            (opts.open(path).map_err(io_err)?, false)
        }
        Err(e) => return Err(io_err(e)),
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(StoreError::Locked),
        Err(TryLockError::Error(e)) => return Err(io_err(e)),
    }
    if created {
        file.sync_all().map_err(io_err)?;
        sync_parent_dir(path).map_err(io_err)?;
    }
    Ok(file)
}

/// Appends `bytes` and returns once they are on stable storage.
pub(crate) fn append_synced(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes).and_then(|()| file.sync_data())
}

/// Cuts the file to `len` bytes, durably.
pub(crate) fn truncate(file: &File, len: u64) -> Result<(), StoreError> {
    file.set_len(len).map_err(io_err)?;
    file.sync_all().map_err(io_err)
}

pub(crate) fn io_err(e: io::Error) -> StoreError {
    StoreError::Io(e.kind())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

// ponytail: signer hosts are Linux or macOS; elsewhere the directory entry is not synced.
#[cfg(not(unix))]
fn sync_parent_dir(_: &Path) -> io::Result<()> {
    Ok(())
}
