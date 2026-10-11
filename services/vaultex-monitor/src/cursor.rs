//! Persisted block cursor of one provider.
//!
//! The cursor holds the last [`DEPTH`] scanned `(height, block id)` pairs, oldest first. Its tip is
//! the last block whose events were delivered. The ring lets the watcher find a fork point at
//! latest height and re-scan from there, also across restarts. On disk it is a text file, one
//! `height block_id` line per block, replaced atomically (write, fsync, rename, fsync directory).

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

/// Blocks remembered for fork detection. A TRON block is solidified once 19 of the 27 block
/// producers have built on it (≈ 1 min), so a longer reorg at latest is not expected; a deeper one
/// stops the watcher.
pub const DEPTH: usize = 32;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    blocks: VecDeque<(u64, String)>,
    /// Blocks below the oldest entry were scanned and forgotten, so a fork that reaches past the
    /// oldest entry cannot be resolved.
    truncated: bool,
}

impl Cursor {
    pub fn tip(&self) -> Option<&(u64, String)> {
        self.blocks.back()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Records the next scanned block. The caller keeps heights consecutive.
    pub fn push(&mut self, height: u64, id: String) {
        debug_assert!(self.tip().is_none_or(|(h, _)| *h + 1 == height));
        if self.blocks.len() == DEPTH {
            self.blocks.pop_front();
            self.truncated = true;
        }
        self.blocks.push_back((height, id));
    }

    /// Drops the tip (it was orphaned by a fork).
    pub fn pop(&mut self) -> Option<(u64, String)> {
        self.blocks.pop_back()
    }

    /// Loads a cursor; `None` if there is no file. A file that fails validation is an error, never
    /// a silent restart (which could skip blocks).
    pub fn load(path: &Path) -> io::Result<Option<Cursor>> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let bad = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {why}", path.display()),
            )
        };
        let mut cursor = Cursor::default();
        for line in text.lines() {
            let (height, id) = line.split_once(' ').ok_or_else(|| bad("malformed line"))?;
            let height: u64 = height.parse().map_err(|_| bad("malformed height"))?;
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad("malformed block id"));
            }
            if cursor.tip().is_some_and(|(h, _)| *h + 1 != height) {
                return Err(bad("heights are not consecutive"));
            }
            if cursor.blocks.len() == DEPTH {
                return Err(bad("more blocks than the cursor keeps"));
            }
            cursor.blocks.push_back((height, id.to_ascii_lowercase()));
        }
        if cursor.is_empty() {
            return Err(bad("empty cursor"));
        }
        // A full ring means older blocks were forgotten before the save.
        cursor.truncated = cursor.blocks.len() == DEPTH;
        Ok(Some(cursor))
    }

    /// Replaces the file atomically and durably. An empty cursor is not saved: the previous file
    /// (if any) stays, and replays from its tip.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let text: String = self
            .blocks
            .iter()
            .map(|(h, id)| format!("{h} {id}\n"))
            .collect();
        write_atomic(path, text.as_bytes())
    }
}

/// Replaces the file at `path` with `bytes` atomically and durably: write a temporary file,
/// fsync it, rename it over `path`, fsync the directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    // Make the rename itself durable.
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(height: u64) -> String {
        format!("{height:016x}{:048x}", 0xab)
    }

    #[test]
    fn round_trips_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trongrid.cursor");
        assert_eq!(Cursor::load(&path).unwrap(), None);

        let mut c = Cursor::default();
        for h in 100..103 {
            c.push(h, id(h));
        }
        c.save(&path).unwrap();
        let loaded = Cursor::load(&path).unwrap().unwrap();
        assert_eq!(loaded, c);
        assert_eq!(loaded.tip(), Some(&(102, id(102))));
        assert!(!loaded.is_truncated());
        // No temporary file is left behind.
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn keeps_depth_blocks_and_remembers_that_it_forgot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.cursor");
        let mut c = Cursor::default();
        for h in 0..DEPTH as u64 {
            c.push(h, id(h));
        }
        assert!(!c.is_truncated());
        c.push(DEPTH as u64, id(DEPTH as u64));
        assert!(c.is_truncated());
        assert_eq!(c.blocks.len(), DEPTH);
        assert_eq!(c.blocks.front().unwrap().0, 1);

        c.save(&path).unwrap();
        assert!(Cursor::load(&path).unwrap().unwrap().is_truncated());
    }

    #[test]
    fn an_empty_cursor_keeps_the_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.cursor");
        let mut c = Cursor::default();
        c.push(7, id(7));
        c.save(&path).unwrap();
        c.pop();
        c.save(&path).unwrap();
        assert_eq!(
            Cursor::load(&path).unwrap().unwrap().tip(),
            Some(&(7, id(7)))
        );
    }

    #[test]
    fn refuses_a_damaged_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.cursor");
        let gap = format!("5 {}\n7 {}\n", id(5), id(7));
        let too_long: String = (0..=DEPTH as u64)
            .map(|h| format!("{h} {}\n", id(h)))
            .collect();
        for text in [
            String::new(),
            "5\n".to_owned(),
            format!("x {}\n", id(5)),
            "5 nothex\n".to_owned(),
            gap,
            too_long,
        ] {
            fs::write(&path, &text).unwrap();
            let err = Cursor::load(&path).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{text:?}");
        }
    }
}
