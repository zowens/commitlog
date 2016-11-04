#![feature(test)]
#[macro_use] extern crate log;
extern crate crc;
extern crate memmap;
extern crate byteorder;
extern crate env_logger;

#[cfg(test)] extern crate test;
#[cfg(test)] extern crate rand;

use log::LogLevel;
use std::path::{Path, PathBuf};
use std::fs;
use std::io;

mod segment;

pub struct Offset(u64);

#[derive(Debug)]
pub enum AppendError {
    IoError(io::Error),
    FileError,
}

impl From<io::Error> for AppendError {
    fn from(e: io::Error) -> AppendError {
        AppendError::IoError(e)
    }
}

pub struct LogOptions {
    log_max_bytes: usize,
    index_max_bytes: usize,
}

impl Default for LogOptions {
    fn default() -> LogOptions {
        LogOptions {
            log_max_bytes: 100 * 1024 * 1024,
            index_max_bytes: 10 * 1024 * 1024,
        }
    }

}

impl LogOptions {
    #[inline]
    pub fn max_bytes_log(&mut self, bytes: usize) -> &mut LogOptions {
        self.log_max_bytes = bytes;
        self
    }

    #[inline]
    pub fn max_log_items(&mut self, items: usize) -> &mut LogOptions {
        self.index_max_bytes = items * segment::INDEX_ENTRY_BYTES;
        self
    }
}

pub struct CommitLog {
    active_segment: segment::Segment,
    log_dir: PathBuf,
    options: LogOptions,
}

impl CommitLog {
    pub fn new<P>(log_dir: P, opts: LogOptions) -> io::Result<CommitLog>
        where P : AsRef<Path>
    {
        // TODO: figure out what's already been written to
        fs::create_dir_all(&log_dir).unwrap_or(());

        let owned_path = log_dir.as_ref().to_owned();
        info!("Opening log at path {:?}", owned_path.to_str());
        let seg = try!(segment::Segment::new(&owned_path, 0u64, opts.log_max_bytes, opts.index_max_bytes));
        Ok(CommitLog {
            active_segment: seg,
            log_dir: owned_path,
            options: opts,
        })
    }

    pub fn append(&mut self, payload: &[u8]) -> Result<Offset, AppendError> {
        match self.active_segment.append(payload) {
            Ok(offset) => {
                trace!("Successfully appended message at offset {}", offset);
                Ok(Offset(offset))
            },
            Err(segment::SegmentAppendError::LogFull) => {
                // close segment
                try!(self.active_segment.flush_sync());
                let next_offset = self.active_segment.next_offset();
                info!("Closing segment at offset {}", next_offset);
                self.active_segment = try!(segment::Segment::new(
                    &self.log_dir,
                    next_offset,
                    self.options.log_max_bytes,
                    self.options.index_max_bytes));

                // try again
                self.append(payload)
            },
            Err(segment::SegmentAppendError::IndexError(_)) => {
                // TODO: no idea
                Err(AppendError::FileError)
            },
            Err(segment::SegmentAppendError::IoError(e)) => Err(AppendError::IoError(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use test::*;
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use env_logger;
    use rand::{self, Rng};

    #[bench]
    fn benchmark_append(b: &mut test::Bencher) {
        let mut rng = rand::OsRng::new().unwrap();

        let mut path = PathBuf::new();
        path.push("target");
        path.push(format!("logbench{}", rng.gen::<u64>()));

        let mut log = CommitLog::new(&path, LogOptions::default()).unwrap();
        let msg = b"0123456789abcdefghijklmnopqrstuvwxyz";
        b.iter(|| {
            log.append(msg).unwrap();
        });

        fs::remove_dir_all(&path).unwrap();
    }
}
