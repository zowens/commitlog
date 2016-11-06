#![feature(test)]
// This is silly...
#![allow(unused_features)]

#[macro_use]
extern crate log;
extern crate crc;
extern crate memmap;
extern crate byteorder;
extern crate env_logger;

#[cfg(test)]
extern crate test;
#[cfg(test)]
extern crate rand;

use std::path::{Path, PathBuf};
use std::fs;
use std::io;

mod segment;
mod index;
#[cfg(test)]
mod testutil;

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
            index_max_bytes: 800_000,
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
        self.index_max_bytes = items * index::INDEX_ENTRY_BYTES;
        self
    }
}

pub struct CommitLog {
    active_segment: segment::Segment,
    active_index: index::Index,
    log_dir: PathBuf,
    options: LogOptions,
}

impl CommitLog {
    pub fn new<P>(log_dir: P, opts: LogOptions) -> io::Result<CommitLog>
        where P: AsRef<Path>
    {
        // TODO: figure out what's already been written to
        fs::create_dir_all(&log_dir).unwrap_or(());

        let owned_path = log_dir.as_ref().to_owned();
        info!("Opening log at path {:?}", owned_path.to_str());
        let seg = try!(segment::Segment::new(&owned_path, 0u64, opts.log_max_bytes));
        let ind = try!(index::Index::new(&owned_path, 0u64, opts.index_max_bytes));

        Ok(CommitLog {
            active_segment: seg,
            active_index: ind,
            log_dir: owned_path,
            options: opts,
        })
    }

    fn index_append(&mut self, offset: u64, pos: u32) -> Result<(), AppendError> {
        match self.active_index.append(offset, pos) {
            Ok(()) => Ok(()),
            Err(index::IndexWriteError::IndexFull) => {
                try!(self.active_index.set_readonly());
                self.active_index =
                    try!(index::Index::new(&self.log_dir, offset, self.options.index_max_bytes));
                self.index_append(offset, pos)
            }
            Err(index::IndexWriteError::OffsetLessThanBase) => unreachable!(),
        }
    }

    pub fn append(&mut self, payload: &[u8]) -> Result<Offset, AppendError> {
        let meta = match self.active_segment.append(payload) {
            Ok(meta) => {
                trace!("Successfully appended message {:?}", meta);
                meta
            }
            Err(segment::SegmentAppendError::LogFull) => {
                // close segment
                try!(self.active_segment.flush_sync());
                let next_offset = self.active_segment.next_offset();
                info!("Closing segment at offset {}", next_offset);
                self.active_segment = try!(segment::Segment::new(&self.log_dir,
                                                                 next_offset,
                                                                 self.options.log_max_bytes));

                // try again
                return self.append(payload);
            }
            Err(segment::SegmentAppendError::IoError(e)) => {
                return Err(AppendError::IoError(e));
            }
        };
        try!(self.index_append(meta.offset(), meta.file_pos()));
        Ok(Offset(meta.offset()))
    }

    pub fn flush(&mut self) -> io::Result<()> {
        try!(self.active_segment.flush_sync());
        self.active_index.flush_sync()
    }
}
