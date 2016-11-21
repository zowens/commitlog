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

mod segment;
mod index;
#[cfg(test)]
mod testutil;

use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use segment::*;
use index::*;


/// Offset of an appended log segment.
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct Offset(u64);

#[derive(Debug)]
pub enum AppendError {
    IoError(io::Error),
    NewIndexAppendError,
    NewSegmentAppendError,
}

impl From<io::Error> for AppendError {
    fn from(e: io::Error) -> AppendError {
        AppendError::IoError(e)
    }
}

/// Commit log options allow customization of the commit
/// log behavior.
#[derive(Clone, Debug)]
pub struct LogOptions {
    log_dir: PathBuf,
    log_max_bytes: usize,
    index_max_bytes: usize,
}

impl LogOptions {
    pub fn new<P>(log_dir: P) -> LogOptions
        where P: AsRef<Path>
    {
        LogOptions {
            log_dir: log_dir.as_ref().to_owned(),
            log_max_bytes: 100 * 1024 * 1024,
            index_max_bytes: 800_000,
        }
    }

    /// Bounds the size of a log segment to a number of bytes.
    #[inline]
    pub fn max_bytes_log(&mut self, bytes: usize) -> &mut LogOptions {
        self.log_max_bytes = bytes;
        self
    }

    /// Bounds the size of an individual memory-mapped index file.
    #[inline]
    pub fn max_index_items(&mut self, items: usize) -> &mut LogOptions {
        self.index_max_bytes = items * INDEX_ENTRY_BYTES;
        self
    }
}

/// The commit log is an append-only data structure that can be used in a variety
/// of use-cases, such as tracking sequences of events, logging transactions in a
/// local database, or replicated state machines.
///
/// This implementation of the commit log data structure uses log segments
/// that roll over at pre-defined maximum size boundaries. The messages appended
/// to the log have a unique, monotonically incrasing offset that can be used as
/// a pointer to a log entry.
///
/// The index of the commit log logically stores the offset to a position in the
/// log segment corresponding. The index and segments are separated, in that a
/// segment file does not necessarily correspond to one particular segment file,
/// it could contain file pointers to many index files. In addition, index files
/// are memory-mapped for efficient read and write access.
pub struct CommitLog {
    active_segment: Segment,
    active_index: Index,
    options: LogOptions,
}

impl CommitLog {
    pub fn new(opts: LogOptions) -> io::Result<CommitLog> {
        // TODO: figure out what's already been written to
        fs::create_dir_all(&opts.log_dir).unwrap_or(());

        info!("Opening log at path {:?}", &opts.log_dir.to_str());
        let seg = try!(Segment::new(&opts.log_dir, 0u64, opts.log_max_bytes));
        let ind = try!(Index::new(&opts.log_dir, 0u64, opts.index_max_bytes));

        Ok(CommitLog {
            active_segment: seg,
            active_index: ind,
            options: opts,
        })
    }

    /// Appends a log entry to the commit log. The offset of the appended entry
    /// is the result of the comutation.
    pub fn append(&mut self, payload: &[u8]) -> Result<Offset, AppendError> {
        // first write to the current segment
        let meta = try!(self.active_segment
            .append(payload)
            .or_else(|e| {
                match e {
                    // if the log is full, gracefully close the current segment
                    // and create new one starting from the new offset
                    SegmentAppendError::LogFull => {
                        try!(self.active_segment.flush_sync());
                        let next_offset = self.active_segment.next_offset();
                        info!("Closing active segment at offset {}", next_offset);
                        self.active_segment = try!(Segment::new(&self.options.log_dir,
                                                                next_offset,
                                                                self.options.log_max_bytes));

                        // try again, giving up if we have to
                        self.active_segment
                            .append(payload)
                            .map_err(|_| AppendError::NewIndexAppendError)
                    }
                    SegmentAppendError::IoError(e) => Err(AppendError::IoError(e)),
                }
            }));

        // write to the index
        try!(self.active_index
            .append(meta.offset(), meta.file_pos())
            .or_else(|e| {
                match e {
                    // if the index is full, close the current index and open a new index
                    IndexWriteError::IndexFull => {
                        try!(self.active_index.set_readonly());
                        self.active_index = try!(Index::new(&self.options.log_dir,
                                                            meta.offset(),
                                                            self.options.index_max_bytes));

                        // if the new index cannot append, we're out of luck
                        self.active_index
                            .append(meta.offset(), meta.file_pos())
                            .map_err(|_| AppendError::NewIndexAppendError)
                    }
                    IndexWriteError::OffsetLessThanBase => unreachable!(),
                }
            }));

        Ok(Offset(meta.offset()))
    }

    pub fn flush(&mut self) -> io::Result<()> {
        try!(self.active_segment.flush_sync());
        self.active_index.flush_sync()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::testutil::*;
    use std::fs;
    use std::collections::HashSet;

    #[test]
    pub fn append() {
        let dir = TestDir::new();
        let mut log = CommitLog::new(LogOptions::new(&dir)).unwrap();
        assert_eq!(log.append(b"123456").unwrap(), Offset(0));
        assert_eq!(log.append(b"abcdefg").unwrap(), Offset(1));
        assert_eq!(log.append(b"foobarbaz").unwrap(), Offset(2));
        assert_eq!(log.append(b"bing").unwrap(), Offset(3));
        log.flush().unwrap();
    }

    #[test]
    pub fn append_new_segment() {
        let dir = TestDir::new();
        let mut opts = LogOptions::new(&dir);
        opts.max_bytes_log(52);

        {
            let mut log = CommitLog::new(opts).unwrap();
            // first 2 entries fit (both 26 bytes with encoding)
            log.append(b"0123456789").unwrap();
            log.append(b"0123456789").unwrap();

            // this one should roll the log
            log.append(b"0123456789").unwrap();
            log.flush().unwrap();
        }

        let files = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path().file_name().unwrap().to_str().unwrap().to_string())
            .collect::<HashSet<String>>();

        let expected =
            ["00000000000000000000.index", "00000000000000000000.log", "00000000000000000002.log"]
                .iter()
                .cloned()
                .map(|s| s.to_string())
                .collect::<HashSet<String>>();

        assert_eq!(files.intersection(&expected).count(), 3);
    }

    #[test]
    pub fn append_new_index() {
        let dir = TestDir::new();
        let mut opts = LogOptions::new(&dir);
        opts.max_index_items(2);

        {
            let mut log = CommitLog::new(opts).unwrap();
            // first 2 entries fit
            log.append(b"0123456789").unwrap();
            log.append(b"0123456789").unwrap();

            // this one should roll the index, but not the segment
            log.append(b"0123456789").unwrap();
            log.flush().unwrap();
        }

        let files = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path().file_name().unwrap().to_str().unwrap().to_string())
            .collect::<HashSet<String>>();

        let expected = ["00000000000000000000.index",
                        "00000000000000000000.log",
                        "00000000000000000002.index"]
            .iter()
            .cloned()
            .map(|s| s.to_string())
            .collect::<HashSet<String>>();

        assert_eq!(files.intersection(&expected).count(), 3);
    }
}
