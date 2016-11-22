#![feature(test, btree_range, collections_bound)]

// (for test) This is silly...
#![allow(unused_features)]

#[macro_use]
extern crate log;
extern crate crc;
extern crate memmap;
extern crate byteorder;

#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
extern crate test;
#[cfg(test)]
extern crate rand;

mod segment;
mod index;
#[cfg(test)]
mod testutil;

use std::collections::{Bound, BTreeMap};
use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::mem::swap;
use segment::{Segment, SegmentAppendError};
use index::*;

pub use segment::ReadLimit;
pub use segment::Message;


/// Offset of an appended log segment.
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct Offset(pub u64);

/// Error enum for commit log Append operation.
#[derive(Debug)]
pub enum AppendError {
    /// The underlying file operations failed during the append attempt.
    Io(io::Error),
    /// A new index was created, but was unable to receive writes
    /// during the append operation. This could point to exhaustion
    /// of machine resources or other I/O issue.
    FreshIndexNotWritable,
    /// A new segment was created, but was unable to receive writes
    /// during the append operation. This could point to exhaustion
    /// of machine resources or other I/O issue.
    FreshSegmentNotWritable,
}

impl From<io::Error> for AppendError {
    fn from(e: io::Error) -> AppendError {
        AppendError::Io(e)
    }
}


/// Starting location of a read
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum ReadPosition {
    /// Start reading from the initial offset
    Beginning,
    /// Start reading from a specified offset
    Offset(Offset), // TODO: particular pointer
}

/// Error enum for commit log read operation.
#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    CorruptLog,
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> ReadError {
        ReadError::Io(e)
    }
}

impl From<segment::MessageError> for ReadError {
    fn from(e: segment::MessageError) -> ReadError {
        match e {
            segment::MessageError::IoError(e) => ReadError::Io(e),
            segment::MessageError::InvalidCRC => ReadError::CorruptLog,
        }
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
    /// Creates minimal LogOptions with a directory containing the log.
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
/// of use-cases, such as tracking sequences of events, transactions
/// or replicated state machines.
///
/// This implementation of the commit log data structure uses log segments
/// that roll over at pre-defined maximum size boundaries. The messages appended
/// to the log have a unique, monotonically increasing offset that can be used as
/// a pointer to a log entry.
///
/// The index of the commit log logically stores the offset to a position in the
/// log segment corresponding. The index and segments are separated, in that a
/// segment file does not necessarily correspond to one particular segment file,
/// it could contain file pointers to many segment files. In addition, index files
/// are memory-mapped for efficient read and write access.
pub struct CommitLog {
    closed_segments: BTreeMap<u64, Segment>,
    closed_indexes: BTreeMap<u64, Index>,

    active_segment: Segment,
    active_index: Index,
    options: LogOptions,
}

impl CommitLog {
    pub fn new(opts: LogOptions) -> io::Result<CommitLog> {
        // TODO: figure out what's already been written to
        fs::create_dir_all(&opts.log_dir).unwrap_or(());

        info!("Opening log at path {:?}", &opts.log_dir.to_str());
        let seg = Segment::new(&opts.log_dir, 0u64, opts.log_max_bytes)?;
        let ind = Index::new(&opts.log_dir, 0u64, opts.index_max_bytes)?;

        Ok(CommitLog {
            closed_segments: BTreeMap::new(),
            closed_indexes: BTreeMap::new(),

            active_segment: seg,
            active_index: ind,
            options: opts,
        })
    }

    /// Appends a log entry to the commit log, returning the offset of the appended entry.
    pub fn append(&mut self, payload: &[u8]) -> Result<Offset, AppendError> {
        // first write to the current segment
        let meta = self.active_segment
            .append(payload)
            .or_else(|e| {
                match e {
                    // if the log is full, gracefully close the current segment
                    // and create new one starting from the new offset
                    SegmentAppendError::LogFull => {
                        self.active_segment.flush_sync()?;
                        let next_offset = self.active_segment.next_offset();

                        info!("Starting new segment at offset {}", next_offset);

                        let mut seg = Segment::new(&self.options.log_dir,
                                                   next_offset,
                                                   self.options.log_max_bytes)?;


                        // set the active segment to the new segment,
                        // swap in order to insert the segment into
                        // the closed segments tree
                        swap(&mut seg, &mut self.active_segment);
                        self.closed_segments.insert(seg.starting_offset(), seg);


                        // try again, giving up if we have to
                        self.active_segment
                            .append(payload)
                            .map_err(|_| AppendError::FreshSegmentNotWritable)
                    }
                    SegmentAppendError::IoError(e) => Err(AppendError::Io(e)),
                }
            })?;

        // write to the index
        self.active_index
            .append(meta.offset(), meta.file_pos())
            .or_else(|e| {
                match e {
                    // if the index is full, close the current index and open a new index
                    IndexWriteError::IndexFull => {
                        info!("Starting new index at offset {}", meta.offset());

                        try!(self.active_index.set_readonly());
                        let mut ind = try!(Index::new(&self.options.log_dir,
                                                      meta.offset(),
                                                      self.options.index_max_bytes));

                        // set the active index to the new index,
                        // swap in order to insert the index into
                        // the closed index tree
                        swap(&mut ind, &mut self.active_index);
                        self.closed_indexes.insert(ind.starting_offset(), ind);

                        // if the new index cannot append, we're out of luck
                        self.active_index
                            .append(meta.offset(), meta.file_pos())
                            .map_err(|_| AppendError::FreshIndexNotWritable)
                    }
                    IndexWriteError::OffsetLessThanBase => unreachable!(),
                }
            })?;

        Ok(Offset(meta.offset()))
    }

    pub fn read(&mut self,
                start: ReadPosition,
                limit: ReadLimit)
                -> Result<Vec<Message>, ReadError> {
        let start_off = match start {
            ReadPosition::Beginning => 0,
            ReadPosition::Offset(Offset(v)) => v,
        };

        // TODO: change index find to be >= to offset

        // find the file position from the index
        let active_start_off = self.active_index.starting_offset();
        let index_entry_res = if start_off >= active_start_off {
            trace!("Reading offset {} from active index", start_off);
            self.active_index.find(start_off)
        } else {
            trace!("Reading offset {} from old index", start_off);
            let found_index = self.closed_indexes
                .range(Bound::Unbounded, Bound::Included(&start_off))
                .next_back();
            found_index.and_then(|(_, i)| i.find(start_off))
        };

        let file_pos = match index_entry_res {
            Some(e) => e.file_position(),
            None => {
                info!("No index entry found for {}", start_off);
                return Ok(Vec::with_capacity(0));
            }
        };

        // find the correct segment and read the log entry
        let active_seg_start_off = self.active_segment.starting_offset();

        if start_off >= active_seg_start_off {
            trace!("Reading from active index at file pos {}", file_pos);
            Ok(self.active_segment.read(file_pos, limit)?)
        } else {
            let mut r = self.closed_segments
                .range_mut(Bound::Unbounded, Bound::Included(&start_off));
            match r.next_back() {
                Some((_, ref mut s)) => {
                    trace!("Reading messages from old index at file pos {}", file_pos);
                    Ok(s.read(file_pos, limit)?)
                }
                _ => {
                    warn!("No segment found for offset {}", start_off);
                    Ok(Vec::with_capacity(0))
                }
            }
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.active_segment.flush_sync()?;
        self.active_index.flush_sync()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::testutil::*;
    use std::fs;
    use std::collections::HashSet;
    use env_logger;

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

    #[test]
    pub fn read_entries() {
        env_logger::init().unwrap();

        let dir = TestDir::new();
        let mut opts = LogOptions::new(&dir);
        opts.max_index_items(20);
        opts.max_bytes_log(1000);
        let mut log = CommitLog::new(opts).unwrap();

        for i in 0..100 {
            let s = format!("some data {}", i);
            log.append(s.as_bytes()).unwrap();
        }
        log.flush().unwrap();

        {
            let active_index_read =
                log.read(ReadPosition::Offset(Offset(82)), ReadLimit::Messages(5)).unwrap();
            assert_eq!(5, active_index_read.len());
            assert_eq!(vec![82, 83, 84, 85, 86],
                       active_index_read.into_iter().map(|v| v.offset()).collect::<Vec<_>>());
        }

        {
            let old_index_read = log.read(ReadPosition::Offset(Offset(5)), ReadLimit::Messages(5))
                .unwrap();
            assert_eq!(5, old_index_read.len());
            assert_eq!(vec![5, 6, 7, 8, 9],
                       old_index_read.into_iter().map(|v| v.offset()).collect::<Vec<_>>());
        }

        // read at the boundary (not going to get full message limit)
        {
            // log rolls at offset 36
            let boundary_read = log.read(ReadPosition::Offset(Offset(33)), ReadLimit::Messages(5))
                .unwrap();
            assert_eq!(3, boundary_read.len());
            assert_eq!(vec![33, 34, 35],
                       boundary_read.into_iter().map(|v| v.offset()).collect::<Vec<_>>());
        }

    }
}
