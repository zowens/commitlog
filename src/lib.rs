//! The commit log is an append-only data structure that can be used in a variety
//! of use-cases, such as tracking sequences of events, transactions
//! or replicated state machines.
//!
//! This implementation of the commit log data structure uses log segments
//! that roll over at pre-defined maximum size boundaries. The messages appended
//! to the log have a unique, monotonically increasing offset that can be used as
//! a pointer to a log entry.
//!
//! The index of the commit log logically stores the offset to a position in a
//! log segment. The index and segments are separated, in that a
//! segment file does not necessarily correspond to one particular segment file,
//! it could contain file pointers to many segment files. In addition, index files
//! are memory-mapped for efficient read and write access.
//!
//! ## Example
//!
//! ```rust,ignore
//! extern crate commitlog;
//!
//! use commitlog::*;
//!
//! fn main() {
//!     // open a directory called 'log' for segment and index storage
//!     let opts = LogOptions::new("log");
//!     let mut log = CommitLog::new(opts).unwrap();
//!
//!     // append to the log
//!     log.append_msg("hello world").unwrap(); // offset 0
//!     log.append_msg("second message").unwrap(); // offset 1
//!
//!     // read the messages
//!     let messages = log.read(0, ReadLimit::default()).unwrap();
//!     for msg in messages {
//!         println!("{} - {}", msg.offset(), String::from_utf8_lossy(msg.payload()));
//!     }
//!
//!     // prints:
//!     //    0 - hello world
//!     //    1 - second message
//! }
//! ```
#![feature(test, collections_bound, step_by)]
// (for test) This is silly...
#![allow(unused_features, unknown_lints)]

extern crate byteorder;
extern crate crc32c;
#[macro_use]
extern crate log;
extern crate memmap;

#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
extern crate rand;
#[cfg(test)]
extern crate test;

mod file_set;
mod index;
pub mod message;
pub mod reader;
mod segment;
#[cfg(test)]
mod testutil;

use index::*;
use segment::SegmentAppendError;
use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::iter::{DoubleEndedIterator, ExactSizeIterator};
use std::path::{Path, PathBuf};

use file_set::FileSet;
use message::MessageError;
use message::{MessageBuf, MessageSetMut};
use reader::{LogSliceReader, MessageBufReader};

/// Offset of an appended log segment.
pub type Offset = u64;

/// Offset range of log append.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OffsetRange(u64, usize);

impl OffsetRange {
    /// Starting offset of the range.
    pub fn first(&self) -> Offset {
        self.0
    }

    /// Number of offsets within the range.
    pub fn len(&self) -> usize {
        self.1
    }

    /// Boolean indicating whether the range has offsets.
    pub fn is_empty(&self) -> bool {
        self.1 == 0
    }

    /// Iterator containing all offsets within the offset range.
    pub fn iter(&self) -> OffsetRangeIter {
        OffsetRangeIter {
            pos: self.0,
            end: self.0 + (self.1 as u64),
            size: self.1,
        }
    }
}

/// Iterator of offsets within an `OffsetRange`.
pub struct OffsetRangeIter {
    pos: u64,
    end: u64,
    size: usize,
}

impl Iterator for OffsetRangeIter {
    type Item = Offset;
    fn next(&mut self) -> Option<Offset> {
        if self.pos >= self.end {
            None
        } else {
            let v = self.pos;
            self.pos += 1;
            Some(v)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.size))
    }
}

impl ExactSizeIterator for OffsetRangeIter {
    fn len(&self) -> usize {
        self.size
    }
}

impl DoubleEndedIterator for OffsetRangeIter {
    fn next_back(&mut self) -> Option<Offset> {
        if self.pos >= self.end {
            None
        } else {
            let v = self.end - 1;
            self.end -= 1;
            Some(v)
        }
    }
}

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
    /// If a message that is larger than the per message size is tried to be appended
    /// it will not be allowed an will return an error
    MessageSizeExceeded,
}

impl From<io::Error> for AppendError {
    fn from(e: io::Error) -> AppendError {
        AppendError::Io(e)
    }
}

impl error::Error for AppendError {
    fn description(&self) -> &str {
        match *self {
            AppendError::Io(_) => "File IO error occurred while appending to the log",
            AppendError::FreshIndexNotWritable => {
                "While attempting to create a new index, the new index was not writabe"
            }
            AppendError::FreshSegmentNotWritable => {
                "While attempting to create a new segment, the new segment was not writabe"
            }
            AppendError::MessageSizeExceeded => {
                "While attempting to write a message, the per message size was exceeded"
            }
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            AppendError::Io(ref e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for AppendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AppendError::Io(_) => write!(f, "IO Error"),
            AppendError::FreshIndexNotWritable => write!(f, "Fresh index error"),
            AppendError::FreshSegmentNotWritable => write!(f, "Fresh segment error"),
            AppendError::MessageSizeExceeded => write!(f, "Message Size exceeded error"),
        }
    }
}

/// Error enum for commit log read operation.
#[derive(Debug)]
pub enum ReadError {
    /// Underlying IO error encountered by reading from the log
    Io(io::Error),
    /// A segment in the log is corrupt, or the index itself is corrupt
    CorruptLog,
    /// Offset supplied was not invalid.
    NoSuchSegment,
}

/// Batch size limitation on read.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Ord, PartialOrd)]
pub struct ReadLimit(usize);
impl ReadLimit {
    /// Read limit byte number of bytes.
    pub fn max_bytes(n: usize) -> ReadLimit {
        ReadLimit(n)
    }
}

impl Default for ReadLimit {
    fn default() -> ReadLimit {
        // 8kb default
        ReadLimit(8 * 1024)
    }
}

impl error::Error for ReadError {
    fn description(&self) -> &str {
        match *self {
            ReadError::Io(_) => "File IO error occurred while reading to the log",
            ReadError::CorruptLog => "Corrupt log segment has been detected",
            ReadError::NoSuchSegment => "The offset requested does not exist in the log",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ReadError::Io(ref e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReadError::Io(_) => write!(f, "IO Error"),
            ReadError::CorruptLog => write!(f, "Corrupt Log Error"),
            ReadError::NoSuchSegment => write!(f, "Offset does not exist"),
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> ReadError {
        ReadError::Io(e)
    }
}

impl From<MessageError> for ReadError {
    fn from(e: MessageError) -> ReadError {
        match e {
            MessageError::IoError(e) => ReadError::Io(e),
            MessageError::InvalidHash | MessageError::InvalidPayloadLength => ReadError::CorruptLog,
        }
    }
}

impl From<RangeFindError> for ReadError {
    fn from(e: RangeFindError) -> ReadError {
        match e {
            RangeFindError::OffsetNotAppended => ReadError::NoSuchSegment,
            RangeFindError::MessageExceededMaxBytes => ReadError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Message exceeded max byte size",
            )),
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
    message_max_bytes: usize,
}

impl LogOptions {
    /// Creates minimal log options value with a directory containing the log.
    ///
    /// The default values are:
    /// - *segment_max_bytes*: 1GB
    /// - *index_max_entries*: 100,000
    /// - *message_max_bytes*: 1mb
    pub fn new<P>(log_dir: P) -> LogOptions
    where
        P: AsRef<Path>,
    {
        LogOptions {
            log_dir: log_dir.as_ref().to_owned(),
            log_max_bytes: 1_000_000_000,
            index_max_bytes: 800_000,
            message_max_bytes: 1_000_000,
        }
    }

    /// Bounds the size of a log segment to a number of bytes.
    #[inline]
    pub fn segment_max_bytes(&mut self, bytes: usize) -> &mut LogOptions {
        self.log_max_bytes = bytes;
        self
    }

    /// Bounds the size of an individual memory-mapped index file.
    #[inline]
    pub fn index_max_items(&mut self, items: usize) -> &mut LogOptions {
        // TODO: this should be renamed to starting bytes
        self.index_max_bytes = items * INDEX_ENTRY_BYTES;
        self
    }

    /// Bounds the size of a message to a number of bytes.
    #[inline]
    pub fn message_max_bytes(&mut self, bytes: usize) -> &mut LogOptions {
        self.message_max_bytes = bytes;
        self
    }
}

/// The commit log is an append-only sequence of messages.
pub struct CommitLog {
    file_set: FileSet,
}

impl CommitLog {
    /// Creates or opens an existing commit log.
    pub fn new(opts: LogOptions) -> io::Result<CommitLog> {
        fs::create_dir_all(&opts.log_dir).unwrap_or(());

        info!("Opening log in directory {:?}", &opts.log_dir.to_str());

        let fs = FileSet::load_log(opts)?;
        Ok(CommitLog { file_set: fs })
    }

    /// Appends a single message to the log, returning the offset appended.
    pub fn append_msg<B: AsRef<[u8]>>(&mut self, payload: B) -> Result<Offset, AppendError> {
        let mut buf = MessageBuf::default();
        buf.push(payload);
        let res = self.append(&mut buf)?;
        assert_eq!(res.len(), 1);
        Ok(res.first())
    }

    /// Appends log entrites to the commit log, returning the offsets appended.
    pub fn append<T>(&mut self, buf: &mut T) -> Result<OffsetRange, AppendError>
    where
        T: MessageSetMut,
    {
        //Check if given message exceeded the max size
        if buf.bytes().len() > self.file_set.log_options().message_max_bytes {
            return Err(AppendError::MessageSizeExceeded);
        }

        // first write to the current segment
        let start_off = self.file_set.active_index_mut().next_offset();
        let entry_res = self.file_set.active_segment_mut().append(buf, start_off);
        let entries = entry_res.or_else(|e| {
            match e {
                // if the log is full, gracefully close the current segment
                // and create new one starting from the new offset
                SegmentAppendError::LogFull => {
                    try!(self.file_set.roll_segment());

                    // try again, giving up if we have to
                    self.file_set
                        .active_segment_mut()
                        .append(buf, start_off)
                        .map_err(|_| AppendError::FreshSegmentNotWritable)
                }
                SegmentAppendError::IoError(e) => Err(AppendError::Io(e)),
            }
        })?;

        // write to the index
        {
            let index = self.file_set.active_index_mut();
            let mut index_pos_buf = IndexBuf::new(entries.len(), index.starting_offset());
            for meta in &entries {
                index_pos_buf.push(meta.offset, meta.file_pos);
            }
            // TODO: what happens when this errors out? Do we truncate the log...?
            index.append(index_pos_buf)?;
        }

        // TODO: fix this with Option?
        match entries.first() {
            Some(v) => Ok(OffsetRange(v.offset, entries.len())),
            None => Ok(OffsetRange(start_off, 0)),
        }
    }

    /// Gets the last written offset.
    pub fn last_offset(&self) -> Option<Offset> {
        let next_off = self.file_set.active_index().next_offset();
        if next_off == 0 {
            None
        } else {
            Some(next_off - 1)
        }
    }

    /// Reads a portion of the log, starting with the `start` offset, inclusive, up to the limit.
    #[inline]
    pub fn read(&self, start: Offset, limit: ReadLimit) -> Result<MessageBuf, ReadError> {
        let mut rd = MessageBufReader;
        self.reader(&mut rd, start, limit)
    }

    /// Reads a portion of the log, starting with the `start` offset, inclusive, up to the limit
    /// via the reader.
    pub fn reader<R: LogSliceReader>(
        &self,
        reader: &mut R,
        start: Offset,
        limit: ReadLimit,
    ) -> Result<R::Result, ReadError> {
        // TODO: can this be caught at the index level insead?
        if start >= self.file_set.active_index().next_offset() {
            return Ok(R::empty());
        }

        let max_bytes = limit.0 as u32;

        // find the correct segment
        let &(ref ind, ref seg) = match self.file_set.find(start) {
            Some(v) => v,
            None => {
                warn!("No segment found for offset {}", start);
                return Err(ReadError::NoSuchSegment);
            }
        };

        let seg_bytes = seg.size() as u32;

        // grab the range from the contained index
        let range = ind.find_segment_range(start, max_bytes, seg_bytes)?;
        Ok(seg.read_slice(reader, range.file_position(), range.bytes())?)
    }

    /// Truncates a file after the offset supplied. The resulting log will contain
    /// entries up to the offset.
    pub fn truncate(&mut self, offset: Offset) -> io::Result<()> {
        info!("Truncating log to offset {}", offset);

        // remove index/segment files rolled after the offset
        let to_remove = self.file_set.take_after(offset);
        for p in to_remove {
            trace!(
                "Removing segment and index starting at {}",
                p.0.starting_offset()
            );
            assert!(p.0.starting_offset() > offset);

            p.0.remove()?;
            p.1.remove()?;
        }

        // truncate the current index
        match self.file_set.active_index_mut().truncate(offset) {
            Some(len) => self.file_set.active_segment_mut().truncate(len),
            // index outside of appended range
            None => Ok(()),
        }
    }

    /// Forces a flush of the log.
    pub fn flush(&mut self) -> io::Result<()> {
        self.file_set.active_segment_mut().flush_sync()?;
        self.file_set.active_index_mut().flush_sync()
    }
}

#[cfg(test)]
mod tests {
    use super::message::*;
    use super::testutil::*;
    use super::*;
    use env_logger;
    use std::collections::HashSet;
    use std::fs;

    #[test]
    pub fn offset_range() {
        let range = OffsetRange(2, 6);

        assert_eq!(vec![2, 3, 4, 5, 6, 7], range.iter().collect::<Vec<u64>>());

        assert_eq!(
            vec![7, 6, 5, 4, 3, 2],
            range.iter().rev().collect::<Vec<u64>>()
        );
    }

    #[test]
    pub fn append() {
        let dir = TestDir::new();
        let mut log = CommitLog::new(LogOptions::new(&dir)).unwrap();
        assert_eq!(log.append_msg("123456").unwrap(), 0);
        assert_eq!(log.append_msg("abcdefg").unwrap(), 1);
        assert_eq!(log.append_msg("foobarbaz").unwrap(), 2);
        assert_eq!(log.append_msg("bing").unwrap(), 3);
        log.flush().unwrap();
    }

    #[test]
    pub fn append_multiple() {
        let dir = TestDir::new();
        let mut log = CommitLog::new(LogOptions::new(&dir)).unwrap();
        let mut buf = {
            let mut buf = MessageBuf::default();
            buf.push(b"123456");
            buf.push(b"789012");
            buf.push(b"345678");
            buf
        };
        let range = log.append(&mut buf).unwrap();
        assert_eq!(0, range.first());
        assert_eq!(3, range.len());
        assert_eq!(vec![0, 1, 2], range.iter().collect::<Vec<u64>>());
    }

    #[test]
    pub fn append_new_segment() {
        let dir = TestDir::new();
        let mut opts = LogOptions::new(&dir);
        opts.segment_max_bytes(62);

        {
            let mut log = CommitLog::new(opts).unwrap();
            // first 2 entries fit (both 30 bytes with encoding)
            log.append_msg("0123456789").unwrap();
            log.append_msg("0123456789").unwrap();

            // this one should roll the log
            log.append_msg("0123456789").unwrap();
            log.flush().unwrap();
        }

        expect_files(
            &dir,
            vec![
                "00000000000000000000.index",
                "00000000000000000000.log",
                "00000000000000000002.log",
                "00000000000000000002.index",
            ],
        );
    }

    #[test]
    pub fn read_entries() {
        env_logger::try_init().unwrap_or(());

        let dir = TestDir::new();
        let mut opts = LogOptions::new(&dir);
        opts.index_max_items(20);
        opts.segment_max_bytes(1000);
        let mut log = CommitLog::new(opts).unwrap();

        for i in 0..100 {
            let s = format!("-data {}", i);
            log.append_msg(s.as_str()).unwrap();
        }
        log.flush().unwrap();

        {
            let active_index_read = log.read(82, ReadLimit::max_bytes(168)).unwrap();
            assert_eq!(6, active_index_read.len());
            assert_eq!(
                vec![82, 83, 84, 85, 86, 87],
                active_index_read
                    .iter()
                    .map(|v| v.offset())
                    .collect::<Vec<_>>()
            );
        }

        {
            let old_index_read = log.read(5, ReadLimit::max_bytes(112)).unwrap();
            assert_eq!(4, old_index_read.len());
            assert_eq!(
                vec![5, 6, 7, 8],
                old_index_read
                    .iter()
                    .map(|v| v.offset())
                    .collect::<Vec<_>>()
            );
        }

        // read at the boundary (not going to get full message limit)
        {
            // log rolls at offset 36
            let boundary_read = log.read(33, ReadLimit::max_bytes(100)).unwrap();
            assert_eq!(3, boundary_read.len());
            assert_eq!(
                vec![33, 34, 35],
                boundary_read.iter().map(|v| v.offset()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    pub fn reopen_log() {
        env_logger::try_init().unwrap_or(());

        let dir = TestDir::new();
        let mut opts = LogOptions::new(&dir);
        opts.index_max_items(20);
        opts.segment_max_bytes(1000);

        {
            let mut log = CommitLog::new(opts.clone()).unwrap();

            for i in 0..99 {
                let s = format!("some data {}", i);
                let off = log.append_msg(s.as_str()).unwrap();
                assert_eq!(i, off);
            }
            log.flush().unwrap();
        }

        {
            let mut log = CommitLog::new(opts).unwrap();

            let active_index_read = log.read(82, ReadLimit::max_bytes(130)).unwrap();

            assert_eq!(4, active_index_read.len());
            assert_eq!(
                vec![82, 83, 84, 85],
                active_index_read
                    .iter()
                    .map(|v| v.offset())
                    .collect::<Vec<_>>()
            );

            let off = log.append_msg("moar data").unwrap();
            assert_eq!(99, off);
        }
    }

    #[test]
    pub fn reopen_log_without_segment_write() {
        env_logger::try_init().unwrap_or(());

        let dir = TestDir::new();
        let mut opts = LogOptions::new(&dir);
        opts.index_max_items(20);
        opts.segment_max_bytes(1000);

        {
            let mut log = CommitLog::new(opts.clone()).unwrap();
            log.flush().unwrap();
        }

        {
            CommitLog::new(opts.clone()).expect("Should be able to reopen log without writes");
        }

        {
            CommitLog::new(opts).expect("Should be able to reopen log without writes");
        }
    }

    #[test]
    pub fn append_message_greater_than_max() {
        let dir = TestDir::new();
        let mut log = CommitLog::new(LogOptions::new(&dir)).unwrap();
        //create vector with 1.2mb of size, u8 = 1 byte thus,
        //1mb = 1000000 bytes, 1200000 items needed
        let mut value = String::new();
        let mut target = 0;
        while target != 2000000 {
            value.push_str("a");
            target += 1;
        }
        let res = log.append_msg(value);
        //will fail if no error is found which means a message greater than the limit passed through
        assert!(res.is_err());
        log.flush().unwrap();
    }

    #[test]
    pub fn truncate_from_active() {
        let dir = TestDir::new();
        let mut log = CommitLog::new(LogOptions::new(&dir)).unwrap();

        // append 5 messages
        {
            let mut buf = MessageBuf::default();
            buf.push(b"123456");
            buf.push(b"789012");
            buf.push(b"345678");
            buf.push(b"aaaaaa");
            buf.push(b"bbbbbb");
            log.append(&mut buf).unwrap();
        }

        // truncate to offset 2 (should remove 2 messages)
        log.truncate(2).expect("Unable to truncate file");

        assert_eq!(Some(2), log.last_offset());
    }

    #[test]
    pub fn truncate_after_offset_removes_segments() {
        env_logger::try_init().unwrap_or(());
        let dir = TestDir::new();

        let mut opts = LogOptions::new(&dir);
        opts.index_max_items(20);
        opts.segment_max_bytes(52);
        let mut log = CommitLog::new(opts).unwrap();

        // append 6 messages (4 segments)
        {
            for _ in 0..7 {
                log.append_msg(b"12345").unwrap();
            }
        }

        // ensure we have the expected index/logs
        expect_files(
            &dir,
            vec![
                "00000000000000000000.index",
                "00000000000000000000.log",
                "00000000000000000002.log",
                "00000000000000000002.index",
                "00000000000000000004.log",
                "00000000000000000004.index",
                "00000000000000000006.log",
                "00000000000000000006.index",
            ],
        );

        // truncate to offset 2 (should remove 2 messages)
        log.truncate(3).expect("Unable to truncate file");

        assert_eq!(Some(3), log.last_offset());

        // ensure we have the expected index/logs
        expect_files(
            &dir,
            vec![
                "00000000000000000000.index",
                "00000000000000000000.log",
                "00000000000000000002.log",
                "00000000000000000002.index",
            ],
        );
    }

    #[test]
    pub fn truncate_at_segment_boundary_removes_segments() {
        env_logger::try_init().unwrap_or(());
        let dir = TestDir::new();

        let mut opts = LogOptions::new(&dir);
        opts.index_max_items(20);
        opts.segment_max_bytes(52);
        let mut log = CommitLog::new(opts).unwrap();

        // append 6 messages (4 segments)
        {
            for _ in 0..7 {
                log.append_msg(b"12345").unwrap();
            }
        }

        // ensure we have the expected index/logs
        expect_files(
            &dir,
            vec![
                "00000000000000000000.index",
                "00000000000000000000.log",
                "00000000000000000002.log",
                "00000000000000000002.index",
                "00000000000000000004.log",
                "00000000000000000004.index",
                "00000000000000000006.log",
                "00000000000000000006.index",
            ],
        );

        // truncate to offset 2 (should remove 2 messages)
        log.truncate(2).expect("Unable to truncate file");

        assert_eq!(Some(2), log.last_offset());

        // ensure we have the expected index/logs
        expect_files(
            &dir,
            vec![
                "00000000000000000000.index",
                "00000000000000000000.log",
                "00000000000000000002.log",
                "00000000000000000002.index",
            ],
        );
    }

    #[test]
    pub fn truncate_after_last_append_does_nothing() {
        env_logger::try_init().unwrap_or(());
        let dir = TestDir::new();

        let mut opts = LogOptions::new(&dir);
        opts.index_max_items(20);
        opts.segment_max_bytes(52);
        let mut log = CommitLog::new(opts).unwrap();

        // append 6 messages (4 segments)
        {
            for _ in 0..7 {
                log.append_msg(b"12345").unwrap();
            }
        }

        // ensure we have the expected index/logs
        expect_files(
            &dir,
            vec![
                "00000000000000000000.index",
                "00000000000000000000.log",
                "00000000000000000002.log",
                "00000000000000000002.index",
                "00000000000000000004.log",
                "00000000000000000004.index",
                "00000000000000000006.log",
                "00000000000000000006.index",
            ],
        );

        // truncate to offset 2 (should remove 2 messages)
        log.truncate(7).expect("Unable to truncate file");

        assert_eq!(Some(6), log.last_offset());

        // ensure we have the expected index/logs
        expect_files(
            &dir,
            vec![
                "00000000000000000000.index",
                "00000000000000000000.log",
                "00000000000000000002.log",
                "00000000000000000002.index",
                "00000000000000000004.log",
                "00000000000000000004.index",
                "00000000000000000006.log",
                "00000000000000000006.index",
            ],
        );
    }

    fn expect_files<P: AsRef<Path>, I>(dir: P, files: I)
    where
        I: IntoIterator<Item = &'static str>,
    {
        let dir_files = fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect::<HashSet<String>>();
        let expected = files
            .into_iter()
            .map(|s| s.to_string())
            .collect::<HashSet<String>>();
        assert_eq!(
            dir_files.len(),
            expected.len(),
            "Invalid file count, expected {:?} got {:?}",
            expected,
            dir_files
        );
        assert_eq!(
            dir_files.intersection(&expected).count(),
            expected.len(),
            "Invalid file count, expected {:?} got {:?}",
            expected,
            dir_files
        );
    }
}
