use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use crc::crc32::checksum_ieee;
use memmap::{Mmap, Protection};
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, Write};
use std;

// TODO: ...
// pub type Offset(u64);


/// Messages are appended to the log with the following encoding:
///
/// +-----------+--------------+
/// | Bytes     | Value        |
/// +-----------+--------------+
/// | 0-7       | Offset       |
/// | 8-11      | Payload Size |
/// | 12-15     | CRC32 (IEEE) |
/// | 16+       | Payload      |
/// +-----------+--------------+
pub struct Message {
    bytes: Vec<u8>,
}

impl Message {
    pub fn new(payload: &[u8], offset: u64) -> Message {
        let mut bytes = vec![0; 16 + payload.len()];
        BigEndian::write_u64(&mut bytes[0..8], offset);
        BigEndian::write_u32(&mut bytes[8..12], payload.len() as u32);
        BigEndian::write_u32(&mut bytes[12..16], checksum_ieee(&payload));
        bytes[16..].copy_from_slice(payload);
        Message { bytes: bytes }
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    pub fn crc(&self) -> u32 {
        BigEndian::read_u32(&self.bytes[12..16])
    }

    #[inline]
    pub fn size(&self) -> u32 {
        BigEndian::read_u32(&self.bytes[8..12])
    }

    #[inline]
    pub fn offset(&self) -> u64 {
        BigEndian::read_u64(&self.bytes[0..8])
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[16..]
    }
}

/// An index is a file with pairs of relative offset to file position offset
/// messages. Both are stored as 4 bytes.
pub struct Index {
    file: File,
    mmap: Mmap,

    /// next starting byte in index file offset to write
    next_write_offset: usize,
    base_offset: u64,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct IndexEntry {
    rel_offset: u32,
    base_offset: u64,
    file_pos: u32,
}

impl IndexEntry {
    pub fn relative_offset(&self) -> u32 {
        self.rel_offset
    }

    #[inline]
    pub fn offset(&self) -> u64 {
        self.base_offset + (self.rel_offset as u64)
    }

    #[inline]
    pub fn file_position(&self) -> u32 {
        self.file_pos
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum IndexWriteError {
    IndexFull,
    OffsetLessThanBase,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum IndexReadError {
    OutOfBounds,
}

impl Index {
    pub fn new<P>(path: P, file_bytes: u64, base_offset: u64) -> io::Result<Index>
        where P: AsRef<Path>
    {
        // open the file, expecting to create it
        let index_file = try!(OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .open(path));

        // read the metadata and truncate
        let meta = try!(index_file.metadata());
        let len = meta.len();
        if len == 0 {
            try!(index_file.set_len(file_bytes));
        }

        let mmap = try!(Mmap::open(&index_file, Protection::ReadWrite));

        Ok(Index {
            file: index_file,
            mmap: mmap,
            next_write_offset: len as usize,
            base_offset: base_offset,
        })
    }

    #[inline]
    pub fn can_write(&self) -> bool {
        self.len() >= (self.next_write_offset + 8)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    pub fn append(&mut self, abs_offset: u64, position: u32) -> Result<(), IndexWriteError> {
        // TODO: test to ensure abs_offset is < last offset written (invariant of the index)
        if !self.can_write() {
            return Err(IndexWriteError::IndexFull);
        }

        if abs_offset < self.base_offset {
            return Err(IndexWriteError::OffsetLessThanBase);
        }

        unsafe {
            let mem_slice: &mut [u8] = self.mmap.as_mut_slice();
            let offset = (abs_offset - self.base_offset) as u32;
            let buf_pos = self.next_write_offset;

            BigEndian::write_u32(&mut mem_slice[buf_pos..buf_pos + 4], offset);
            BigEndian::write_u32(&mut mem_slice[buf_pos + 4..buf_pos + 8], position);

            self.next_write_offset += 8;

            Ok(())
        }
    }

    pub fn flush_sync(&mut self) -> io::Result<()> {
        try!(self.mmap.flush());
        self.file.flush()
    }

    pub fn read_entry(&self, i: usize) -> Result<Option<IndexEntry>, IndexReadError> {
        if self.len() < (i + 1) * 8 {
            return Err(IndexReadError::OutOfBounds);
        }

        unsafe {
            let mem_slice = self.mmap.as_slice();
            let start = i * 8;
            let offset = BigEndian::read_u32(&mem_slice[start..start + 4]);
            if offset == 0 && i > 0 {
                Ok(None)
            } else {
                let pos = BigEndian::read_u32(&mem_slice[start + 4..start + 8]);
                Ok(Some(IndexEntry {
                    rel_offset: offset,
                    base_offset: self.base_offset,
                    file_pos: pos,
                }))
            }
        }
    }
}

pub struct Log {
    f: File,
    max_bytes: usize,
    pos: usize,
}

#[derive(Debug)]
pub enum LogAppendError {
    LogFull,
    IoError(io::Error),
}

impl From<std::io::Error> for LogAppendError {
    #[inline]
    fn from(e: std::io::Error) -> LogAppendError {
        LogAppendError::IoError(e)
    }
}

impl Log {
    pub fn new<P>(p: P, max_bytes: usize) -> io::Result<Log>
        where P: AsRef<Path>
    {
        let f = try!(OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .append(true)
            .open(p));
        Ok(Log {
            f: f,
            max_bytes: max_bytes,
            pos: 0,
        })
    }

    pub fn can_write(&self) -> bool {
        self.pos < self.max_bytes
    }

    pub fn append(&mut self, msg: Message) -> Result<u32, LogAppendError> {
        // ensure we won't go over the max
        if msg.bytes().len() + self.pos > self.max_bytes {
            return Err(LogAppendError::LogFull);
        }

        try!(self.f.write_all(msg.bytes()));
        let write_pos = self.pos;
        self.pos += msg.bytes().len();
        Ok(write_pos as u32)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}

pub struct Segment {
    log: Log,
    index: Index,
    next_offset: u64,
}

#[derive(Debug)]
pub enum SegmentAppendError {
    LogFull,
    IndexError(IndexWriteError),
    IoError(io::Error),
}

impl From<io::Error> for SegmentAppendError {
    #[inline]
    fn from(e: io::Error) -> SegmentAppendError {
        SegmentAppendError::IoError(e)
    }
}

impl From<LogAppendError> for SegmentAppendError {
    #[inline]
    fn from(e: LogAppendError) -> SegmentAppendError {
        match e {
            LogAppendError::LogFull => SegmentAppendError::LogFull,
            LogAppendError::IoError(e) => SegmentAppendError::IoError(e),
        }
    }
}

impl From<IndexWriteError> for SegmentAppendError {
    #[inline]
    fn from(e: IndexWriteError) -> SegmentAppendError {
        SegmentAppendError::IndexError(e)
    }
}


impl Segment {
    // TODO: open variant for reading

    pub fn new<P>(log_dir: P,
                  base_offset: u64,
                  max_bytes: usize,
                  index_bytes: usize)
                  -> io::Result<Segment>
        where P: AsRef<Path>
    {
        let log = {
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", base_offset));
            path_buf.set_extension("log");
            try!(Log::new(&path_buf, max_bytes))
        };

        let index = {
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", base_offset));
            path_buf.set_extension("index");
            try!(Index::new(&path_buf, index_bytes as u64, base_offset))
        };

        Ok(Segment {
            log: log,
            index: index,
            next_offset: base_offset,
        })
    }

    #[inline]
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub fn append(&mut self, msg: &[u8]) -> Result<u64, SegmentAppendError> {
        if !self.index.can_write() || !self.log.can_write() {
            return Err(SegmentAppendError::LogFull);
        }

        let off = self.next_offset;
        let pos = try!(self.log.append(Message::new(msg, off)));
        try!(self.index.append(off, pos));

        self.next_offset += 1;
        Ok(off)
    }

    // TODO: async flush strategy
    pub fn flush_sync(&mut self) -> io::Result<()> {
        try!(self.index.flush_sync());
        self.log.flush()
    }
}


#[cfg(test)]
mod tests {
    use std::fs;
    use super::*;
    use test::Bencher;

    #[test]
    fn message_construction() {
        let msg = Message::new(b"123456789", 1234567u64);
        assert_eq!(msg.offset(), 1234567u64);
        assert_eq!(msg.payload(), b"123456789");
        assert_eq!(msg.crc(), 0xcbf43926);
        assert_eq!(msg.size(), 9u32);
    }

    #[test]
    fn index() {
        let index_path = "target/.test-index";

        // remove before running (may be around from failing test run)
        fs::remove_file(index_path).unwrap_or(());

        {
            let mut index = Index::new(index_path, 1000u64, 10u64).unwrap();
            assert_eq!(1000, index.len());
            index.append(11u64, 0xffff).unwrap();
            index.append(12u64, 0xeeee).unwrap();
            index.flush_sync().unwrap();
        }

        // reopen it for read
        {
            let index = Index::new(index_path, 1000u64, 10u64).unwrap();

            let e0 = index.read_entry(0).unwrap().unwrap();
            assert_eq!(1u32, e0.relative_offset());
            assert_eq!(11u64, e0.offset());
            assert_eq!(0xffff, e0.file_position());

            let e1 = index.read_entry(1).unwrap().unwrap();
            assert_eq!(2u32, e1.relative_offset());
            assert_eq!(12u64, e1.offset());
            assert_eq!(0xeeee, e1.file_position());

            // read an entry that does not exist
            let e2 = index.read_entry(2).unwrap();
            assert_eq!(None, e2);
        }
        fs::remove_file(index_path).unwrap();
    }

    #[test]
    pub fn log() {
        let log_path = "target/.test-log";
        fs::remove_file(log_path).unwrap_or(());
        {
            let mut f = Log::new(log_path, 1024).unwrap();

            let m0 = Message::new(b"12345", 1000);
            assert_eq!(m0.bytes().len(), 21);
            let p0 = f.append(m0).unwrap();
            assert_eq!(p0, 0);

            let m1 = Message::new(b"66666", 1001);
            let p1 = f.append(m1).unwrap();
            assert_eq!(p1, 21);

            f.flush().unwrap();
        }
        fs::remove_file(log_path).unwrap();
    }

    #[bench]
    fn bench_segment_append(b: &mut Bencher) {
        let log_path = "target/test-log";
        fs::remove_dir_all(log_path).unwrap_or(());
        fs::create_dir_all(log_path).unwrap_or(());

        let mut seg = Segment::new(log_path, 100u64, 100 * 1024 * 1024, 10 * 1024 * 1024).unwrap();
        let buf = b"01234567891011121314151617181920";

        b.iter(|| {
            seg.append(buf).unwrap();
        });

        fs::remove_dir_all(log_path).unwrap_or(());
    }
}
