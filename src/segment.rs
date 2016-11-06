use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use crc::crc32::checksum_ieee;
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, Write};
use std;


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
        BigEndian::write_u32(&mut bytes[12..16], checksum_ieee(payload));
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

/// The log is an append-only file with strictly montonically increasing offsets. The log
/// returns a starting position of a message upon append. The size of the log is size-limited.
pub struct Log {
    /// File descriptor
    file: File,
    /// Maximum number of bytes permitted to be appended to the log
    max_bytes: usize,
    /// current file position for the write
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
            .create_new(true)
            .append(true)
            .open(p));
        Ok(Log {
            file: f,
            max_bytes: max_bytes,
            pos: 0,
        })
    }

    #[inline]
    pub fn can_write(&self) -> bool {
        self.pos < self.max_bytes
    }

    /// Appends a message to the log, returning the position in the log where
    /// the message starts.
    pub fn append(&mut self, msg: Message) -> Result<u32, LogAppendError> {
        // ensure we have the capacity
        if msg.bytes().len() + self.pos > self.max_bytes {
            return Err(LogAppendError::LogFull);
        }

        // write to the log file, then to the index
        try!(self.file.write_all(msg.bytes()));
        let write_pos = self.pos;
        self.pos += msg.bytes().len();

        Ok(write_pos as u32)
    }

    #[inline]
    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// A segment is a portion of the commit log. Segments are written to until the maximum
/// size is reached in the log.
pub struct Segment {
    /// Log file
    log: Log,
    /// Next offset of the log
    next_offset: u64,
    /// Base offset of the log
    base_offset: u64,
}

#[derive(Debug)]
pub enum SegmentAppendError {
    LogFull,
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

#[derive(Copy, Clone, Debug)]
pub struct LogEntryMetadata {
    offset: u64,
    file_pos: u32,
}

impl LogEntryMetadata {
    #[inline]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    #[inline]
    pub fn file_pos(&self) -> u32 {
        self.file_pos
    }
}



impl Segment {
    // TODO: open variant for reading

    pub fn new<P>(log_dir: P, base_offset: u64, max_bytes: usize) -> io::Result<Segment>
        where P: AsRef<Path>
    {
        // TODO: inline the log
        let log = {
            // the log is of the form BASE_OFFSET.log
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", base_offset));
            path_buf.set_extension("log");
            try!(Log::new(&path_buf, max_bytes))
        };

        Ok(Segment {
            log: log,
            next_offset: base_offset,
            base_offset: base_offset,
        })
    }

    #[inline]
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    #[inline]
    pub fn starting_offset(&self) -> u64 {
        self.base_offset
    }

    pub fn append(&mut self, msg: &[u8]) -> Result<LogEntryMetadata, SegmentAppendError> {
        if !self.log.can_write() {
            return Err(SegmentAppendError::LogFull);
        }

        let off = self.next_offset;
        let pos = try!(self.log.append(Message::new(msg, off)));

        self.next_offset += 1;
        Ok(LogEntryMetadata {
            offset: off,
            file_pos: pos,
        })
    }

    // TODO: async flush strategy
    pub fn flush_sync(&mut self) -> io::Result<()> {
        self.log.flush()
    }
}


#[cfg(test)]
mod tests {
    use std::fs;
    use super::*;
    use test::Bencher;
    use super::super::testutil::*;

    #[test]
    fn message_construction() {
        let msg = Message::new(b"123456789", 1234567u64);
        assert_eq!(msg.offset(), 1234567u64);
        assert_eq!(msg.payload(), b"123456789");
        assert_eq!(msg.crc(), 0xcbf43926);
        assert_eq!(msg.size(), 9u32);
    }

    #[test]
    pub fn log() {
        let log_path = "target/.test-log";
        fs::remove_file(&log_path).unwrap_or(());
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
        fs::remove_file(&log_path).unwrap_or(());
    }

    #[bench]
    fn bench_segment_append(b: &mut Bencher) {
        let log_path = "target/test-log";
        fs::remove_dir_all(log_path).unwrap_or(());
        fs::create_dir_all(log_path).unwrap_or(());

        let mut seg = Segment::new(log_path, 100u64, 100 * 1024 * 1024).unwrap();
        let buf = b"01234567891011121314151617181920";

        b.iter(|| {
            seg.append(buf).unwrap();
        });

        fs::remove_dir_all(log_path).unwrap_or(());
    }
}
