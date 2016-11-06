use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use crc::crc32::checksum_ieee;
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, Write};


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
    #[allow(dead_code)]
    pub fn crc(&self) -> u32 {
        BigEndian::read_u32(&self.bytes[12..16])
    }

    #[inline]
    #[allow(dead_code)]
    pub fn size(&self) -> u32 {
        BigEndian::read_u32(&self.bytes[8..12])
    }

    #[inline]
    #[allow(dead_code)]
    pub fn offset(&self) -> u64 {
        BigEndian::read_u64(&self.bytes[0..8])
    }

    #[inline]
    #[allow(dead_code)]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[16..]
    }
}


/// A segment is a portion of the commit log. Segments are append-only logs written
/// until the maximum size is reached.
pub struct Segment {
    /// File descriptor
    file: File,
    /// Maximum number of bytes permitted to be appended to the log
    max_bytes: usize,
    /// current file position for the write
    pos: usize,

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

/// Holds the pair of offset written to file position in the segment file.
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
        let log_path = {
            // the log is of the form BASE_OFFSET.log
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", base_offset));
            path_buf.set_extension("log");
            path_buf
        };

        let f = try!(OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .append(true)
            .open(&log_path));

        Ok(Segment {
            file: f,
            max_bytes: max_bytes,
            pos: 0,

            next_offset: base_offset,
            base_offset: base_offset,
        })
    }

    #[inline]
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    #[inline]
    #[allow(dead_code)]
    pub fn starting_offset(&self) -> u64 {
        self.base_offset
    }

    pub fn append(&mut self, payload: &[u8]) -> Result<LogEntryMetadata, SegmentAppendError> {
        let off = self.next_offset;
        let msg = Message::new(payload, off);
        // ensure we have the capacity
        if msg.bytes().len() + self.pos > self.max_bytes {
            return Err(SegmentAppendError::LogFull);
        }

        try!(self.file.write_all(msg.bytes()));
        let write_pos = self.pos;

        self.pos += msg.bytes().len();
        self.next_offset += 1;

        Ok(LogEntryMetadata {
            offset: off,
            file_pos: write_pos as u32,
        })
    }

    // TODO: async flush strategy
    pub fn flush_sync(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}


#[cfg(test)]
mod tests {
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
        let path = TestDir::new();
        let mut f = Segment::new(path, 0, 1024).unwrap();

        let p0 = f.append(b"12345").unwrap();
        assert_eq!(p0.offset(), 0);
        assert_eq!(p0.file_pos(), 0);

        let p1 = f.append(b"66666").unwrap();
        assert_eq!(p1.offset(), 1);
        assert_eq!(p1.file_pos(), 21);

        f.flush_sync().unwrap();
    }

    #[bench]
    fn bench_segment_append(b: &mut Bencher) {
        let path = TestDir::new();

        let mut seg = Segment::new(path, 100u64, 100 * 1024 * 1024).unwrap();
        let buf = b"01234567891011121314151617181920";

        b.iter(|| {
            seg.append(buf).unwrap();
        });
    }
}
