use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use crc::crc32::checksum_ieee;
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, Write, Read};

pub static SEGMENT_FILE_NAME_LEN: usize = 20;
pub static SEGMENT_FILE_NAME_EXTENSION: &'static str = "log";

#[derive(Debug)]
pub enum MessageError {
    IoError(io::Error),
    InvalidCRC,
}

impl From<io::Error> for MessageError {
    fn from(e: io::Error) -> MessageError {
        MessageError::IoError(e)
    }
}

macro_rules! read_n {
    ($reader:expr, $buf:expr, $size:expr, $err_msg:expr) => ({

        match $reader.read(&mut $buf) {
            Ok(s) if s == $size => (),
            Ok(_) => return Err(
                MessageError::IoError(
                    io::Error::new(io::ErrorKind::UnexpectedEof, $err_msg))),
            Err(e) => return Err(MessageError::IoError(e)),
        }
    })
}


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
#[derive(Debug)]
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

    pub fn read<R>(reader: &mut R) -> Result<Message, MessageError>
        where R: Read
    {
        let mut offset_buf = vec![0; 8];
        read_n!(reader, offset_buf, 8, "Unable to read offset");
        let mut size_buf = vec![0; 4];
        read_n!(reader, size_buf, 4, "Unable to read size");
        let mut crc_buf = vec![0; 4];
        read_n!(reader, crc_buf, 4, "Unable to read CRC");

        let size = BigEndian::read_u32(&size_buf) as usize;
        let crc = BigEndian::read_u32(&crc_buf);

        let mut bytes = vec![0; 16 + size];
        read_n!(reader, bytes[16..], size, "Unable to read message payload");

        let payload_crc = checksum_ieee(&bytes[16..]);
        if payload_crc != crc {
            return Err(MessageError::InvalidCRC);
        }

        bytes[0..8].copy_from_slice(&offset_buf);
        bytes[8..12].copy_from_slice(&size_buf);
        bytes[12..16].copy_from_slice(&crc_buf);

        Ok(Message { bytes: bytes })
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

enum SegmentMode {
    ReadWrite {
        /// current file position for the write
        write_pos: usize,

        /// Next offset of the log
        next_offset: u64,

        /// Maximum number of bytes permitted to be appended to the log
        max_bytes: usize,
    },
    Read,
}


/// A segment is a portion of the commit log. Segments are append-only logs written
/// until the maximum size is reached.
pub struct Segment {
    /// File descriptor
    file: File,

    mode: SegmentMode,

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
    pub fn new<P>(log_dir: P, base_offset: u64, max_bytes: usize) -> io::Result<Segment>
        where P: AsRef<Path>
    {
        let log_path = {
            // the log is of the form BASE_OFFSET.log
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", base_offset));
            path_buf.set_extension(SEGMENT_FILE_NAME_EXTENSION);
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

            mode: SegmentMode::ReadWrite {
                write_pos: 0,
                next_offset: base_offset,
                max_bytes: max_bytes,
            },

            base_offset: base_offset,
        })
    }

    pub fn open<P>(seg_path: P) -> io::Result<Segment>
        where P: AsRef<Path>
    {
        let seg_file = try!(OpenOptions::new()
            .read(true)
            .write(false)
            .append(false)
            .open(&seg_path));


        let filename = seg_path.as_ref().file_name().unwrap().to_str().unwrap();
        let base_offset = match u64::from_str_radix(&filename[0..SEGMENT_FILE_NAME_LEN], 10) {
            Ok(v) => v,
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                          "Segment file name does not parse as u64"))
            }
        };


        Ok(Segment {
            file: seg_file,
            mode: SegmentMode::Read,
            base_offset: base_offset,
        })
    }

    // TODO: doesn't make sense
    pub fn next_offset(&self) -> u64 {
        match self.mode {
            SegmentMode::ReadWrite { write_pos, next_offset, max_bytes } => next_offset,
            _ => 0
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn starting_offset(&self) -> u64 {
        self.base_offset
    }

    pub fn append(&mut self, payload: &[u8]) -> Result<LogEntryMetadata, SegmentAppendError> {
        let (write_pos, off, max_bytes) = match self.mode {
            SegmentMode::ReadWrite { write_pos, next_offset, max_bytes } =>
                (write_pos, next_offset, max_bytes),
            _ => return Err(SegmentAppendError::LogFull),
        };

        let msg = Message::new(payload, off);
        // ensure we have the capacity
        if msg.bytes().len() + write_pos > max_bytes {
            return Err(SegmentAppendError::LogFull);
        }

        try!(self.file.write_all(msg.bytes()));
        self.mode = SegmentMode::ReadWrite {
            write_pos: write_pos + msg.bytes().len(),
            next_offset: off + 1,
            max_bytes: max_bytes,
        };
        Ok(LogEntryMetadata {
            offset: off,
            file_pos: write_pos as u32,
        })
    }

    // TODO: async flush strategy
    pub fn flush_sync(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    /*pub fn read_at_pos(&mut self, pos: u32) -> Result<Message, MessageError> {

    }*/
}


#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
    use super::super::testutil::*;
    use std::io;

    #[test]
    fn message_construction() {
        let msg = Message::new(b"123456789", 1234567u64);
        assert_eq!(msg.offset(), 1234567u64);
        assert_eq!(msg.payload(), b"123456789");
        assert_eq!(msg.crc(), 0xcbf43926);
        assert_eq!(msg.size(), 9u32);
    }

    #[test]
    fn message_read() {
        let msg = Message::new(b"123456789", 1234567u64);
        let mut buf_reader = io::BufReader::new(msg.bytes());
        let read_msg_result = Message::read(&mut buf_reader);
        assert!(read_msg_result.is_ok(), "result = {:?}", read_msg_result);

        let read_msg = read_msg_result.unwrap();
        assert_eq!(read_msg.offset(), 1234567u64);
        assert_eq!(read_msg.payload(), b"123456789");
        assert_eq!(read_msg.crc(), 0xcbf43926);
        assert_eq!(read_msg.size(), 9u32);
    }

    #[test]
    fn message_read_invalid_crc() {
        let mut msg =
            Message::new(b"123456789", 1234567u64).bytes().iter().cloned().collect::<Vec<u8>>();
        // mess with the payload such that the CRC does not match
        let last_ind = msg.len() - 1;
        msg[last_ind] += 1u8;

        let mut buf_reader = io::BufReader::new(msg.as_slice());
        let read_msg_result = Message::read(&mut buf_reader);
        let matches_invalid_crc = match read_msg_result {
            Err(MessageError::InvalidCRC) => true,
            _ => false,
        };
        assert!(matches_invalid_crc,
                "Invalid result, not CRC error. Result = {:?}",
                read_msg_result);
    }

    #[test]
    fn message_read_invalid_payload_length() {
        let mut msg =
            Message::new(b"123456789", 1234567u64).bytes().iter().cloned().collect::<Vec<u8>>();
        // pop the last byte
        msg.pop();

        let mut buf_reader = io::BufReader::new(msg.as_slice());
        let read_msg_result = Message::read(&mut buf_reader);
        let matches_invalid_crc = match read_msg_result {
            Err(MessageError::IoError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => true,
            _ => false,
        };
        assert!(matches_invalid_crc,
                "Invalid result, not CRC error. Result = {:?}",
                read_msg_result);
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
