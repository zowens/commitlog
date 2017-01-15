use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use std::io::{self, Write, Read, BufReader, Seek, SeekFrom};
use std::iter::{IntoIterator, FromIterator};
use seahash;
use byteorder::{LittleEndian, ByteOrder};
use super::Offset;

/// Number of bytes contained in the base name of the file.
pub static SEGMENT_FILE_NAME_LEN: usize = 20;
/// File extension for the segment file.
pub static SEGMENT_FILE_NAME_EXTENSION: &'static str = "log";

#[derive(Debug)]
pub enum MessageError {
    IoError(io::Error),
    InvalidHash,
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


/// Messages contain finite-sized binary values with an offset from
/// the beginning of the log.
///
/// | Bytes     | Encoding          | Value        |
/// | --------- | ----------------- | ------------ |
/// | 0-7       | Little Endian u64 | Offset       |
/// | 8-11      | Little Endian u32 | Payload Size |
/// | 12-19     | Little Endian u64 | SeaHash      |
/// | 20+       |                   | Payload      |
///
/// Seahash is chosen because of its performance and quality. It is seeded
/// with the following constants:
/// 0x16f11fe89b0d677c, 0xb480a793d8e6c86c, 0x6fe2e5aaf078ebc9, 0x14f994a4c5259381
#[derive(Debug)]
pub struct Message<'a> {
    bytes: &'a [u8],
}

impl<'a> Message<'a> {
    /// Seahash of the payload.
    #[inline]
    pub fn hash(&self) -> u64 {
        LittleEndian::read_u64(&self.bytes[12..20])
    }

    /// Size of the payload.
    #[inline]
    pub fn size(&self) -> u32 {
        LittleEndian::read_u32(&self.bytes[8..12])
    }

    /// Offset of the message in the log.
    #[inline]
    pub fn offset(&self) -> Offset {
        Offset(LittleEndian::read_u64(&self.bytes[0..8]))
    }

    /// Payload of the message.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[20..]
    }

    /// Serializes a new message into a buffer
    pub fn serialize<B: AsRef<[u8]>>(bytes: &mut Vec<u8>, offset: u64, payload: B) {
        let payload_slice = payload.as_ref();

        // offset
        let mut buf = vec![0; 8];
        LittleEndian::write_u64(&mut buf, offset);
        bytes.extend_from_slice(&buf);

        // size
        LittleEndian::write_u32(&mut buf[0..4], payload_slice.len() as u32);
        bytes.extend_from_slice(&buf[0..4]);

        // hash
        LittleEndian::write_u64(&mut buf, seahash::hash(payload_slice));
        bytes.extend_from_slice(&buf);

        // payload
        bytes.extend_from_slice(payload_slice);
    }
}

/// Last position read from the log.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct LogPosition {
    pub(super) segment: u64,
    pub(super) pos: u32,
}


/// Readonly set of messages from the log.
pub struct MessageSet {
    bytes: Vec<u8>,
    size: usize,
    last_off: Option<u64>,

    // TODO: remove this
    next_position: Option<LogPosition>,
}

impl MessageSet {
    /// Creates a new MessageSet from which messages can be read.
    fn new() -> MessageSet {
        MessageSet {
            bytes: Vec::new(),
            size: 0,
            last_off: None,
            next_position: None,
        }
    }

    /// Creates an empty MessageSet.
    pub fn empty() -> MessageSet {
        MessageSet {
            bytes: Vec::with_capacity(0),
            size: 0,
            last_off: None,
            next_position: None,
        }
    }

    /// Reads a single message.
    fn read<R>(&mut self, reader: &mut R) -> Result<(), MessageError>
        where R: Read
    {
        let mut offset_buf = vec![0; 8];
        read_n!(reader, offset_buf, 8, "Unable to read offset");
        let mut size_buf = vec![0; 4];
        read_n!(reader, size_buf, 4, "Unable to read size");
        let mut hash_buf = vec![0; 8];
        read_n!(reader, hash_buf, 8, "Unable to read hash");

        let off = LittleEndian::read_u64(&offset_buf);
        let size = LittleEndian::read_u32(&size_buf) as usize;
        let hash = LittleEndian::read_u64(&hash_buf);

        let mut bytes = vec![0; size];
        read_n!(reader, bytes, size, "Unable to read message payload");

        let payload_hash = seahash::hash(&bytes);
        if payload_hash != hash {
            return Err(MessageError::InvalidHash);
        }

        self.bytes.extend(offset_buf);
        self.bytes.extend(size_buf);
        self.bytes.extend(hash_buf);
        self.bytes.extend(bytes);

        self.size += 1;
        self.last_off = Some(off);

        Ok(())
    }

    /// Number of messages within the message set.
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Last offset in the MessageSet.
    pub fn last_offset(&self) -> Option<Offset> {
        self.last_off.map(Offset)
    }

    /// Next read position within the log.
    pub fn next_read_position(&self) -> Option<LogPosition> {
        self.next_position.clone()
    }

    fn set_next_read_position(&mut self, log_start: u64, starting_file_pos: u32) {
        self.next_position = Some(LogPosition {
            segment: log_start,
            pos: starting_file_pos + self.bytes.len() as u32,
        });
    }

    /// Message iterator.
    pub fn iter<'a>(&'a self) -> MessageIter<'a> {
        MessageIter {
            bytes: &self.bytes,
            offset: 0,
        }
    }

    /// Serializes the message into a byte vector.
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.bytes.as_slice());
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<MessageSet, MessageError> {
        let mut msgs = 0usize;
        let mut last_off = None;

        // iterate over the bytes to initialize size and ensure we have
        // a properly formed message set
        {
            let mut bytes = bytes.as_slice();
            while bytes.len() > 0 {
                // check that the offset, size and hash are present
                if bytes.len() < 20 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Message set has invlid length")).into());
                }

                let offset = LittleEndian::read_u64(&bytes[0..8]);
                let size = LittleEndian::read_u32(&bytes[8..12]) as usize;
                let hash = LittleEndian::read_u64(&bytes[12..20]);
                if bytes.len() < (20 + size) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Message set has invlid length")).into());
                }

                // check the hash
                let payload_hash = seahash::hash(&bytes[20..(size+20)]);
                if payload_hash != hash {
                    return Err(MessageError::InvalidHash);
                }

                // update metadata
                msgs += 1;
                last_off = Some(offset);

                // move the slice along
                bytes = &bytes[20+size..];
            }
        }
        Ok(MessageSet {
            bytes: bytes,
            size: msgs,
            last_off: last_off,
            next_position: None,
        })
    }
}


/// Iterator for Message within a MessageSet.
pub struct MessageIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = Message<'a>;

    fn next(&mut self) -> Option<Message<'a>> {
        if self.offset + 20 >= self.bytes.len() {
            return None;
        }

        let off_slice = &self.bytes[self.offset..];
        let size = LittleEndian::read_u32(&off_slice[8..12]) as usize;
        trace!("message iterator: size {} bytes", size);
        let message_slice = &off_slice[0..20 + size];
        self.offset += 20 + size;
        trace!("message iterator: at offset {}", self.offset);
        Some(Message { bytes: message_slice })
    }
}

/// Buffer of message payloads prior to append to the log. The buffer allows a batch
/// of messages to be appended to the log.
pub struct MessageBuf {
    bytes: Vec<u8>,
    size: usize,
    byte_offsets: Vec<usize>,
}

impl MessageBuf {
    /// Creates an empty MessageBuf.
    pub fn new() -> MessageBuf {
        MessageBuf {
            bytes: Vec::new(),
            size: 0,
            byte_offsets: Vec::new(),
        }
    }

    /// Number of messages added to the buffer.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Clears the message buffer.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.byte_offsets.clear();
        self.size = 0;
    }

    /// Adds a new message with a given payload.
    pub fn push<B: AsRef<[u8]>>(&mut self, payload: B) {
        let start_len = self.bytes.len();

        // blank offset, expect the log to set the offsets
        Message::serialize(&mut self.bytes, 0u64, payload);

        self.size += 1;
        self.byte_offsets.push(start_len);
    }

    /// Iterates over the messages added to the buffer.
    pub fn iter<'a>(&'a self) -> MessageIter<'a> {
        MessageIter {
            bytes: &self.bytes,
            offset: 0,
        }
    }

    fn set_offsets(&mut self, starting_offset: u64) {
        for (i, pos) in self.byte_offsets.iter().enumerate() {
            LittleEndian::write_u64(&mut self.bytes[*pos..*pos + 8],
                                 (i as u64) + starting_offset);
        }
    }

    fn create_metadata(&self, starting_offset: u64, base_file_pos: u32) -> Vec<LogEntryMetadata> {
        self.byte_offsets
            .iter()
            .enumerate()
            .map(move |(i, pos)| {
                LogEntryMetadata {
                    offset: starting_offset + (i as u64),
                    file_pos: (*pos as u32) + base_file_pos,
                }
            })
            .collect()
    }
}

impl<R: AsRef<[u8]>> FromIterator<R> for MessageBuf {
    fn from_iter<T>(iter: T) -> MessageBuf
        where T: IntoIterator<Item = R>
    {
        let mut buf = MessageBuf::new();
        for v in iter.into_iter() {
            buf.push(v);
        }
        buf
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
    Read {
        /// Cached size of the file
        file_size: usize,
    },
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

/// Batch size limitation on read.
pub enum ReadLimit {
    /// Limit the number of bytes read from the log. This is recommended.
    Bytes(usize),

    /// Limit the number of messages read from the log.
    Messages(usize),
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

        let f = OpenOptions::new().write(true)
            .read(true)
            .create_new(true)
            .append(true)
            .open(&log_path)?;

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
        let seg_file = OpenOptions::new().read(true)
            .write(false)
            .append(false)
            .open(&seg_path)?;


        let filename = seg_path.as_ref().file_name().unwrap().to_str().unwrap();
        let base_offset = match u64::from_str_radix(&filename[0..SEGMENT_FILE_NAME_LEN], 10) {
            Ok(v) => v,
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                          "Segment file name does not parse as u64"))
            }
        };


        let meta = seg_file.metadata()?;

        Ok(Segment {
            file: seg_file,
            mode: SegmentMode::Read { file_size: meta.len() as usize },
            base_offset: base_offset,
        })
    }

    pub fn next_offset(&self) -> u64 {
        match self.mode {
            SegmentMode::ReadWrite { next_offset, .. } => next_offset,
            _ => 0,
        }
    }

    pub fn size(&self) -> usize {
        match self.mode {
            SegmentMode::ReadWrite { write_pos, .. } => write_pos as usize,
            SegmentMode::Read { file_size } => file_size,
        }
    }

    #[inline]
    pub fn starting_offset(&self) -> u64 {
        self.base_offset
    }

    pub fn append(&mut self,
                  payload: &mut MessageBuf)
                  -> Result<Vec<LogEntryMetadata>, SegmentAppendError> {
        let (write_pos, off, max_bytes) = match self.mode {
            SegmentMode::ReadWrite { write_pos, next_offset, max_bytes } => {
                (write_pos, next_offset, max_bytes)
            }
            _ => return Err(SegmentAppendError::LogFull),
        };

        payload.set_offsets(off);

        // ensure we have the capacity
        if payload.bytes.len() + write_pos > max_bytes {
            return Err(SegmentAppendError::LogFull);
        }

        self.file.write_all(&payload.bytes)?;
        self.mode = SegmentMode::ReadWrite {
            write_pos: write_pos + payload.bytes.len(),
            next_offset: off + payload.len() as u64,
            max_bytes: max_bytes,
        };
        Ok(payload.create_metadata(off, write_pos as u32))
    }

    pub fn flush_sync(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    pub fn read(&mut self, file_pos: u32, limit: ReadLimit) -> Result<MessageSet, MessageError> {
        self.file.seek(SeekFrom::Start(file_pos as u64))?;

        let mut buf_reader = match limit {
            ReadLimit::Bytes(n) => BufReader::with_capacity(n, &mut self.file),
            _ => BufReader::new(&mut self.file),
        };

        let mut msgs = MessageSet::new();

        loop {
            match msgs.read(&mut buf_reader) {
                Ok(()) => {
                    match limit {
                        ReadLimit::Messages(l) if l <= msgs.len() => {
                            break;
                        },
                        _ => {}
                    }
                }
                // EOF counts as an end to the stream, thus we're done fetching messages
                Err(MessageError::IoError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => return Err(e),
            }
        }


        msgs.set_next_read_position(self.base_offset, file_pos);
        Ok(msgs)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
    use super::super::testutil::*;
    use std::io;
    use std::path::PathBuf;
    use env_logger;

    #[test]
    fn message_construction() {
        env_logger::init().unwrap_or(());
        let mut msg_buf = MessageBuf::new();
        msg_buf.push("123456789");
        msg_buf.push("000000000");
        msg_buf.set_offsets(100);

        let mut msg_it = msg_buf.iter();
        {
            let msg = msg_it.next().unwrap();
            assert_eq!(msg.payload(), b"123456789");
            assert_eq!(msg.hash(), 13331223911193280505);
            assert_eq!(msg.size(), 9u32);
            assert_eq!(msg.offset().0, 100);
        }
        {
            let msg = msg_it.next().unwrap();
            assert_eq!(msg.payload(), b"000000000");
            assert_eq!(msg.hash(), 8467704495454493044);
            assert_eq!(msg.size(), 9u32);
            assert_eq!(msg.offset().0, 101);
        }

        assert!(msg_it.next().is_none());
    }

    #[test]
    fn message_read() {
        let mut buf = MessageBuf::new();
        buf.push("123456789");
        let bytes = buf.bytes;

        let mut buf_reader = io::BufReader::new(bytes.as_slice());

        let mut reader = MessageSet::new();
        let read_msg_result = reader.read(&mut buf_reader);
        assert!(read_msg_result.is_ok(), "result = {:?}", read_msg_result);

        let read_msg = reader.iter().next().unwrap();
        assert_eq!(read_msg.payload(), b"123456789");
        // TODO: ... change this
        // assert_eq!(read_msg.hash(), 0xcbf43926);
        assert_eq!(read_msg.size(), 9u32);
    }


    #[test]
    fn message_read_invalid_hash() {
        let mut buf = MessageBuf::new();
        buf.push("123456789");
        let mut msg = buf.bytes;
        // mess with the payload such that the hash does not match
        let last_ind = msg.len() - 1;
        msg[last_ind] += 1u8;

        let mut buf_reader = io::BufReader::new(msg.as_slice());

        let mut reader = MessageSet::new();
        let read_msg_result = reader.read(&mut buf_reader);
        let matches_invalid_hash = match read_msg_result {
            Err(MessageError::InvalidHash) => true,
            _ => false,
        };
        assert!(matches_invalid_hash,
                "Invalid result, not Hash error. Result = {:?}",
                read_msg_result);
    }


    #[test]
    fn message_read_invalid_payload_length() {
        let mut buf = MessageBuf::new();
        buf.push("123456789");
        let mut msg = buf.bytes;
        // pop the last byte
        msg.pop();

        let mut buf_reader = io::BufReader::new(msg.as_slice());
        let mut msg_reader = MessageSet::new();
        let read_msg_result = msg_reader.read(&mut buf_reader);
        let matches_invalid_hash = match read_msg_result {
            Err(MessageError::IoError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => true,
            _ => false,
        };
        assert!(matches_invalid_hash,
                "Invalid result, not Hasherror. Result = {:?}",
                read_msg_result);
    }


    #[test]
    pub fn log_append() {
        let path = TestDir::new();
        let mut f = Segment::new(path, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::new();
            buf.push("12345");
            let meta = f.append(&mut buf).unwrap();

            assert_eq!(1, meta.len());
            let p0 = meta.iter().next().unwrap();
            assert_eq!(p0.offset(), 0);
            assert_eq!(p0.file_pos(), 0);
        }

        {
            let mut buf = MessageBuf::new();
            buf.push("66666");
            buf.push("77777");
            let meta = f.append(&mut buf).unwrap();
            assert_eq!(2, meta.len());

            let mut it = meta.iter();
            let p0 = it.next().unwrap();
            assert_eq!(p0.offset(), 1);
            assert_eq!(p0.file_pos(), 25);

            let p1 = it.next().unwrap();
            assert_eq!(p1.offset(), 2);
            assert_eq!(p1.file_pos(), 50);
        }

        f.flush_sync().unwrap();
    }

    #[test]
    pub fn log_open() {
        let log_dir = TestDir::new();

        {
            let mut f = Segment::new(&log_dir, 0, 1024).unwrap();
            let mut buf = MessageBuf::new();
            buf.push("12345");
            buf.push("66666");
            f.append(&mut buf).unwrap();
            f.flush_sync().unwrap();
        }

        // open it
        {
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", 0));
            path_buf.set_extension(SEGMENT_FILE_NAME_EXTENSION);

            let res = Segment::open(&path_buf);
            assert!(res.is_ok(), "Err {:?}", res.err());

            let f = res.unwrap();
            assert_eq!(0, f.starting_offset());
        }
    }


    #[test]
    pub fn log_read() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::new();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        let msgs = f.read(0, ReadLimit::Messages(10)).unwrap();
        assert_eq!(3, msgs.len());

        {
            let log_pos = msgs.next_read_position();
            assert!(log_pos.is_some());
            let log_pos = log_pos.unwrap();
            assert_eq!(0, log_pos.segment);
            assert_eq!(msgs.bytes.len() as u32, log_pos.pos);
        }

        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(i as u64, m.offset().0);
        }
    }

    #[test]
    pub fn log_read_with_msg_limit() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::new();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        let msgs = f.read(0, ReadLimit::Messages(2)).unwrap();
        assert_eq!(2, msgs.len());

        {
            let log_pos = msgs.next_read_position();
            assert!(log_pos.is_some());
            let log_pos = log_pos.unwrap();
            assert_eq!(0, log_pos.segment);
            assert_eq!(msgs.bytes.len() as u32, log_pos.pos);
        }
    }


    #[test]
    pub fn log_read_with_size_limit() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        let meta = {
            let mut buf = MessageBuf::new();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap()
        };

        // byte max contains message 0, but not the entirety of message 1
        let msgs = f.read(0, ReadLimit::Bytes((meta[1].file_pos() + 1) as usize))
            .unwrap();
        assert_eq!(1, msgs.len());
    }

    #[test]
    pub fn log_read_with_log_position() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::new();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        // byte max contains message 0, but not the entirety of message 1
        let mut file_pos = 0;
        for i in 0..3 {
            let msgs = f.read(file_pos, ReadLimit::Messages(1))
                .unwrap();
            assert_eq!(1, msgs.len());
            assert_eq!(i, msgs.iter().next().unwrap().offset().0);

            let next_pos = msgs.next_read_position();
            assert!(next_pos.is_some());
            file_pos = next_pos.unwrap().pos;
        }

        // last read should be empty
        let msgs = f.read(file_pos, ReadLimit::Messages(1)).unwrap();
        assert_eq!(0, msgs.len());

        // next_pos should be the same as the input file pos
        let next_pos = msgs.next_read_position();
        assert!(next_pos.is_some());
        assert_eq!(file_pos, next_pos.unwrap().pos);
    }

    #[test]
    pub fn log_read_from_write() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::new();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        let msgs = f.read(0, ReadLimit::Messages(10)).unwrap();
        assert_eq!(3, msgs.len());

        {
            let mut buf = MessageBuf::new();
            buf.push("foo");
            f.append(&mut buf).unwrap();
        }

        let msgs = f.read(0, ReadLimit::Messages(10)).unwrap();
        assert_eq!(4, msgs.len());

        {
            let log_pos = msgs.next_read_position();
            assert!(log_pos.is_some());
            let log_pos = log_pos.unwrap();
            assert_eq!(0, log_pos.segment);
            assert_eq!(msgs.bytes.len() as u32, log_pos.pos);
        }


        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(i as u64, m.offset().0);
        }
    }

    #[test]
    pub fn messagebuf_fromiterator() {
        let buf = vec!["test", "123"].iter().collect::<MessageBuf>();
        assert_eq!(2, buf.len());
    }

    #[test]
    pub fn messageset_deserialize() {
        let bytes = {
            let mut buf = MessageBuf::new();
            buf.push("foo");
            buf.push("bar");
            buf.push("baz");
            buf.set_offsets(10);
            buf.bytes
        };

        let bytes_copy = bytes.clone();

        // deserialize it
        let res = MessageSet::from_bytes(bytes_copy);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(3, res.len());
        assert_eq!(Some(Offset(12)), res.last_offset());

        let mut it = res.iter();

        {
            let m0 = it.next().unwrap();
            assert_eq!(10, m0.offset().0);
            assert_eq!(b"foo", m0.payload());
        }

        {
            let m1 = it.next().unwrap();
            assert_eq!(11, m1.offset().0);
            assert_eq!(b"bar", m1.payload());
        }

        {
            let m2 = it.next().unwrap();
            assert_eq!(12, m2.offset().0);
            assert_eq!(b"baz", m2.payload());
        }

        let n = it.next();
        assert!(n.is_none());
    }

    #[bench]
    fn bench_segment_append(b: &mut Bencher) {
        let path = TestDir::new();

        let mut seg = Segment::new(path, 100u64, 100 * 1024 * 1024).unwrap();
        let payload = b"01234567891011121314151617181920";

        b.iter(|| {
            let mut buf = MessageBuf::new();
            buf.push(payload);
            seg.append(&mut buf).unwrap();
        });
    }

    #[bench]
    fn bench_message_construct(b: &mut Bencher) {
        b.iter(|| {
            let mut msg_buf = MessageBuf::new();
            msg_buf.push("719c3b4556066a1c7a06c9d55959d003d9b46273aabe2eae15ef4ba78321ae2a68b0997a4abbd035a4cdbc8b27d701089a5af63a8b81f9dc16a874d0eda0983b79c1a6f79fe3ae61612ba2558562a85595f2f3f07fab8faba1b849685b61aad6b131b7041ca79cc662b4c5aad4d1b78fb1034fafa2fe4f30207395e399c6d724");
            msg_buf.push("2cea26f165640d448a9b89f1f871e6fca80a1255b1daea6752bf99d8c5f90e706deaecddf304b2bf5a5e72e32b29bc7c54018265d17317a670ea406fd7e6b485a19f5fb1efe686badb6599d45106b95b55695cd4e24729edb312a5dec1bc80e8d8b3ee4b69af1f3a9c801e7fb527e65f7c13c62bb37261c0");
            msg_buf.set_offsets(1250);
        });
    }
}
