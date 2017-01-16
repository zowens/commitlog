use std::iter::{IntoIterator, FromIterator};
use std::io::{self, Read};
use byteorder::{LittleEndian, ByteOrder};
use super::Offset;
use seahash;

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
/// `0x16f11fe89b0d677c`, `0xb480a793d8e6c86c`, `0x6fe2e5aaf078ebc9`, `0x14f994a4c5259381`
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

/// Readonly set of messages from the log.
pub struct MessageSet {
    bytes: Vec<u8>,
    size: usize,
    last_off: Option<u64>,
}

impl MessageSet {
    /// Creates a new MessageSet from which messages can be read.
    pub fn new() -> MessageSet {
        MessageSet {
            bytes: Vec::new(),
            size: 0,
            last_off: None,
        }
    }

    /// Creates an empty MessageSet.
    pub fn empty() -> MessageSet {
        MessageSet {
            bytes: Vec::with_capacity(0),
            size: 0,
            last_off: None,
        }
    }

    /// Reads a single message.
    pub fn read<R>(&mut self, reader: &mut R) -> Result<(), MessageError>
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

    /// Number of bytes contained in the message set.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Last offset in the MessageSet.
    pub fn last_offset(&self) -> Option<Offset> {
        self.last_off.map(Offset)
    }

    /// Message iterator.
    pub fn iter<'a>(&'a self) -> MessageIter<'a> {
        MessageIter {
            bytes: &self.bytes,
            offset: 0,
        }
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
    byte_offsets: Vec<usize>,
}

impl MessageBuf {
    /// Creates an empty MessageBuf.
    pub fn new() -> MessageBuf {
        MessageBuf {
            bytes: Vec::new(),
            byte_offsets: Vec::new(),
        }
    }

    /// Number of messages added to the buffer.
    pub fn len(&self) -> usize {
        self.byte_offsets.len()
    }

    /// Gets the underlying bytes of the buffer
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Clears the message buffer.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.byte_offsets.clear();
    }

    /// Adds a new message with a given payload.
    pub fn push<B: AsRef<[u8]>>(&mut self, payload: B) {
        let start_len = self.bytes.len();

        // blank offset, expect the log to set the offsets
        Message::serialize(&mut self.bytes, 0u64, payload);

        self.byte_offsets.push(start_len);
    }

    /// Iterates over the messages added to the buffer.
    pub fn iter<'a>(&'a self) -> MessageIter<'a> {
        MessageIter {
            bytes: &self.bytes,
            offset: 0,
        }
    }

    /// Mutates the buffer with starting offset
    #[doc(hidden)]
    pub fn set_offsets(&mut self, starting_offset: u64) {
        for (i, pos) in self.byte_offsets.iter().enumerate() {
            LittleEndian::write_u64(&mut self.bytes[*pos..*pos + 8],
                                 (i as u64) + starting_offset);
        }
    }

    #[doc(hidden)]
    pub fn create_metadata(&self, starting_offset: u64, base_file_pos: u32) -> Vec<LogEntryMetadata> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
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
        let mut buf_reader = io::BufReader::new(buf.bytes());

        let mut reader = MessageSet::new();
        let read_msg_result = reader.read(&mut buf_reader);
        assert!(read_msg_result.is_ok(), "result = {:?}", read_msg_result);

        let read_msg = reader.iter().next().unwrap();
        assert_eq!(read_msg.payload(), b"123456789");
        assert_eq!(read_msg.size(), 9u32);
    }


    #[test]
    fn message_read_invalid_hash() {
        let mut buf = MessageBuf::new();
        buf.push("123456789");
        let mut msg = Vec::from(buf.bytes());
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
        let mut msg = Vec::from(buf.bytes());
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
}

