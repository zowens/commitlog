use std::fs::File;
use super::message::{MessageBuf, MessageError};

/// Trait that allows reading from a slice of the log.
pub trait LogSliceReader {
    /// Result type of this reader.
    type Result: 'static;

    /// Reads the slice of the file containing the message set.
    ///
    /// * `file` - The segment file that contains the slice of the log.
    /// * `file_position` - The offset within the file that starts the slice.
    /// * `bytes` - Total number of bytes, from the offset, that contains the message set slice.
    fn read_from(&mut self,
                 file: &File,
                 file_position: u32,
                 bytes: usize)
                 -> Result<Self::Result, MessageError>;

    /// Called when there are no commits in the log in the desired range.
    fn empty() -> Self::Result;
}

#[cfg(unix)]
#[derive(Default)]
/// Reader of the file segment into memory.
pub struct MessageBufReader;

impl LogSliceReader for MessageBufReader {
    type Result = MessageBuf;

    fn read_from(&mut self,
                 file: &File,
                 file_position: u32,
                 bytes: usize)
                 -> Result<Self::Result, MessageError> {
        use std::os::unix::fs::FileExt;

        let mut vec = vec![0; bytes];
        try!(file.read_at(&mut vec, file_position as u64));
        MessageBuf::from_bytes(vec)
    }

    fn empty() -> Self::Result {
        MessageBuf::default()
    }
}
