use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File};
use std::io::{self, Write, BufReader, Seek, SeekFrom};
use super::message::*;

/// Number of bytes contained in the base name of the file.
pub static SEGMENT_FILE_NAME_LEN: usize = 20;
/// File extension for the segment file.
pub static SEGMENT_FILE_NAME_EXTENSION: &'static str = "log";

/// Last position read from the log.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NextPosition(pub u32);

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
            .write(true)
            .append(true)
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

    pub fn append<T: MessageSetMut>(&mut self,
                                    payload: &mut T)
                                    -> Result<Vec<LogEntryMetadata>, SegmentAppendError> {
        let (write_pos, off, max_bytes) = match self.mode {
            SegmentMode::ReadWrite { write_pos, next_offset, max_bytes } => {
                (write_pos, next_offset, max_bytes)
            }
            _ => return Err(SegmentAppendError::LogFull),
        };

        // ensure we have the capacity
        let payload_len = payload.bytes().len();
        if payload_len + write_pos > max_bytes {
            return Err(SegmentAppendError::LogFull);
        }

        let meta = super::message::set_offsets(payload, off, write_pos);

        self.file.write_all(payload.bytes())?;
        self.mode = SegmentMode::ReadWrite {
            write_pos: write_pos + payload_len,
            next_offset: meta.iter().next_back().unwrap().offset + 1,
            max_bytes: max_bytes,
        };
        Ok(meta)
    }

    pub fn flush_sync(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    pub fn read(&mut self,
                file_pos: u32,
                limit: ReadLimit)
                -> Result<(MessageBuf, NextPosition), MessageError> {
        self.file.seek(SeekFrom::Start(file_pos as u64))?;

        let mut buf_reader = match limit {
            ReadLimit::Bytes(n) => BufReader::with_capacity(n, &mut self.file),
            _ => BufReader::new(&mut self.file),
        };

        let mut msgs = MessageBuf::default();

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

        let next_pos = file_pos + msgs.bytes().len() as u32;
        Ok((msgs, NextPosition(next_pos)))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::testutil::*;
    use test::Bencher;
    use std::path::PathBuf;

    #[test]
    pub fn log_append() {
        let path = TestDir::new();
        let mut f = Segment::new(path, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::default();
            buf.push("12345");
            let meta = f.append(&mut buf).unwrap();

            assert_eq!(1, meta.len());
            let p0 = meta.iter().next().unwrap();
            assert_eq!(p0.offset, 0);
            assert_eq!(p0.file_pos, 0);
        }

        {
            let mut buf = MessageBuf::default();
            buf.push("66666");
            buf.push("77777");
            let meta = f.append(&mut buf).unwrap();
            assert_eq!(2, meta.len());

            let mut it = meta.iter();
            let p0 = it.next().unwrap();
            assert_eq!(p0.offset, 1);
            assert_eq!(p0.file_pos, 25);

            let p1 = it.next().unwrap();
            assert_eq!(p1.offset, 2);
            assert_eq!(p1.file_pos, 50);
        }

        f.flush_sync().unwrap();
    }

    #[test]
    pub fn log_open() {
        let log_dir = TestDir::new();

        {
            let mut f = Segment::new(&log_dir, 0, 1024).unwrap();
            let mut buf = MessageBuf::default();
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
            let mut buf = MessageBuf::default();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        let (msgs, NextPosition(log_pos)) = f.read(0, ReadLimit::Messages(10)).unwrap();
        assert_eq!(3, msgs.len());
        assert_eq!(msgs.bytes().len() as u32, log_pos);

        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(i as u64, m.offset().0);
        }
    }

    #[test]
    pub fn log_read_with_msg_limit() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::default();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        let (msgs, NextPosition(log_pos)) = f.read(0, ReadLimit::Messages(2)).unwrap();
        assert_eq!(2, msgs.len());
        assert_eq!(msgs.bytes().len() as u32, log_pos);
    }


    #[test]
    pub fn log_read_with_size_limit() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        let meta = {
            let mut buf = MessageBuf::default();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap()
        };

        // byte max contains message 0, but not the entirety of message 1
        let msgs = f.read(0, ReadLimit::Bytes((meta[1].file_pos + 1) as usize))
            .unwrap()
            .0;

        assert_eq!(1, msgs.len());
    }

    #[test]
    pub fn log_read_with_log_position() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::default();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        // byte max contains message 0, but not the entirety of message 1
        let mut file_pos = 0;
        for i in 0..3 {
            let (msgs, NextPosition(next_pos)) = f.read(file_pos, ReadLimit::Messages(1))
                .unwrap();
            assert_eq!(1, msgs.len());
            assert_eq!(i, msgs.iter().next().unwrap().offset().0);

            file_pos = next_pos;
        }

        // last read should be empty
        let (msgs, NextPosition(next_pos)) = f.read(file_pos, ReadLimit::Messages(1)).unwrap();
        assert_eq!(0, msgs.len());

        // next_pos should be the same as the input file pos
        assert_eq!(file_pos, next_pos);
    }

    #[test]
    pub fn log_read_from_write() {
        let log_dir = TestDir::new();
        let mut f = Segment::new(&log_dir, 0, 1024).unwrap();

        {
            let mut buf = MessageBuf::default();
            buf.push("0123456789");
            buf.push("aaaaaaaaaa");
            buf.push("abc");
            f.append(&mut buf).unwrap();
        }

        let (msgs, _) = f.read(0, ReadLimit::Messages(10)).unwrap();
        assert_eq!(3, msgs.len());

        {
            let mut buf = MessageBuf::default();
            buf.push("foo");
            f.append(&mut buf).unwrap();
        }

        let (msgs, NextPosition(log_pos)) = f.read(0, ReadLimit::Messages(10)).unwrap();
        assert_eq!(4, msgs.len());
        assert_eq!(msgs.bytes().len() as u32, log_pos);

        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(i as u64, m.offset().0);
        }
    }

    #[bench]
    fn bench_segment_append(b: &mut Bencher) {
        let path = TestDir::new();

        let mut seg = Segment::new(path, 100u64, 100 * 1024 * 1024).unwrap();
        let payload = b"01234567891011121314151617181920";

        b.iter(|| {
            let mut buf = MessageBuf::default();
            buf.push(payload);
            seg.append(&mut buf).unwrap();
        });
    }
}
