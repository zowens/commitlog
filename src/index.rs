use byteorder::{BigEndian, ByteOrder};
use memmap::{Mmap, Protection};
use std::path::{Path, PathBuf};
use std::io::{self, Write};
use std::fs::{OpenOptions, File};

/// Number of byes in each entry pair
pub static INDEX_ENTRY_BYTES: usize = 8;

/// An index is a file with pairs of relative offset to file position offset
/// of messages at the relative offset messages. The index is Memory Mapped.
pub struct Index {
    file: File,
    mmap: Mmap,
    mode: AccessMode,

    /// next starting byte in index file offset to write
    next_write_pos: usize,
    base_offset: u64,
}

/// Describes the access mode of the index
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AccessMode {
    /// Only reads are permitted.
    Read,
    /// This is the active index and can be read or written to.
    ReadWrite,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct IndexEntry {
    rel_offset: u32,
    base_offset: u64,
    file_pos: u32,
}

impl IndexEntry {
    #[inline]
    #[allow(dead_code)]
    pub fn relative_offset(&self) -> u32 {
        self.rel_offset
    }

    #[inline]
    #[allow(dead_code)]
    pub fn offset(&self) -> u64 {
        self.base_offset + (self.rel_offset as u64)
    }

    #[inline]
    #[allow(dead_code)]
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
    pub fn new<P>(log_dir: P, base_offset: u64, file_bytes: usize) -> io::Result<Index>
        where P: AsRef<Path>
    {
        // open the file, expecting to create it
        let index_path = {
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", base_offset));
            path_buf.set_extension("index");
            path_buf
        };

        let index_file = try!(OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create_new(true)
            .open(&index_path));

        // read the metadata and truncate
        let meta = try!(index_file.metadata());
        let len = meta.len();
        if len == 0 {
            try!(index_file.set_len(file_bytes as u64));
        }

        let mmap = try!(Mmap::open(&index_file, Protection::ReadWrite));

        Ok(Index {
            file: index_file,
            mmap: mmap,
            mode: AccessMode::ReadWrite,
            next_write_pos: 0,
            base_offset: base_offset,
        })
    }

    pub fn can_write(&self) -> bool {
        self.mode == AccessMode::ReadWrite && self.size() >= (self.next_write_pos + 8)
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.mmap.len()
    }

    pub fn append(&mut self, abs_offset: u64, position: u32) -> Result<(), IndexWriteError> {
        assert!(abs_offset >= self.base_offset);

        if !self.can_write() {
            return Err(IndexWriteError::IndexFull);
        }

        if abs_offset < self.base_offset {
            return Err(IndexWriteError::OffsetLessThanBase);
        }

        unsafe {
            let mem_slice: &mut [u8] = self.mmap.as_mut_slice();
            let offset = (abs_offset - self.base_offset) as u32;
            let buf_pos = self.next_write_pos;

            BigEndian::write_u32(&mut mem_slice[buf_pos..buf_pos + 4], offset);
            BigEndian::write_u32(&mut mem_slice[buf_pos + 4..buf_pos + 8], position);

            self.next_write_pos += 8;

            Ok(())
        }
    }

    pub fn set_readonly(&mut self) -> io::Result<()> {
        if self.mode != AccessMode::Read {
            self.mode = AccessMode::Read;
            self.flush_sync()
        } else {
            Ok(())
        }
    }

    pub fn flush_sync(&mut self) -> io::Result<()> {
        try!(self.mmap.flush());
        self.file.flush()
    }

    #[allow(dead_code)]
    pub fn read_entry(&self, i: usize) -> Result<Option<IndexEntry>, IndexReadError> {
        if self.size() < (i + 1) * 8 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::testutil::*;

    #[test]
    fn index() {
        let path = TestDir::new();
        let mut index = Index::new(&path, 9u64, 1000usize).unwrap();

        assert_eq!(1000, index.size());
        index.append(11u64, 0xffff).unwrap();
        index.append(12u64, 0xeeee).unwrap();
        index.flush_sync().unwrap();

        let e0 = index.read_entry(0).unwrap().unwrap();
        assert_eq!(2u32, e0.relative_offset());
        assert_eq!(11u64, e0.offset());
        assert_eq!(0xffff, e0.file_position());

        let e1 = index.read_entry(1).unwrap().unwrap();
        assert_eq!(3u32, e1.relative_offset());
        assert_eq!(12u64, e1.offset());
        assert_eq!(0xeeee, e1.file_position());

        // read an entry that does not exist
        let e2 = index.read_entry(2).unwrap();
        assert_eq!(None, e2);
    }

    #[test]
    fn index_set_readonly() {
        let path = TestDir::new();
        let mut index = Index::new(&path, 10u64, 1000usize).unwrap();

        index.append(11u64, 0xffff).unwrap();
        index.append(12u64, 0xeeee).unwrap();

        // set_readonly it
        index.set_readonly().expect("Unable to set readonly");

        // append should fail with insertion error
        assert_eq!(index.append(13u64, 0xeeeeee),
                   Err(IndexWriteError::IndexFull));


        let e1 = index.read_entry(1).unwrap().unwrap();
        assert_eq!(2u32, e1.relative_offset());
        assert_eq!(12u64, e1.offset());
        assert_eq!(0xeeee, e1.file_position());

        // read an entry that does not exist
        let e2 = index.read_entry(2).unwrap();
        assert_eq!(None, e2);
    }

}
