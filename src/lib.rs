extern crate crc;
extern crate memmap;
extern crate byteorder;

use std::path::Path;
use std::fs::{OpenOptions, File};
use crc::crc32::checksum_ieee;
use memmap::{Mmap, Protection};
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, Write};

pub struct Message {
    crc: u32,
    payload: Vec<u8>,
}

impl Message {
    pub fn new(payload: Vec<u8>) -> Message {
        let payload_crc = checksum_ieee(&payload);
        Message {
            crc: payload_crc,
            payload: payload,
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn crc(&self) -> u32 {
        self.crc
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

    pub fn offset(&self) -> u64 {
        self.base_offset + (self.rel_offset as u64)
    }

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
    OutOfBounds
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

    pub fn can_write(&self) -> bool {
        self.len() >= (self.next_write_offset + 8)
    }

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

            BigEndian::write_u32(&mut mem_slice[buf_pos..buf_pos+4], offset);
            BigEndian::write_u32(&mut mem_slice[buf_pos+4..buf_pos+8], position);

            self.next_write_offset += 8;

            Ok(())
        }
    }

    pub fn flush_sync(&mut self) -> io::Result<()> {
        try!(self.mmap.flush());
        self.file.flush()
    }

    pub fn read_entry(&self, i: usize) -> Result<Option<IndexEntry>, IndexReadError> {
        if self.len() < (i+1)*8 {
            return Err(IndexReadError::OutOfBounds);
        }

        unsafe {
            let mem_slice = self.mmap.as_slice();
            let start = i*8;
            let offset = BigEndian::read_u32(&mem_slice[start..start+4]);
            if offset == 0 {
                Ok(None)
            } else {
                let pos = BigEndian::read_u32(&mem_slice[start+4..start+8]);
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
    use std::fs;
    use super::*;

    #[test]
    fn message_construction() {
        let msg = Message::new(b"123456789".to_vec());
        assert_eq!(msg.payload(), b"123456789");
        assert_eq!(msg.crc(), 0xcbf43926);
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

        // reopen it
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
}
