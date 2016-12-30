use byteorder::{LittleEndian, ByteOrder};
use memmap::{Mmap, MmapViewSync, Protection};
use std::path::{Path, PathBuf};
use std::io::{self, Write};
use std::fs::{OpenOptions, File};
use std::{u64, usize};
use std::cmp::Ordering;

/// Number of byes in each entry pair
pub static INDEX_ENTRY_BYTES: usize = 8;
/// Number of bytes contained in the base name of the file.
pub static INDEX_FILE_NAME_LEN: usize = 20;
/// File extension for the index file.
pub static INDEX_FILE_NAME_EXTENSION: &'static str = "index";

#[inline]
fn binary_search<F>(index: &[u8], f: F) -> usize
    where F: Fn(usize, u32) -> Ordering
{
    assert!(index.len() % INDEX_ENTRY_BYTES == 0);

    let mut i = 0usize;
    let mut j = (index.len() / INDEX_ENTRY_BYTES) - 1;

    while i < j {
        // grab midpoint
        let m = i + ((j - i) / 2);

        // read the relative offset at the midpoint
        let mi = m * INDEX_ENTRY_BYTES;
        let rel_off = LittleEndian::read_u32(&index[mi..mi + 4]);

        match f(m, rel_off) {
            Ordering::Equal => return m,
            Ordering::Less => {
                i = m + 1;
            }
            Ordering::Greater => {
                j = m;
            }
        }
    }
    i
}


/// An index is a file with pairs of relative offset to file position offset
/// of messages at the relative offset messages. The index is Memory Mapped.
pub struct Index {
    file: File,
    mmap: MmapViewSync,
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
    #[cfg(test)]
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

impl Index {
    pub fn new<P>(log_dir: P, base_offset: u64, file_bytes: usize) -> io::Result<Index>
        where P: AsRef<Path>
    {
        // open the file, expecting to create it
        let index_path = {
            let mut path_buf = PathBuf::new();
            path_buf.push(&log_dir);
            path_buf.push(format!("{:020}", base_offset));
            path_buf.set_extension(INDEX_FILE_NAME_EXTENSION);
            path_buf
        };

        info!("Creating index file {:?}", &index_path);

        let index_file = OpenOptions::new().read(true)
            .write(true)
            .append(true)
            .create_new(true)
            .open(&index_path)?;

        // read the metadata and truncate
        let meta = index_file.metadata()?;
        let len = meta.len();
        if len == 0 {
            index_file.set_len(file_bytes as u64)?;
        }

        let mmap = Mmap::open(&index_file, Protection::ReadWrite)?.into_view_sync();

        Ok(Index {
            file: index_file,
            mmap: mmap,
            mode: AccessMode::ReadWrite,
            next_write_pos: 0,
            base_offset: base_offset,
        })
    }

    pub fn open<P>(index_path: P) -> io::Result<Index>
        where P: AsRef<Path>
    {
        let index_file = OpenOptions::new().read(true)
            .write(true)
            .append(true)
            .open(&index_path)?;


        let filename = index_path.as_ref().file_name().unwrap().to_str().unwrap();
        let base_offset = match u64::from_str_radix(&filename[0..INDEX_FILE_NAME_LEN], 10) {
            Ok(v) => v,
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                          "Index file name does not parse as u64"))
            }
        };

        let mmap = Mmap::open(&index_file, Protection::ReadWrite)?.into_view_sync();

        let next_write_pos = unsafe {
            let index = mmap.as_slice();
            assert!(index.len() % INDEX_ENTRY_BYTES == 0);

            // check if this is a full or partial index
            let last_rel_ind_start = index.len() - INDEX_ENTRY_BYTES;
            let last_val = LittleEndian::read_u32(&index[last_rel_ind_start..last_rel_ind_start + 4]);
            if last_val == 0 {
                // partial index, search for break point
                INDEX_ENTRY_BYTES *
                binary_search(index, |i, rel_off| {
                    // if the relative offset is > 0 OR we're
                    // at the first position (its assumed that the
                    // file entry is 0) then go right
                    //
                    // otherwise, go left to find the first relative
                    // offset equal to 0, but not the first
                    if rel_off > 0 || i == 0 {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                })
            } else {
                index.len()
            }
        };

        info!("Opening index {}, next write pos {}",
              filename,
              next_write_pos);

        Ok(Index {
            file: index_file,
            mmap: mmap,
            mode: AccessMode::ReadWrite,
            next_write_pos: next_write_pos,
            base_offset: base_offset,
        })
    }

    pub fn can_write(&self) -> bool {
        self.mode == AccessMode::ReadWrite &&
        self.size() >= (self.next_write_pos + INDEX_ENTRY_BYTES)
    }

    #[inline]
    pub fn starting_offset(&self) -> u64 {
        self.base_offset
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.mmap.len()
    }

    pub fn append(&mut self, abs_offset: u64, position: u32) -> Result<(), IndexWriteError> {
        trace!("Index append {} => {}", abs_offset, position);

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

            LittleEndian::write_u32(&mut mem_slice[buf_pos..buf_pos + 4], offset);
            LittleEndian::write_u32(&mut mem_slice[buf_pos + 4..buf_pos + 8], position);

            self.next_write_pos += 8;

            Ok(())
        }
    }

    pub fn set_readonly(&mut self) -> io::Result<()> {
        if self.mode != AccessMode::Read {
            self.mode = AccessMode::Read;

            // trim un-used entries by reducing mmap view and truncating file
            if self.next_write_pos < self.mmap.len() {
                self.mmap.restrict(0, self.next_write_pos)?;
                if let Err(e) = self.file.set_len(self.next_write_pos as u64) {
                    warn!("Unable to truncate index file {:020}.{} to proper length: {:?}",
                          self.base_offset,
                          INDEX_FILE_NAME_EXTENSION,
                          e);
                }
            }

            self.flush_sync()
        } else {
            Ok(())
        }
    }

    pub fn flush_sync(&mut self) -> io::Result<()> {
        self.mmap.flush()?;
        self.file.flush()
    }

    pub fn last_entry(&self) -> Option<IndexEntry> {
        self.read_entry((self.next_write_pos / INDEX_ENTRY_BYTES) - 1)
    }

    pub fn read_entry(&self, i: usize) -> Option<IndexEntry> {
        if self.size() < (i + 1) * 8 {
            return None;
        }

        unsafe {
            let mem_slice = self.mmap.as_slice();
            let start = i * 8;
            let offset = LittleEndian::read_u32(&mem_slice[start..start + 4]);
            if offset == 0 && i > 0 {
                None
            } else {
                let pos = LittleEndian::read_u32(&mem_slice[start + 4..start + 8]);
                Some(IndexEntry {
                    rel_offset: offset,
                    base_offset: self.base_offset,
                    file_pos: pos,
                })
            }
        }
    }

    // Finds the index entry corresponding to the offset.
    //
    // If the entry does not exist in the index buy an entry > the offset
    // exists, that entry is used.
    //
    // If the entry does not exist and the last entry is < the desired,
    // the offset has not been written to this index and None value is returned.
    pub fn find(&self, offset: u64) -> Option<IndexEntry> {
        if offset < self.base_offset {
            // pathological case... not worth exposing Result
            return None;
        }

        let rel_offset = (offset - self.base_offset) as u32;

        unsafe {
            let mem_slice = self.mmap.as_slice();
            trace!("offset={} Next write pos = {}", offset, self.next_write_pos);
            let i = binary_search(&mem_slice[0..self.next_write_pos],
                                  |_, v| v.cmp(&rel_offset));
            trace!("Found offset {} at entry {}", offset, i);

            if i < self.next_write_pos / INDEX_ENTRY_BYTES {
                let entry_start = i * INDEX_ENTRY_BYTES;
                let rel_offset_val = LittleEndian::read_u32(&mem_slice[entry_start..entry_start + 4]);
                let file_pos_val = LittleEndian::read_u32(&mem_slice[entry_start + 4..entry_start +
                                                                                   8]);

                // ignore if the offset is < desired (does not exist in this index)
                if rel_offset_val < rel_offset {
                    None
                } else {
                    Some(IndexEntry {
                        rel_offset: rel_offset_val,
                        base_offset: self.base_offset,
                        file_pos: file_pos_val,
                    })
                }
            } else {
                None
            }
        }

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::testutil::*;
    use std::fs;
    use std::path::PathBuf;
    use env_logger;

    #[test]
    pub fn index() {
        let path = TestDir::new();
        let mut index = Index::new(&path, 9u64, 1000usize).unwrap();

        assert_eq!(1000, index.size());
        index.append(11u64, 0xffff).unwrap();
        index.append(12u64, 0xeeee).unwrap();
        index.flush_sync().unwrap();

        let e0 = index.read_entry(0).unwrap();
        assert_eq!(2u32, e0.relative_offset());
        assert_eq!(11u64, e0.offset());
        assert_eq!(0xffff, e0.file_position());

        let e1 = index.read_entry(1).unwrap();
        assert_eq!(3u32, e1.relative_offset());
        assert_eq!(12u64, e1.offset());
        assert_eq!(0xeeee, e1.file_position());

        // read an entry that does not exist
        let e2 = index.read_entry(2);
        assert_eq!(None, e2);
    }

    #[test]
    pub fn index_set_readonly() {
        let path = TestDir::new();
        let mut index = Index::new(&path, 10u64, 1000usize).unwrap();

        index.append(11u64, 0xffff).unwrap();
        index.append(12u64, 0xeeee).unwrap();

        // set_readonly it
        index.set_readonly().expect("Unable to set readonly");

        // append should fail with insertion error
        assert_eq!(index.append(13u64, 0xeeeeee),
                   Err(IndexWriteError::IndexFull));


        let e1 = index.read_entry(1).unwrap();
        assert_eq!(2u32, e1.relative_offset());
        assert_eq!(12u64, e1.offset());
        assert_eq!(0xeeee, e1.file_position());

        // read an entry that does not exist
        let e2 = index.read_entry(2);
        assert_eq!(None, e2);
    }

    #[test]
    pub fn open_index() {
        let dir = TestDir::new();
        // issue some writes
        {
            let mut index = Index::new(&dir, 10u64, 1000usize).unwrap();
            index.append(10, 0).unwrap();
            index.append(11, 10).unwrap();
            index.append(12, 20).unwrap();
            index.append(13, 30).unwrap();
            index.append(14, 40).unwrap();
            index.set_readonly().unwrap();
        }

        // now open it
        {
            let mut index_path = PathBuf::new();
            index_path.push(&dir);
            index_path.push("00000000000000000010.index");

            let meta = fs::metadata(&index_path).unwrap();
            assert!(meta.is_file());

            let index = Index::open(&index_path).unwrap();

            for i in 0..5usize {
                let e = index.read_entry(i);
                assert!(e.is_some());
                assert_eq!(e.unwrap().relative_offset(), i as u32);
                assert_eq!(e.unwrap().offset(), (i + 10) as u64);
                assert_eq!(e.unwrap().file_position(), (i * 10) as u32);
            }
        }
    }

    #[test]
    pub fn find() {
        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 1000usize).unwrap();
        index.append(10, 1).unwrap();
        index.append(11, 2).unwrap();
        index.append(12, 3).unwrap();
        index.append(15, 4).unwrap();
        index.append(16, 5).unwrap();
        index.append(17, 6).unwrap();
        index.append(18, 7).unwrap();
        index.append(20, 8).unwrap();

        let res = index.find(16).unwrap();
        assert_eq!(6, res.relative_offset());
        assert_eq!(16, res.offset());
        assert_eq!(5, res.file_position());
    }

    #[test]
    pub fn find_nonexistant_value_finds_next() {
        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 1000usize).unwrap();
        index.append(10, 1).unwrap();
        index.append(11, 2).unwrap();
        index.append(12, 3).unwrap();
        index.append(15, 4).unwrap();
        index.append(16, 5).unwrap();
        index.append(17, 6).unwrap();
        index.append(18, 7).unwrap();
        index.append(20, 8).unwrap();

        let res = index.find(14).unwrap();
        assert_eq!(15, res.offset());
        assert_eq!(5, res.relative_offset());
        assert_eq!(4, res.file_position());
    }

    #[test]
    pub fn find_nonexistant_value_greater_than_max() {
        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 1000usize).unwrap();
        index.append(10, 1).unwrap();
        index.append(11, 2).unwrap();
        index.append(12, 3).unwrap();
        index.append(15, 4).unwrap();
        index.append(16, 5).unwrap();
        index.append(17, 6).unwrap();
        index.append(18, 7).unwrap();
        index.append(20, 8).unwrap();

        let res = index.find(21);
        assert!(res.is_none());
    }

    #[test]
    pub fn find_out_of_bounds() {
        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 1000usize).unwrap();
        index.append(10, 1).unwrap();
        index.append(11, 2).unwrap();
        index.append(12, 3).unwrap();
        index.append(15, 4).unwrap();
        index.append(16, 5).unwrap();
        index.append(17, 6).unwrap();
        index.append(18, 7).unwrap();
        index.append(20, 8).unwrap();

        let res = index.find(2);
        assert!(res.is_none());
    }

    #[test]
    pub fn reopen_partial_index() {
        env_logger::init().unwrap_or(());
        let dir = TestDir::new();
        {
            let mut index = Index::new(&dir, 10u64, 1000usize).unwrap();
            index.append(10, 1).unwrap();
            index.append(11, 2).unwrap();
            index.flush_sync().unwrap();
        }

        {
            let mut index_path = PathBuf::new();
            index_path.push(&dir);
            index_path.push("00000000000000000010.index");
            let index = Index::open(&index_path).unwrap();

            let e0 = index.find(10);
            assert!(e0.is_some());
            assert_eq!(0, e0.unwrap().relative_offset());

            let e1 = index.find(11);
            assert!(e1.is_some());
            assert_eq!(1, e1.unwrap().relative_offset());

            let e2 = index.find(12);
            assert!(e2.is_none());

            let e_last = index.last_entry();
            assert!(e_last.is_some());
            let last_entry = e_last.unwrap();
            assert_eq!(1, last_entry.relative_offset());
            assert_eq!(2, last_entry.file_position());

            // assert_eq!(16, index.size());
            assert!(index.can_write());
        }
    }

    #[test]
    pub fn reopen_full_index() {
        env_logger::init().unwrap_or(());
        let dir = TestDir::new();
        {
            let mut index = Index::new(&dir, 10u64, 16usize).unwrap();
            index.append(10, 1).unwrap();
            index.append(11, 2).unwrap();
            index.flush_sync().unwrap();
        }

        {
            let mut index_path = PathBuf::new();
            index_path.push(&dir);
            index_path.push("00000000000000000010.index");
            let index = Index::open(&index_path).unwrap();
            assert!(!index.can_write());

            let e0 = index.find(10);
            assert!(e0.is_some());
            assert_eq!(0, e0.unwrap().relative_offset());

            let e1 = index.find(11);
            assert!(e1.is_some());
            assert_eq!(1, e1.unwrap().relative_offset());

            let e2 = index.find(12);
            assert!(e2.is_none());

            let e_last = index.last_entry();
            assert!(e_last.is_some());
            let last_entry = e_last.unwrap();
            assert_eq!(1, last_entry.relative_offset());
            assert_eq!(2, last_entry.file_position());
        }
    }
}
