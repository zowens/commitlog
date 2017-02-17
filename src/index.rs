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
    where F: Fn(u32) -> Ordering
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

        match f(rel_off) {
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

macro_rules! entry {
    ($mem:ident, $pos:expr) => (
        (LittleEndian::read_u32(&$mem[($pos)..($pos) + 4]), LittleEndian::read_u32(&$mem[($pos) + 4..($pos) + 8]))
    )
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RangeFindError {
    /// The starting offset supplied was not found.
    OffsetNotAppended,
    /// The offset requested exceeded the max bytes.
    MessageExceededMaxBytes,
}

/// Range within a single segment file of messages.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MessageSetRange {
    /// A slice within the log has been found.
    Slice { start: IndexEntry, bytes: u32 },
    IncompleteSlice { start: IndexEntry, last: IndexEntry },
}

impl MessageSetRange {
    pub fn complete(self,
                    max_bytes: u32,
                    next_index_entry: Option<IndexEntry>)
                    -> Result<MessageSetRange, RangeFindError> {
        match self {
            v @ MessageSetRange::Slice { .. } => Ok(v),
            MessageSetRange::IncompleteSlice { start, last } => {
                match next_index_entry {
                    // use the last entry if it falls within max_bytes range
                    Some(e) if e.file_pos - start.file_pos <= max_bytes => {
                        Ok(MessageSetRange::Slice {
                            start: start,
                            bytes: e.file_pos - start.file_pos,
                        })
                    }
                    _ => {
                        // reject start == end (empty append)
                        if start.file_pos == last.file_pos {
                            trace!("Cannot append last message since it exceeded max bytes");
                            Err(RangeFindError::MessageExceededMaxBytes)
                        } else {
                            Ok(MessageSetRange::Slice {
                                start: start,
                                bytes: last.file_pos - start.file_pos,
                            })
                        }
                    }
                }
            }
        }
    }

    pub fn is_incomplete(&self) -> bool {
        match *self {
            MessageSetRange::IncompleteSlice { .. } => true,
            _ => false,
        }
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    /// Only reads are permitted.
    Read,
    /// This is the active index and can be read or written to.
    ReadWrite,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
            let rel_ind_start = index.len() - INDEX_ENTRY_BYTES;
            let last_val = LittleEndian::read_u32(&index[rel_ind_start..rel_ind_start + 4]);
            if last_val == 0 {
                // partial index, search for break point
                INDEX_ENTRY_BYTES *
                binary_search(index, |rel_off| {
                    // if the relative offset is 0 then go to the left,
                    // otherwise go to the right to find a slot with 0
                    //
                    // NOTE: it is assumed the segment will new start at 0
                    // since it contains at least 1 byte of magic
                    if rel_off == 0 {
                        Ordering::Greater
                    } else {
                        Ordering::Less
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
        self.mode == AccessMode::ReadWrite
    }

    #[inline]
    pub fn starting_offset(&self) -> u64 {
        self.base_offset
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.mmap.len()
    }

    // TODO: use memremap on linux
    fn resize(&mut self) -> io::Result<()> {
        // increase length by 50% += 8 for alignment
        let new_len = {
            let l = self.size();
            let new_size = l + (l / 2);
            // align to byte size
            new_size - (new_size % INDEX_ENTRY_BYTES)
        };

        // unmap the file (Set to dummy anonymous map)
        self.mmap = Mmap::anonymous(32, Protection::ReadWrite)?.into_view_sync();
        self.file.set_len(new_len as u64)?;
        self.mmap = Mmap::open(&self.file, Protection::ReadWrite)?.into_view_sync();
        Ok(())
    }

    pub fn append(&mut self, abs_offset: u64, position: u32) -> io::Result<()> {
        trace!("Index append {} => {}", abs_offset, position);

        assert!(abs_offset >= self.base_offset, "Attempt to append to an offset before base offset in index");
        assert!(self.mode == AccessMode::ReadWrite, "Attempt to append to readonly index");

        // check if we need to resize
        if self.size() < (self.next_write_pos + INDEX_ENTRY_BYTES) {
            self.resize()?;
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
        if self.next_write_pos == 0 {
            None
        } else {
            self.read_entry((self.next_write_pos / INDEX_ENTRY_BYTES) - 1)
        }
    }

    pub fn read_entry(&self, i: usize) -> Option<IndexEntry> {
        if self.size() < (i + 1) * 8 {
            return None;
        }

        unsafe {
            let mem_slice = self.mmap.as_slice();
            let start = i * INDEX_ENTRY_BYTES;
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

    /// Finds the index entry corresponding to the offset.
    ///
    /// If the entry does not exist in the index buy an entry > the offset
    /// exists, that entry is used.
    ///
    /// If the entry does not exist and the last entry is < the desired,
    /// the offset has not been written to this index and None value is returned.
    #[allow(dead_code)]
    pub fn find(&self, offset: u64) -> Option<IndexEntry> {
        self.find_index_pos(offset)
            .and_then(|p| {
                let mem_slice = unsafe { self.mmap.as_slice() };
                let (rel_off, file_pos) = entry!(mem_slice, p);
                if rel_off as u64 + self.base_offset < offset {
                    None
                } else {
                    Some(IndexEntry {
                        rel_offset: rel_off,
                        base_offset: self.base_offset,
                        file_pos: file_pos,
                    })
                }
            })
    }

    /// Finds the longest message set range within a single segment aligning to the
    /// `max_bytes` parameter.
    pub fn find_segment_range(&self,
                              offset: u64,
                              max_bytes: u32,
                              seg_bytes: u32)
                              -> Result<MessageSetRange, RangeFindError> {
        assert!(max_bytes > 0, "Cannot request 0 bytes to be read");

        // position within the index to start finding a sequence
        let start_ind_pos = match self.find_index_pos(offset) {
            Some(v) => v,
            _ => return Err(RangeFindError::OffsetNotAppended),
        };

        let mem_slice = unsafe { self.mmap.as_slice() };
        let (start_off, start_file_pos) = entry!(mem_slice, start_ind_pos);

        // try to get until the end of the segment
        if seg_bytes - start_file_pos < max_bytes {
            trace!("Requested range contains the rest of the segment, does not exceed max bytes");
            return Ok(MessageSetRange::Slice {
                start: IndexEntry {
                    rel_offset: start_off,
                    base_offset: self.base_offset,
                    file_pos: start_file_pos,
                },
                bytes: seg_bytes - start_file_pos,
            });
        }

        let mut last_offset = start_off;
        let mut last_file_pos = start_file_pos;
        for p in (start_ind_pos + INDEX_ENTRY_BYTES..self.next_write_pos)
            .step_by(INDEX_ENTRY_BYTES) {
            let (p_off, p_file_pos) = entry!(mem_slice, p);

            // segment reached the end, the slice is complete and contains the
            // last message appended to the segment
            if p_file_pos <= last_file_pos {
                // NOTE: this really shouldn't happen, its a pathological case that should
                // have been tripped by the previous check. Rather than assert here, I'm going
                // to allow it.
                trace!("Segment ended within the index, message set will contain the rest of the \
                        segment");
                return Ok(MessageSetRange::Slice {
                    start: IndexEntry {
                        rel_offset: start_off,
                        base_offset: self.base_offset,
                        file_pos: start_file_pos,
                    },
                    bytes: seg_bytes - start_file_pos,
                });
            }

            // ending at this position would exceed the log.
            if p_file_pos - start_file_pos > max_bytes {
                // read one position back to get the correct size under max_bytes
                let (end_offset, end_file_pos) = entry!(mem_slice, p - INDEX_ENTRY_BYTES);
                if end_offset == start_off {
                    trace!("Message at offset {} exceeds max bytes and cannot be added to the \
                            read set",
                           start_off);
                    return Err(RangeFindError::MessageExceededMaxBytes);
                } else {
                    return Ok(MessageSetRange::Slice {
                        start: IndexEntry {
                            rel_offset: start_off,
                            base_offset: self.base_offset,
                            file_pos: start_file_pos,
                        },
                        bytes: end_file_pos - start_file_pos,
                    });
                }
            }

            last_file_pos = p_file_pos;
            last_offset = p_off;
        }

        Ok(MessageSetRange::IncompleteSlice {
            start: IndexEntry {
                rel_offset: start_off,
                base_offset: self.base_offset,
                file_pos: start_file_pos,
            },
            last: IndexEntry {
                rel_offset: last_offset,
                base_offset: self.base_offset,
                file_pos: last_file_pos,
            },
        })
    }

    fn find_index_pos(&self, offset: u64) -> Option<usize> {
        if offset < self.base_offset {
            // pathological case... not worth exposing Result
            return None;
        }

        let rel_offset = (offset - self.base_offset) as u32;

        let mem_slice = unsafe { self.mmap.as_slice() };
        trace!("offset={} Next write pos = {}", offset, self.next_write_pos);

        // attempt to find the offset assuming no truncation
        // and fall back to binary search otherwise
        if (rel_offset as usize) < self.next_write_pos / INDEX_ENTRY_BYTES {
            trace!("Attempting to read offset from exact location");
            // read exact entry
            let entry_pos = rel_offset as usize * INDEX_ENTRY_BYTES;
            let rel_offset_val = LittleEndian::read_u32(&mem_slice[entry_pos..entry_pos + 4]);
            trace!("Found relative offset. rel_offset = {}, entry offset = {}",
                   rel_offset,
                   rel_offset_val);
            if rel_offset_val == rel_offset {
                return Some(entry_pos);
            }
        }

        let i = binary_search(&mem_slice[0..self.next_write_pos],
                              |v| v.cmp(&rel_offset));
        trace!("Found offset {} at entry {}", offset, i);

        if i < self.next_write_pos / INDEX_ENTRY_BYTES {
            Some(i * INDEX_ENTRY_BYTES)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::testutil::*;
    use std::fs;
    use std::path::PathBuf;
    use test::test::Bencher;
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

        assert!(!index.can_write());

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
    pub fn find_exact() {
        env_logger::init().unwrap_or(());

        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 1000usize).unwrap();
        index.append(10, 1).unwrap();
        index.append(11, 2).unwrap();
        index.append(12, 3).unwrap();
        index.append(13, 4).unwrap();
        index.append(14, 5).unwrap();
        index.append(15, 6).unwrap();
        index.append(16, 7).unwrap();
        index.append(17, 8).unwrap();

        let res = index.find(16).unwrap();
        assert_eq!(6, res.relative_offset());
        assert_eq!(16, res.offset());
        assert_eq!(7, res.file_position());
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

    #[test]
    fn find_segment_range_offset() {
        env_logger::init().unwrap_or(());
        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 40usize).unwrap();
        // -----
        // INSERTION POINT
        //  => 5 messages, each 10 bytes
        // -----
        index.append(10, 10).unwrap();
        index.append(11, 20).unwrap();
        index.append(12, 30).unwrap();
        index.append(13, 40).unwrap();
        index.append(14, 50).unwrap();

        // test offset not in index
        let res = index.find_segment_range(9, 50, 60);
        assert_eq!(Err(RangeFindError::OffsetNotAppended), res);

        // test message exceeds max bytes
        let res = index.find_segment_range(10, 5, 60);
        assert_eq!(Err(RangeFindError::MessageExceededMaxBytes), res);

        // test message within range, not including last message
        let res = index.find_segment_range(10, 20, 60);
        assert_eq!(Ok(MessageSetRange::Slice {
                       start: IndexEntry {
                           rel_offset: 0,
                           base_offset: 10,
                           file_pos: 10,
                       },
                       bytes: 20,
                   }),
                   res);

        // test message set that spans indexes
        //
        // Segment is 1000 bytes long, index knows about first 50 bytes
        // and the max we can read from the range is 500, meaning the
        // range cannot contain the rest of the log.
        let res = index.find_segment_range(10, 500, 1000);
        assert_eq!(Ok(MessageSetRange::IncompleteSlice {
                       start: IndexEntry {
                           rel_offset: 0,
                           base_offset: 10,
                           file_pos: 10,
                       },
                       last: IndexEntry {
                           rel_offset: 4,
                           base_offset: 10,
                           file_pos: 50,
                       },
                   }),
                   res);

        // TODO: do we really want this behavior...?
        let res = index.find_segment_range(14, 500, 1000);
        assert_eq!(Ok(MessageSetRange::IncompleteSlice {
                       start: IndexEntry {
                           rel_offset: 4,
                           base_offset: 10,
                           file_pos: 50,
                       },
                       last: IndexEntry {
                           rel_offset: 4,
                           base_offset: 10,
                           file_pos: 50,
                       },
                   }),
                   res);
    }

    #[test]
    fn message_set_range_complete() {
        // without entry should use last entry as range end
        let starting = MessageSetRange::IncompleteSlice {
            start: IndexEntry {
                rel_offset: 0,
                base_offset: 10,
                file_pos: 10,
            },
            last: IndexEntry {
                rel_offset: 4,
                base_offset: 10,
                file_pos: 50,
            },
        };

        // complete with acceptable range
        assert_eq!(Ok(MessageSetRange::Slice {
                       start: IndexEntry {
                           rel_offset: 0,
                           base_offset: 10,
                           file_pos: 10,
                       },
                       bytes: 50,
                   }),
                   starting.clone().complete(1000,
                                             Some(IndexEntry {
                                                 rel_offset: 0,
                                                 base_offset: 15,
                                                 file_pos: 60,
                                             })));

        // complete with last entry dictating range
        assert_eq!(Ok(MessageSetRange::Slice {
                       start: IndexEntry {
                           rel_offset: 0,
                           base_offset: 10,
                           file_pos: 10,
                       },
                       bytes: 40,
                   }),
                   starting.clone().complete(50,
                                             Some(IndexEntry {
                                                 rel_offset: 0,
                                                 base_offset: 15,
                                                 file_pos: 600,
                                             })));

        // complete with same entry (error)
        let incomplete_same_slice = MessageSetRange::IncompleteSlice {
            start: IndexEntry {
                rel_offset: 0,
                base_offset: 10,
                file_pos: 10,
            },
            last: IndexEntry {
                rel_offset: 0,
                base_offset: 10,
                file_pos: 10,
            },
        };
        assert_eq!(Err(RangeFindError::MessageExceededMaxBytes),
                   incomplete_same_slice.complete(50, None));
    }

    #[test]
    fn index_resize() {
        env_logger::init().unwrap_or(());
        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 32usize).unwrap();
        assert_eq!(32, index.size());
        index.append(10, 10).unwrap();
        index.append(11, 20).unwrap();
        index.append(12, 30).unwrap();
        index.append(13, 40).unwrap();
        assert_eq!(32, index.size());

        assert!(index.append(14, 50).is_ok());

        // make sure the index was resized
        assert_eq!(48, index.size());

        assert_eq!(50, index.find(14).unwrap().file_position());
    }

    #[bench]
    fn bench_find_exact(b: &mut Bencher) {
        let dir = TestDir::new();
        let mut index = Index::new(&dir, 10u64, 9000usize).unwrap();
        for i in 10u32..1010 {
            index.append(i as u64, i).unwrap();
        }
        index.flush_sync().unwrap();
        b.iter(|| { index.find(943).unwrap(); })
    }
}
