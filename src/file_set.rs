use std::fs;
use std::io;
use std::mem::swap;

use std::collections::BTreeMap;
use super::index::*;
use super::segment::*;
use super::LogOptions;

pub struct FileSet {
    active_index: Index,
    active_segment: Segment,
    closed_indexes: BTreeMap<u64, Index>,
    closed_segments: BTreeMap<u64, Segment>,
    opts: LogOptions,
}

impl FileSet {
    pub fn load_log(opts: LogOptions) -> io::Result<FileSet> {
        let mut segments = BTreeMap::new();
        let mut indexes = BTreeMap::new();

        let files = fs::read_dir(&opts.log_dir)?
            // ignore Err results
            .filter_map(|e| e.ok())
            // ignore directories
            .filter(|e| e.metadata().map(|m| m.is_file()).unwrap_or(false));

        for f in files {
            match f.path().extension() {
                Some(ext) if SEGMENT_FILE_NAME_EXTENSION.eq(ext) => {
                    let segment = match Segment::open(f.path()) {
                        Ok(seg) => seg,
                        Err(e) => {
                            error!("Unable to open segment {:?}: {}", f.path(), e);
                            return Err(e);
                        }
                    };

                    let offset = segment.starting_offset();
                    segments.insert(offset, segment);
                }
                Some(ext) if INDEX_FILE_NAME_EXTENSION.eq(ext) => {
                    let index = match Index::open(f.path()) {
                        Ok(ind) => ind,
                        Err(e) => {
                            error!("Unable to open index {:?}: {}", f.path(), e);
                            return Err(e);
                        }
                    };

                    let offset = index.starting_offset();
                    indexes.insert(offset, index);
                    // TODO: fix missing index updates (crash before write to index)
                }
                _ => {}
            }
        }

        // try to reuse the last index if it is not full. otherwise, open a new index
        // at the correct offset
        let (ind, next_offset) = {
            let last_ind = indexes.values()
                .next_back()
                .and_then(|ind| if ind.can_write() {
                    Some(ind.starting_offset())
                } else {
                    None
                });
            match last_ind {
                Some(starting_off) => {
                    info!("Reusing index starting at offset {}", starting_off);
                    // invariant: index exists in the closed_indexes BTree
                    let ind = indexes.remove(&starting_off).unwrap();
                    let next_off = ind.last_entry()
                        .map(|e| e.offset() + 1)
                        .unwrap_or(starting_off);
                    (ind, next_off)
                }
                None => {
                    let next_off = indexes.values()
                        .next_back()
                        .map(|ind| {
                            let last_entry = ind.last_entry();
                            assert!(last_entry.is_some());
                            last_entry.unwrap().offset() + 1
                        })
                        .unwrap_or(0u64);
                    info!("Starting new index at offset {}", next_off);
                    let ind = Index::new(&opts.log_dir, next_off, opts.index_max_bytes)?;
                    (ind, next_off)
                }
            }
        };

        // mark all closed indexes as readonly (indexes are not opened as readonly)
        for ind in indexes.values_mut() {
            ind.set_readonly()?;
        }

        // reuse closed segment
        let seg = match segments.remove(&next_offset) {
            Some(s) => s,
            None => {
                info!("Starting fresh segment {}", next_offset);
                Segment::new(&opts.log_dir, next_offset, opts.log_max_bytes)?
            }
        };

        Ok(FileSet {
            active_index: ind,
            active_segment: seg,
            closed_indexes: indexes,
            closed_segments: segments,
            opts: opts,
        })
    }

    pub fn active_segment_mut(&mut self) -> &mut Segment {
        &mut self.active_segment
    }

    pub fn active_segment(&self) -> &Segment {
        &self.active_segment
    }

    pub fn active_index_mut(&mut self) -> &mut Index {
        &mut self.active_index
    }

    pub fn find_segment(&self, offset: u64) -> Option<&Segment> {
        let active_seg_start_off = self.active_segment.starting_offset();
        if offset >= active_seg_start_off {
            trace!("Segment is contained in the active segment for offset {}",
                   offset);
            Some(&self.active_segment)
        } else {
            self.closed_segments.range(..(offset + 1)).next_back().map(|p| p.1)
        }
    }

    pub fn find_index(&self, offset: u64) -> Option<&Index> {
        let active_seg_start_off = self.active_index.starting_offset();
        if offset >= active_seg_start_off {
            trace!("Index is contained in the active index for offset {}",
                   offset);
            Some(&self.active_index)
        } else {
            self.closed_indexes.range(..(offset + 1)).next_back().map(|p| p.1)
        }
    }

    pub fn roll_segment(&mut self) -> io::Result<()> {
        self.active_segment.flush_sync()?;
        let next_offset = self.active_segment.next_offset();

        info!("Starting new segment at offset {}", next_offset);

        let mut seg = Segment::new(&self.opts.log_dir, next_offset, self.opts.log_max_bytes)?;

        // set the active segment to the new segment,
        // swap in order to insert the segment into
        // the closed segments tree
        swap(&mut seg, &mut self.active_segment);
        self.closed_segments.insert(seg.starting_offset(), seg);
        Ok(())
    }

    pub fn roll_index(&mut self) -> io::Result<()> {
        try!(self.active_index.set_readonly());

        let offset = self.active_index.last_entry().unwrap().offset() + 1;
        info!("Starting new index at offset {}", offset);

        let mut ind = Index::new(&self.opts.log_dir, offset, self.opts.index_max_bytes)?;

        // set the active index to the new index,
        // swap in order to insert the index into
        // the closed index tree
        swap(&mut ind, &mut self.active_index);
        self.closed_indexes.insert(ind.starting_offset(), ind);
        Ok(())
    }
}
