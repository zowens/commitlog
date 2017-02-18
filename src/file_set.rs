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
    closed: BTreeMap<u64, (Index, Segment)>,
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
                    let segment = match Segment::open(f.path(), opts.log_max_bytes) {
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

        // pair up the index and segments (there should be an index per segment)
        let mut closed = segments.into_iter()
            .map(move |(i, s)| {
                match indexes.remove(&i) {
                    Some(v) => (i, (v, s)),
                    None => {
                        // TODO: create the index from the segment
                        panic!("No index found for segment starting at {}", i);
                    }
                }
            })
            .collect::<BTreeMap<u64, (Index, Segment)>>();

        // try to reuse the last index if it is not full. otherwise, open a new index
        // at the correct offset
        let last_entry = closed.keys().next_back().map(|v| *v);
        let (ind, seg) = match last_entry {
            Some(off) => {
                info!("Reusing index and segment starting at offset {}", off);
                closed.remove(&off).unwrap()
            }
            None => {
                info!("Starting new index and segment at offset 0");
                let ind = Index::new(&opts.log_dir, 0, opts.index_max_bytes)?;
                let seg = Segment::new(&opts.log_dir, 0, opts.log_max_bytes)?;
                (ind, seg)
            }
        };

        // mark all closed indexes as readonly (indexes are not opened as readonly)
        for &mut (ref mut ind, _) in closed.values_mut() {
            ind.set_readonly()?;
        }

        Ok(FileSet {
            active_index: ind,
            active_segment: seg,
            closed: closed,
            opts: opts,
        })
    }

    pub fn active_segment_mut(&mut self) -> &mut Segment {
        &mut self.active_segment
    }

    pub fn active_index_mut(&mut self) -> &mut Index {
        &mut self.active_index
    }

    pub fn active_index(&self) -> &Index {
        &self.active_index
    }

    pub fn find_segment(&self, offset: u64) -> Option<&Segment> {
        let active_seg_start_off = self.active_segment.starting_offset();
        if offset >= active_seg_start_off {
            trace!("Segment is contained in the active segment for offset {}",
                   offset);
            Some(&self.active_segment)
        } else {
            self.closed.range(..(offset + 1)).next_back().map(|p| &(p.1).1)
        }
    }

    pub fn find_index(&self, offset: u64) -> Option<&Index> {
        let active_seg_start_off = self.active_index.starting_offset();
        if offset >= active_seg_start_off {
            trace!("Index is contained in the active index for offset {}",
                   offset);
            Some(&self.active_index)
        } else {
            self.closed.range(..(offset + 1)).next_back().map(|p| &(p.1).0)
        }
    }

    pub fn roll_segment(&mut self) -> io::Result<()> {
        self.active_segment.flush_sync()?;
        self.active_index.set_readonly()?;

        let next_offset = self.active_index.next_offset();

        info!("Starting new segment and index at offset {}", next_offset);

        let mut seg = Segment::new(&self.opts.log_dir, next_offset, self.opts.log_max_bytes)?;
        let mut ind = Index::new(&self.opts.log_dir, next_offset, self.opts.index_max_bytes)?;

        // set the segment and index to the new active index/seg
        swap(&mut seg, &mut self.active_segment);
        swap(&mut ind, &mut self.active_index);

        self.closed.insert(seg.starting_offset(), (ind, seg));
        Ok(())
    }

    pub fn log_options(&self) -> &LogOptions {
        &self.opts
    }
}
