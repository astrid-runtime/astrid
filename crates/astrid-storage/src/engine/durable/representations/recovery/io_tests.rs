//! Observe media reads through production map serialization and recovery.

use std::cell::Cell;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use super::*;
use crate::engine::durable::media::StoreMetadata;
use crate::engine::durable::representations::activation::visit_new_reachable_map_nodes;
use crate::storage_model::PhysicalMapDomain;

struct ObservedFile {
    file: File,
    positioned_reads: Cell<usize>,
    positioned_bytes: Cell<usize>,
}

impl Read for ObservedFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Write for ObservedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for ObservedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl DurableIo for ObservedFile {
    fn durable_metadata(&self) -> io::Result<StoreMetadata> {
        self.file.durable_metadata()
    }

    fn durable_set_len(&self, length: u64) -> io::Result<()> {
        self.file.durable_set_len(length)
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        self.file.durable_sync_data()
    }

    fn durable_read_at_preserves_cursor(&self) -> bool {
        self.file.durable_read_at_preserves_cursor()
    }

    fn durable_read_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<usize> {
        self.positioned_reads
            .set(self.positioned_reads.get().strict_add(1));
        let read = self.file.durable_read_at(bytes, offset)?;
        self.positioned_bytes
            .set(self.positioned_bytes.get().strict_add(read));
        Ok(read)
    }
}

#[test]
fn active_map_materialization_reads_only_its_framed_bytes() {
    let entries: Vec<_> = (0_u32..8192)
        .map(|ordinal| {
            (
                PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                ordinal.to_le_bytes().repeat(8),
            )
        })
        .collect();
    let original = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        entries.clone(),
    )
    .unwrap();
    let node_count = original.nodes().len();
    assert!(node_count > 16, "fixture must span many physical nodes");
    let mut file = ObservedFile {
        file: tempfile::tempfile().unwrap(),
        positioned_reads: Cell::new(0),
        positioned_bytes: Cell::new(0),
    };
    visit_new_reachable_map_nodes(
        &original,
        &BTreeSet::new(),
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        |node| {
            let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)?;
            super::super::append_frame(&mut file, METADATA_MAGIC, &frame.encode()?)?;
            Ok(())
        },
    )
    .unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut index = recover_metadata(&mut file, limits).unwrap();
    file.positioned_reads.set(0);
    file.positioned_bytes.set(0);
    let recovered = index
        .recover_active_map(
            PhysicalMapDomain::Representation,
            original.root(),
            &file,
            limits,
        )
        .unwrap();
    assert_eq!(recovered.root(), original.root());
    assert_eq!(recovered.nodes().len(), node_count);
    for (key, value) in entries {
        assert_eq!(recovered.get(key), Some(value.as_slice()));
    }
    assert_eq!(index.nodes.len(), 0);
    assert!(
        index.values.is_empty(),
        "only the active closure stays decoded"
    );
    let reads = file.positioned_reads.get();
    eprintln!(
        "active nodes={node_count}; positioned reads={reads}; bytes={}",
        file.positioned_bytes.get()
    );
    assert!(
        reads <= node_count * 2,
        "at most header and body reads per node"
    );
    assert_eq!(
        u64::try_from(file.positioned_bytes.get()).unwrap(),
        file.durable_metadata().unwrap().len(),
        "reconstruction must not reread or prefetch unrelated metadata"
    );
}
