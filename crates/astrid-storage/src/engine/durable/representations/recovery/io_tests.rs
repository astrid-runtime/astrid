//! Observe media reads through production map serialization and recovery.

use std::cell::Cell;
use std::io::{self, Read, Seek, SeekFrom, Write};

use super::*;
use crate::engine::durable::media::{File, StoreMetadata};
use crate::engine::durable::representations::activation::visit_new_reachable_map_nodes;
use crate::storage_model::PhysicalMapDomain;
use crate::storage_model::physical::RepresentationMap;
use crate::volume::HostedFileVolume;

struct ObservedFile {
    file: File,
    positioned_reads: Cell<usize>,
    positioned_bytes: Cell<usize>,
    requested_bytes: Cell<usize>,
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
        self.requested_bytes
            .set(self.requested_bytes.get().strict_add(bytes.len()));
        let read = self.file.durable_read_at(bytes, offset)?;
        self.positioned_bytes
            .set(self.positioned_bytes.get().strict_add(read));
        Ok(read)
    }
}

fn append_active_map(
    file: &mut ObservedFile,
    original: &CanonicalPhysicalMap,
    historical: bool,
) -> u64 {
    let mut active_bytes = 0_u64;
    let mut ordinal = 0_u64;
    visit_new_reachable_map_nodes(
        original,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        |node| {
            let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)?;
            let location = super::super::append_frame(file, METADATA_MAGIC, &frame.encode()?)?;
            active_bytes =
                active_bytes.strict_add(FRAME_HEADER_LEN.strict_add(location.payload_len));
            if historical {
                let node = PhysicalMapNode::leaf(
                    PhysicalMapDomain::Representation,
                    PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    vec![0x71; 4096],
                );
                let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node)?;
                super::super::append_frame(file, METADATA_MAGIC, &frame.encode()?)?;
                ordinal = ordinal.strict_add(1);
            }
            Ok(())
        },
    )
    .unwrap();
    active_bytes
}

fn assert_active_map_reads(hosted: bool, historical: bool) {
    let count = if historical { 256 } else { 8192 };
    let entries: Vec<_> = (0_u32..count)
        .map(|ordinal| {
            (
                PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                ordinal.to_le_bytes().repeat(8),
            )
        })
        .collect();
    let original = if historical {
        CanonicalPhysicalMap::build(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            entries.clone(),
        )
    } else {
        CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            entries.clone(),
        )
    }
    .unwrap();
    let node_count = original.nodes().len();
    assert!(node_count > 16, "fixture must span many physical nodes");
    let dir = tempfile::tempdir().unwrap();
    let source = if hosted {
        File::volume(
            HostedFileVolume::open(dir.path().join("frames.volume")).unwrap(),
            "metadata",
            true,
        )
        .unwrap()
    } else {
        File::native(tempfile::tempfile().unwrap())
    };
    let mut file = ObservedFile {
        file: source,
        positioned_reads: Cell::new(0),
        positioned_bytes: Cell::new(0),
        requested_bytes: Cell::new(0),
    };
    let active_bytes = append_active_map(&mut file, &original, historical);
    let limits = RecoveryLimits::process_addressable();
    let mut index = recover_metadata(&mut file, limits).unwrap();
    file.positioned_reads.set(0);
    file.positioned_bytes.set(0);
    file.requested_bytes.set(0);
    let recovered = RepresentationMap::recover_exact(
        original.root(),
        index
            .recover_active_nodes(
                PhysicalMapDomain::Representation,
                original.root(),
                &file,
                limits,
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(recovered.root(), original.root());
    assert_eq!(recovered.nodes().len(), node_count);
    for (key, value) in entries {
        assert_eq!(recovered.get(key), Some(value.as_slice()));
    }
    assert_eq!(index.nodes.len(), if historical { node_count } else { 0 });
    assert!(
        index.values.is_empty(),
        "only the active closure stays decoded"
    );
    let reads = file.positioned_reads.get();
    eprintln!(
        "hosted={hosted} historical={historical} active nodes={node_count}; positioned reads={reads}; bytes={}",
        file.positioned_bytes.get()
    );
    assert_eq!(reads, node_count, "one exact read per active node");
    assert_eq!(file.requested_bytes.get(), file.positioned_bytes.get());
    assert_eq!(
        u64::try_from(file.positioned_bytes.get()).unwrap(),
        active_bytes,
        "reconstruction must not reread or prefetch unrelated metadata"
    );
    if historical {
        assert!(active_bytes < file.durable_metadata().unwrap().len());
    }
}

#[test]
fn active_map_materialization_reads_only_its_framed_bytes() {
    for hosted in [false, true] {
        for historical in [false, true] {
            assert_active_map_reads(hosted, historical);
        }
    }
}
