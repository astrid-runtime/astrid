//! Verifier and adoption integration checks for automatic checkpoint maintenance.
//!
//! Reconstruction-count regressions live in `adoption_counter_tests`.

use std::io::{self, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::super::volume::{generation_region, remove_region_if_present};
use super::super::{
    ArenaLocation, Blake3PhysicalIdentity, DurableFile, JOURNAL_MAGIC, JournalEntry,
    METADATA_MAGIC, MetadataFrame, MetadataKind, ObjectId, RecoveryLimits, RepresentationStore,
    append_frame, generation_name, increment, open_store_root,
};
use crate::volume::{AstridVolume, HostedFileVolume, VolumeMetadataMutation, VolumeRegion};

fn advance(store: &mut RepresentationStore, offset: u64) {
    let object = store
        .describe_direct(
            ObjectId::new([7; 32]),
            &[42; 8],
            ArenaLocation {
                offset,
                payload_len: 8,
                checksum: [3; 32],
            },
        )
        .unwrap();
    store.rebase_all_direct(&[object]).unwrap();
}

pub(super) fn primed_volume() -> (
    tempfile::TempDir,
    Arc<dyn AstridVolume>,
    RepresentationStore,
    RecoveryLimits,
) {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("adopt.volume")).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for offset in 1..=8 {
        advance(&mut store, offset);
    }
    (directory, volume, store, limits)
}

pub(super) fn next_generation_files(
    store: &RepresentationStore,
    volume: &Arc<dyn AstridVolume>,
) -> (DurableFile, DurableFile) {
    let next = generation_name(increment(store.journal_generation).unwrap());
    let metadata_path = generation_region(&next, "metadata.arena");
    let journal_path = generation_region(&next, "state.journal");
    for path in [&metadata_path, &journal_path] {
        remove_region_if_present(volume, path).unwrap();
    }
    let metadata = DurableFile::volume(Arc::clone(volume), &metadata_path, true).unwrap();
    let journal = DurableFile::volume(Arc::clone(volume), &journal_path, true).unwrap();
    (metadata, journal)
}

#[test]
fn automatic_volume_adoption_preserves_authority_and_replaces_generation_memos() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let active = store.active;
    let reverse = store.reverse.clone();
    let before = store.journal_generation;
    let stale = crate::storage_model::PhysicalMapNodeId::new([255; 32]);
    assert!(!store.profiles.nodes().contains_key(&stale));
    assert!(!store.representations.nodes().contains_key(&stale));
    assert!(!store.placement_entries.nodes().contains_key(&stale));
    store.complete_map_subtrees.insert(stale);
    store.persisted_map_nodes.insert(stale);
    store.checkpoint_volume(&volume, limits).unwrap();
    assert_eq!(store.active, active);
    assert_eq!(store.reverse, reverse);
    assert_eq!(store.journal_generation, before + 1);
    assert!(store.persisted_map_nodes.is_empty());
    assert!(!store.complete_map_subtrees.contains(&stale));
    assert_eq!(
        u64::try_from(store.complete_map_subtrees.len()).unwrap(),
        store.map_frame_count()
    );
    drop(store);
    let recovered = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.active, active);
    assert_eq!(recovered.reverse, reverse);
    assert!(recovered.contains_direct(ObjectId::new([7; 32])));
}

#[test]
fn automatic_native_adoption_preserves_authority_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let root = open_store_root(directory.path()).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate(&root, limits, ObjectId::new([1; 32]), []).unwrap();
    for offset in 1..=8 {
        advance(&mut store, offset);
    }
    let active = store.active;
    store.checkpoint_native_adopting(&root, limits).unwrap();
    assert_eq!(store.active, active);
    assert!(store.persisted_map_nodes.is_empty());
    drop(store);
    let recovered = RepresentationStore::open(&root, limits).unwrap().unwrap();
    assert_eq!(recovered.active, active);
    assert!(recovered.contains_direct(ObjectId::new([7; 32])));
}

#[test]
fn sealed_journal_rejects_altered_prior_digest_with_matching_length() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let mut emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    let metadata_len = metadata.metadata().unwrap().len();
    let mut altered_prior = emit.prior_journal_digest();
    altered_prior[0] ^= 1;
    let bad = JournalEntry::Checkpoint {
        journal_generation: emit.generation(),
        active: Some(store.active),
        state_generation: store.state.generation(),
        prior_journal_digest: Some(altered_prior),
    };
    journal.set_len(0).unwrap();
    journal.seek(SeekFrom::Start(0)).unwrap();
    append_frame(&mut journal, JOURNAL_MAGIC, &bad.encode()).unwrap();
    journal.sync_data().unwrap();
    emit.retarget_expected_lengths(metadata_len, journal.metadata().unwrap().len());
    let err = store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .expect_err("altered prior digest must fail closed");
    let message = format!("{err:?}");
    assert!(
        message.contains("journal entry disagrees") || message.contains("digest disagrees"),
        "{message}"
    );
}

#[test]
fn sealed_journal_rejects_extra_valid_state_cas_frame() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let mut emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    let metadata_len = metadata.metadata().unwrap().len();
    let extra = JournalEntry::StateCas {
        journal_generation: emit.generation(),
        expected: Some(store.active),
        replacement: store.active,
    };
    append_frame(&mut journal, JOURNAL_MAGIC, &extra.encode()).unwrap();
    journal.sync_data().unwrap();
    emit.retarget_expected_lengths(metadata_len, journal.metadata().unwrap().len());
    let err = store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .expect_err("extra StateCas must fail closed");
    let message = format!("{err:?}");
    assert!(
        message.contains("exactly one frame") || message.contains("journal"),
        "{message}"
    );
}

#[test]
fn sealed_metadata_rejects_duplicate_map_node_frame() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let mut emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    let journal_len = journal.metadata().unwrap().len();
    let node = store
        .profiles
        .nodes()
        .values()
        .next()
        .expect("activated store has profile nodes");
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node).unwrap();
    append_frame(&mut metadata, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    metadata.sync_data().unwrap();
    emit.retarget_expected_lengths(metadata.metadata().unwrap().len(), journal_len);
    let err = store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .expect_err("duplicate map node must fail closed");
    let message = format!("{err:?}");
    assert!(
        message.contains("frame count")
            || message.contains("unique node")
            || message.contains("disagree"),
        "{message}"
    );
}

#[test]
fn sealed_metadata_rejects_envelope_identity_body_mismatch() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let mut emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    let journal_len = journal.metadata().unwrap().len();
    let (id_a, _) = store.profiles.nodes().iter().next().unwrap();
    let node_b = store
        .placement_entries
        .nodes()
        .values()
        .chain(store.representations.nodes().values())
        .find(|node| {
            MetadataFrame::map_node(&Blake3PhysicalIdentity, node)
                .ok()
                .is_some_and(|frame| frame.identity != *id_a.as_bytes())
        })
        .expect("need a distinct live map node body");
    let mismatched = MetadataFrame {
        kind: MetadataKind::MapNode,
        identity: *id_a.as_bytes(),
        value: node_b.encode().unwrap(),
    };
    // Replace sealed metadata with only the mismatched frame so length retargeting
    // exercises the body/identity correspondence check rather than pre-length alone.
    metadata.set_len(0).unwrap();
    metadata.seek(SeekFrom::Start(0)).unwrap();
    append_frame(&mut metadata, METADATA_MAGIC, &mismatched.encode().unwrap()).unwrap();
    metadata.sync_data().unwrap();
    emit.retarget_expected_lengths(metadata.metadata().unwrap().len(), journal_len);
    let err = store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .expect_err("identity/body mismatch must fail closed");
    let message = format!("{err:?}");
    assert!(
        message.contains("body disagrees")
            || message.contains("disagree")
            || message.contains("identity")
            || message.contains("contents"),
        "{message}"
    );
}

#[test]
fn unpublished_verified_adoption_candidate_does_not_publish_current() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let before = store.journal_generation;
    let active = store.active;
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .unwrap();
    drop(metadata);
    drop(journal);
    drop(store);
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.journal_generation, before);
    assert_eq!(reopened.active, active);
}

#[derive(Debug)]
pub(super) struct SyncFailOnceVolume {
    inner: Arc<dyn AstridVolume>,
    fail_next_sync: AtomicBool,
    arm_after_current: AtomicBool,
    watched_metadata: Mutex<Option<VolumeRegion>>,
    fail_metadata_write: AtomicBool,
    private_written: AtomicU64,
}

impl SyncFailOnceVolume {
    pub(super) fn new(inner: Arc<dyn AstridVolume>) -> Self {
        Self {
            inner,
            fail_next_sync: AtomicBool::new(false),
            arm_after_current: AtomicBool::new(false),
            watched_metadata: Mutex::new(None),
            fail_metadata_write: AtomicBool::new(false),
            private_written: AtomicU64::new(0),
        }
    }

    pub(super) fn watch_metadata(&self, region: VolumeRegion, fail: bool) {
        *self.watched_metadata.lock().unwrap() = Some(region);
        self.fail_metadata_write.store(fail, Ordering::SeqCst);
        self.private_written.store(0, Ordering::SeqCst);
    }

    pub(super) fn private_written(&self) -> u64 {
        self.private_written.load(Ordering::SeqCst)
    }

    pub(super) fn arm_next_sync_failure(&self) {
        self.arm_after_current.store(true, Ordering::SeqCst);
    }
}

impl AstridVolume for SyncFailOnceVolume {
    fn create_region(&self, region: &VolumeRegion, create_new: bool) -> io::Result<()> {
        self.inner.create_region(region, create_new)
    }

    fn region_exists(&self, region: &VolumeRegion) -> io::Result<bool> {
        self.inner.region_exists(region)
    }

    fn region_len(&self, region: &VolumeRegion) -> io::Result<u64> {
        self.inner.region_len(region)
    }

    fn read_region_at(
        &self,
        region: &VolumeRegion,
        offset: u64,
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        self.inner.read_region_at(region, offset, buffer)
    }

    fn write_region_from(
        &self,
        region: &VolumeRegion,
        offset: u64,
        payload_len: u64,
        payload: &mut dyn io::Read,
    ) -> io::Result<()> {
        let watched = self.watched_metadata.lock().unwrap().as_ref() == Some(region);
        if watched && self.fail_metadata_write.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected private metadata write failure"));
        }
        self.inner
            .write_region_from(region, offset, payload_len, payload)?;
        if watched {
            self.private_written
                .fetch_add(payload_len, Ordering::SeqCst);
        }
        Ok(())
    }

    fn set_region_len(&self, region: &VolumeRegion, length: u64) -> io::Result<()> {
        self.inner.set_region_len(region, length)
    }

    fn remove_region(&self, region: &VolumeRegion) -> io::Result<()> {
        self.inner.remove_region(region)
    }

    fn rename_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        self.inner.rename_region(source, destination)
    }

    fn replace_region(&self, source: &VolumeRegion, destination: &VolumeRegion) -> io::Result<()> {
        self.inner.replace_region(source, destination)
    }

    fn commit_metadata(&self, mutations: &[VolumeMetadataMutation]) -> io::Result<()> {
        self.inner.commit_metadata(mutations)?;
        if mutations.iter().any(|mutation| {
            matches!(mutation,
            VolumeMetadataMutation::Replace { destination, .. }
                if destination.as_str() == "representations/CURRENT")
        }) && self.arm_after_current.swap(false, Ordering::SeqCst)
        {
            self.fail_next_sync.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    fn list_regions(&self, prefix: &str) -> io::Result<Vec<VolumeRegion>> {
        self.inner.list_regions(prefix)
    }

    fn available_space(&self) -> io::Result<Option<u64>> {
        self.inner.available_space()
    }

    fn reclaim(&self) -> io::Result<()> {
        self.inner.reclaim()
    }

    fn sync(&self) -> io::Result<()> {
        if self
            .fail_next_sync
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(io::Error::other("injected post-CURRENT sync failure"));
        }
        self.inner.sync()
    }
}

#[test]
fn sealed_media_rejects_partial_tails_without_repairing_the_file() {
    for journal_tail in [false, true] {
        let (_directory, volume, mut store, limits) = primed_volume();
        let (mut metadata, mut journal) = next_generation_files(&store, &volume);
        let emit = store
            .emit_sealed_generation(&mut metadata, &mut journal)
            .unwrap();
        let length = {
            let file = if journal_tail {
                &mut journal
            } else {
                &mut metadata
            };
            let length = file.metadata().unwrap().len();
            file.set_len(length + 1).unwrap();
            file.sync_data().unwrap();
            length
        };
        let error = store
            .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
            .unwrap_err();
        assert!(format!("{error:?}").contains("length disagrees"));
        let file = if journal_tail { &journal } else { &metadata };
        assert_eq!(
            file.metadata().unwrap().len(),
            length + 1,
            "a fresh generation must be rejected before a cold scanner repairs its tail"
        );
    }
}

#[test]
fn sealed_metadata_requires_all_authority_frames() {
    use super::super::super::scan_frames;
    let (_directory, volume, mut store, limits) = primed_volume();
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let mut emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    let mut payloads = Vec::new();
    scan_frames(
        &mut metadata,
        super::super::format::METADATA_FILE,
        METADATA_MAGIC,
        limits,
        |_, payload| {
            payloads.push(payload.to_vec());
            Ok(())
        },
    )
    .unwrap();
    metadata.set_len(0).unwrap();
    metadata.seek(SeekFrom::Start(0)).unwrap();
    let mut removed = 0;
    for payload in payloads {
        if MetadataFrame::decode(&payload).unwrap().kind == MetadataKind::Catalogue {
            removed += 1;
        } else {
            append_frame(&mut metadata, METADATA_MAGIC, &payload).unwrap();
        }
    }
    assert_eq!(removed, 1);
    metadata.sync_data().unwrap();
    // Match lengths deliberately to exercise authority completeness, not only EOF.
    emit.retarget_expected_lengths(
        metadata.metadata().unwrap().len(),
        journal.metadata().unwrap().len(),
    );
    let error = store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .unwrap_err();
    assert!(format!("{error:?}").contains("contents disagree"));
}

#[test]
fn corrupt_live_reverse_is_rejected_before_current_publication() {
    let (_directory, volume, mut store, limits) = primed_volume();
    let generation = store.journal_generation;
    let active = store.active;
    store.reverse.clear();
    let error = store.checkpoint_volume(&volume, limits).unwrap_err();
    assert!(format!("{error:?}").contains("reverse index disagrees"));
    assert_eq!(store.journal_generation, generation);
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.journal_generation, generation);
    assert_eq!(reopened.active, active);
    assert!(!reopened.reverse.is_empty());
}

#[test]
fn coherent_wrong_slot_domain_is_rejected_before_current_publication() {
    use crate::storage_model::{
        CanonicalPhysicalMap, PhysicalMapDomain, RepresentationCatalogueRoot, RepresentationState,
    };
    let (_directory, volume, mut store, limits) = primed_volume();
    let generation = store.journal_generation;
    let active = store.active;
    let mut entries = Vec::new();
    super::super::recovery::visit_active_entries(&store.profiles, |key, bytes| {
        entries.push((key, bytes.to_vec()));
        Ok(())
    })
    .unwrap();
    store.profiles = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        entries,
    )
    .unwrap();
    store.catalogue = RepresentationCatalogueRoot::new(
        store.catalogue.generation() + 1,
        store.profiles.root(),
        store.profiles.entry_count(),
        store.representations.root(),
        store.representations.entry_count(),
    )
    .unwrap();
    store.state = RepresentationState::new(
        store.state.generation() + 1,
        Some(active),
        store.catalogue.identify(&Blake3PhysicalIdentity),
        store.state.placements(),
    )
    .unwrap();
    store.active = store.state.identify(&Blake3PhysicalIdentity);
    assert!(store.checkpoint_volume(&volume, limits).is_err());
    assert_eq!(store.journal_generation, generation);
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.journal_generation, generation);
    assert_eq!(reopened.active, active);
}

#[test]
fn publication_sync_failure_installs_new_handles_and_preserves_old_media() {
    let directory = tempfile::tempdir().unwrap();
    let inner: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("sync-failure.volume")).unwrap();
    let failing = Arc::new(SyncFailOnceVolume::new(inner));
    let volume: Arc<dyn AstridVolume> = failing.clone();
    let limits = RecoveryLimits::process_addressable();
    let mut store =
        RepresentationStore::activate_volume(&volume, limits, ObjectId::new([1; 32]), []).unwrap();
    for offset in 1..=32 {
        advance(&mut store, offset);
    }
    let generation = store.journal_generation;
    let active = store.active;
    let old_prefix = format!(
        "representations/generations/{}/",
        generation_name(generation)
    );
    let old_media = volume.list_regions(&old_prefix).unwrap();
    assert_eq!(old_media.len(), 2);
    failing.arm_next_sync_failure();
    let error = store.checkpoint_volume(&volume, limits).unwrap_err();
    assert!(
        format!("{error:?}").contains("flush checkpoint publication"),
        "{error:?}"
    );
    assert_eq!(store.journal_generation, generation + 1);
    assert_eq!(store.active, active);
    assert_eq!(volume.list_regions(&old_prefix).unwrap(), old_media);
    let new_metadata = generation_region(&generation_name(generation + 1), "metadata.arena");
    let new_length = volume
        .region_len(&VolumeRegion::new(new_metadata).unwrap())
        .unwrap();
    assert_eq!(store.metadata.metadata().unwrap().len(), new_length);
    assert!(store.persisted_map_nodes.is_empty());
    assert_eq!(
        u64::try_from(store.complete_map_subtrees.len()).unwrap(),
        store.map_frame_count()
    );
    drop(store);
    let reopened = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.journal_generation, generation + 1);
    assert_eq!(reopened.active, active);
}

#[test]
fn coherent_extra_orphan_in_emitter_memo_cannot_authorize_sealed_media() {
    use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapKey};
    let (_directory, volume, mut store, limits) = primed_volume();
    let orphan = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        vec![(PhysicalMapKey::new([253; 32]), vec![19])],
    )
    .unwrap();
    let id = orphan.root().unwrap();
    let mut nodes = store.profiles.nodes().clone();
    nodes.extend(orphan.nodes().iter().map(|(id, node)| (*id, node.clone())));
    store.profiles = CanonicalPhysicalMap::recover(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        store.profiles.root(),
        nodes,
    )
    .unwrap();
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let mut emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, &orphan.nodes()[&id]).unwrap();
    append_frame(&mut metadata, METADATA_MAGIC, &frame.encode().unwrap()).unwrap();
    metadata.sync_data().unwrap();
    emit.include_emitter_node(id);
    emit.retarget_expected_lengths(
        metadata.metadata().unwrap().len(),
        journal.metadata().unwrap().len(),
    );
    let error = store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("unsealed map node"),
        "{error:?}"
    );
}

#[test]
fn sealed_metadata_rejects_missing_live_node_with_coherent_frames() {
    use super::super::super::scan_frames;
    let (_directory, volume, mut store, limits) = primed_volume();
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let mut emit = store
        .emit_sealed_generation(&mut metadata, &mut journal)
        .unwrap();
    let mut payloads = Vec::new();
    scan_frames(
        &mut metadata,
        super::super::format::METADATA_FILE,
        METADATA_MAGIC,
        limits,
        |_, payload| {
            payloads.push(payload.to_vec());
            Ok(())
        },
    )
    .unwrap();
    metadata.set_len(0).unwrap();
    metadata.seek(SeekFrom::Start(0)).unwrap();
    let mut removed = false;
    for payload in payloads {
        if !removed && MetadataFrame::decode(&payload).unwrap().kind == MetadataKind::MapNode {
            removed = true;
        } else {
            append_frame(&mut metadata, METADATA_MAGIC, &payload).unwrap();
        }
    }
    assert!(removed);
    metadata.sync_data().unwrap();
    emit.retarget_expected_lengths(
        metadata.metadata().unwrap().len(),
        journal.metadata().unwrap().len(),
    );
    let error = store
        .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("contents disagree"),
        "{error:?}"
    );
}

#[test]
fn automatic_checkpoint_rejects_forged_authority_counts_before_emission() {
    use crate::storage_model::{RepresentationCatalogueRoot, RepresentationState};
    let (_directory, volume, mut store, limits) = primed_volume();
    store.catalogue = RepresentationCatalogueRoot::new(
        store.catalogue.generation(),
        store.profiles.root(),
        store.profiles.entry_count() + 1,
        store.representations.root(),
        store.representations.entry_count(),
    )
    .unwrap();
    store.state = RepresentationState::new(
        store.state.generation(),
        Some(store.active),
        store.catalogue.identify(&Blake3PhysicalIdentity),
        store.state.placements(),
    )
    .unwrap();
    store.active = store.state.identify(&Blake3PhysicalIdentity);
    let (mut metadata, mut journal) = next_generation_files(&store, &volume);
    let error = store
        .prepare_sealed_adoption(&mut metadata, &mut journal, limits)
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("authority roots disagree"),
        "{error:?}"
    );
    assert_eq!(metadata.metadata().unwrap().len(), 0);
    assert_eq!(journal.metadata().unwrap().len(), 0);
}

#[test]
fn sealed_media_fresh_scan_rejects_same_length_crc_corruption() {
    use std::io::{Read, Write};
    for corrupt_journal in [false, true] {
        let (_directory, volume, mut store, limits) = primed_volume();
        let (mut metadata, mut journal) = next_generation_files(&store, &volume);
        let emit = store
            .emit_sealed_generation(&mut metadata, &mut journal)
            .unwrap();
        let file = if corrupt_journal {
            &mut journal
        } else {
            &mut metadata
        };
        let length = file.metadata().unwrap().len();
        file.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_data().unwrap();
        assert_eq!(file.metadata().unwrap().len(), length);
        store
            .verify_sealed_generation_for_adoption(&mut metadata, &mut journal, &emit, limits)
            .unwrap_err();
    }
}

#[test]
fn sealed_node_body_is_compared_against_every_matching_live_arena() {
    use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode};
    let (_directory, volume, mut store, limits) = primed_volume();
    let (id, node) = store
        .placement_entries
        .nodes()
        .iter()
        .find(|(_, node)| {
            matches!(
                node,
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. }
            )
        })
        .unwrap();
    let id = *id;
    let mut forged = node.clone();
    match &mut forged {
        PhysicalMapNode::Leaf { value, .. } => value[0] ^= 1,
        PhysicalMapNode::Page { entries, .. } => entries[0].1[0] ^= 1,
        _ => unreachable!(),
    }
    let mut nodes = store.profiles.nodes().clone();
    assert!(nodes.insert(id, forged).is_none());
    // A historical unreachable entry may occupy the same ID in another arena.
    // The active canonical proof cannot alone establish cross-arena equality.
    store.profiles = CanonicalPhysicalMap::recover(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Profile,
        store.profiles.root(),
        nodes,
    )
    .unwrap();
    let error = store.checkpoint_volume(&volume, limits).unwrap_err();
    assert!(format!("{error:?}").contains("body disagrees"), "{error:?}");
}
