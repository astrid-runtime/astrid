//! Explicit persistence models and deterministic crash-image generation.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroUsize};
use std::path::Path;

use super::{CrashReplayError, CrashTrace, TraceEffect, TraceFileId};

/// Hard bounds for one exhaustive replay run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayLimits {
    incomplete_append_bytes: usize,
    volatile_blocks: NonZeroU8,
    images: NonZeroUsize,
}

impl ReplayLimits {
    /// Construct explicit exhaustive-generation bounds.
    #[must_use]
    pub const fn new(
        max_incomplete_append_bytes: usize,
        max_volatile_blocks: NonZeroU8,
        max_images: NonZeroUsize,
    ) -> Self {
        Self {
            incomplete_append_bytes: max_incomplete_append_bytes,
            volatile_blocks: max_volatile_blocks,
            images: max_images,
        }
    }

    /// Conservative limits for small normal-CI traces.
    #[must_use]
    pub fn ci() -> Self {
        let volatile_blocks = NonZeroU8::new(16).unwrap_or(NonZeroU8::MIN);
        let images = NonZeroUsize::new(100_000).unwrap_or(NonZeroUsize::MIN);
        Self::new(16 * 1024, volatile_blocks, images)
    }
}

/// Explicit filesystem persistence contract used to generate crash states.
pub trait PersistenceModel {
    /// Stable model name written into failure diagnostics.
    fn name(&self) -> &'static str;

    /// Storage block size used for torn/stale/reordered persistence choices.
    fn block_bytes(&self) -> NonZeroUsize;

    /// Deterministic stand-in for unknown pre-write physical bytes.
    ///
    /// This does not claim that a filesystem exposes old allocation contents.
    /// It ensures recovery is tested against non-zero stale data rather than
    /// accidentally treating zero-fill as the only incomplete-write shape.
    fn stale_byte(&self, offset: usize) -> u8;
}

/// Conservative append/write model around completed per-file `sync_data`.
///
/// A completed barrier makes all earlier effects on that file durable. Since
/// the last barrier, an inode length may remain old or become current; every
/// byte prefix of the latest append may survive; and arbitrary changed blocks
/// may reach their new values while other blocks retain stale bytes. Effects
/// never move across a completed barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConservativeDataSync {
    block_bytes: NonZeroUsize,
}

impl ConservativeDataSync {
    /// Construct the model with the filesystem block granularity under test.
    #[must_use]
    pub const fn new(block_bytes: NonZeroUsize) -> Self {
        Self { block_bytes }
    }
}

impl PersistenceModel for ConservativeDataSync {
    fn name(&self) -> &'static str {
        "conservative-per-file-sync-data-v1"
    }

    fn block_bytes(&self) -> NonZeroUsize {
        self.block_bytes
    }

    fn stale_byte(&self, offset: usize) -> u8 {
        0xa5_u8
            ^ offset
                .to_le_bytes()
                .iter()
                .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
    }
}

/// One generated authoritative-file image at an operation prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashImage {
    model: &'static str,
    operation_prefix: usize,
    ordinal: usize,
    files: BTreeMap<TraceFileId, Vec<u8>>,
    acknowledged: Vec<String>,
    publications: Vec<(TraceFileId, u64, u64)>,
}

impl CrashImage {
    /// Persistence model that admitted this image.
    #[must_use]
    pub const fn model(&self) -> &'static str {
        self.model
    }

    /// Number of trace effects observed before the simulated crash.
    #[must_use]
    pub const fn operation_prefix(&self) -> usize {
        self.operation_prefix
    }

    /// Deterministic image number within this prefix.
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// Borrow the generated file bytes.
    #[must_use]
    pub const fn files(&self) -> &BTreeMap<TraceFileId, Vec<u8>> {
        &self.files
    }

    /// Borrow all commit labels acknowledged by this prefix.
    #[must_use]
    pub fn acknowledged_commits(&self) -> &[String] {
        &self.acknowledged
    }

    /// Borrow root-publication ranges observed by this prefix.
    #[must_use]
    pub fn root_publications(&self) -> &[(TraceFileId, u64, u64)] {
        &self.publications
    }

    /// Materialize this image without inventing non-traced files.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the directory or a file cannot be written.
    pub fn materialize(&self, directory: &Path) -> Result<(), CrashReplayError> {
        std::fs::create_dir_all(directory).map_err(|source| CrashReplayError::Io {
            operation: "create crash-image directory",
            path: directory.to_path_buf(),
            source,
        })?;
        for (file, bytes) in &self.files {
            let path = directory.join(file.as_str());
            std::fs::write(&path, bytes).map_err(|source| CrashReplayError::Io {
                operation: "write crash-image file",
                path,
                source,
            })?;
        }
        Ok(())
    }
}

/// Deterministically ordered crash images from all operation prefixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashImageSet {
    images: Vec<CrashImage>,
}

impl CrashImageSet {
    /// Borrow the generated images.
    #[must_use]
    pub fn images(&self) -> &[CrashImage] {
        &self.images
    }

    /// Consume the set into generated images.
    #[must_use]
    pub fn into_images(self) -> Vec<CrashImage> {
        self.images
    }
}

#[derive(Clone, Debug)]
struct FileState {
    durable: Vec<u8>,
    visible: Vec<u8>,
    latest_append: Option<(usize, usize)>,
}

pub(super) fn generate(
    trace: &CrashTrace,
    model: &impl PersistenceModel,
    limits: ReplayLimits,
) -> Result<CrashImageSet, CrashReplayError> {
    let mut files: BTreeMap<_, _> = trace
        .initial_files()
        .iter()
        .map(|(file, bytes)| {
            (
                file.clone(),
                FileState {
                    durable: bytes.clone(),
                    visible: bytes.clone(),
                    latest_append: None,
                },
            )
        })
        .collect();
    let mut acknowledged = trace.initial_acknowledgements().to_vec();
    let mut publications = Vec::new();
    let mut images = Vec::new();
    append_prefix_images(
        &files,
        &acknowledged,
        &publications,
        model,
        limits,
        0,
        &mut images,
    )?;

    for (effect_index, effect) in trace.effects().iter().enumerate() {
        apply_effect(&mut files, &mut acknowledged, &mut publications, effect)?;
        append_prefix_images(
            &files,
            &acknowledged,
            &publications,
            model,
            limits,
            effect_index
                .checked_add(1)
                .ok_or(CrashReplayError::LengthOverflow)?,
            &mut images,
        )?;
    }
    Ok(CrashImageSet { images })
}

fn apply_effect(
    files: &mut BTreeMap<TraceFileId, FileState>,
    acknowledged: &mut Vec<String>,
    publications: &mut Vec<(TraceFileId, u64, u64)>,
    effect: &TraceEffect,
) -> Result<(), CrashReplayError> {
    match effect {
        TraceEffect::Append {
            file,
            pre_len,
            bytes,
        } => {
            let state = file_state(files, file)?;
            if usize::try_from(*pre_len).ok() != Some(state.visible.len()) {
                return Err(CrashReplayError::TraceMismatch("append pre-length differs"));
            }
            let start = state.visible.len();
            state.visible.extend_from_slice(bytes);
            state.latest_append = Some((start, bytes.len()));
        },
        TraceEffect::Write {
            file,
            offset,
            previous,
            bytes,
        } => {
            if previous.len() != bytes.len() {
                return Err(CrashReplayError::TraceMismatch("write changed length"));
            }
            let state = file_state(files, file)?;
            let start = usize::try_from(*offset).map_err(|_| CrashReplayError::LengthOverflow)?;
            let end = start
                .checked_add(bytes.len())
                .ok_or(CrashReplayError::LengthOverflow)?;
            if state.visible.get(start..end) != Some(previous.as_slice()) {
                return Err(CrashReplayError::TraceMismatch(
                    "write previous bytes differ",
                ));
            }
            state.visible[start..end].copy_from_slice(bytes);
            state.latest_append = None;
        },
        TraceEffect::Truncate { file, pre_len, len } => {
            let state = file_state(files, file)?;
            if usize::try_from(*pre_len).ok() != Some(state.visible.len()) {
                return Err(CrashReplayError::TraceMismatch(
                    "truncate pre-length differs",
                ));
            }
            let len = usize::try_from(*len).map_err(|_| CrashReplayError::LengthOverflow)?;
            if len > state.visible.len() {
                return Err(CrashReplayError::TraceMismatch("truncate grew the file"));
            }
            state.visible.truncate(len);
            state.latest_append = None;
        },
        TraceEffect::Barrier { file } => {
            let state = file_state(files, file)?;
            state.durable.clone_from(&state.visible);
            state.latest_append = None;
        },
        TraceEffect::RootPublication { file, offset, len } => {
            let state = file_state(files, file)?;
            let end = offset
                .checked_add(*len)
                .ok_or(CrashReplayError::LengthOverflow)?;
            if end
                > u64::try_from(state.visible.len())
                    .map_err(|_| CrashReplayError::LengthOverflow)?
            {
                return Err(CrashReplayError::TraceMismatch("publication exceeds file"));
            }
            publications.push((file.clone(), *offset, *len));
        },
        TraceEffect::AcknowledgedCommit { label } => acknowledged.push(label.clone()),
    }
    Ok(())
}

fn file_state<'a>(
    files: &'a mut BTreeMap<TraceFileId, FileState>,
    file: &TraceFileId,
) -> Result<&'a mut FileState, CrashReplayError> {
    files
        .get_mut(file)
        .ok_or_else(|| CrashReplayError::UnknownFile(file.clone()))
}

#[allow(clippy::too_many_arguments)]
fn append_prefix_images(
    files: &BTreeMap<TraceFileId, FileState>,
    acknowledged: &[String],
    publications: &[(TraceFileId, u64, u64)],
    model: &impl PersistenceModel,
    limits: ReplayLimits,
    operation_prefix: usize,
    images: &mut Vec<CrashImage>,
) -> Result<(), CrashReplayError> {
    let mut combinations = vec![BTreeMap::new()];
    for (file, state) in files {
        let variants = file_variants(state, model, limits)?;
        let next_count = combinations
            .len()
            .checked_mul(variants.len())
            .ok_or(CrashReplayError::LengthOverflow)?;
        require_bound(
            "images",
            images.len().saturating_add(next_count),
            limits.images.get(),
        )?;
        let mut next = Vec::with_capacity(next_count);
        for combination in combinations {
            for variant in &variants {
                let mut extended = combination.clone();
                extended.insert(file.clone(), variant.clone());
                next.push(extended);
            }
        }
        combinations = next;
    }
    for (ordinal, files) in combinations.into_iter().enumerate() {
        images.push(CrashImage {
            model: model.name(),
            operation_prefix,
            ordinal,
            files,
            acknowledged: acknowledged.to_vec(),
            publications: publications.to_vec(),
        });
    }
    Ok(())
}

fn file_variants(
    state: &FileState,
    model: &impl PersistenceModel,
    limits: ReplayLimits,
) -> Result<Vec<Vec<u8>>, CrashReplayError> {
    let mut variants = BTreeSet::new();
    variants.insert(state.durable.clone());
    variants.insert(state.visible.clone());
    if state.durable == state.visible {
        return Ok(variants.into_iter().collect());
    }

    if let Some((start, len)) = state.latest_append {
        require_bound(
            "incomplete-append-bytes",
            len,
            limits.incomplete_append_bytes,
        )?;
        for written in 0..=len {
            let visible_len = start
                .checked_add(written)
                .ok_or(CrashReplayError::LengthOverflow)?;
            insert_length_variants(&mut variants, state, visible_len, model, limits)?;
        }
    } else {
        insert_length_variants(&mut variants, state, state.visible.len(), model, limits)?;
    }
    Ok(variants.into_iter().collect())
}

fn insert_length_variants(
    variants: &mut BTreeSet<Vec<u8>>,
    state: &FileState,
    visible_len: usize,
    model: &impl PersistenceModel,
    limits: ReplayLimits,
) -> Result<(), CrashReplayError> {
    let visible = state
        .visible
        .get(..visible_len)
        .ok_or(CrashReplayError::LengthOverflow)?;
    if visible_len >= state.durable.len() {
        let mut zero_prior = state.durable.clone();
        zero_prior.resize(visible_len, 0);
        let mut stale_prior = state.durable.clone();
        stale_prior
            .extend((state.durable.len()..visible_len).map(|offset| model.stale_byte(offset)));
        for baseline in [zero_prior, stale_prior] {
            insert_block_subsets(variants, &baseline, visible, visible_len, model, limits)?;
        }
    } else {
        for baseline in [state.durable.clone(), state.durable[..visible_len].to_vec()] {
            insert_block_subsets(variants, &baseline, visible, visible_len, model, limits)?;
        }
    }
    Ok(())
}

fn insert_block_subsets(
    variants: &mut BTreeSet<Vec<u8>>,
    baseline: &[u8],
    visible: &[u8],
    changed_len: usize,
    model: &impl PersistenceModel,
    limits: ReplayLimits,
) -> Result<(), CrashReplayError> {
    let block_bytes = model.block_bytes().get();
    let changed_blocks: Vec<_> = (0..changed_len.div_ceil(block_bytes))
        .filter(|block| {
            let start = block.saturating_mul(block_bytes);
            let end = start.saturating_add(block_bytes).min(changed_len);
            baseline[start..end] != visible[start..end]
        })
        .collect();
    require_bound(
        "volatile-blocks",
        changed_blocks.len(),
        usize::from(limits.volatile_blocks.get()),
    )?;
    let combinations = 1_usize
        .checked_shl(
            u32::try_from(changed_blocks.len()).map_err(|_| CrashReplayError::LengthOverflow)?,
        )
        .ok_or(CrashReplayError::LengthOverflow)?;
    for mask in 0..combinations {
        let mut torn = baseline.to_vec();
        for (position, block) in changed_blocks.iter().copied().enumerate() {
            if mask & (1_usize << position) == 0 {
                continue;
            }
            let start = block.saturating_mul(block_bytes);
            let end = start.saturating_add(block_bytes).min(changed_len);
            torn[start..end].copy_from_slice(&visible[start..end]);
        }
        if variants.insert(torn) {
            require_bound("file-variants", variants.len(), limits.images.get())?;
        }
    }
    Ok(())
}

fn require_bound(bound: &'static str, actual: usize, limit: usize) -> Result<(), CrashReplayError> {
    if actual > limit {
        return Err(CrashReplayError::ReplayBound {
            bound,
            actual,
            limit,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash_replay::CrashTraceRecorder;

    fn file() -> TraceFileId {
        TraceFileId::new("arena").unwrap()
    }

    #[test]
    fn append_prefixes_and_reordered_blocks_are_exhaustive() {
        let file = file();
        let recorder = CrashTraceRecorder::new(
            BTreeMap::from([(file.clone(), b"old".to_vec())]),
            ["initial".to_owned()],
        )
        .unwrap();
        recorder
            .capture_bytes(&file, b"oldabcdefgh".to_vec())
            .unwrap();
        let trace = recorder.trace().unwrap();
        let model = ConservativeDataSync::new(NonZeroUsize::new(4).unwrap());
        let images = trace.replay(&model, ReplayLimits::ci()).unwrap();
        let bytes: BTreeSet<_> = images
            .images()
            .iter()
            .filter(|image| image.operation_prefix() == 1)
            .map(|image| image.files()[&file].clone())
            .collect();
        for written in 0..=8 {
            let end = 3_usize.checked_add(written).unwrap();
            assert!(bytes.contains(&b"oldabcdefgh"[..end]));
        }
        assert!(bytes.contains(b"old\0\0\0\0\0fgh".as_slice()));
        assert!(bytes.contains(b"old\0bcde\0\0\0".as_slice()));
        let mut stale = b"old".to_vec();
        stale.extend((3..11).map(|offset| model.stale_byte(offset)));
        assert!(bytes.contains(stale.as_slice()));
        let mut stale_with_middle_block = stale;
        stale_with_middle_block[4..8].copy_from_slice(b"bcde");
        assert!(bytes.contains(stale_with_middle_block.as_slice()));
    }

    #[test]
    fn truncate_crosses_inode_lengths_with_prior_write_blocks() {
        let file = file();
        let recorder = CrashTraceRecorder::new(
            BTreeMap::from([(file.clone(), b"abcdefgh".to_vec())]),
            std::iter::empty(),
        )
        .unwrap();
        recorder.capture_bytes(&file, b"ABCD".to_vec()).unwrap();
        let trace = recorder.trace().unwrap();
        let images = trace
            .replay(
                &ConservativeDataSync::new(NonZeroUsize::new(4).unwrap()),
                ReplayLimits::ci(),
            )
            .unwrap();
        let bytes: BTreeSet<_> = images
            .images()
            .iter()
            .filter(|image| image.operation_prefix() == 2)
            .map(|image| image.files()[&file].clone())
            .collect();
        assert_eq!(
            bytes,
            BTreeSet::from([
                b"ABCD".to_vec(),
                b"ABCDefgh".to_vec(),
                b"abcd".to_vec(),
                b"abcdefgh".to_vec(),
            ])
        );
    }

    #[test]
    fn append_prefixes_cross_prior_volatile_write_blocks() {
        let file = file();
        let recorder = CrashTraceRecorder::new(
            BTreeMap::from([(file.clone(), b"old0".to_vec())]),
            std::iter::empty(),
        )
        .unwrap();
        recorder.capture_bytes(&file, b"NEW0abcd".to_vec()).unwrap();
        let trace = recorder.trace().unwrap();
        let images = trace
            .replay(
                &ConservativeDataSync::new(NonZeroUsize::new(4).unwrap()),
                ReplayLimits::ci(),
            )
            .unwrap();
        let bytes: BTreeSet<_> = images
            .images()
            .iter()
            .filter(|image| image.operation_prefix() == 2)
            .map(|image| image.files()[&file].clone())
            .collect();

        assert!(bytes.contains(b"old0a".as_slice()));
        assert!(bytes.contains(b"NEW0\0".as_slice()));
    }

    #[test]
    fn completed_barrier_forbids_earlier_torn_states() {
        let file = file();
        let recorder = CrashTraceRecorder::new(
            BTreeMap::from([(file.clone(), Vec::new())]),
            std::iter::empty(),
        )
        .unwrap();
        recorder.capture_bytes(&file, b"complete".to_vec()).unwrap();
        recorder.barrier(&file).unwrap();
        let trace = recorder.trace().unwrap();
        let images = trace
            .replay(
                &ConservativeDataSync::new(NonZeroUsize::new(4).unwrap()),
                ReplayLimits::ci(),
            )
            .unwrap();
        let after_barrier: Vec<_> = images
            .images()
            .iter()
            .filter(|image| image.operation_prefix() == 2)
            .collect();
        assert_eq!(after_barrier.len(), 1);
        assert_eq!(after_barrier[0].files()[&file], b"complete");
    }

    #[test]
    fn recorder_emits_write_truncate_and_append_in_execution_order() {
        let file = file();
        let recorder = CrashTraceRecorder::new(
            BTreeMap::from([(file.clone(), b"abcdef".to_vec())]),
            std::iter::empty(),
        )
        .unwrap();
        recorder.capture_bytes(&file, b"aZc".to_vec()).unwrap();
        assert_eq!(
            recorder.trace().unwrap().effects(),
            &[
                TraceEffect::Write {
                    file: file.clone(),
                    offset: 1,
                    previous: b"b".to_vec(),
                    bytes: b"Z".to_vec(),
                },
                TraceEffect::Truncate {
                    file,
                    pre_len: 6,
                    len: 3,
                },
            ]
        );
    }
}
