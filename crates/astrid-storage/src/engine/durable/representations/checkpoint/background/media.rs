//! Independent media capabilities for captured checkpoint preparation.
//!
//! Live writer handles must not be `try_clone`d: native duplicates can share a
//! seek cursor. Open generation files through a retained directory capability
//! or volume so prefix recovery and tail replay keep independent cursors.

use std::path::Path;
use std::sync::Arc;

use cap_std::fs::Dir;

use crate::volume::AstridVolume;

use super::super::super::contiguous::{open_component, open_representation_root};
use super::super::super::volume::{generation_region, remove_region_if_present};
use super::super::super::{
    CURRENT_PATH, CURRENT_TEMP_PATH, CurrentPointer, DurableError, DurableFile,
    GENERATIONS_DIRECTORY, JOURNAL_PATH, METADATA_PATH, RecoveryLimits, RepresentationStore,
    create_cap_file, generation_name, io_error, open_cap_file, sync_directory,
};

/// Capability that can reopen a generation without borrowing live writer media.
#[derive(Clone)]
pub(in crate::engine::durable) enum CheckpointMedia {
    /// Store-root capability used by native representation layouts.
    Directory(Arc<Dir>),
    /// Astrid volume that owns representation regions.
    Volume(Arc<dyn AstridVolume>),
}

impl CheckpointMedia {
    /// The existing obsolete-frame threshold and conservative free-space gate.
    /// Unknown volume space skips maintenance; it never weakens write admission.
    pub(in crate::engine::durable) fn should_prepare(
        &self,
        store: &RepresentationStore,
    ) -> Result<bool, DurableError> {
        if !store.should_checkpoint_representations_metadata() {
            return Ok(false);
        }
        let Self::Volume(volume) = self else {
            return Ok(true);
        };
        let durable_len = store
            .metadata
            .metadata()
            .map_err(|source| io_error("measure representation metadata length", source))?
            .len();
        Ok(matches!(volume.available_space(), Ok(Some(space)) if space >= durable_len))
    }

    /// Open existing generation files through this capability.
    pub(super) fn open_generation_files(
        &self,
        generation: u64,
    ) -> Result<(DurableFile, DurableFile), DurableError> {
        let name = generation_name(generation);
        match self {
            Self::Directory(store_root) => {
                let root = open_representation_root(store_root)?;
                let generations = open_component(&root, Path::new(GENERATIONS_DIRECTORY), false)?;
                let directory = open_component(&generations, Path::new(&name), false)?;
                let metadata =
                    DurableFile::native(open_cap_file(&directory, Path::new(METADATA_PATH))?);
                let journal =
                    DurableFile::native(open_cap_file(&directory, Path::new(JOURNAL_PATH))?);
                Ok((metadata, journal))
            },
            Self::Volume(volume) => {
                let metadata = DurableFile::volume(
                    Arc::clone(volume),
                    &generation_region(&name, METADATA_PATH),
                    false,
                )?;
                let journal = DurableFile::volume(
                    Arc::clone(volume),
                    &generation_region(&name, JOURNAL_PATH),
                    false,
                )?;
                Ok((metadata, journal))
            },
        }
    }

    /// Create private next-generation media for sealed emission.
    ///
    /// Removes any unpublished next-generation files owned by this preparation
    /// attempt. Does not touch CURRENT or the captured source generation.
    pub(super) fn create_next_generation_files(
        &self,
        next_generation: u64,
    ) -> Result<GenerationFiles, DurableError> {
        let name = generation_name(next_generation);
        match self {
            Self::Directory(store_root) => {
                let root = open_representation_root(store_root)?;
                let generations = open_component(&root, Path::new(GENERATIONS_DIRECTORY), true)?;
                let directory = open_component(&generations, Path::new(&name), true)?;
                for path in [METADATA_PATH, JOURNAL_PATH] {
                    remove_file_if_present(&directory, path)?;
                }
                let guard = NextGenerationGuard {
                    media: self.clone(),
                    generation: next_generation,
                    armed: true,
                };
                let metadata =
                    DurableFile::native(create_cap_file(&directory, Path::new(METADATA_PATH))?);
                let journal =
                    DurableFile::native(create_cap_file(&directory, Path::new(JOURNAL_PATH))?);
                sync_directory(&directory)
                    .map_err(|source| io_error("flush prepared checkpoint generation", source))?;
                sync_directory(&generations).map_err(|source| {
                    io_error("flush prepared checkpoint generations directory", source)
                })?;
                Ok(GenerationFiles {
                    metadata,
                    journal,
                    guard,
                })
            },
            Self::Volume(volume) => {
                let metadata_path = generation_region(&name, METADATA_PATH);
                let journal_path = generation_region(&name, JOURNAL_PATH);
                for path in [&metadata_path, &journal_path] {
                    remove_region_if_present(volume, path)?;
                }
                // Never clear live CURRENT here. CURRENT.tmp belongs to the
                // engine publication owner, not preparation.
                let guard = NextGenerationGuard {
                    media: self.clone(),
                    generation: next_generation,
                    armed: true,
                };
                let metadata = DurableFile::volume(Arc::clone(volume), &metadata_path, true)?;
                let journal = DurableFile::volume(Arc::clone(volume), &journal_path, true)?;
                Ok(GenerationFiles {
                    metadata,
                    journal,
                    guard,
                })
            },
        }
    }

    pub(super) fn write_current(
        &self,
        current: CurrentPointer,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        let pointer = match self {
            Self::Directory(store_root) => {
                let root = open_representation_root(store_root)?;
                remove_file_if_present(&root, CURRENT_TEMP_PATH)?;
                DurableFile::native(create_cap_file(&root, Path::new(CURRENT_TEMP_PATH))?)
            },
            Self::Volume(volume) => {
                remove_region_if_present(volume, "representations/CURRENT.tmp")?;
                DurableFile::volume(Arc::clone(volume), "representations/CURRENT.tmp", true)?
            },
        };
        super::super::adoption::write_verified_current_tmp(pointer, current, limits)
    }

    pub(super) fn publish_current(&self) -> Result<(), DurableError> {
        match self {
            Self::Directory(store_root) => {
                let root = open_representation_root(store_root)?;
                root.rename(CURRENT_TEMP_PATH, &root, CURRENT_PATH)
                    .map_err(|source| io_error("publish native checkpoint", source))
            },
            Self::Volume(volume) => volume
                .commit_metadata(&[RepresentationStore::checkpoint_volume_publication()?])
                .map_err(|source| io_error("publish checkpoint pointer", source)),
        }
    }

    pub(super) fn sync_publication(&self) -> Result<(), DurableError> {
        match self {
            Self::Directory(store_root) => sync_directory(&open_representation_root(store_root)?)
                .map_err(|source| io_error("flush native checkpoint publication", source)),
            Self::Volume(volume) => volume
                .sync()
                .map_err(|source| io_error("flush checkpoint publication", source)),
        }
    }

    pub(in crate::engine::durable::representations) fn reclaim_before(
        &self,
        current: u64,
    ) -> Result<(), DurableError> {
        match self {
            Self::Directory(store_root) => {
                let root = open_representation_root(store_root)?;
                let generations = open_component(&root, Path::new(GENERATIONS_DIRECTORY), false)?;
                super::super::native::reclaim_generations(&generations, current)
            },
            Self::Volume(volume) => {
                for region in volume
                    .list_regions("representations/generations/")
                    .map_err(|source| io_error("list obsolete checkpoint regions", source))?
                {
                    let Some(suffix) = region.as_str().strip_prefix("representations/generations/")
                    else {
                        continue;
                    };
                    let Some((generation, file)) = suffix.split_once('/') else {
                        continue;
                    };
                    if super::super::obsolete_generation(generation, current)
                        && matches!(file, METADATA_PATH | JOURNAL_PATH)
                    {
                        remove_region_if_present(volume, region.as_str())?;
                    }
                }
                volume
                    .sync()
                    .map_err(|source| io_error("flush checkpoint reclamation", source))
            },
        }
    }

    fn remove_generation_files(&self, generation: u64) -> Result<(), DurableError> {
        let name = generation_name(generation);
        match self {
            Self::Directory(store_root) => {
                let root = open_representation_root(store_root)?;
                let generations = open_component(&root, Path::new(GENERATIONS_DIRECTORY), false)?;
                let directory = match open_component(&generations, Path::new(&name), false) {
                    Ok(directory) => directory,
                    Err(DurableError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound =>
                    {
                        return Ok(());
                    },
                    Err(error) => return Err(error),
                };
                for path in [METADATA_PATH, JOURNAL_PATH] {
                    remove_file_if_present(&directory, path)?;
                }
                drop(directory);
                match generations.remove_dir(&name) {
                    Ok(()) => {},
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {},
                    Err(source) => {
                        return Err(io_error("remove unpublished checkpoint generation", source));
                    },
                }
                sync_directory(&generations).map_err(|source| {
                    io_error("flush unpublished checkpoint generation removal", source)
                })
            },
            Self::Volume(volume) => {
                for path in [
                    generation_region(&name, METADATA_PATH),
                    generation_region(&name, JOURNAL_PATH),
                ] {
                    remove_region_if_present(volume, &path)?;
                }
                Ok(())
            },
        }
    }
}

/// Declaration order closes both files before the cleanup guard, including on
/// early proof failure or panic. This matters on native Windows filesystems.
pub(super) struct GenerationFiles {
    pub(super) metadata: DurableFile,
    pub(super) journal: DurableFile,
    pub(super) guard: NextGenerationGuard,
}

/// Removes unpublished next-generation media unless preparation succeeds.
pub(super) struct NextGenerationGuard {
    media: CheckpointMedia,
    generation: u64,
    armed: bool,
}

impl NextGenerationGuard {
    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for NextGenerationGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.media.remove_generation_files(self.generation);
        }
    }
}

fn remove_file_if_present(directory: &Dir, path: &str) -> Result<(), DurableError> {
    match directory.remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove unused checkpoint file", source)),
    }
}
