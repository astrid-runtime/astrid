//! Capability-relative publication of compact representation generations.

use super::super::{
    CURRENT_PATH, CURRENT_TEMP_PATH, CurrentPointer, DurableError, DurableFile,
    GENERATIONS_DIRECTORY, JOURNAL_PATH, METADATA_PATH, Path, RecoveryLimits, RepresentationStore,
    contiguous, create_cap_file, generation_name, increment, io_error, open_component,
    sync_directory,
};
use super::adoption::{self, VerifiedSealedAdoption};

/// Private native tip preparation before the shared publish/sync/reclaim path.
enum PreparedNativeCheckpoint {
    /// Compaction/recovery: independently rebuild maps from sealed media.
    Reconstruct {
        replacement: Box<RepresentationStore>,
        current: CurrentPointer,
    },
    /// Automatic maintenance: adopt live maps after sealed-media proof.
    Adopt {
        metadata: DurableFile,
        journal: DurableFile,
        current: CurrentPointer,
        proof: VerifiedSealedAdoption,
    },
}

impl PreparedNativeCheckpoint {
    const fn current(&self) -> CurrentPointer {
        match self {
            Self::Reconstruct { current, .. } | Self::Adopt { current, .. } => *current,
        }
    }
}

/// Select reconstructing or adopting tip preparation for native media.
#[derive(Clone, Copy)]
enum NativeCheckpointInstall {
    Reconstruct,
    Adopt,
}

impl RepresentationStore {
    /// Reconstructing native checkpoint. Native compaction calls this after
    /// rebase; automatic maintenance uses [`Self::checkpoint_native_adopting`].
    pub(in crate::engine::durable) fn checkpoint_native(
        &mut self,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        self.checkpoint_native_install(store_root, limits, NativeCheckpointInstall::Reconstruct)
    }

    /// Automatic native maintenance: adopt live maps after sealed-media proof.
    pub(super) fn checkpoint_native_adopting(
        &mut self,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        self.checkpoint_native_install(store_root, limits, NativeCheckpointInstall::Adopt)
    }

    fn checkpoint_native_install(
        &mut self,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
        install: NativeCheckpointInstall,
    ) -> Result<(), DurableError> {
        let root = contiguous::open_representation_root(store_root)?;
        let generations = open_component(&root, Path::new(GENERATIONS_DIRECTORY), false)?;
        let next_name = generation_name(increment(self.journal_generation)?);
        let next = open_component(&generations, Path::new(&next_name), true)?;
        for path in [METADATA_PATH, JOURNAL_PATH] {
            remove_file_if_present(&next, path)?;
        }
        remove_file_if_present(&root, CURRENT_TEMP_PATH)?;
        let metadata = DurableFile::native(create_cap_file(&next, Path::new(METADATA_PATH))?);
        let journal = DurableFile::native(create_cap_file(&next, Path::new(JOURNAL_PATH))?);
        let prepared = match install {
            NativeCheckpointInstall::Reconstruct => {
                let (replacement, current) = self.checkpoint_into(metadata, journal, limits)?;
                PreparedNativeCheckpoint::Reconstruct {
                    replacement: Box::new(replacement),
                    current,
                }
            },
            NativeCheckpointInstall::Adopt => {
                let mut metadata = metadata;
                let mut journal = journal;
                let emit = self.emit_sealed_generation(&mut metadata, &mut journal)?;
                let current = emit.current;
                let proof = self.verify_sealed_generation_for_adoption(
                    &mut metadata,
                    &mut journal,
                    emit,
                    limits,
                )?;
                PreparedNativeCheckpoint::Adopt {
                    metadata,
                    journal,
                    current,
                    proof,
                }
            },
        };
        sync_directory(&next).map_err(|source| io_error("flush checkpoint generation", source))?;
        sync_directory(&generations)
            .map_err(|source| io_error("flush checkpoint generations", source))?;
        let pointer = DurableFile::native(create_cap_file(&root, Path::new(CURRENT_TEMP_PATH))?);
        adoption::write_verified_current_tmp(pointer, prepared.current(), limits)?;
        root.rename(CURRENT_TEMP_PATH, &root, CURRENT_PATH)
            .map_err(|source| io_error("publish native checkpoint", source))?;
        // Once CURRENT publishes, install the selected custody before the root sync
        // barrier. Reconstruct replaces the store; adopt swaps handles in place.
        match prepared {
            PreparedNativeCheckpoint::Reconstruct { replacement, .. } => {
                *self = *replacement;
            },
            PreparedNativeCheckpoint::Adopt {
                metadata,
                journal,
                proof,
                ..
            } => {
                self.adopt_sealed_generation(metadata, journal, proof)?;
            },
        }
        sync_directory(&root)
            .map_err(|source| io_error("flush native checkpoint publication", source))?;
        self.reclaim_native_generations(&generations)
    }

    fn reclaim_native_generations(
        &self,
        generations: &cap_std::fs::Dir,
    ) -> Result<(), DurableError> {
        for entry in generations
            .entries()
            .map_err(|source| io_error("list checkpoint generations", source))?
        {
            let entry = entry.map_err(|source| io_error("read checkpoint generation", source))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !super::obsolete_generation(name, self.journal_generation) {
                continue;
            }
            let old = open_component(generations, Path::new(name), false)?;
            for path in [METADATA_PATH, JOURNAL_PATH] {
                remove_file_if_present(&old, path)?;
            }
            drop(old);
            generations
                .remove_dir(name)
                .map_err(|source| io_error("remove obsolete checkpoint generation", source))?;
        }
        sync_directory(generations)
            .map_err(|source| io_error("flush checkpoint reclamation", source))
    }
}

fn remove_file_if_present(directory: &cap_std::fs::Dir, path: &str) -> Result<(), DurableError> {
    match directory.remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove unused checkpoint file", source)),
    }
}
