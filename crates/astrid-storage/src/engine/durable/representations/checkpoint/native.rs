//! Capability-relative publication of compact representation generations.

use super::super::{
    CURRENT_PATH, CURRENT_TEMP_PATH, DurableError, DurableFile, GENERATIONS_DIRECTORY,
    JOURNAL_PATH, METADATA_PATH, Path, RecoveryLimits, RepresentationStore, contiguous,
    create_cap_file, generation_name, increment, io_error, open_component, sync_directory,
};
use super::adoption;

impl RepresentationStore {
    /// Reconstructing native checkpoint after exclusive compaction/rebase.
    pub(in crate::engine::durable) fn checkpoint_native(
        &mut self,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
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
        let (replacement, current) = self.checkpoint_into(metadata, journal, limits)?;
        sync_directory(&next).map_err(|source| io_error("flush checkpoint generation", source))?;
        sync_directory(&generations)
            .map_err(|source| io_error("flush checkpoint generations", source))?;
        let pointer = DurableFile::native(create_cap_file(&root, Path::new(CURRENT_TEMP_PATH))?);
        adoption::write_verified_current_tmp(pointer, current, limits)?;
        root.rename(CURRENT_TEMP_PATH, &root, CURRENT_PATH)
            .map_err(|source| io_error("publish native checkpoint", source))?;
        // Install new custody before a possible publication-barrier failure.
        *self = replacement;
        sync_directory(&root)
            .map_err(|source| io_error("flush native checkpoint publication", source))?;
        self.reclaim_native_generations(&generations)
    }

    fn reclaim_native_generations(
        &self,
        generations: &cap_std::fs::Dir,
    ) -> Result<(), DurableError> {
        reclaim_generations(generations, self.journal_generation)
    }
}

pub(super) fn reclaim_generations(
    generations: &cap_std::fs::Dir,
    current: u64,
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
        if !super::obsolete_generation(name, current) {
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
    sync_directory(generations).map_err(|source| io_error("flush checkpoint reclamation", source))
}
fn remove_file_if_present(directory: &cap_std::fs::Dir, path: &str) -> Result<(), DurableError> {
    match directory.remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove unused checkpoint file", source)),
    }
}
