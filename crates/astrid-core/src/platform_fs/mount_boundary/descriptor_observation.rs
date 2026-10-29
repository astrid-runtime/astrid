//! One descriptor-bound metadata observation within a validation checkpoint.

use std::fs::File;
use std::io;

use nix::sys::stat::FileStat;

/// The descriptor and its stat cannot be supplied independently. Keep each
/// observation local to one checkpoint; mutable policy is read afresh at the
/// next checkpoint, while identity/device predicates share this same read.
pub(crate) struct DescriptorObservation<'fd> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    file: &'fd File,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    _file: &'fd File,
    stat: FileStat,
}

impl<'fd> DescriptorObservation<'fd> {
    pub(crate) fn read(file: &'fd File) -> io::Result<Self> {
        let stat = counted_fstat(file).map_err(super::super::nix_io_error)?;
        Ok(Self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            file,
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            _file: file,
            stat,
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn file(&self) -> &'fd File {
        self.file
    }

    pub(crate) fn stat(&self) -> &FileStat {
        &self.stat
    }

    #[cfg(test)]
    pub(crate) fn reset_syscall_count() {
        FSTAT_SYSCALL_COUNT.set(0);
    }

    #[cfg(test)]
    pub(crate) fn syscall_count() -> usize {
        FSTAT_SYSCALL_COUNT.get()
    }
}

#[cfg(test)]
thread_local! {
    static FSTAT_SYSCALL_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Instrument the actual ordinary fstat syscall, including failed attempts.
/// Darwin ACL fstatx queries remain separate and are deliberately not counted.
pub(crate) fn counted_fstat(file: &File) -> nix::Result<FileStat> {
    let result = nix::sys::stat::fstat(file);
    #[cfg(test)]
    FSTAT_SYSCALL_COUNT.with(|count| count.set(count.get().strict_add(1)));
    result
}
