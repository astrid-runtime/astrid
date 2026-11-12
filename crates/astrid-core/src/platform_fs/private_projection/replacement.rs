//! One-file backup identity, publication outcome and guarded rollback.
use super::{PrivateFileProjection, RelativePath, platform};
use std::io;
use std::path::Path;

/// Captured target for one replacement after its prior generation was backed up.
/// No directory authority is cached beyond this one synchronous operation.
#[must_use = "publish the captured replacement or leave the target unchanged"]
pub struct PrivateFileReplacement<'a> {
    relative: RelativePath,
    platform: platform::Replacement<'a>,
    binding: std::sync::Arc<()>,
}

/// Evidence that this operation actually renamed a file into its destination.
/// Fields are private: failed prepublication writes cannot manufacture a receipt.
#[must_use = "retain publication evidence until batch completion or rollback"]
pub struct PrivateFilePublication {
    relative: RelativePath,
    identity: platform::FileIdentity,
    binding: std::sync::Arc<()>,
}

/// Publication evidence remains available even when a post-rename fence fails.
#[must_use = "enroll publication evidence before propagating a failed fence"]
pub struct PrivateFileWriteOutcome {
    publication: Option<PrivateFilePublication>,
    result: io::Result<()>,
}
impl PrivateFileWriteOutcome {
    /// Enroll rollback only when a receipt exists, before propagating the result.
    #[must_use = "handle publication evidence before propagating the I/O result"]
    pub fn into_parts(self) -> (Option<PrivateFilePublication>, io::Result<()>) {
        (self.publication, self.result)
    }
}
impl PrivateFileReplacement<'_> {
    /// Replace the captured generation; changes observed before rename fail closed.
    /// Synchronous interruption leaves the caller's durable restoration intent intact.
    pub fn write_from(self, source: &mut dyn io::Read, length: u64) -> PrivateFileWriteOutcome {
        let (identity, result) = self.platform.write_from(source, length);
        PrivateFileWriteOutcome {
            publication: identity.map(|identity| PrivateFilePublication {
                relative: self.relative,
                identity,
                binding: self.binding,
            }),
            result,
        }
    }
}
impl PrivateFileProjection {
    /// Back up a target and retain its identity and bounded parent authority.
    ///
    /// # Errors
    /// Rejects unsafe paths, changed identities, or backup IO errors without
    /// replacing the destination file. Parent directories may be created or
    /// repaired; transactional callers must establish recovery intent first.
    pub fn capture_replacement<'a>(
        &'a self,
        relative: &Path,
        sink: &mut dyn io::Write,
    ) -> io::Result<(PrivateFileReplacement<'a>, Option<u64>)> {
        let relative = RelativePath::parse(relative)?;
        let (platform, length) = self.platform.capture_replacement(&relative, sink)?;
        Ok((
            PrivateFileReplacement {
                relative,
                platform,
                binding: std::sync::Arc::clone(&self.binding),
            },
            length,
        ))
    }

    /// Restore prior bytes, or absence, only over this attempt's installed identity.
    ///
    /// # Errors
    /// Refuses a changed target, and preserves normal private-file durability fences.
    pub fn rollback_publication(
        &self,
        publication: PrivateFilePublication,
        prior: Option<(&mut dyn io::Read, u64)>,
    ) -> io::Result<()> {
        let PrivateFilePublication {
            relative,
            identity,
            binding,
        } = publication;
        if !std::sync::Arc::ptr_eq(&self.binding, &binding) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication belongs to a different captured projection",
            ));
        }
        self.platform
            .rollback_publication(&relative, identity, prior)
    }
}
