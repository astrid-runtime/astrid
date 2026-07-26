//! Host-only registry for invocation workspace attachments.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use astrid_core::PrincipalId;
use dashmap::DashMap;
use uuid::Uuid;

use crate::engine::wasm::host_state::PrincipalMount;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct WorkspaceAttachmentRef {
    pub(crate) id: Uuid,
    pub(crate) epoch: u64,
}

#[derive(Debug)]
struct WorkspaceAttachment {
    owner: PrincipalId,
    mount: PrincipalMount,
    message_sequences: parking_lot::Mutex<Vec<u64>>,
}

/// Maps a host-only bus sidecar to a canonical host directory.
///
/// The registry is shared by every capsule engine in one kernel. Only the
/// authenticated local-socket accept path can add an entry. Neither the
/// physical path nor the private [`WorkspaceAttachmentRef`] enters an IPC
/// message, capsule, or serialized wire shape.
#[derive(Debug)]
pub struct WorkspaceAttachmentRegistry {
    entries: DashMap<WorkspaceAttachmentRef, WorkspaceAttachment>,
    message_attachments: DashMap<u64, WorkspaceAttachmentRef>,
    next_epoch: AtomicU64,
}

impl Default for WorkspaceAttachmentRegistry {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            message_attachments: DashMap::new(),
            next_epoch: AtomicU64::new(1),
        }
    }
}

impl WorkspaceAttachmentRegistry {
    /// Admit a canonical directory for one verified principal.
    pub(crate) fn attach(
        &self,
        owner: PrincipalId,
        root: PathBuf,
    ) -> Result<WorkspaceAttachmentRef, String> {
        let canonical = root
            .canonicalize()
            .map_err(|error| format!("workspace cannot be resolved: {error}"))?;
        let metadata = canonical
            .metadata()
            .map_err(|error| format!("workspace cannot be inspected: {error}"))?;
        if !metadata.is_dir() {
            return Err("workspace is not a directory".to_string());
        }
        let handle = astrid_capabilities::DirHandle::new();
        let vfs = astrid_vfs::HostVfs::with_registered_dir(handle.clone(), &canonical)
            .map_err(|error| format!("workspace capability could not be opened: {error}"))?;
        let mount = PrincipalMount {
            root: canonical,
            vfs: std::sync::Arc::new(vfs),
            handle,
        };
        let attachment = WorkspaceAttachmentRef {
            id: Uuid::new_v4(),
            epoch: self.next_epoch.fetch_add(1, Ordering::Relaxed),
        };
        self.entries.insert(
            attachment,
            WorkspaceAttachment {
                owner,
                mount,
                message_sequences: parking_lot::Mutex::new(Vec::new()),
            },
        );
        Ok(attachment)
    }

    /// Bind a bus-assigned sequence to a live attachment before delivery.
    pub(crate) fn bind_message(&self, sequence: u64, attachment: WorkspaceAttachmentRef) -> bool {
        let Some(entry) = self.entries.get(&attachment) else {
            return false;
        };
        entry.message_sequences.lock().push(sequence);
        self.message_attachments.insert(sequence, attachment);
        true
    }

    /// Resolve the live attachment carried by a bus message.
    #[must_use]
    pub(crate) fn attachment_for_message(&self, sequence: u64) -> Option<WorkspaceAttachmentRef> {
        self.message_attachments.get(&sequence).map(|entry| *entry)
    }

    /// Resolve an attachment for the same verified principal.
    #[must_use]
    pub(crate) fn resolve(
        &self,
        attachment: WorkspaceAttachmentRef,
        principal: &PrincipalId,
    ) -> Option<PrincipalMount> {
        self.entries
            .get(&attachment)
            .and_then(|entry| (entry.owner == *principal).then(|| entry.mount.clone()))
    }

    /// Revoke an attachment when its source connection closes.
    pub(crate) fn detach(&self, attachment: WorkspaceAttachmentRef) {
        let Some((_, entry)) = self.entries.remove(&attachment) else {
            return;
        };
        for sequence in entry.message_sequences.into_inner() {
            self.message_attachments
                .remove_if(&sequence, |_, current| *current == attachment);
        }
    }

    /// Whether `root` is the canonical directory currently selected by an
    /// attachment. Test and diagnostics helper; no path leaves the host.
    #[must_use]
    pub(crate) fn resolves_to(
        &self,
        attachment: WorkspaceAttachmentRef,
        principal: &PrincipalId,
        root: &Path,
    ) -> bool {
        self.resolve(attachment, principal)
            .is_some_and(|mount| mount.root.as_path() == root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_is_principal_bound_and_revocable() {
        let registry = WorkspaceAttachmentRegistry::default();
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let workspace = tempfile::tempdir().expect("workspace");
        let root = workspace
            .path()
            .canonicalize()
            .expect("canonical workspace");
        let attachment = registry
            .attach(alice.clone(), root.clone())
            .expect("attach workspace");
        let message_sequence = 3;

        assert!(registry.resolves_to(attachment, &alice, &root));
        assert!(registry.resolve(attachment, &bob).is_none());
        assert!(registry.bind_message(message_sequence, attachment));
        assert_eq!(
            registry.attachment_for_message(message_sequence),
            Some(attachment)
        );

        registry.detach(attachment);
        assert!(registry.resolve(attachment, &alice).is_none());
        assert!(
            registry.attachment_for_message(message_sequence).is_none(),
            "revocation must clear queued-message sidecars"
        );
    }
}
