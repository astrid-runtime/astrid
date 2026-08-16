//! Linux FUSE implementation backed by the private authenticated callback.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, bail};
use astrid_core::storage_filesystem::{
    StorageFilesystemEntryKindV1, StorageFilesystemEntryV1, StorageFilesystemOperationV1,
    StorageFilesystemSuccessV1, StorageMountLeaseV1,
};
use astrid_core::storage_provider::StorageProviderAccessV1;
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, Session, SessionACL,
};

use crate::callback::{CALLBACK_CHUNK_BYTES, CallbackClient, callback_errno};
use crate::mountpoint::owner_ids;

// Astrid is the authority and may be changed through another principal view or
// native client. Do not let the kernel serve stale lengths or bytes from an
// earlier callback result.
const ATTRIBUTE_TTL: Duration = Duration::ZERO;

/// Start a real kernel FUSE session for one admitted lease.
pub(crate) type FuseBackgroundSession = fuser::BackgroundSession;

/// Mount the filesystem and return the owner-owned background session.
pub(crate) fn start_session(
    lease: StorageMountLeaseV1,
    mountpoint: &Path,
) -> Result<FuseBackgroundSession> {
    let access = lease.access;
    let filesystem = AstridFuseFilesystem::new(lease);
    let mount_option = match access {
        StorageProviderAccessV1::ReadOnly => MountOption::RO,
        StorageProviderAccessV1::ReadWrite => MountOption::RW,
    };
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("astrid".to_owned()),
        MountOption::Subtype("astrid".to_owned()),
        mount_option,
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::NoExec,
    ];
    config.acl = SessionACL::Owner;
    config.n_threads = Some(1);
    config.clone_fd = false;
    let session = Session::new(filesystem, mountpoint, &config)
        .with_context(|| format!("mount Astrid FUSE filesystem at {}", mountpoint.display()))?;
    let background = session.spawn()?;
    if !crate::mountpoint::mountinfo_contains(mountpoint)? {
        bail!("FUSE mount completed but is absent from the Linux mount table");
    }
    Ok(background)
}

/// FUSE filesystem bound to one immutable owner, access mode, and lease token.
pub(crate) struct AstridFuseFilesystem {
    callback: CallbackClient,
    inodes: Mutex<InodeTable>,
    read_only: bool,
    uid: u32,
    gid: u32,
}

impl AstridFuseFilesystem {
    pub(crate) fn new(lease: StorageMountLeaseV1) -> Self {
        let read_only = lease.access == StorageProviderAccessV1::ReadOnly;
        let (uid, gid) = owner_ids();
        let mut inodes = InodeTable::default();
        inodes
            .intern("")
            .ok_or_else(|| anyhow::anyhow!("initialize FUSE root inode"))
            .expect("the first inode allocation cannot fail");
        Self {
            callback: CallbackClient::new(lease),
            inodes: Mutex::new(inodes),
            read_only,
            uid,
            gid,
        }
    }

    fn stat_path(&self, path: &str) -> Result<StorageFilesystemEntryV1, Errno> {
        self.callback
            .call(StorageFilesystemOperationV1::Stat {
                path: path.to_owned(),
            })
            .and_then(|success| match success {
                StorageFilesystemSuccessV1::Entry(entry) => Ok(entry),
                _ => Err(crate::callback::CallbackError::Transport(
                    "stat callback returned an incompatible result".to_owned(),
                )),
            })
            .map_err(callback_errno)
    }

    fn path_for_inode(&self, ino: INodeNo) -> Result<String, Errno> {
        self.inodes
            .lock()
            .map_err(|_| Errno::EIO)?
            .path(ino)
            .cloned()
            .ok_or(Errno::ENOENT)
    }

    fn attributes_for(&self, path: &str, ino: INodeNo) -> Result<FileAttr, Errno> {
        let entry = self.stat_path(path)?;
        Ok(self.attributes(ino, &entry))
    }

    fn attributes(&self, ino: INodeNo, entry: &StorageFilesystemEntryV1) -> FileAttr {
        let kind = match entry.kind {
            StorageFilesystemEntryKindV1::File => FileType::RegularFile,
            StorageFilesystemEntryKindV1::Directory => FileType::Directory,
        };
        let permission = if self.read_only {
            if kind == FileType::Directory {
                0o500
            } else {
                0o400
            }
        } else if kind == FileType::Directory {
            0o700
        } else {
            0o600
        };
        let now = SystemTime::now();
        FileAttr {
            ino,
            size: entry.logical_bytes,
            blocks: entry.logical_bytes.div_ceil(512),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm: permission,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn child_path(&self, parent: INodeNo, name: &OsStr) -> Result<String, Errno> {
        let parent = self.path_for_inode(parent)?;
        valid_name(name).and_then(|name| join_path(&parent, name))
    }

    fn inode_for_path(&self, path: &str) -> Result<INodeNo, Errno> {
        self.inodes
            .lock()
            .map_err(|_| Errno::EIO)?
            .intern(path)
            .map(INodeNo)
            .ok_or(Errno::EIO)
    }

    fn entry_reply(&self, path: &str, reply: ReplyEntry) {
        match self.stat_path(path).and_then(|entry| {
            let ino = self.inode_for_path(path)?;
            Ok((entry, ino))
        }) {
            Ok((entry, ino)) => {
                let attributes = self.attributes(ino, &entry);
                reply.entry(&ATTRIBUTE_TTL, &attributes, Generation(0));
            },
            Err(errno) => reply.error(errno),
        }
    }

    fn mutation_allowed(&self) -> Result<(), Errno> {
        if self.read_only {
            Err(Errno::EROFS)
        } else {
            Ok(())
        }
    }

    fn done(&self, operation: StorageFilesystemOperationV1, reply: ReplyEmpty) {
        match self.callback.call(operation).map_err(callback_errno) {
            Ok(StorageFilesystemSuccessV1::Done) => reply.ok(),
            Ok(_) => reply.error(Errno::EIO),
            Err(errno) => reply.error(errno),
        }
    }

    fn read_range(&self, path: &str, offset: u64, length: u32) -> Result<Vec<u8>, Errno> {
        let length = u64::from(length);
        let end = offset.checked_add(length).ok_or(Errno::EFBIG)?;
        let mut result = Vec::with_capacity(usize::try_from(length).map_err(|_| Errno::EFBIG)?);
        let mut current = offset;
        while current < end {
            let wanted = end
                .checked_sub(current)
                .ok_or(Errno::EFBIG)?
                .min(CALLBACK_CHUNK_BYTES as u64);
            let success = self
                .callback
                .call(StorageFilesystemOperationV1::Read {
                    path: path.to_owned(),
                    offset: current,
                    length: wanted,
                })
                .map_err(callback_errno)?;
            let StorageFilesystemSuccessV1::Data(mut bytes) = success else {
                return Err(Errno::EIO);
            };
            if bytes.len() as u64 > wanted {
                return Err(Errno::EIO);
            }
            let reached_end = (bytes.len() as u64) < wanted;
            result.append(&mut bytes);
            current = end.min(current.saturating_add(wanted));
            if reached_end {
                break;
            }
        }
        Ok(result)
    }

    fn write_range(&self, path: &str, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        self.mutation_allowed()?;
        let total = u64::try_from(data.len()).map_err(|_| Errno::EFBIG)?;
        offset.checked_add(total).ok_or(Errno::EFBIG)?;
        for (index, chunk) in data.chunks(CALLBACK_CHUNK_BYTES).enumerate() {
            let relative_offset = u64::try_from(index)
                .map_err(|_| Errno::EFBIG)?
                .checked_mul(CALLBACK_CHUNK_BYTES as u64)
                .ok_or(Errno::EFBIG)?;
            let chunk_offset = offset.checked_add(relative_offset).ok_or(Errno::EFBIG)?;
            let success = self
                .callback
                .call(StorageFilesystemOperationV1::Write {
                    path: path.to_owned(),
                    offset: chunk_offset,
                    data: chunk.to_vec(),
                })
                .map_err(callback_errno)?;
            let expected_length = chunk_offset
                .checked_add(u64::try_from(chunk.len()).map_err(|_| Errno::EFBIG)?)
                .ok_or(Errno::EFBIG)?;
            match success {
                StorageFilesystemSuccessV1::Written(length) if length >= expected_length => {},
                _ => return Err(Errno::EIO),
            }
        }
        u32::try_from(data.len()).map_err(|_| Errno::EFBIG)
    }
}

impl Filesystem for AstridFuseFilesystem {
    fn open(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::FOPEN_DIRECT_IO);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.child_path(parent, name) {
            Ok(path) => self.entry_reply(&path, reply),
            Err(errno) => reply.error(errno),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, _nlookup: u64) {
        if let Ok(mut inodes) = self.inodes.lock() {
            inodes.forget(ino);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let result = self
            .path_for_inode(ino)
            .and_then(|path| self.attributes_for(&path, ino));
        match result {
            Ok(attributes) => reply.attr(&ATTRIBUTE_TTL, &attributes),
            Err(errno) => reply.error(errno),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = self.path_for_inode(ino).and_then(|path| {
            if mode.is_some() || uid.is_some() || gid.is_some() {
                return Err(Errno::EPERM);
            }
            let Some(length) = size else {
                return self.attributes_for(&path, ino);
            };
            self.mutation_allowed()?;
            self.callback
                .call(StorageFilesystemOperationV1::SetLength {
                    path: path.clone(),
                    length,
                })
                .and_then(|success| match success {
                    StorageFilesystemSuccessV1::Written(written) if written == length => Ok(()),
                    _ => Err(crate::callback::CallbackError::Transport(
                        "set-length callback returned an incompatible result".to_owned(),
                    )),
                })
                .map_err(callback_errno)?;
            self.attributes_for(&path, ino)
        });
        match result {
            Ok(attributes) => reply.attr(&ATTRIBUTE_TTL, &attributes),
            Err(errno) => reply.error(errno),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if mode & 0o170_000 != 0o100_000 {
            return reply.error(Errno::EPERM);
        }
        if let Err(errno) = self.mutation_allowed() {
            return reply.error(errno);
        }
        match self.child_path(parent, name) {
            Ok(path) => {
                match self
                    .callback
                    .call(StorageFilesystemOperationV1::Create {
                        path: path.clone(),
                        kind: StorageFilesystemEntryKindV1::File,
                    })
                    .map_err(callback_errno)
                {
                    Ok(StorageFilesystemSuccessV1::Done) => self.entry_reply(&path, reply),
                    Ok(_) => reply.error(Errno::EIO),
                    Err(errno) => reply.error(errno),
                }
            },
            Err(errno) => reply.error(errno),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if let Err(errno) = self.mutation_allowed() {
            return reply.error(errno);
        }
        match self.child_path(parent, name) {
            Ok(path) => {
                match self
                    .callback
                    .call(StorageFilesystemOperationV1::Create {
                        path: path.clone(),
                        kind: StorageFilesystemEntryKindV1::Directory,
                    })
                    .map_err(callback_errno)
                {
                    Ok(StorageFilesystemSuccessV1::Done) => self.entry_reply(&path, reply),
                    Ok(_) => reply.error(Errno::EIO),
                    Err(errno) => reply.error(errno),
                }
            },
            Err(errno) => reply.error(errno),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(errno) = self.mutation_allowed() {
            return reply.error(errno);
        }
        match self.child_path(parent, name) {
            Ok(path) => {
                self.done(StorageFilesystemOperationV1::Remove { path }, reply);
            },
            Err(errno) => reply.error(errno),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(errno) = self.mutation_allowed() {
            return reply.error(errno);
        }
        match self.child_path(parent, name) {
            Ok(path) => {
                self.done(StorageFilesystemOperationV1::Remove { path }, reply);
            },
            Err(errno) => reply.error(errno),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
            return reply.error(Errno::EINVAL);
        }
        if let Err(errno) = self.mutation_allowed() {
            return reply.error(errno);
        }
        let result = self.child_path(parent, name).and_then(|from| {
            let to = self.child_path(newparent, newname)?;
            Ok((from, to))
        });
        let (from, to) = match result {
            Ok(paths) => paths,
            Err(errno) => return reply.error(errno),
        };
        let operation = StorageFilesystemOperationV1::Rename {
            from: from.clone(),
            to: to.clone(),
            replace: !flags.contains(RenameFlags::RENAME_NOREPLACE),
        };
        match self.callback.call(operation).map_err(callback_errno) {
            Ok(StorageFilesystemSuccessV1::Done) => {
                if let Ok(mut inodes) = self.inodes.lock() {
                    inodes.renamed(&from, &to);
                }
                reply.ok();
            },
            Ok(_) => reply.error(Errno::EIO),
            Err(errno) => reply.error(errno),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let result = self
            .path_for_inode(ino)
            .and_then(|path| self.read_range(&path, offset, size));
        match result {
            Ok(bytes) => reply.data(&bytes),
            Err(errno) => reply.error(errno),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let result = self
            .path_for_inode(ino)
            .and_then(|path| self.write_range(&path, offset, data));
        match result {
            Ok(count) => reply.written(count),
            Err(errno) => reply.error(errno),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.done(StorageFilesystemOperationV1::Sync, reply);
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.done(StorageFilesystemOperationV1::Sync, reply);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let result = self.path_for_inode(ino).and_then(|path| {
            self.callback
                .call(StorageFilesystemOperationV1::ReadDirectory { path })
                .map_err(callback_errno)
        });
        let entries = match result.and_then(|success| match success {
            StorageFilesystemSuccessV1::Entries(entries) => Ok(entries),
            _ => Err(Errno::EIO),
        }) {
            Ok(entries) => entries,
            Err(errno) => return reply.error(errno),
        };
        for (index, entry) in entries.into_iter().enumerate() {
            let entry_offset = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1));
            let Some(entry_offset) = entry_offset else {
                return reply.error(Errno::EFBIG);
            };
            if entry_offset <= offset {
                continue;
            }
            let path = match self
                .path_for_inode(ino)
                .and_then(|parent| join_path(&parent, entry.name.as_str()))
            {
                Ok(path) => path,
                Err(errno) => return reply.error(errno),
            };
            let ino = match self.inode_for_path(&path) {
                Ok(ino) => ino,
                Err(errno) => return reply.error(errno),
            };
            let kind = match entry.kind {
                StorageFilesystemEntryKindV1::File => FileType::RegularFile,
                StorageFilesystemEntryKindV1::Directory => FileType::Directory,
            };
            if reply.add(ino, entry_offset, kind, entry.name.as_str()) {
                break;
            }
        }
        reply.ok();
    }
}

fn valid_name(name: &OsStr) -> Result<&str, Errno> {
    let name = name.to_str().ok_or(Errno::EINVAL)?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
        || name.len() > 255
    {
        return Err(Errno::EINVAL);
    }
    Ok(name)
}

fn join_path(parent: &str, name: &str) -> Result<String, Errno> {
    if parent.is_empty() {
        Ok(name.to_owned())
    } else if parent.ends_with('/') && parent != "/" {
        Err(Errno::EINVAL)
    } else {
        Ok(format!("{parent}/{name}"))
    }
}

#[derive(Default)]
struct InodeTable {
    next_inode: u64,
    by_inode: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
}

impl InodeTable {
    fn intern(&mut self, path: &str) -> Option<u64> {
        if let Some(ino) = self.by_path.get(path) {
            return Some(*ino);
        }
        self.next_inode = self.next_inode.checked_add(1)?;
        let ino = self.next_inode;
        if ino == u64::MAX {
            return None;
        }
        self.by_inode.insert(ino, path.to_owned());
        self.by_path.insert(path.to_owned(), ino);
        Some(ino)
    }

    fn path(&self, ino: INodeNo) -> Option<&String> {
        self.by_inode.get(&ino.0)
    }

    fn forget(&mut self, ino: INodeNo) {
        if ino.0 == 1 {
            return;
        }
        if let Some(path) = self.by_inode.remove(&ino.0) {
            self.by_path.remove(&path);
        }
    }

    fn renamed(&mut self, from: &str, to: &str) {
        let destination_prefix = format!("{to}/");
        let replaced = self
            .by_path
            .iter()
            .filter(|(path, _)| *path == to || path.starts_with(&destination_prefix))
            .map(|(path, ino)| (path.clone(), *ino))
            .collect::<Vec<_>>();
        for (path, ino) in replaced {
            self.by_path.remove(&path);
            self.by_inode.remove(&ino);
        }

        let source_prefix = format!("{from}/");
        let descendants = self
            .by_path
            .iter()
            .filter(|(path, _)| *path == from || path.starts_with(&source_prefix))
            .map(|(path, ino)| (path.clone(), *ino))
            .collect::<Vec<_>>();
        for (path, ino) in descendants {
            let renamed = path
                .strip_prefix(&source_prefix)
                .map_or_else(|| to.to_owned(), |suffix| format!("{to}/{suffix}"));
            self.by_path.remove(&path);
            self.by_inode.insert(ino, renamed.clone());
            self.by_path.insert(renamed, ino);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::if_not_else,
        clippy::let_and_return,
        clippy::manual_assert,
        clippy::match_same_arms,
        clippy::too_many_lines,
        clippy::unwrap_used
    )]
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use astrid_core::PrincipalId;
    use astrid_core::storage_filesystem::{
        STORAGE_FILESYSTEM_PROTOCOL_V2, StorageFilesystemEntryKindV1, StorageFilesystemEntryV1,
        StorageFilesystemFailureV1, StorageFilesystemOperationV1, StorageFilesystemOperationV2,
        StorageFilesystemOutcomeV2, StorageFilesystemRequestV2, StorageFilesystemResponseV2,
        StorageFilesystemSuccessV1, StorageFilesystemSuccessV2, StorageMountLeaseV1,
    };
    use astrid_core::storage_provider::{
        StorageMountId, StorageProviderAccessV1, StorageProviderViewV1,
    };
    use base64::Engine as _;
    use uuid::Uuid;

    use super::{AstridFuseFilesystem, CALLBACK_CHUNK_BYTES, InodeTable, join_path, start_session};
    use crate::callback::{CallbackClient, CallbackError, callback_errno};

    const TOKEN: &str = "fuse-test-lease-token";

    #[derive(Clone, Debug, Default)]
    struct FakeFilesystem {
        files: BTreeMap<String, Vec<u8>>,
        directories: BTreeSet<String>,
    }

    #[derive(Clone, Debug, Default)]
    struct CallbackTelemetry {
        maximum_read: usize,
        maximum_write: usize,
        authenticated_calls: usize,
        rejected_calls: usize,
    }

    fn entry(
        path: &str,
        kind: StorageFilesystemEntryKindV1,
        length: u64,
    ) -> StorageFilesystemEntryV1 {
        let name = path.rsplit('/').next().unwrap_or(path);
        StorageFilesystemEntryV1 {
            name: if path.is_empty() {
                "/".to_owned()
            } else {
                name.to_owned()
            },
            kind,
            logical_bytes: length,
        }
    }

    fn parent(path: &str) -> String {
        match path.rfind('/') {
            None | Some(0) => String::new(),
            Some(index) => path[..index].to_owned(),
        }
    }

    fn fake_operation(
        state: &FakeFilesystem,
        operation: StorageFilesystemOperationV1,
    ) -> Result<StorageFilesystemSuccessV1, StorageFilesystemFailureV1> {
        let result = match operation {
            StorageFilesystemOperationV1::Stat { path } => {
                if let Some(data) = state.files.get(&path) {
                    Ok(StorageFilesystemSuccessV1::Entry(entry(
                        &path,
                        StorageFilesystemEntryKindV1::File,
                        data.len() as u64,
                    )))
                } else if state.directories.contains(&path) {
                    Ok(StorageFilesystemSuccessV1::Entry(entry(
                        &path,
                        StorageFilesystemEntryKindV1::Directory,
                        0,
                    )))
                } else {
                    return Err(failure_detail("not-found", "entry does not exist"));
                }
            },
            StorageFilesystemOperationV1::ReadDirectory { path } => {
                if !state.directories.contains(&path) {
                    return Err(failure_detail("not-found", "directory does not exist"));
                }
                let mut entries = Vec::new();
                for (child, data) in &state.files {
                    if parent(child) == path {
                        entries.push(entry(
                            child,
                            StorageFilesystemEntryKindV1::File,
                            data.len() as u64,
                        ));
                    }
                }
                for child in &state.directories {
                    if parent(child) == path {
                        entries.push(entry(child, StorageFilesystemEntryKindV1::Directory, 0));
                    }
                }
                Ok(StorageFilesystemSuccessV1::Entries(entries))
            },
            StorageFilesystemOperationV1::Read {
                path,
                offset,
                length,
            } => {
                let Some(data) = state.files.get(&path) else {
                    return Err(failure_detail("not-found", "file does not exist"));
                };
                let start = usize::try_from(offset).unwrap_or(data.len());
                let end = start.saturating_add(usize::try_from(length).unwrap_or(0));
                let bytes = data.get(start..end).unwrap_or(&[]).to_vec();
                Ok(StorageFilesystemSuccessV1::Data(bytes))
            },
            StorageFilesystemOperationV1::Write { path, offset, data } => {
                let Some(file) = state.files.get(&path) else {
                    return Err(failure_detail("not-found", "file does not exist"));
                };
                let mut updated = file.clone();
                let start = usize::try_from(offset).unwrap_or(updated.len());
                let end = start.saturating_add(data.len());
                if updated.len() < end {
                    updated.resize(end, 0);
                }
                if start <= updated.len() {
                    updated[start..end].copy_from_slice(&data);
                }
                Ok(StorageFilesystemSuccessV1::Written(updated.len() as u64))
            },
            StorageFilesystemOperationV1::SetLength { path, length } => {
                let Some(file) = state.files.get(&path) else {
                    return Err(failure_detail("not-found", "file does not exist"));
                };
                let mut updated = file.clone();
                updated.resize(usize::try_from(length).unwrap_or(usize::MAX), 0);
                Ok(StorageFilesystemSuccessV1::Written(updated.len() as u64))
            },
            StorageFilesystemOperationV1::Create { path, kind } => {
                if state.files.contains_key(&path) || state.directories.contains(&path) {
                    return Err(failure_detail("already-exists", "entry already exists"));
                }
                if !state.directories.contains(&parent(&path)) {
                    return Err(failure_detail("not-directory", "parent does not exist"));
                }
                match kind {
                    StorageFilesystemEntryKindV1::File => Ok(StorageFilesystemSuccessV1::Done),
                    StorageFilesystemEntryKindV1::Directory => Ok(StorageFilesystemSuccessV1::Done),
                }
            },
            StorageFilesystemOperationV1::Remove { path } => {
                if state.directories.contains(&path)
                    && (state.files.keys().any(|child| parent(child) == path)
                        || state.directories.iter().any(|child| parent(child) == path))
                {
                    Err(failure_detail(
                        "directory-not-empty",
                        "directory is not empty",
                    ))
                } else if state.files.contains_key(&path) || state.directories.contains(&path) {
                    Ok(StorageFilesystemSuccessV1::Done)
                } else {
                    Err(failure_detail("not-found", "entry does not exist"))
                }
            },
            StorageFilesystemOperationV1::Rename { from, to, replace } => {
                if !state.files.contains_key(&from) && !state.directories.contains(&from) {
                    return Err(failure_detail("not-found", "source does not exist"));
                }
                if state.files.contains_key(&to) && !replace {
                    return Err(failure_detail("already-exists", "destination exists"));
                }
                Ok(StorageFilesystemSuccessV1::Done)
            },
            StorageFilesystemOperationV1::Sync => Ok(StorageFilesystemSuccessV1::Done),
        };
        result
    }

    fn failure(code: &str, message: &str) -> StorageFilesystemOutcomeV2 {
        StorageFilesystemOutcomeV2::Failure(failure_detail(code, message))
    }

    fn failure_detail(code: &str, message: &str) -> StorageFilesystemFailureV1 {
        StorageFilesystemFailureV1 {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }

    fn decode_operation(operation: StorageFilesystemOperationV2) -> StorageFilesystemOperationV1 {
        match operation {
            StorageFilesystemOperationV2::Stat { path } => {
                StorageFilesystemOperationV1::Stat { path }
            },
            StorageFilesystemOperationV2::ReadDirectory { path } => {
                StorageFilesystemOperationV1::ReadDirectory { path }
            },
            StorageFilesystemOperationV2::Read {
                path,
                offset,
                length,
            } => StorageFilesystemOperationV1::Read {
                path,
                offset,
                length,
            },
            StorageFilesystemOperationV2::Write {
                path,
                offset,
                data_base64,
            } => StorageFilesystemOperationV1::Write {
                path,
                offset,
                data: base64::engine::general_purpose::STANDARD
                    .decode(data_base64)
                    .expect("decode fake callback payload"),
            },
            StorageFilesystemOperationV2::SetLength { path, length } => {
                StorageFilesystemOperationV1::SetLength { path, length }
            },
            StorageFilesystemOperationV2::Create { path, kind } => {
                StorageFilesystemOperationV1::Create { path, kind }
            },
            StorageFilesystemOperationV2::Remove { path } => {
                StorageFilesystemOperationV1::Remove { path }
            },
            StorageFilesystemOperationV2::Rename { from, to, replace } => {
                StorageFilesystemOperationV1::Rename { from, to, replace }
            },
            StorageFilesystemOperationV2::Sync => StorageFilesystemOperationV1::Sync,
        }
    }

    fn encode_success(success: StorageFilesystemSuccessV1) -> StorageFilesystemSuccessV2 {
        match success {
            StorageFilesystemSuccessV1::Done => StorageFilesystemSuccessV2::Done,
            StorageFilesystemSuccessV1::Entry(entry) => StorageFilesystemSuccessV2::Entry(entry),
            StorageFilesystemSuccessV1::Entries(entries) => {
                StorageFilesystemSuccessV2::Entries(entries)
            },
            StorageFilesystemSuccessV1::Data(data) => StorageFilesystemSuccessV2::Data {
                data_base64: base64::engine::general_purpose::STANDARD.encode(data),
            },
            StorageFilesystemSuccessV1::Written(length) => {
                StorageFilesystemSuccessV2::Written(length)
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    fn spawn_fake_callback(
        path: &Path,
        state: FakeFilesystem,
    ) -> (Arc<Mutex<FakeFilesystem>>, Arc<Mutex<CallbackTelemetry>>) {
        let state = Arc::new(Mutex::new(state));
        let telemetry = Arc::new(Mutex::new(CallbackTelemetry::default()));
        let listener = UnixListener::bind(path).expect("bind fake callback socket");
        let callback_state = Arc::clone(&state);
        let callback_telemetry = Arc::clone(&telemetry);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                let mut length = [0_u8; 4];
                if stream.read_exact(&mut length).is_err() {
                    break;
                }
                let length = u32::from_be_bytes(length) as usize;
                let mut bytes = vec![0_u8; length];
                if stream.read_exact(&mut bytes).is_err() {
                    break;
                }
                let request: StorageFilesystemRequestV2 =
                    serde_json::from_slice(&bytes).expect("decode fake callback request");
                assert_eq!(request.protocol_version, STORAGE_FILESYSTEM_PROTOCOL_V2);
                let operation = decode_operation(request.operation);
                let outcome = if request.lease_token != TOKEN {
                    callback_telemetry.lock().unwrap().rejected_calls += 1;
                    failure("unauthorized", "invalid lease token")
                } else {
                    let maximum_read = match &operation {
                        StorageFilesystemOperationV1::Read { length, .. } => Some(*length),
                        _ => None,
                    };
                    let maximum_write = match &operation {
                        StorageFilesystemOperationV1::Write { data, .. } => Some(data.len() as u64),
                        _ => None,
                    };
                    {
                        let mut telemetry = callback_telemetry.lock().unwrap();
                        telemetry.authenticated_calls += 1;
                        telemetry.maximum_read = telemetry
                            .maximum_read
                            .max(maximum_read.unwrap_or(0) as usize);
                        telemetry.maximum_write = telemetry
                            .maximum_write
                            .max(maximum_write.unwrap_or(0) as usize);
                    }
                    let mut state = callback_state.lock().unwrap();
                    match fake_operation(&state, operation.clone()) {
                        Ok(success) => {
                            apply_fake_mutation(&mut state, &operation);
                            StorageFilesystemOutcomeV2::Success(encode_success(success))
                        },
                        Err(failure) => StorageFilesystemOutcomeV2::Failure(failure),
                    }
                };
                let response = StorageFilesystemResponseV2 {
                    protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
                    request_id: request.request_id,
                    outcome,
                };
                let bytes = serde_json::to_vec(&response).expect("encode fake callback response");
                let length = u32::try_from(bytes.len()).expect("bounded fake response");
                stream
                    .write_all(&length.to_be_bytes())
                    .expect("write length");
                stream.write_all(&bytes).expect("write fake response");
            }
        });
        (state, telemetry)
    }

    fn apply_fake_mutation(state: &mut FakeFilesystem, operation: &StorageFilesystemOperationV1) {
        match operation {
            StorageFilesystemOperationV1::Create { path, kind } => match kind {
                StorageFilesystemEntryKindV1::File => {
                    state.files.insert(path.clone(), Vec::new());
                },
                StorageFilesystemEntryKindV1::Directory => {
                    state.directories.insert(path.clone());
                },
            },
            StorageFilesystemOperationV1::Write { path, offset, data } => {
                if let Some(file) = state.files.get_mut(path) {
                    let start = usize::try_from(*offset).unwrap_or(file.len());
                    let end = start.saturating_add(data.len());
                    if file.len() < end {
                        file.resize(end, 0);
                    }
                    file[start..end].copy_from_slice(data);
                }
            },
            StorageFilesystemOperationV1::SetLength { path, length } => {
                if let Some(file) = state.files.get_mut(path) {
                    file.resize(usize::try_from(*length).unwrap_or(usize::MAX), 0);
                }
            },
            StorageFilesystemOperationV1::Remove { path } => {
                state.files.remove(path);
                state.directories.remove(path);
            },
            StorageFilesystemOperationV1::Rename { from, to, .. } => {
                if let Some(file) = state.files.remove(from) {
                    state.files.insert(to.clone(), file);
                } else if state.directories.remove(from) {
                    state.directories.insert(to.clone());
                }
            },
            _ => {},
        }
    }

    fn test_lease(callback_path: &Path, access: StorageProviderAccessV1) -> StorageMountLeaseV1 {
        StorageMountLeaseV1 {
            mount_id: StorageMountId::from_uuid(Uuid::new_v4()),
            view: StorageProviderViewV1::Principal(PrincipalId::default()),
            access,
            resource_path: callback_path.parent().unwrap().join("resource"),
            callback_path: callback_path.to_path_buf(),
            lease_token: TOKEN.to_owned(),
            expires_at_epoch_secs: u64::MAX,
        }
    }

    #[test]
    fn callback_io_is_chunked_and_authenticated() {
        let temporary = tempfile::tempdir().unwrap();
        let callback_path = temporary.path().join("callback.sock");
        let mut fake = FakeFilesystem::default();
        fake.directories.insert(String::new());
        fake.files.insert(
            "large.bin".to_owned(),
            vec![0; CALLBACK_CHUNK_BYTES * 2 + 1024],
        );
        let (_state, telemetry) = spawn_fake_callback(&callback_path, fake);
        let lease = test_lease(&callback_path, StorageProviderAccessV1::ReadWrite);
        let filesystem = AstridFuseFilesystem::new(lease.clone());
        let data: Vec<_> = (0..(CALLBACK_CHUNK_BYTES * 2 + 1024))
            .map(|index| (index % 251) as u8)
            .collect();

        filesystem
            .write_range("large.bin", 0, &data)
            .expect("chunked FUSE write");
        let read = filesystem
            .read_range("large.bin", 0, u32::try_from(data.len()).unwrap())
            .expect("chunked FUSE read");

        assert_eq!(read, data);
        let telemetry = telemetry.lock().unwrap();
        assert!(telemetry.authenticated_calls >= 6);
        assert!(telemetry.maximum_write <= CALLBACK_CHUNK_BYTES);
        assert!(telemetry.maximum_read <= CALLBACK_CHUNK_BYTES);
        assert_eq!(telemetry.rejected_calls, 0);

        let mut unauthorized = lease;
        unauthorized.lease_token = "wrong-token".to_owned();
        let error = CallbackClient::new(unauthorized)
            .call(StorageFilesystemOperationV1::Stat {
                path: String::new(),
            })
            .expect_err("callback must reject an invalid bearer");
        assert!(matches!(error, CallbackError::Failure(_)));
        assert_eq!(
            callback_errno(error),
            fuser::Errno::EACCES,
            "unauthorized callback must map to EACCES"
        );
        assert_eq!(telemetry.rejected_calls, 1);
    }

    #[test]
    fn native_paths_reject_traversal_and_alias_segments() {
        assert_eq!(join_path("", "file.txt").unwrap(), "file.txt");
        assert_eq!(join_path("dir", "file.txt").unwrap(), "dir/file.txt");
        assert!(super::valid_name(std::ffi::OsStr::new("..")).is_err());
        assert!(super::valid_name(std::ffi::OsStr::new("a/b")).is_err());
        assert!(super::valid_name(std::ffi::OsStr::new("")).is_err());
    }

    #[test]
    fn directory_rename_updates_cached_descendant_inodes() {
        let mut inodes = InodeTable::default();
        let source = inodes.intern("old").unwrap();
        let child = inodes.intern("old/child").unwrap();
        let replaced = inodes.intern("new").unwrap();

        inodes.renamed("old", "new");

        assert_eq!(
            inodes.path(fuser::INodeNo(source)).map(String::as_str),
            Some("new")
        );
        assert_eq!(
            inodes.path(fuser::INodeNo(child)).map(String::as_str),
            Some("new/child")
        );
        assert!(inodes.path(fuser::INodeNo(replaced)).is_none());
    }

    #[test]
    #[ignore = "requires a Linux kernel FUSE device; run with ASTRID_FUSE_E2E=1"]
    fn linux_native_fuse_mount_supports_all_required_operations() {
        assert_eq!(
            std::env::var("ASTRID_FUSE_E2E").as_deref(),
            Ok("1"),
            "native E2E was selected but ASTRID_FUSE_E2E is not explicitly enabled"
        );
        if !Path::new("/dev/fuse").exists() {
            panic!("native E2E was selected but /dev/fuse is unavailable");
        }

        let temporary = tempfile::tempdir().unwrap();
        let callback_path = temporary.path().join("callback.sock");
        let mut fake = FakeFilesystem::default();
        fake.directories.insert(String::new());
        let (state, telemetry) = spawn_fake_callback(&callback_path, fake);
        let mountpoint = temporary.path().join("native-mount");
        std::fs::create_dir(&mountpoint).unwrap();
        std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lease = test_lease(&callback_path, StorageProviderAccessV1::ReadWrite);
        let session = start_session(lease, &mountpoint).expect("mount real Linux FUSE filesystem");

        assert!(crate::mountpoint::mountinfo_contains(&mountpoint).unwrap());
        std::fs::write(mountpoint.join("hello.txt"), b"Astrid FUSE").unwrap();
        assert_eq!(
            std::fs::read(mountpoint.join("hello.txt")).unwrap(),
            b"Astrid FUSE".to_vec()
        );
        std::fs::create_dir(mountpoint.join("directory")).unwrap();
        std::fs::rename(
            mountpoint.join("hello.txt"),
            mountpoint.join("directory").join("renamed.txt"),
        )
        .unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(mountpoint.join("directory").join("renamed.txt"))
            .unwrap();
        file.set_len(6).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            std::fs::metadata(mountpoint.join("directory").join("renamed.txt"))
                .unwrap()
                .len(),
            6
        );
        assert!(std::fs::read_dir(&mountpoint).unwrap().count() >= 1);
        std::fs::remove_file(mountpoint.join("directory").join("renamed.txt")).unwrap();
        std::fs::remove_dir(mountpoint.join("directory")).unwrap();

        let fake_state = state.lock().unwrap();
        assert!(fake_state.files.is_empty());
        assert!(fake_state.directories.contains(""));
        drop(fake_state);
        let telemetry = telemetry.lock().unwrap();
        assert!(telemetry.authenticated_calls >= 10);
        assert_eq!(telemetry.rejected_calls, 0);
        drop(telemetry);
        session
            .umount_and_join()
            .expect("unmount real FUSE session");

        let readonly_mountpoint = temporary.path().join("read-only-mount");
        std::fs::create_dir(&readonly_mountpoint).unwrap();
        std::fs::set_permissions(&readonly_mountpoint, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let readonly_lease = test_lease(&callback_path, StorageProviderAccessV1::ReadOnly);
        let readonly_session = start_session(readonly_lease, &readonly_mountpoint)
            .expect("mount read-only Linux FUSE filesystem");
        let denied = std::fs::write(readonly_mountpoint.join("denied.txt"), b"denied")
            .expect_err("read-only mount must reject writes");
        assert_eq!(
            denied.raw_os_error(),
            Some(nix::errno::Errno::EROFS as i32),
            "read-only mount must return EROFS, got {denied}"
        );
        readonly_session
            .umount_and_join()
            .expect("unmount read-only FUSE session");
    }
}
