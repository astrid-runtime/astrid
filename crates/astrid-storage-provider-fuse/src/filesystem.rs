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
#[path = "filesystem/tests.rs"]
mod tests;
