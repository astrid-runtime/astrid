//! `astrid:fs@1.0.0` host implementation.
//!
//! STUB SHELL — trait shape matches the new WIT but all methods return
//! `todo!()`. The previous 836-line implementation (VFS path resolution,
//! cap-std confinement, security-gate plumbing) ports back in a follow-up
//! commit alongside the FileHandle resource integration.

use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::fs::host::{
    self as fs, ErrorCode, FileHandle, FileStat, HostFileHandle, OpenMode,
};
use crate::engine::wasm::host_state::HostState;

impl fs::Host for HostState {
    fn fs_open(
        &mut self,
        _path: String,
        _mode: OpenMode,
    ) -> Result<Resource<FileHandle>, ErrorCode> {
        todo!("fs_open: FileHandle resource integration pending")
    }

    fn fs_exists(&mut self, _path: String) -> Result<bool, ErrorCode> {
        todo!("fs_exists: VFS plumbing port pending")
    }

    fn fs_mkdir(&mut self, _path: String) -> Result<(), ErrorCode> {
        todo!("fs_mkdir: VFS plumbing port pending")
    }

    fn fs_mkdir_all(&mut self, _path: String) -> Result<(), ErrorCode> {
        todo!("fs_mkdir_all: VFS plumbing port pending")
    }

    fn fs_readdir(&mut self, _path: String) -> Result<Vec<String>, ErrorCode> {
        todo!("fs_readdir: VFS plumbing port pending")
    }

    fn fs_stat(&mut self, _path: String) -> Result<FileStat, ErrorCode> {
        todo!("fs_stat: VFS plumbing port pending")
    }

    fn fs_stat_symlink(&mut self, _path: String) -> Result<FileStat, ErrorCode> {
        todo!("fs_stat_symlink: lstat impl pending")
    }

    fn fs_unlink(&mut self, _path: String) -> Result<(), ErrorCode> {
        todo!("fs_unlink: VFS plumbing port pending")
    }

    fn read_file(&mut self, _path: String) -> Result<Vec<u8>, ErrorCode> {
        todo!("read_file: VFS plumbing port pending")
    }

    fn write_file(&mut self, _path: String, _content: Vec<u8>) -> Result<(), ErrorCode> {
        todo!("write_file: VFS plumbing port pending")
    }

    fn fs_append(&mut self, _path: String, _content: Vec<u8>) -> Result<(), ErrorCode> {
        todo!("fs_append: append-mode impl pending")
    }

    fn fs_copy(&mut self, _src: String, _dst: String) -> Result<(), ErrorCode> {
        todo!("fs_copy: cross-scheme guard + VFS copy pending")
    }

    fn fs_rename(&mut self, _src: String, _dst: String) -> Result<(), ErrorCode> {
        todo!("fs_rename: cross-scheme guard + VFS rename pending")
    }

    fn fs_remove_dir_all(&mut self, _path: String) -> Result<u64, ErrorCode> {
        todo!("fs_remove_dir_all: recursive remove pending")
    }

    fn fs_canonicalize(&mut self, _path: String) -> Result<String, ErrorCode> {
        todo!("fs_canonicalize: VFS-scheme canonicalization pending")
    }

    fn fs_read_link(&mut self, _path: String) -> Result<String, ErrorCode> {
        todo!("fs_read_link: readlink impl pending")
    }

    fn fs_hard_link(&mut self, _src: String, _link_path: String) -> Result<(), ErrorCode> {
        todo!("fs_hard_link: cross-scheme guard + hard-link impl pending")
    }
}

impl HostFileHandle for HostState {
    fn read_at(
        &mut self,
        _self_: Resource<FileHandle>,
        _offset: u64,
        _max_bytes: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        todo!("FileHandle.read_at: positional read impl pending")
    }

    fn write_at(
        &mut self,
        _self_: Resource<FileHandle>,
        _offset: u64,
        _data: Vec<u8>,
    ) -> Result<u32, ErrorCode> {
        todo!("FileHandle.write_at: positional write impl pending")
    }

    fn sync_data(&mut self, _self_: Resource<FileHandle>) -> Result<(), ErrorCode> {
        todo!("FileHandle.sync_data: fdatasync impl pending")
    }

    fn sync_all(&mut self, _self_: Resource<FileHandle>) -> Result<(), ErrorCode> {
        todo!("FileHandle.sync_all: fsync impl pending")
    }

    fn stat(&mut self, _self_: Resource<FileHandle>) -> Result<FileStat, ErrorCode> {
        todo!("FileHandle.stat: fstat impl pending")
    }

    fn set_len(&mut self, _self_: Resource<FileHandle>, _size: u64) -> Result<(), ErrorCode> {
        todo!("FileHandle.set_len: ftruncate impl pending")
    }

    fn drop(&mut self, _rep: Resource<FileHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}
