//! `HostFileHandle` impl — file-handle resource methods (pread/pwrite,
//! fsync, set-len, stat).
//!
//! STUB SHELL — every method returns `Unknown("port pending")`.
//! Implementation depends on the FileHandle resource lifecycle work
//! (open-mode + per-call positional I/O over the VFS), which is the
//! single biggest fs port-back. Tracked as a dedicated follow-up
//! commit.

use wasmtime::component::Resource;

use crate::engine::wasm::bindings::astrid::fs::host::{
    ErrorCode, FileHandle, FileStat, HostFileHandle,
};
use crate::engine::wasm::host_state::HostState;

impl HostFileHandle for HostState {
    fn read_at(
        &mut self,
        _self_: Resource<FileHandle>,
        _offset: u64,
        _max_bytes: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        Err(ErrorCode::Unknown(
            "FileHandle.read-at: positional read port pending".to_string(),
        ))
    }

    fn write_at(
        &mut self,
        _self_: Resource<FileHandle>,
        _offset: u64,
        _data: Vec<u8>,
    ) -> Result<u32, ErrorCode> {
        Err(ErrorCode::Unknown(
            "FileHandle.write-at: positional write port pending".to_string(),
        ))
    }

    fn sync_data(&mut self, _self_: Resource<FileHandle>) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "FileHandle.sync-data: fdatasync port pending".to_string(),
        ))
    }

    fn sync_all(&mut self, _self_: Resource<FileHandle>) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "FileHandle.sync-all: fsync port pending".to_string(),
        ))
    }

    fn stat(&mut self, _self_: Resource<FileHandle>) -> Result<FileStat, ErrorCode> {
        Err(ErrorCode::Unknown(
            "FileHandle.stat: fstat port pending".to_string(),
        ))
    }

    fn set_len(&mut self, _self_: Resource<FileHandle>, _size: u64) -> Result<(), ErrorCode> {
        Err(ErrorCode::Unknown(
            "FileHandle.set-len: ftruncate port pending".to_string(),
        ))
    }

    fn drop(&mut self, _rep: Resource<FileHandle>) -> wasmtime::Result<()> {
        Ok(())
    }
}
