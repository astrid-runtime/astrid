//! Authenticated provider callback client.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;

use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_PROTOCOL_V2, StorageFilesystemFailureV1, StorageFilesystemOperationV1,
    StorageFilesystemOperationV2, StorageFilesystemOutcomeV2, StorageFilesystemRequestV2,
    StorageFilesystemResponseV2, StorageFilesystemSuccessV1, StorageFilesystemSuccessV2,
    StorageMountLeaseV1,
};
use base64::Engine as _;
use fuser::Errno;
use uuid::Uuid;

/// Version-two base64 framing carries the kernel's complete bounded I/O payload.
pub(crate) const CALLBACK_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const MAX_CALLBACK_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// A local callback transport error mapped directly to an errno.
#[derive(Debug)]
pub(crate) enum CallbackError {
    /// The kernel returned a structured operation failure.
    Failure(StorageFilesystemFailureV1),
    /// Transport, framing, protocol, or result-shape validation failed.
    Transport(String),
}

/// Client bound to one immutable lease.
pub(crate) struct CallbackClient {
    lease: StorageMountLeaseV1,
}

impl CallbackClient {
    /// Create a client for the lease returned by the authenticated kernel.
    pub(crate) fn new(lease: StorageMountLeaseV1) -> Self {
        Self { lease }
    }

    /// Issue one authenticated owner-bound operation.
    pub(crate) fn call(
        &self,
        operation: StorageFilesystemOperationV1,
    ) -> Result<StorageFilesystemSuccessV1, CallbackError> {
        let request = StorageFilesystemRequestV2 {
            protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
            request_id: Uuid::new_v4().to_string(),
            lease_token: self.lease.lease_token.clone(),
            operation: encode_operation(operation),
        };
        let bytes = serde_json::to_vec(&request)
            .map_err(|error| CallbackError::Transport(error.to_string()))?;
        if bytes.len() > MAX_CALLBACK_FRAME_BYTES {
            return Err(CallbackError::Transport(
                "callback request exceeds the bounded frame size".to_owned(),
            ));
        }
        let length = u32::try_from(bytes.len())
            .map_err(|_| CallbackError::Transport("callback frame length is invalid".to_owned()))?;
        let mut stream = UnixStream::connect(&self.lease.callback_path)
            .map_err(|error| CallbackError::Transport(error.to_string()))?;
        stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(&bytes))
            .map_err(|error| CallbackError::Transport(error.to_string()))?;
        stream
            .flush()
            .map_err(|error| CallbackError::Transport(error.to_string()))?;

        let mut length_bytes = [0_u8; 4];
        stream
            .read_exact(&mut length_bytes)
            .map_err(|error| CallbackError::Transport(error.to_string()))?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| {
            CallbackError::Transport("callback response length is invalid".to_owned())
        })?;
        if length > MAX_CALLBACK_FRAME_BYTES {
            return Err(CallbackError::Transport(
                "callback response exceeds the bounded frame size".to_owned(),
            ));
        }
        let mut response_bytes = vec![0_u8; length];
        stream
            .read_exact(&mut response_bytes)
            .map_err(|error| CallbackError::Transport(error.to_string()))?;
        let response: StorageFilesystemResponseV2 = serde_json::from_slice(&response_bytes)
            .map_err(|error| CallbackError::Transport(error.to_string()))?;
        if response.protocol_version != STORAGE_FILESYSTEM_PROTOCOL_V2
            || response.request_id != request.request_id
        {
            return Err(CallbackError::Transport(
                "callback response protocol or correlation identity is invalid".to_owned(),
            ));
        }
        match response.outcome {
            StorageFilesystemOutcomeV2::Success(success) => decode_success(success),
            StorageFilesystemOutcomeV2::Failure(failure) => Err(CallbackError::Failure(failure)),
        }
    }
}

fn encode_operation(operation: StorageFilesystemOperationV1) -> StorageFilesystemOperationV2 {
    match operation {
        StorageFilesystemOperationV1::Stat { path } => StorageFilesystemOperationV2::Stat { path },
        StorageFilesystemOperationV1::ReadDirectory { path } => {
            StorageFilesystemOperationV2::ReadDirectory { path }
        },
        StorageFilesystemOperationV1::Read {
            path,
            offset,
            length,
        } => StorageFilesystemOperationV2::Read {
            path,
            offset,
            length,
        },
        StorageFilesystemOperationV1::Write { path, offset, data } => {
            StorageFilesystemOperationV2::Write {
                path,
                offset,
                data_base64: base64::engine::general_purpose::STANDARD.encode(data),
            }
        },
        StorageFilesystemOperationV1::SetLength { path, length } => {
            StorageFilesystemOperationV2::SetLength { path, length }
        },
        StorageFilesystemOperationV1::Create { path, kind } => {
            StorageFilesystemOperationV2::Create { path, kind }
        },
        StorageFilesystemOperationV1::Remove { path } => {
            StorageFilesystemOperationV2::Remove { path }
        },
        StorageFilesystemOperationV1::Rename { from, to, replace } => {
            StorageFilesystemOperationV2::Rename { from, to, replace }
        },
        StorageFilesystemOperationV1::Sync => StorageFilesystemOperationV2::Sync,
    }
}

fn decode_success(
    success: StorageFilesystemSuccessV2,
) -> Result<StorageFilesystemSuccessV1, CallbackError> {
    Ok(match success {
        StorageFilesystemSuccessV2::Done => StorageFilesystemSuccessV1::Done,
        StorageFilesystemSuccessV2::Entry(entry) => StorageFilesystemSuccessV1::Entry(entry),
        StorageFilesystemSuccessV2::Entries(entries) => {
            StorageFilesystemSuccessV1::Entries(entries)
        },
        StorageFilesystemSuccessV2::Data { data_base64 } => {
            let data = base64::engine::general_purpose::STANDARD
                .decode(data_base64.as_bytes())
                .map_err(|error| CallbackError::Transport(error.to_string()))?;
            if data.len() > CALLBACK_CHUNK_BYTES {
                return Err(CallbackError::Transport(
                    "callback response payload exceeds the bounded I/O size".to_owned(),
                ));
            }
            StorageFilesystemSuccessV1::Data(data)
        },
        StorageFilesystemSuccessV2::Written(length) => StorageFilesystemSuccessV1::Written(length),
    })
}

/// Map callback and transport failures to Linux errno values.
pub(crate) fn callback_errno(error: CallbackError) -> Errno {
    match error {
        CallbackError::Failure(failure) => match failure.code.as_str() {
            "not-found" => Errno::ENOENT,
            "already-exists" => Errno::EEXIST,
            "is-directory" => Errno::EISDIR,
            "not-directory" | "namespace-conflict" => Errno::ENOTDIR,
            "directory-not-empty" => Errno::ENOTEMPTY,
            "invalid-path" => Errno::EINVAL,
            "read-only" => Errno::EROFS,
            "unauthorized" | "stale-lease" => Errno::EACCES,
            _ => Errno::EIO,
        },
        CallbackError::Transport(message) => {
            eprintln!("astrid-storage-provider-fuse callback transport error: {message}");
            Errno::EIO
        },
    }
}
