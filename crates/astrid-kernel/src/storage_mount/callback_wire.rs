//! Bounded framing and protocol translation for private mount callbacks.

use std::io;

use astrid_core::local_transport::LocalStream;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_MAX_IO_BYTES, STORAGE_FILESYSTEM_PROTOCOL_V1,
    STORAGE_FILESYSTEM_PROTOCOL_V2, StorageFilesystemOperationV1, StorageFilesystemOperationV2,
    StorageFilesystemOutcomeV1, StorageFilesystemOutcomeV2, StorageFilesystemRequestV1,
    StorageFilesystemRequestV2, StorageFilesystemResponseV1, StorageFilesystemResponseV2,
    StorageFilesystemSuccessV1, StorageFilesystemSuccessV2,
};
use base64::Engine as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const MAX_CALLBACK_FRAME_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct CallbackRequest {
    pub(super) request: StorageFilesystemRequestV1,
    pub(super) response_version: u16,
}

#[derive(serde::Deserialize)]
struct ProtocolProbe {
    protocol_version: u16,
}

pub(super) enum CallbackResponse {
    V1(StorageFilesystemResponseV1),
    V2(StorageFilesystemResponseV2),
}

#[cfg(any(unix, windows))]
pub(super) async fn read_request(
    stream: &mut LocalStream,
) -> Result<Option<CallbackRequest>, io::Error> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {},
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_CALLBACK_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount callback frame exceeds limit",
        ));
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    let protocol = serde_json::from_slice::<ProtocolProbe>(&bytes)
        .map_err(io::Error::other)?
        .protocol_version;
    if protocol == STORAGE_FILESYSTEM_PROTOCOL_V2 {
        let request = serde_json::from_slice::<StorageFilesystemRequestV2>(&bytes)
            .map_err(io::Error::other)?;
        let operation = decode_operation_v2(request.operation)?;
        Ok(Some(CallbackRequest {
            request: StorageFilesystemRequestV1 {
                protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
                request_id: request.request_id,
                lease_token: request.lease_token,
                operation,
            },
            response_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
        }))
    } else if protocol == STORAGE_FILESYSTEM_PROTOCOL_V1 {
        let request = serde_json::from_slice::<StorageFilesystemRequestV1>(&bytes)
            .map_err(io::Error::other)?;
        Ok(Some(CallbackRequest {
            request,
            response_version: STORAGE_FILESYSTEM_PROTOCOL_V1,
        }))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported storage filesystem protocol",
        ))
    }
}

fn decode_operation_v2(
    operation: StorageFilesystemOperationV2,
) -> io::Result<StorageFilesystemOperationV1> {
    Ok(match operation {
        StorageFilesystemOperationV2::Stat { path } => StorageFilesystemOperationV1::Stat { path },
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
        } => {
            let data = base64::engine::general_purpose::STANDARD
                .decode(data_base64.as_bytes())
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid base64 filesystem payload: {error}"),
                    )
                })?;
            let data_length = u64::try_from(data.len()).unwrap_or(u64::MAX);
            if data_length > STORAGE_FILESYSTEM_MAX_IO_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "filesystem payload exceeds limit",
                ));
            }
            StorageFilesystemOperationV1::Write { path, offset, data }
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
    })
}

#[cfg(any(unix, windows))]
pub(super) async fn write_response(
    stream: &mut LocalStream,
    response: CallbackResponse,
) -> Result<(), io::Error> {
    let bytes = match response {
        CallbackResponse::V1(response) => serde_json::to_vec(&response),
        CallbackResponse::V2(response) => serde_json::to_vec(&response),
    }
    .map_err(io::Error::other)?;
    if bytes.len() > MAX_CALLBACK_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount callback response exceeds limit",
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mount callback response is too large",
        )
    })?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

pub(super) fn response_v2(response: StorageFilesystemResponseV1) -> StorageFilesystemResponseV2 {
    let outcome = match response.outcome {
        StorageFilesystemOutcomeV1::Success(success) => {
            StorageFilesystemOutcomeV2::Success(match success {
                StorageFilesystemSuccessV1::Done => StorageFilesystemSuccessV2::Done,
                StorageFilesystemSuccessV1::Entry(entry) => {
                    StorageFilesystemSuccessV2::Entry(entry)
                },
                StorageFilesystemSuccessV1::Entries(entries) => {
                    StorageFilesystemSuccessV2::Entries(entries)
                },
                StorageFilesystemSuccessV1::Data(data) => StorageFilesystemSuccessV2::Data {
                    data_base64: base64::engine::general_purpose::STANDARD.encode(data),
                },
                StorageFilesystemSuccessV1::Written(length) => {
                    StorageFilesystemSuccessV2::Written(length)
                },
            })
        },
        StorageFilesystemOutcomeV1::Failure(failure) => {
            StorageFilesystemOutcomeV2::Failure(failure)
        },
    };
    StorageFilesystemResponseV2 {
        protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
        request_id: response.request_id,
        outcome,
    }
}
