use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use astrid_core::local_transport;
use astrid_core::storage_filesystem::{
    STORAGE_FILESYSTEM_MAX_IO_BYTES, STORAGE_FILESYSTEM_PROTOCOL_V2, StorageFilesystemOperationV1,
    StorageFilesystemOperationV2, StorageFilesystemOutcomeV2, StorageFilesystemRequestV2,
    StorageFilesystemResponseV2, StorageFilesystemSuccessV1, StorageFilesystemSuccessV2,
};
use base64::Engine as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::runtime::Runtime;

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(30);

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum AdapterFailure {
    Transport(String),
    Filesystem { code: String, message: String },
}

pub(crate) struct CallbackClient {
    callback_path: PathBuf,
    lease_token: Arc<str>,
    runtime: Arc<Runtime>,
    request_sequence: std::sync::atomic::AtomicU64,
}

impl CallbackClient {
    pub(crate) fn new(callback_path: PathBuf, lease_token: String, runtime: Arc<Runtime>) -> Self {
        Self {
            callback_path,
            lease_token: Arc::from(lease_token),
            runtime,
            request_sequence: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub(crate) fn invoke(
        &self,
        operation: StorageFilesystemOperationV1,
    ) -> Result<StorageFilesystemSuccessV1, AdapterFailure> {
        self.runtime.block_on(self.invoke_async(operation))
    }

    async fn invoke_async(
        &self,
        operation: StorageFilesystemOperationV1,
    ) -> Result<StorageFilesystemSuccessV1, AdapterFailure> {
        let sequence = self
            .request_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = StorageFilesystemRequestV2 {
            protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
            request_id: format!("winfsp-{sequence}"),
            lease_token: self.lease_token.to_string(),
            operation: encode_operation(operation)?,
        };
        let bytes = serde_json::to_vec(&request)
            .map_err(|error| AdapterFailure::Transport(format!("encode callback: {error}")))?;
        let length = u32::try_from(bytes.len())
            .map_err(|_| AdapterFailure::Transport("callback frame is too large".to_owned()))?;

        let future = async {
            let mut stream = local_transport::connect(&self.callback_path)
                .await
                .map_err(|error| AdapterFailure::Transport(format!("connect callback: {error}")))?;
            stream
                .write_all(&length.to_be_bytes())
                .await
                .map_err(|error| {
                    AdapterFailure::Transport(format!("send callback length: {error}"))
                })?;
            stream.write_all(&bytes).await.map_err(|error| {
                AdapterFailure::Transport(format!("send callback request: {error}"))
            })?;
            stream.flush().await.map_err(|error| {
                AdapterFailure::Transport(format!("flush callback request: {error}"))
            })?;

            let mut response_length = [0_u8; 4];
            stream
                .read_exact(&mut response_length)
                .await
                .map_err(|error| {
                    AdapterFailure::Transport(format!("read callback length: {error}"))
                })?;
            let response_bytes = receive_bounded(&mut stream, response_length).await?;
            let response = serde_json::from_slice::<StorageFilesystemResponseV2>(&response_bytes)
                .map_err(|error| {
                AdapterFailure::Transport(format!("decode callback: {error}"))
            })?;
            if response.protocol_version != STORAGE_FILESYSTEM_PROTOCOL_V2 {
                return Err(AdapterFailure::Transport(
                    "unsupported callback response protocol".to_owned(),
                ));
            }
            if response.request_id != request.request_id {
                return Err(AdapterFailure::Transport(
                    "callback response correlation mismatch".to_owned(),
                ));
            }
            match response.outcome {
                StorageFilesystemOutcomeV2::Success(success) => decode_success(success),
                StorageFilesystemOutcomeV2::Failure(failure) => Err(AdapterFailure::Filesystem {
                    code: failure.code,
                    message: failure.message,
                }),
            }
        };

        tokio::time::timeout(CALLBACK_TIMEOUT, future)
            .await
            .map_err(|_| AdapterFailure::Transport("callback timed out".to_owned()))?
    }
}

fn encode_operation(
    operation: StorageFilesystemOperationV1,
) -> Result<StorageFilesystemOperationV2, AdapterFailure> {
    Ok(match operation {
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
            if u64::try_from(data.len()).unwrap_or(u64::MAX) > STORAGE_FILESYSTEM_MAX_IO_BYTES {
                return Err(AdapterFailure::Transport(
                    "callback write exceeds I/O limit".to_owned(),
                ));
            }
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
    })
}

fn decode_success(
    success: StorageFilesystemSuccessV2,
) -> Result<StorageFilesystemSuccessV1, AdapterFailure> {
    match success {
        StorageFilesystemSuccessV2::Done => Ok(StorageFilesystemSuccessV1::Done),
        StorageFilesystemSuccessV2::Entry(entry) => Ok(StorageFilesystemSuccessV1::Entry(entry)),
        StorageFilesystemSuccessV2::Entries(entries) => {
            Ok(StorageFilesystemSuccessV1::Entries(entries))
        },
        StorageFilesystemSuccessV2::Data { data_base64 } => {
            let data = base64::engine::general_purpose::STANDARD
                .decode(data_base64.as_bytes())
                .map_err(|error| {
                    AdapterFailure::Transport(format!("decode callback data: {error}"))
                })?;
            if u64::try_from(data.len()).unwrap_or(u64::MAX) > STORAGE_FILESYSTEM_MAX_IO_BYTES {
                return Err(AdapterFailure::Transport(
                    "callback data exceeds I/O limit".to_owned(),
                ));
            }
            Ok(StorageFilesystemSuccessV1::Data(data))
        },
        StorageFilesystemSuccessV2::Written(length) => {
            Ok(StorageFilesystemSuccessV1::Written(length))
        },
    }
}

async fn receive_bounded<S>(stream: &mut S, length: [u8; 4]) -> Result<Vec<u8>, AdapterFailure>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(AdapterFailure::Transport(
            "callback response exceeds frame limit".to_owned(),
        ));
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| AdapterFailure::Transport(format!("read callback response: {error}")))?;
    Ok(bytes)
}

pub(crate) fn normalize_path(path: &str) -> Result<String, AdapterFailure> {
    if path == "\\" {
        return Ok(String::new());
    }
    if !path.starts_with('\\') || path.contains('/') || path.ends_with('\\') {
        return Err(invalid_path());
    }

    let source = &path[1..];
    let mut segments = Vec::new();
    for segment in source.split('\\') {
        if segment.is_empty()
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || segment.starts_with(' ')
            || segment.bytes().any(|byte| byte <= 0x1f || byte == 0x7f)
            || segment.chars().any(char::is_control)
            || segment.contains(':')
        {
            return Err(invalid_path());
        }
        let encoded_length = segment.encode_utf16().count();
        if encoded_length == 0 || encoded_length > 255 {
            return Err(invalid_path());
        }
        if is_reserved_windows_name(segment) {
            return Err(invalid_path());
        }
        segments.push(segment);
    }

    let normalized = segments.join("/");
    if normalized.encode_utf16().count() > 32_000 {
        return Err(invalid_path());
    }
    Ok(normalized)
}

fn is_reserved_windows_name(segment: &str) -> bool {
    let Some((stem, suffix)) = segment.split_once('.') else {
        return is_reserved_windows_stem(segment);
    };
    suffix.is_empty() || is_reserved_windows_stem(stem)
}

fn is_reserved_windows_stem(stem: &str) -> bool {
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("com"))
        && stem.as_bytes()[3].is_ascii_digit()
        && stem.as_bytes()[3] != b'0')
        || (stem.len() == 4
            && (stem.starts_with("LPT") || stem.starts_with("lpt"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

fn invalid_path() -> AdapterFailure {
    AdapterFailure::Filesystem {
        code: "invalid-path".to_owned(),
        message: "WinFsp path is outside the mounted canonical namespace".to_owned(),
    }
}

#[allow(dead_code)]
pub(crate) fn maximum_io_bytes() -> u64 {
    STORAGE_FILESYSTEM_MAX_IO_BYTES
}

#[allow(dead_code)]
pub(crate) fn endpoint_is_present(path: &Path) -> bool {
    local_transport::endpoint_is_present(path).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_root_and_backslash_paths() {
        assert_eq!(normalize_path("\\").unwrap(), "");
        assert_eq!(
            normalize_path("\\notes\\deep\\file.txt").unwrap(),
            "notes/deep/file.txt"
        );
    }

    #[test]
    fn normalize_rejects_escape_alias_and_reserved_paths() {
        for path in [
            "",
            "notes",
            "\\notes\\",
            "\\notes\\\\file",
            "\\notes/file",
            "\\..\\escape",
            "\\notes\\..\\escape",
            "\\notes\\.\\file",
            "\\notes\\file.txt\\..",
            "\\notes\\file:",
            "\\notes\\ file",
            "\\notes\\file.",
            "\\con",
            "\\COM1.txt",
            "\\lpt1",
        ] {
            assert!(normalize_path(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn protocol_v2_carries_the_full_io_limit_without_json_byte_arrays() {
        let data = vec![0xa5; usize::try_from(STORAGE_FILESYSTEM_MAX_IO_BYTES).unwrap()];
        let operation = encode_operation(StorageFilesystemOperationV1::Write {
            path: "large.bin".to_owned(),
            offset: 0,
            data: data.clone(),
        })
        .unwrap();
        let StorageFilesystemOperationV2::Write { data_base64, .. } = operation else {
            panic!("write operation changed kind");
        };
        assert!(!data_base64.contains('['));
        assert!(data_base64.len() < MAX_FRAME_BYTES);

        let decoded = decode_success(StorageFilesystemSuccessV2::Data { data_base64 }).unwrap();
        assert_eq!(decoded, StorageFilesystemSuccessV1::Data(data));
    }

    #[test]
    fn protocol_v2_rejects_decoded_data_above_the_io_limit() {
        let too_large = usize::try_from(STORAGE_FILESYSTEM_MAX_IO_BYTES)
            .unwrap()
            .saturating_add(1);
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(vec![0_u8; too_large]);
        assert!(decode_success(StorageFilesystemSuccessV2::Data { data_base64 }).is_err());
        assert!(
            encode_operation(StorageFilesystemOperationV1::Write {
                path: "too-large.bin".to_owned(),
                offset: 0,
                data: vec![0_u8; too_large],
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn callback_frames_bind_protocol_token_and_correlation() {
        let temporary = tempfile::tempdir().unwrap();
        let endpoint = temporary.path().join("callback.endpoint");
        let listener = local_transport::bind(&endpoint).unwrap();
        let server = tokio::spawn(async move {
            let mut stream = local_transport::accept(&listener).await.unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).await.unwrap();
            let value = serde_json::from_slice::<serde_json::Value>(&request).unwrap();
            let text = value.to_string();
            assert_eq!(value["protocol_version"], 2);
            assert_eq!(value["lease_token"], "test-token");
            assert!(!text.contains("\"principal\""));
            assert!(!text.contains("\"fleet\""));
            assert!(!text.contains("\"admin\""));

            let response = StorageFilesystemResponseV2 {
                protocol_version: STORAGE_FILESYSTEM_PROTOCOL_V2,
                request_id: value["request_id"].as_str().unwrap().to_owned(),
                outcome: StorageFilesystemOutcomeV2::Success(StorageFilesystemSuccessV2::Done),
            };
            let bytes = serde_json::to_vec(&response).unwrap();
            let length = u32::try_from(bytes.len()).unwrap();
            stream.write_all(&length.to_be_bytes()).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            stream.flush().await.unwrap();
        });

        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let client = CallbackClient::new(endpoint, "test-token".to_owned(), runtime);
        let outcome = tokio::task::spawn_blocking(move || {
            client.invoke(StorageFilesystemOperationV1::Sync).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(outcome, StorageFilesystemSuccessV1::Done);
        server.await.unwrap();
    }
}
