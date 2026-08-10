//! Cancellation-safe length-prefixed IPC framing.

use astrid_types::ipc::IpcMessage;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::MAX_FRAME_BYTES;

pub(super) struct FramedReader<R> {
    reader: R,
    buffered: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            buffered: Vec::new(),
        }
    }

    /// Read one length-prefixed message while retaining partial frame state.
    ///
    /// `AsyncReadExt::read` is cancellation-safe, and all bytes returned by a
    /// completed read are appended before the next await. Recreating this
    /// future after another `select!` branch wins therefore cannot discard a
    /// partially received prefix or body.
    pub(super) async fn read_message(&mut self) -> std::io::Result<Option<IpcMessage>> {
        loop {
            if self.buffered.len() >= 4 {
                let len = u32::from_be_bytes(
                    self.buffered[..4]
                        .try_into()
                        .expect("four-byte frame prefix"),
                ) as usize;
                if len > MAX_FRAME_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("IPC frame too large: {len} bytes"),
                    ));
                }
                let frame_len = 4_usize.checked_add(len).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "IPC frame overflow")
                })?;
                if self.buffered.len() >= frame_len {
                    let message =
                        serde_json::from_slice(&self.buffered[4..frame_len]).map_err(|error| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("invalid IPC message: {error}"),
                            )
                        })?;
                    self.buffered.drain(..frame_len);
                    return Ok(Some(message));
                }
            }

            let mut chunk = [0_u8; 8192];
            let read = self.reader.read(&mut chunk).await?;
            if read == 0 {
                if self.buffered.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "local IPC stream ended within a frame",
                ));
            }
            self.buffered.extend_from_slice(&chunk[..read]);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use astrid_types::Topic;
    use astrid_types::ipc::IpcPayload;
    use tokio::io::AsyncWriteExt;
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn retains_partial_body_when_read_is_cancelled() {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let expected = IpcMessage::new(
            Topic::from_raw("astrid.v1.admin.status.test"),
            IpcPayload::RawJson(serde_json::json!({"request": "status"})),
            Uuid::new_v4(),
        );
        let body = serde_json::to_vec(&expected).expect("serialize frame");
        let split = body.len() / 2;
        writer
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .expect("write prefix");
        writer
            .write_all(&body[..split])
            .await
            .expect("write partial body");

        let mut reader = FramedReader::new(reader);
        tokio::time::timeout(Duration::from_millis(20), reader.read_message())
            .await
            .expect_err("partial frame should remain pending");

        writer
            .write_all(&body[split..])
            .await
            .expect("write body remainder");
        let actual = tokio::time::timeout(Duration::from_secs(2), reader.read_message())
            .await
            .expect("completed frame timeout")
            .expect("read completed frame")
            .expect("frame present");
        assert_eq!(actual.topic, expected.topic);
        assert_eq!(actual.payload, expected.payload);
        assert_eq!(actual.source_id, expected.source_id);
    }
}
