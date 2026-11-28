//! Cancellation-safe length-prefixed IPC framing.

use astrid_types::ipc::IpcMessage;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::MAX_FRAME_BYTES;
use crate::frame_segments::{Incoming, incoming};

pub(super) use crate::frame_writer::write_frame;

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
            match incoming(&self.buffered, MAX_FRAME_BYTES) {
                Incoming::Incomplete => {},
                Incoming::Oversized(len) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("IPC frame too large: {len} bytes"),
                    ));
                },
                Incoming::Complete { body, consumed } => {
                    let message = serde_json::from_slice(body).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid IPC message")
                    })?;
                    self.buffered.drain(..consumed);
                    return Ok(Some(message));
                },
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
    async fn short_writes_preserve_back_to_back_frame_boundaries() {
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let send = async move {
            write_frame(&mut writer, &[]).await.unwrap();
            write_frame(&mut writer, b"abc").await.unwrap();
        };
        let receive = async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"\0\0\0\0\0\0\0\x03abc");
        };
        tokio::join!(send, receive);
    }

    #[tokio::test]
    async fn dropping_connection_task_during_write_leaves_only_a_frame_prefix() {
        for capacity in [1, 4, 6] {
            let (mut writer, mut reader) = tokio::io::duplex(capacity);
            let task = tokio::spawn(async move {
                write_frame(&mut writer, b"payload").await.unwrap();
                write_frame(&mut writer, b"later").await.unwrap();
            });
            // Observe the first byte before cancellation so the test cannot
            // pass just because the connection task has not started writing.
            let first = reader.read_u8().await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            let mut written = vec![first];
            reader.read_to_end(&mut written).await.unwrap();
            assert!(b"\0\0\0\x07payload".starts_with(&written));
            assert!(written.len() < 11);
        }
    }

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
            .write_all(
                &u32::try_from(body.len())
                    .expect("test frame fits u32")
                    .to_be_bytes(),
            )
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

    #[tokio::test]
    async fn malformed_payload_error_does_not_echo_submitted_input() {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let message = IpcMessage::new(
            Topic::from_raw("astrid.v1.private.elicit.reply"),
            IpcPayload::Connect,
            Uuid::nil(),
        );
        let mut frame = serde_json::to_value(message).unwrap();
        frame["payload"] = serde_json::json!({
            "type": "elicit_response", "request_id": Uuid::nil(),
            "values": "synthetic-secret-in-invalid-array"
        });
        let bytes = serde_json::to_vec(&frame).unwrap();
        writer
            .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        writer.write_all(&bytes).await.unwrap();
        let error = FramedReader::new(reader).read_message().await.unwrap_err();
        assert_eq!(error.to_string(), "invalid IPC message");
    }

    #[tokio::test]
    async fn buffered_messages_keep_their_own_payload_and_source() {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let messages = ["first", "second"].map(|label| {
            IpcMessage::new(
                Topic::from_raw("astrid.v1.admin.status.test"),
                IpcPayload::RawJson(serde_json::json!({"label":label})),
                Uuid::new_v4(),
            )
        });
        for message in &messages {
            write_frame(&mut writer, &serde_json::to_vec(message).unwrap())
                .await
                .unwrap();
        }
        drop(writer);
        let mut reader = FramedReader::new(reader);
        for expected in messages {
            let actual = reader.read_message().await.unwrap().unwrap();
            assert_eq!(actual.source_id, expected.source_id);
            assert_eq!(actual.payload, expected.payload);
        }
        assert!(reader.read_message().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_oversized_frame_from_prefix_alone() {
        let (mut writer, reader) = tokio::io::duplex(16);
        writer
            .write_all(
                &u32::try_from(MAX_FRAME_BYTES + 1)
                    .expect("frame limit fits u32")
                    .to_be_bytes(),
            )
            .await
            .expect("write prefix");

        let error = FramedReader::new(reader)
            .read_message()
            .await
            .expect_err("oversized frame must be rejected before its body is read");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
