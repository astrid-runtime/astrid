use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Write one length-prefixed frame. A failed or cancelled write can leave a prefix.
pub(super) async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    body: &[u8],
) -> std::io::Result<()> {
    let prefix = crate::frame_segments::body_prefix(body)
        .ok_or_else(|| std::io::Error::other("frame exceeds 4 GiB"))?;
    let mut frame = crate::frame_segments::FrameSegments::new(&prefix, body);
    while !frame.next().is_empty() {
        let count = writer.write(frame.next()).await?;
        if count == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        if !frame.accept(count) {
            return Err(std::io::Error::other(
                "transport reported more bytes than offered",
            ));
        }
    }
    writer.flush().await
}
