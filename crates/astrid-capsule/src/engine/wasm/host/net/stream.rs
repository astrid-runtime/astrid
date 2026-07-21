//! Shared stream helpers — byte-stream framing for the length-prefixed
//! `read` / `write` path and raw byte-stream helpers for the std-style
//! `read-bytes` / `write-bytes` path. Updated for the resource-table
//! storage model in `mod.rs`.

use crate::engine::wasm::bindings::astrid::net::host::NetReadStatus;

/// Bounded timeout on a `connect-tcp` outbound handshake.
pub(super) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Host-side cap on a single byte-stream read/peek buffer.
pub(super) const MAX_BYTES_PER_CALL: usize = 10 * 1024 * 1024;

use crate::engine::wasm::host_state::FrameReadState;

/// Returns true for IO errors that represent a normal peer disconnect.
pub(super) fn is_peer_disconnect(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Read one length-prefixed frame from `stream`.
pub(super) async fn read_frame<S>(
    stream: &mut S,
    state: &mut FrameReadState,
) -> Result<NetReadStatus, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let header_result = tokio::time::timeout(std::time::Duration::from_millis(50), async {
        while state.header_read < state.header.len() {
            let read = stream.read(&mut state.header[state.header_read..]).await?;
            if read == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            state.header_read += read;
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    match header_result {
        Err(_) => return Ok(NetReadStatus::Pending),
        Ok(Err(e)) if is_peer_disconnect(&e) => return Ok(NetReadStatus::Closed),
        Ok(Err(e)) => return Err(format!("socket read error: {e}")),
        Ok(Ok(())) => {},
    }

    if state.payload.is_empty() {
        let len = u32::from_be_bytes(state.header) as usize;
        if len > MAX_BYTES_PER_CALL {
            *state = FrameReadState::default();
            return Err("Payload too large (max 10MB)".to_string());
        }
        state.payload.resize(len, 0);
    }

    let timeout_ms = 5000 + (state.payload.len() as u64 / 1024);
    let payload_result =
        tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), async {
            while state.payload_read < state.payload.len() {
                let read = stream
                    .read(&mut state.payload[state.payload_read..])
                    .await?;
                if read == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                state.payload_read += read;
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
    match payload_result {
        Err(_) => return Err("Payload read timed out".to_string()),
        Ok(Err(e)) if is_peer_disconnect(&e) => return Ok(NetReadStatus::Closed),
        Ok(Err(e)) => return Err(format!("socket payload read error: {e}")),
        Ok(Ok(())) => {},
    }

    let payload = std::mem::take(&mut state.payload);
    *state = FrameReadState::default();
    Ok(NetReadStatus::Data(payload))
}

/// Write one length-prefixed frame to `stream`.
pub(super) async fn write_frame<S>(stream: &mut S, data: &[u8]) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(data.len())
        .map_err(|_| std::io::Error::other("write payload too large for length prefix"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Read up to `max_bytes` from `stream` without length-prefix framing.
pub(super) async fn read_bytes_inner<S>(
    stream: &mut S,
    max_bytes: usize,
    timeout: Option<std::time::Duration>,
) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let max_bytes = max_bytes.min(MAX_BYTES_PER_CALL);
    let mut buf = vec![0u8; max_bytes];
    let result = match timeout {
        Some(d) => tokio::time::timeout(d, stream.read(&mut buf)).await,
        None => Ok(stream.read(&mut buf).await),
    };
    match result {
        Ok(Ok(0)) => Ok(Vec::new()),
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        },
        Ok(Err(e)) if is_peer_disconnect(&e) => Ok(Vec::new()),
        Ok(Err(e)) => Err(format!("read error: {e}")),
        Err(_) => Err("read would block".to_string()),
    }
}

/// Write `data` to `stream` without framing. Returns bytes-written.
pub(super) async fn write_bytes_inner<S>(
    stream: &mut S,
    data: &[u8],
    timeout: Option<std::time::Duration>,
) -> Result<u32, String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let fut = stream.write(data);
    let n = match timeout {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) if is_peer_disconnect(&e) => return Err(format!("write disconnect: {e}")),
            Ok(Err(e)) => return Err(format!("write error: {e}")),
            Err(_) => return Err("write would block".to_string()),
        },
        None => fut.await.map_err(|e| format!("write error: {e}"))?,
    };
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    //! Regression tests for the PR #752 net-stream fixes:
    //!
    //! - `is_peer_disconnect` must cover every error kind the kernel
    //!   treats as a graceful close, otherwise `write` surfaces
    //!   `Unknown(...)` to the guest instead of `ConnectionReset`.
    //! - `write_frame` propagates `BrokenPipe` (the fix replaces a
    //!   silent `Ok(())` swallow in `tcp_stream::write`).
    //! - `read_frame` returns `Closed` on a half-closed peer.
    use super::*;
    use std::io;

    #[test]
    fn peer_disconnect_recognises_all_close_kinds() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::UnexpectedEof,
        ] {
            let e = io::Error::new(kind, "test");
            assert!(is_peer_disconnect(&e), "{kind:?} should be peer-disconnect");
        }
    }

    #[test]
    fn peer_disconnect_rejects_unrelated_kinds() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
        ] {
            let e = io::Error::new(kind, "test");
            assert!(
                !is_peer_disconnect(&e),
                "{kind:?} must NOT be classified as peer-disconnect"
            );
        }
    }

    #[tokio::test]
    async fn write_frame_returns_brokenpipe_when_peer_closes() {
        // tokio::io::duplex pair: closing the read half causes the
        // write half's next write to fail with BrokenPipe. This is
        // the exact failure mode `tcp_stream::write` now surfaces as
        // `ConnectionReset` instead of silently swallowing.
        let (mut tx, rx) = tokio::io::duplex(64);
        drop(rx);
        let err = write_frame(&mut tx, &[1u8; 16])
            .await
            .expect_err("write to closed peer must error");
        assert!(
            is_peer_disconnect(&err),
            "expected peer-disconnect kind, got {:?}",
            err.kind()
        );
    }

    #[tokio::test]
    async fn read_frame_returns_closed_on_half_close() {
        // Peer drops without sending — read_exact gets UnexpectedEof
        // and `read_frame` converts it to `NetReadStatus::Closed`.
        let (tx, mut rx) = tokio::io::duplex(64);
        drop(tx);
        let status = read_frame(&mut rx, &mut FrameReadState::default())
            .await
            .expect("classified, not error");
        assert!(matches!(status, NetReadStatus::Closed));
    }

    #[tokio::test]
    async fn read_frame_preserves_fragmented_header_across_pending() {
        use tokio::io::AsyncWriteExt;

        let (mut tx, mut rx) = tokio::io::duplex(64);
        let mut state = FrameReadState::default();
        tx.write_all(&[0]).await.expect("first header byte");

        let pending = read_frame(&mut rx, &mut state)
            .await
            .expect("partial header is not an error");
        assert!(matches!(pending, NetReadStatus::Pending));
        assert_eq!(state.header_read, 1);

        tx.write_all(&[0, 0, 3, b'a', b'b', b'c'])
            .await
            .expect("remaining frame");
        let complete = read_frame(&mut rx, &mut state)
            .await
            .expect("fragmented frame completes");
        assert!(matches!(complete, NetReadStatus::Data(bytes) if bytes == b"abc"));
        assert_eq!(state.header_read, 0);
    }
}
