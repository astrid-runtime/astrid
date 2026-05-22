//! Shared stream helpers — byte-stream framing for the length-prefixed
//! `read` / `write` path and raw byte-stream helpers for the std-style
//! `read-bytes` / `write-bytes` path. Updated for the resource-table
//! storage model in `mod.rs`.

use crate::engine::wasm::bindings::astrid::net::host::NetReadStatus;

/// Bounded timeout on a `connect-tcp` outbound handshake.
pub(super) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Host-side cap on a single byte-stream read/peek buffer.
pub(super) const MAX_BYTES_PER_CALL: usize = 10 * 1024 * 1024;

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
pub(super) async fn read_frame<S>(stream: &mut S) -> Result<NetReadStatus, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read_exact(&mut len_buf),
    )
    .await
    {
        Err(_) => return Ok(NetReadStatus::Pending),
        Ok(Err(e)) if is_peer_disconnect(&e) => return Ok(NetReadStatus::Closed),
        Ok(Err(e)) => return Err(format!("socket read error: {e}")),
        Ok(Ok(_)) => {},
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_BYTES_PER_CALL {
        return Err("Payload too large (max 10MB)".to_string());
    }

    let mut payload = vec![0u8; len];
    let timeout_ms = 5000 + (len as u64 / 1024);
    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        stream.read_exact(&mut payload),
    )
    .await
    {
        Err(_) => return Err("Payload read timed out".to_string()),
        Ok(Err(e)) if is_peer_disconnect(&e) => return Ok(NetReadStatus::Closed),
        Ok(Err(e)) => return Err(format!("socket payload read error: {e}")),
        Ok(Ok(_)) => {},
    }

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
