//! Shared stream helpers: byte-stream framing for the framed (legacy)
//! `net-read` / `net-write` path, raw byte-stream helpers for the std-style
//! `net-read-bytes` / `net-write-bytes` path, and the `with_tcp_slot` wrapper
//! used by every TCP-only getter/setter (peer-addr, nodelay, ttl, …).

use crate::engine::wasm::bindings::astrid::capsule::types::NetReadStatus;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::{HostState, NetStream};

/// Bounded timeout on a `net-connect-tcp` outbound handshake.
///
/// DNS resolve + TCP `connect` together must complete within this window,
/// otherwise the host fn returns an error rather than holding the WASM
/// guest in a host call indefinitely.
pub(super) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Host-side cap on a single byte-stream read/peek buffer.
///
/// Matches the framed `net-read` payload cap so a malicious or buggy
/// guest passing `u32::MAX` can't trigger a multi-GB allocation on the
/// host. 10 MB is well above any realistic single-call read for the
/// protocols this surface targets (TLS records ≤ 16 KB, WebSocket
/// frames typically ≤ 64 KB, MQTT control packets ≤ 256 MB but
/// streamed in chunks).
pub(super) const MAX_BYTES_PER_CALL: usize = 10 * 1024 * 1024;

/// Returns true for IO errors that represent a normal peer disconnect.
/// These should NOT trap the WASM guest — the run loop handles dead streams.
pub(super) fn is_peer_disconnect(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Read one length-prefixed frame from `stream`. Shared by UnixStream and
/// TcpStream paths — both implement [`tokio::io::AsyncRead`].
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
    if len > 10 * 1024 * 1024 {
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

/// Write one length-prefixed frame to `stream`. Shared across UnixStream
/// and TcpStream — both implement [`tokio::io::AsyncWrite`].
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
///
/// Contract:
/// - `Ok(empty Vec)` = **EOF** (peer disconnected). Unambiguous — matches
///   `std::io::Read::read` returning `Ok(0)`.
/// - `Ok(non-empty Vec)` = data read.
/// - `Err("read would block")` = the caller-supplied `timeout` expired with
///   no data. Maps to `std::io::ErrorKind::WouldBlock` SDK-side. Only
///   returned when the caller has set a read timeout — `timeout = None`
///   blocks indefinitely (until data, EOF, or capsule unload via the
///   outer cancellation token).
/// - `Err(other)` = transient IO error.
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
    // Default (no timeout) blocks indefinitely — matches std::io::Read
    // semantics. Caller cancellation comes from the outer
    // bounded_block_on_cancellable, not from a tight internal poll.
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
/// Honours an optional `timeout`; the host-default behaviour (no
/// timeout) blocks until the write completes or the peer disconnects.
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

/// Run `op` against the inner [`tokio::net::TcpStream`] of an outbound
/// TCP stream handle. Returns an error if the handle is missing or holds
/// a Unix-domain stream (most std-style getters/setters are TCP-only).
pub(super) fn with_tcp_slot<T, F>(state: &mut HostState, handle: u64, op: F) -> Result<T, String>
where
    F: FnOnce(&tokio::net::TcpStream) -> Result<T, String>,
{
    let stream = state
        .active_streams
        .get(&handle)
        .cloned()
        .ok_or_else(|| "Stream handle not found".to_string())?;
    match stream {
        NetStream::Tcp(slot) => {
            let rt = state.runtime_handle.clone();
            let sem = state.host_semaphore.clone();
            let tok = state.cancel_token.clone();
            let result = util::bounded_block_on_cancellable(&rt, &sem, &tok, async move {
                let s = slot.stream.lock().await;
                op(&s)
            });
            match result {
                Some(r) => r,
                None => Err("capsule unloading".to_string()),
            }
        },
        NetStream::Unix(_) => Err("operation not supported on Unix streams".to_string()),
    }
}
