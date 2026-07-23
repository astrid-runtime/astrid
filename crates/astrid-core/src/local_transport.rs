//! Internal host-local byte-stream transport.
//!
//! This is a cross-crate implementation seam, not a stable public API. The
//! only live backend is a Unix-domain socket. Unsupported hosts fail with
//! [`io::ErrorKind::Unsupported`]; no alternate-platform support is implied.
//! Framing, authentication, daemon lifecycle, and endpoint naming remain above
//! this module.
//!
//! On Unix, the stream, listener, and owned-half aliases are the exact Tokio
//! types used before this seam was introduced. The backend owns endpoint
//! presence checks, stale cleanup, path validation, connection probing, and
//! same-user peer verification so callers do not assume filesystem sockets.

use std::io;
use std::path::Path;
#[cfg(not(unix))]
use std::pin::Pin;
#[cfg(not(unix))]
use std::task::{Context, Poll};

#[cfg(not(unix))]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(any(test, not(unix)))]
fn unsupported_backend_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "host-local transport is not implemented on this platform",
    )
}

/// A connected host-local byte stream.
#[cfg(unix)]
pub use tokio::net::UnixStream as LocalStream;

/// An unconstructable placeholder on hosts without a local transport backend.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct LocalStream {
    _private: (),
}

/// A listener for host-local byte streams.
#[cfg(unix)]
pub use tokio::net::UnixListener as LocalListener;

/// An unconstructable placeholder on hosts without a local transport backend.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct LocalListener {
    _private: (),
}

/// The owned read half returned by [`split`].
#[cfg(unix)]
pub use tokio::net::unix::OwnedReadHalf as LocalReadHalf;

/// The owned read half returned by [`split`].
#[cfg(not(unix))]
pub type LocalReadHalf = tokio::io::ReadHalf<LocalStream>;

/// The owned write half returned by [`split`].
#[cfg(unix)]
pub use tokio::net::unix::OwnedWriteHalf as LocalWriteHalf;

/// The owned write half returned by [`split`].
#[cfg(not(unix))]
pub type LocalWriteHalf = tokio::io::WriteHalf<LocalStream>;

/// Result of probing an endpoint by attempting a connection.
#[derive(Debug)]
pub enum ConnectOutcome {
    /// A backend connection was established.
    Connected(LocalStream),
    /// No backend endpoint is present.
    Absent,
    /// A backend endpoint exists but no listener owns it.
    Stale,
}

/// Connect to a host-local endpoint.
///
/// # Errors
///
/// Returns the backend connection error. Hosts without a backend return
/// [`io::ErrorKind::Unsupported`].
pub async fn connect(path: &Path) -> io::Result<LocalStream> {
    backend::connect(path).await
}

/// Attempt a connection and classify backend-owned absence/staleness without
/// requiring callers to inspect a filesystem path.
///
/// # Errors
///
/// Returns connection failures that do not mean "absent" or "stale". Hosts
/// without a backend return [`io::ErrorKind::Unsupported`].
pub async fn connect_outcome(path: &Path) -> io::Result<ConnectOutcome> {
    backend::connect_outcome(path).await
}

/// Bind a host-local endpoint.
///
/// The backend validates its endpoint representation, removes a stale endpoint
/// or unexpected symlink, rejects an active listener, and then binds.
///
/// # Errors
///
/// Returns the backend preparation or bind error. Hosts without a backend
/// return [`io::ErrorKind::Unsupported`].
pub fn bind(path: &Path) -> io::Result<LocalListener> {
    backend::bind(path)
}

/// Accept one connection from a host-local listener.
///
/// Backend-specific address metadata is intentionally discarded: callers
/// authenticate the returned stream through the session-token and principal
/// challenge protocol rather than routing on an endpoint address.
///
/// # Errors
///
/// Returns the backend accept error. Hosts without a backend return
/// [`io::ErrorKind::Unsupported`].
pub async fn accept(listener: &LocalListener) -> io::Result<LocalStream> {
    backend::accept(listener).await
}

/// Split a connected local stream into the backend's independently owned read
/// and write halves.
#[must_use]
pub fn split(stream: LocalStream) -> (LocalReadHalf, LocalWriteHalf) {
    backend::split(stream)
}

/// Probe whether a process is accepting connections at a local endpoint.
///
/// # Errors
///
/// Returns the backend connection error. Hosts without a backend return
/// [`io::ErrorKind::Unsupported`].
pub fn probe(path: &Path) -> io::Result<()> {
    backend::probe(path)
}

/// Report whether the backend endpoint representation is present.
///
/// Presence does not imply reachability. This operation exists for lifecycle
/// code that must wait for endpoint removal without assuming a filesystem.
///
/// # Errors
///
/// Hosts without a backend return [`io::ErrorKind::Unsupported`].
pub fn endpoint_is_present(path: &Path) -> io::Result<bool> {
    backend::endpoint_is_present(path)
}

/// Remove an endpoint after its owning process is known to be gone.
///
/// A missing endpoint is successful.
///
/// # Errors
///
/// Returns backend removal errors. Hosts without a backend return
/// [`io::ErrorKind::Unsupported`].
pub fn remove_endpoint(path: &Path) -> io::Result<()> {
    backend::remove_endpoint(path)
}

/// Remove an endpoint only when a fresh backend probe confirms it is stale.
///
/// Returns `true` when an endpoint was removed and `false` when it was absent
/// or reachable.
///
/// # Errors
///
/// Returns probe/removal errors. Hosts without a backend return
/// [`io::ErrorKind::Unsupported`].
pub fn remove_stale_endpoint(path: &Path) -> io::Result<bool> {
    backend::remove_stale_endpoint(path)
}

/// Verify that the connected peer belongs to the same operating-system user
/// as the current process.
///
/// This is a defense-in-depth check below the session-token and signed
/// principal handshake. Failure to retrieve peer identity is an error, not an
/// implicit match.
///
/// # Errors
///
/// Returns an error when peer credentials cannot be read. Hosts without a
/// backend return [`io::ErrorKind::Unsupported`].
pub fn peer_is_current_user(stream: &LocalStream) -> io::Result<bool> {
    backend::peer_is_current_user(stream)
}

#[cfg(unix)]
mod backend {
    use std::io;
    use std::path::Path;

    use super::{ConnectOutcome, LocalListener, LocalReadHalf, LocalStream, LocalWriteHalf};

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    const MAX_ENDPOINT_PATH_LEN: usize = 104;
    #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd")))]
    const MAX_ENDPOINT_PATH_LEN: usize = 108;

    pub(super) async fn connect(path: &Path) -> io::Result<LocalStream> {
        tokio::net::UnixStream::connect(path).await
    }

    pub(super) async fn connect_outcome(path: &Path) -> io::Result<ConnectOutcome> {
        match connect(path).await {
            Ok(stream) => Ok(ConnectOutcome::Connected(stream)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ConnectOutcome::Absent),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                Ok(ConnectOutcome::Stale)
            },
            Err(error) => Err(error),
        }
    }

    pub(super) fn bind(path: &Path) -> io::Result<LocalListener> {
        prepare_endpoint_for_bind(path)?;
        tokio::net::UnixListener::bind(path)
    }

    pub(super) async fn accept(listener: &LocalListener) -> io::Result<LocalStream> {
        listener.accept().await.map(|(stream, _address)| stream)
    }

    pub(super) fn split(stream: LocalStream) -> (LocalReadHalf, LocalWriteHalf) {
        stream.into_split()
    }

    pub(super) fn probe(path: &Path) -> io::Result<()> {
        std::os::unix::net::UnixStream::connect(path).map(drop)
    }

    pub(super) fn endpoint_is_present(path: &Path) -> io::Result<bool> {
        match std::fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn remove_endpoint(path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) fn remove_stale_endpoint(path: &Path) -> io::Result<bool> {
        match probe(path) {
            Ok(()) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                remove_endpoint(path)?;
                Ok(true)
            },
            Err(error) => Err(error),
        }
    }

    pub(super) fn peer_is_current_user(stream: &LocalStream) -> io::Result<bool> {
        let peer_uid = stream.peer_cred()?.uid();
        Ok(peer_uid == nix::unistd::geteuid().as_raw())
    }

    fn prepare_endpoint_for_bind(path: &Path) -> io::Result<()> {
        let path_len = path.as_os_str().as_encoded_bytes().len();
        if path_len >= MAX_ENDPOINT_PATH_LEN {
            return Err(io::Error::other(format!(
                "Socket path is {path_len} bytes, exceeding the platform limit of \
                 {MAX_ENDPOINT_PATH_LEN} bytes: {}",
                path.display()
            )));
        }

        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(io::Error::other(format!(
                    "Failed to inspect existing socket {}: {error}",
                    path.display()
                )));
            },
        };

        if metadata.is_some_and(|metadata| metadata.file_type().is_symlink()) {
            remove_endpoint(path).map_err(|error| {
                io::Error::other(format!(
                    "Failed to remove symlink at socket path {}: {error}",
                    path.display()
                ))
            })?;
            return Ok(());
        }

        match probe(path) {
            Ok(()) => Err(io::Error::other(format!(
                "Another kernel instance is already running on this socket: {}",
                path.display()
            ))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => remove_endpoint(path)
                .map_err(|remove_error| {
                    io::Error::other(format!(
                        "Failed to remove stale socket {}: {remove_error}",
                        path.display()
                    ))
                }),
            Err(error) => Err(io::Error::other(format!(
                "Failed to probe existing socket {}: {error}",
                path.display()
            ))),
        }
    }
}

#[cfg(not(unix))]
mod backend {
    use std::io;
    use std::path::Path;

    use super::{
        ConnectOutcome, LocalListener, LocalReadHalf, LocalStream, LocalWriteHalf,
        unsupported_backend_error,
    };

    pub(super) async fn connect(path: &Path) -> io::Result<LocalStream> {
        let _ = path;
        Err(unsupported_backend_error())
    }

    pub(super) async fn connect_outcome(path: &Path) -> io::Result<ConnectOutcome> {
        let _ = path;
        Err(unsupported_backend_error())
    }

    pub(super) fn bind(path: &Path) -> io::Result<LocalListener> {
        let _ = path;
        Err(unsupported_backend_error())
    }

    pub(super) async fn accept(listener: &LocalListener) -> io::Result<LocalStream> {
        let _ = listener;
        Err(unsupported_backend_error())
    }

    pub(super) fn split(stream: LocalStream) -> (LocalReadHalf, LocalWriteHalf) {
        tokio::io::split(stream)
    }

    pub(super) fn probe(path: &Path) -> io::Result<()> {
        let _ = path;
        Err(unsupported_backend_error())
    }

    pub(super) fn endpoint_is_present(path: &Path) -> io::Result<bool> {
        let _ = path;
        Err(unsupported_backend_error())
    }

    pub(super) fn remove_endpoint(path: &Path) -> io::Result<()> {
        let _ = path;
        Err(unsupported_backend_error())
    }

    pub(super) fn remove_stale_endpoint(path: &Path) -> io::Result<bool> {
        let _ = path;
        Err(unsupported_backend_error())
    }

    pub(super) fn peer_is_current_user(stream: &LocalStream) -> io::Result<bool> {
        let _ = stream;
        Err(unsupported_backend_error())
    }
}

#[cfg(not(unix))]
impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = self;
        Poll::Ready(Err(unsupported_backend_error()))
    }
}

#[cfg(not(unix))]
impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let _ = self;
        Poll::Ready(Err(unsupported_backend_error()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let _ = self;
        Poll::Ready(Err(unsupported_backend_error()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let _ = self;
        Poll::Ready(Err(unsupported_backend_error()))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        ConnectOutcome, accept, bind, connect, connect_outcome, endpoint_is_present,
        peer_is_current_user, probe, remove_endpoint, split, unsupported_backend_error,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bind_connect_accept_preserves_byte_stream_and_peer_identity() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = directory.path().join("local.sock");
        let listener = bind(&endpoint).unwrap();

        let client = connect(&endpoint).await.unwrap();
        let mut server = accept(&listener).await.unwrap();
        assert!(peer_is_current_user(&server).unwrap());
        let (_reader, mut writer) = split(client);

        writer.write_all(b"astrid-local").await.unwrap();
        writer.flush().await.unwrap();

        let mut bytes = [0; 12];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"astrid-local");

        drop(listener);
        remove_endpoint(&endpoint).unwrap();
    }

    #[tokio::test]
    async fn connect_outcome_distinguishes_absent_connected_and_stale() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = directory.path().join("state.sock");
        assert!(matches!(
            connect_outcome(&endpoint).await.unwrap(),
            ConnectOutcome::Absent
        ));

        let listener = bind(&endpoint).unwrap();
        assert!(matches!(
            connect_outcome(&endpoint).await.unwrap(),
            ConnectOutcome::Connected(_)
        ));
        drop(listener);

        assert!(matches!(
            connect_outcome(&endpoint).await.unwrap(),
            ConnectOutcome::Stale
        ));
        assert!(endpoint_is_present(&endpoint).unwrap());
    }

    #[tokio::test]
    async fn bind_cleans_stale_endpoint_and_rejects_live_listener() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = directory.path().join("bind.sock");
        let listener = bind(&endpoint).unwrap();

        let error = bind(&endpoint).unwrap_err();
        assert!(error.to_string().contains("already running"));
        drop(listener);

        let replacement = bind(&endpoint).expect("stale endpoint should be replaced");
        drop(replacement);
        remove_endpoint(&endpoint).unwrap();
    }

    #[tokio::test]
    async fn bind_removes_symlink_without_touching_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, "not a socket").unwrap();
        let endpoint = directory.path().join("symlink.sock");
        std::os::unix::fs::symlink(&target, &endpoint).unwrap();

        let listener = bind(&endpoint).unwrap();
        assert!(target.exists());
        drop(listener);
        remove_endpoint(&endpoint).unwrap();
    }

    #[test]
    fn bind_rejects_overlong_endpoint_path() {
        let long_name = "a".repeat(120);
        let endpoint = Path::new("/tmp").join(format!("{long_name}.sock"));
        let error = bind(&endpoint).unwrap_err();
        assert!(error.to_string().contains("exceeding the platform limit"));
    }

    #[test]
    fn probe_preserves_missing_endpoint_error() {
        let directory = tempfile::tempdir().unwrap();
        let error = probe(&directory.path().join("missing.sock")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn unsupported_backend_error_is_fail_closed() {
        assert_eq!(
            unsupported_backend_error().kind(),
            io::ErrorKind::Unsupported
        );
    }

    use std::io;
    use std::path::Path;
}

#[cfg(all(test, not(unix)))]
mod unsupported_tests {
    use super::{
        LocalListener, LocalStream, accept, bind, connect, connect_outcome, endpoint_is_present,
        peer_is_current_user, probe, remove_endpoint, remove_stale_endpoint,
    };

    #[tokio::test]
    async fn every_backend_operation_fails_unsupported() {
        let path = std::path::Path::new("unsupported");
        assert_eq!(
            connect(path).await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            connect_outcome(path).await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            bind(path).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            probe(path).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            endpoint_is_present(path).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            remove_endpoint(path).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            remove_stale_endpoint(path).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );

        let listener = LocalListener { _private: () };
        assert_eq!(
            accept(&listener).await.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        let stream = LocalStream { _private: () };
        assert_eq!(
            peer_is_current_user(&stream).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }
}
