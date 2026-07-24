//! Windows named-pipe backend for the host-local transport seam.
//!
//! The filesystem-shaped argument accepted by the portable API is deliberately
//! ignored here. Windows endpoint authority comes from the current process
//! token SID, not a working directory, profile path, display name, or
//! environment variable. The pipe namespace is protected twice: the first
//! instance must own the name, and every instance carries an exact protected
//! DACL for the current user plus Local System.

use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::pin::Pin;
use std::ptr;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED,
    ERROR_SEM_TIMEOUT, GENERIC_ALL, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetLengthSid,
    GetTokenInformation, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    RevertToSelf, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
    WaitNamedPipeW,
};
#[cfg(feature = "test-support")]
use windows_sys::Win32::System::Pipes::{GetNamedPipeInfo, PIPE_REJECT_REMOTE_CLIENTS};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetProcessId, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use self::acl::{ValidatedAce, ValidatedAcl, validate_descriptor_control};
use super::ConnectOutcome;

#[path = "windows/acl.rs"]
mod acl;

const PIPE_PREFIX: &str = r"\\.\pipe\astrid-local-";
const CONNECT_BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_BUSY_WAIT_SLICE: Duration = Duration::from_millis(50);

/// A connected named-pipe endpoint.
#[derive(Debug)]
pub struct LocalStream {
    inner: StreamInner,
    /// The server must consume one real byte before Windows can impersonate
    /// the client that sent it. Replay that byte to the protocol reader so
    /// transport authentication does not alter the higher-level byte stream.
    replay_byte: Option<u8>,
}

#[derive(Debug)]
enum StreamInner {
    Client(NamedPipeClient),
    Server(NamedPipeServer),
}

/// A named-pipe listener with one unconnected instance ready for `accept`.
#[derive(Debug)]
pub struct LocalListener {
    pipe_name: OsString,
    pending: tokio::sync::Mutex<Option<NamedPipeServer>>,
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() != 0
            && let Some(byte) = this.replay_byte.take()
        {
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }

        match &mut this.inner {
            StreamInner::Client(stream) => Pin::new(stream).poll_read(cx, buf),
            StreamInner::Server(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            StreamInner::Client(stream) => Pin::new(stream).poll_write(cx, buf),
            StreamInner::Server(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            StreamInner::Client(stream) => Pin::new(stream).poll_flush(cx),
            StreamInner::Server(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            StreamInner::Client(stream) => Pin::new(stream).poll_shutdown(cx),
            StreamInner::Server(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(super) async fn connect(path: &Path) -> io::Result<LocalStream> {
    let pipe_name = pipe_name(path)?;
    let client = open_client_with_retry(&pipe_name).await?;
    let stream = LocalStream {
        inner: StreamInner::Client(client),
        replay_byte: None,
    };

    // A cross-user process can pre-create a discoverable pipe name. Do not
    // reveal the session token to it: authenticate the creator's process token
    // and the pipe DACL before returning to the wire handshake.
    let peer = require_current_user_process_peer(&stream)?;
    validate_pipe_security(stream_handle(&stream)?)?;
    peer.ensure_still_peer(&stream)?;
    Ok(stream)
}

async fn open_client_with_retry(pipe_name: &OsStr) -> io::Result<NamedPipeClient> {
    let deadline = tokio::time::Instant::now()
        .checked_add(CONNECT_BUSY_TIMEOUT)
        .ok_or_else(|| io::Error::other("named-pipe connect deadline overflow"))?;
    loop {
        let mut options = ClientOptions::new();
        // Pin static SecurityIdentification QoS explicitly. This exposes only
        // enough of the effective client token for the server to query
        // TokenUser; it does not delegate the client's authority.
        options.security_qos_flags(SECURITY_IDENTIFICATION);
        match options.open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error().map(i32::cast_unsigned) == Some(ERROR_PIPE_BUSY) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(classify_connect_error(error));
                }
                let wait = deadline
                    .checked_duration_since(now)
                    .unwrap_or(Duration::ZERO)
                    .min(CONNECT_BUSY_WAIT_SLICE);
                wait_for_pipe_availability(pipe_name, wait).await?;
            },
            Err(error) => return Err(classify_connect_error(error)),
        }
    }
}

async fn wait_for_pipe_availability(pipe_name: &OsStr, wait: Duration) -> io::Result<()> {
    let encoded = wide_nul(pipe_name);
    let milliseconds = u32::try_from(wait.as_millis())
        .map_err(|_| io::Error::other("named-pipe wait duration overflow"))?
        .max(1);
    // `WaitNamedPipeW` is synchronous, so isolate it from the async worker.
    // Each call is capped at 50 ms: cancelling the outer future stops all
    // retries and leaves at most one short detached blocking wait.
    tokio::task::spawn_blocking(move || {
        let ready = unsafe { WaitNamedPipeW(encoded.as_ptr(), milliseconds) };
        if ready != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error().map(i32::cast_unsigned) {
            // A bounded timeout is the backoff between open attempts.
            Some(ERROR_SEM_TIMEOUT | ERROR_PIPE_BUSY) => Ok(()),
            Some(ERROR_FILE_NOT_FOUND) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Windows named-pipe endpoint disappeared while waiting",
            )),
            Some(ERROR_ACCESS_DENIED) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows named-pipe endpoint denied access while waiting",
            )),
            _ => Err(error),
        }
    })
    .await
    .map_err(|error| io::Error::other(format!("named-pipe wait task failed: {error}")))?
}

pub(super) async fn connect_outcome(path: &Path) -> io::Result<ConnectOutcome> {
    match connect(path).await {
        Ok(stream) => Ok(ConnectOutcome::Connected(stream)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ConnectOutcome::Absent),
        // Named pipes have no stale filesystem node: their namespace object
        // vanishes with the last server handle. Busy and access-denied both
        // prove that something owns the name and must never trigger a daemon
        // boot or unauthenticated fallback.
        Err(error) => Err(error),
    }
}

pub(super) fn bind(path: &Path) -> io::Result<LocalListener> {
    let pipe_name = pipe_name(path)?;
    let pending = create_server(&pipe_name, true)?;
    Ok(LocalListener {
        pipe_name,
        pending: tokio::sync::Mutex::new(Some(pending)),
    })
}

pub(super) async fn accept(listener: &LocalListener) -> io::Result<LocalStream> {
    let mut pending = listener.pending.lock().await;
    let server = pending
        .as_ref()
        .ok_or_else(|| io::Error::other("Windows named-pipe listener lost its pending instance"))?;

    // `NamedPipeServer::connect` is cancellation-safe. Keep the server inside
    // `pending` while awaiting it so dropping this future (timeout, task abort,
    // or the host's outer cancellation token) only releases the mutex; the
    // next `accept` resumes against the same kernel instance.
    if let Err(error) = server.connect().await {
        if !is_pre_authentication_disconnect(&error) {
            return Err(error);
        }

        // An availability probe may open and close before the server calls
        // `ConnectNamedPipe`, which reports a disconnected instance instead of
        // a successful connection followed by a zero-byte read. Retire that
        // instance and replenish the listener exactly as the post-connect EOF
        // path does.
        let replacement = create_server(&listener.pipe_name, false)?;
        let disconnected = pending
            .take()
            .ok_or_else(|| io::Error::other("disconnected named-pipe instance disappeared"))?;
        *pending = Some(replacement);
        drop(pending);
        drop(disconnected);
        return Err(pre_authentication_eof(Some(&error)));
    }
    let replacement = create_server(&listener.pipe_name, false)?;
    let mut server = pending
        .take()
        .ok_or_else(|| io::Error::other("connected named-pipe instance disappeared"))?;

    // Install the next instance before exposing this one, so a second client
    // can connect while the first connection remains live. Creating it before
    // consuming the connected pending instance also leaves a recoverable
    // listener state if the replacement allocation fails transiently.
    *pending = Some(replacement);
    drop(pending);

    // `ImpersonateNamedPipeClient` authenticates the security context of the
    // last message actually read by this server handle. A connected handle
    // alone is not sufficient and fails with ERROR_CANNOT_IMPERSONATE. Perform
    // one cancellation-safe byte read before crossing the authorization
    // boundary. The replacement listener is already installed, so an EOF-only
    // availability probe or a cancelled pre-read cannot starve later clients.
    let mut first_byte = [0_u8; 1];
    match server.read(&mut first_byte).await {
        Ok(1) => {},
        Ok(0) => return Err(pre_authentication_eof(None)),
        Ok(_) => unreachable!("one-byte named-pipe read returned more than one byte"),
        Err(error) if is_pre_authentication_disconnect(&error) => {
            return Err(pre_authentication_eof(Some(&error)));
        },
        Err(error) => return Err(error),
    }

    let stream = LocalStream {
        inner: StreamInner::Server(server),
        replay_byte: Some(first_byte[0]),
    };
    require_current_user_effective_client(&stream)?;
    // Effective-token impersonation above is the authorization boundary.
    // The process-token check is independent defense in depth and pins the
    // client process object while re-reading the pipe-reported PID.
    let peer = require_current_user_process_peer(&stream)?;
    validate_pipe_security(stream_handle(&stream)?)?;
    peer.ensure_still_peer(&stream)?;
    Ok(stream)
}

fn pre_authentication_eof(source: Option<&io::Error>) -> io::Error {
    let message = match source {
        Some(source) => {
            format!("named-pipe client disconnected before transport authentication: {source}")
        },
        None => "named-pipe client disconnected before transport authentication".to_string(),
    };
    io::Error::new(io::ErrorKind::UnexpectedEof, message)
}

fn is_pre_authentication_disconnect(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error().map(i32::cast_unsigned),
        Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
    )
}

pub(super) fn split(
    stream: LocalStream,
) -> (
    tokio::io::ReadHalf<LocalStream>,
    tokio::io::WriteHalf<LocalStream>,
) {
    tokio::io::split(stream)
}

pub(super) fn probe(path: &Path) -> io::Result<()> {
    match endpoint_state(path)? {
        EndpointState::Available => Ok(()),
        EndpointState::Absent => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Windows named-pipe endpoint is absent",
        )),
        EndpointState::BusyOrDenied => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Windows named-pipe endpoint is occupied but unavailable",
        )),
    }
}

pub(super) fn endpoint_is_present(path: &Path) -> io::Result<bool> {
    Ok(!matches!(endpoint_state(path)?, EndpointState::Absent))
}

pub(super) fn remove_endpoint(path: &Path) -> io::Result<()> {
    if endpoint_is_present(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows named-pipe endpoints are kernel-owned and cannot be removed while live",
        ));
    }
    Ok(())
}

pub(super) fn remove_stale_endpoint(path: &Path) -> io::Result<bool> {
    // Unlike a Unix socket pathname, a named-pipe endpoint cannot remain stale
    // after its final server handle closes. Never delete or replace an object
    // merely because its DACL makes it inaccessible.
    let _ = endpoint_state(path)?;
    Ok(false)
}

pub(super) fn peer_is_current_user(stream: &LocalStream) -> io::Result<bool> {
    if matches!(&stream.inner, StreamInner::Server(_)) {
        return Ok(effective_client_user_sid(stream)?.equals(&current_user_sid()?));
    }

    let peer = peer_process_identity(stream)?;
    let matches = peer.user_sid.equals(&current_user_sid()?);
    peer.ensure_still_peer(stream)?;
    Ok(matches)
}

fn peer_process_id(stream: &LocalStream) -> io::Result<u32> {
    let mut process_id = 0_u32;
    let ok = unsafe {
        match &stream.inner {
            StreamInner::Client(client) => {
                GetNamedPipeServerProcessId(client.as_raw_handle().cast(), &raw mut process_id)
            },
            StreamInner::Server(server) => {
                GetNamedPipeClientProcessId(server.as_raw_handle().cast(), &raw mut process_id)
            },
        }
    };
    if ok == 0 {
        return Err(last_error(
            "failed to retrieve named-pipe peer process identity",
        ));
    }
    if process_id == 0 {
        return Err(io::Error::other(
            "named-pipe peer process identity was missing",
        ));
    }
    Ok(process_id)
}

struct VerifiedPeerProcess {
    process_id: u32,
    user_sid: OwnedSid,
    // Keeping the process object alive prevents its numeric PID from being
    // recycled while security validation runs. We still re-read the PID from
    // the pipe afterward; this is defense in depth beside the descriptor owner
    // check, not the server's effective-token authorization boundary.
    _process: OwnedHandle,
}

impl VerifiedPeerProcess {
    fn ensure_still_peer(&self, stream: &LocalStream) -> io::Result<()> {
        if peer_process_id(stream)? != self.process_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "named-pipe peer process changed during authentication",
            ));
        }
        Ok(())
    }
}

fn peer_process_identity(stream: &LocalStream) -> io::Result<VerifiedPeerProcess> {
    let process_id = peer_process_id(stream)?;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(last_error("failed to open named-pipe peer process"));
    }
    let process = OwnedHandle(process);
    if unsafe { GetProcessId(process.0) } != process_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe peer PID did not identify the opened process",
        ));
    }

    let mut token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token) };
    if opened == 0 || token.is_null() {
        return Err(last_error("failed to open named-pipe peer process token"));
    }
    let user_sid = token_user_sid(&OwnedHandle(token))?;
    Ok(VerifiedPeerProcess {
        process_id,
        user_sid,
        _process: process,
    })
}

fn require_current_user_process_peer(stream: &LocalStream) -> io::Result<VerifiedPeerProcess> {
    let peer = peer_process_identity(stream)?;
    if peer.user_sid.equals(&current_user_sid()?) {
        Ok(peer)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe peer process belongs to a different operating-system user",
        ))
    }
}

fn require_current_user_effective_client(stream: &LocalStream) -> io::Result<()> {
    let client_sid = effective_client_user_sid(stream)?;
    if client_sid.equals(&current_user_sid()?) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe client's effective token belongs to a different operating-system user",
        ))
    }
}

fn effective_client_user_sid(stream: &LocalStream) -> io::Result<OwnedSid> {
    let server = match &stream.inner {
        StreamInner::Server(server) => server,
        StreamInner::Client(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client effective-token validation requires the server pipe end",
            ));
        },
    };
    let impersonated = unsafe { ImpersonateNamedPipeClient(server.as_raw_handle().cast()) };
    if impersonated == 0 {
        return Err(last_error(
            "failed to impersonate the connected named-pipe client",
        ));
    }
    let guard = ImpersonationGuard { active: true };

    let mut token = ptr::null_mut();
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
    if opened == 0 || token.is_null() {
        return Err(last_error(
            "failed to open impersonated named-pipe client token",
        ));
    }
    let sid = token_user_sid(&OwnedHandle(token))?;
    guard.revert()?;
    Ok(sid)
}

struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    fn revert(mut self) -> io::Result<()> {
        if unsafe { RevertToSelf() } == 0 {
            return Err(last_error(
                "failed to revert named-pipe client impersonation",
            ));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active && unsafe { RevertToSelf() } == 0 {
            // Returning an async-runtime worker to the pool under an
            // untrusted client token would cross the authority boundary.
            // Windows provides no safer recovery once reversion itself fails.
            std::process::abort();
        }
    }
}

fn stream_handle(stream: &LocalStream) -> io::Result<HANDLE> {
    let handle = match &stream.inner {
        StreamInner::Client(client) => client.as_raw_handle(),
        StreamInner::Server(server) => server.as_raw_handle(),
    };
    if handle.is_null() {
        return Err(io::Error::other("named-pipe stream has an invalid handle"));
    }
    Ok(handle.cast())
}

fn create_server(pipe_name: &OsStr, first: bool) -> io::Result<NamedPipeServer> {
    create_server_with_security(pipe_name, first, PipeSecurity::for_current_user()?)
}

fn create_server_with_security(
    pipe_name: &OsStr,
    first: bool,
    mut security: PipeSecurity,
) -> io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);

    // SAFETY: `security.attributes` and its LocalAlloc-owned descriptor remain
    // valid for the complete CreateNamedPipeW call. Tokio does not retain the
    // pointer after `create_with_security_attributes_raw` returns.
    unsafe {
        options
            .create_with_security_attributes_raw(pipe_name, (&raw mut security.attributes).cast())
    }
}

fn pipe_name(path: &Path) -> io::Result<OsString> {
    let _ = path;
    let sid = current_user_sid()?;
    let digest = blake3::hash(sid.as_bytes());
    Ok(OsString::from(format!(
        "{PIPE_PREFIX}{}",
        &digest.to_hex()[..32]
    )))
}

#[cfg(feature = "test-support")]
pub(super) fn endpoint_name_for_test(path: &Path) -> io::Result<OsString> {
    pipe_name(path)
}

#[cfg(feature = "test-support")]
pub(super) fn bind_permissive_first_instance_for_test(path: &Path) -> io::Result<LocalListener> {
    let pipe_name = pipe_name(path)?;
    let user = current_user_sid()?.to_sddl()?;
    let security = PipeSecurity::from_sddl(&format!("O:{user}D:P(A;;GA;;;WD)"))?;
    let pending = create_server_with_security(&pipe_name, true, security)?;
    Ok(LocalListener {
        pipe_name,
        pending: tokio::sync::Mutex::new(Some(pending)),
    })
}

#[cfg(feature = "test-support")]
pub(super) async fn listener_rejects_remote_clients_for_test(
    listener: &LocalListener,
) -> io::Result<bool> {
    let pending = listener.pending.lock().await;
    let server = pending
        .as_ref()
        .ok_or_else(|| io::Error::other("named-pipe listener has no pending instance"))?;
    let mut flags = 0_u32;
    let queried = unsafe {
        GetNamedPipeInfo(
            server.as_raw_handle().cast(),
            &raw mut flags,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if queried == 0 {
        return Err(last_error("failed to query named-pipe mode"));
    }
    Ok(flags & PIPE_REJECT_REMOTE_CLIENTS != 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointState {
    Available,
    Absent,
    BusyOrDenied,
}

fn endpoint_state(path: &Path) -> io::Result<EndpointState> {
    let pipe_name = pipe_name(path)?;
    let encoded = wide_nul(&pipe_name);
    let ready = unsafe { WaitNamedPipeW(encoded.as_ptr(), 0) };
    if ready != 0 {
        return Ok(EndpointState::Available);
    }

    let error = io::Error::last_os_error();
    match error.raw_os_error().map(i32::cast_unsigned) {
        Some(ERROR_FILE_NOT_FOUND) => Ok(EndpointState::Absent),
        Some(ERROR_PIPE_BUSY | ERROR_SEM_TIMEOUT | ERROR_ACCESS_DENIED) => {
            Ok(EndpointState::BusyOrDenied)
        },
        _ => Err(error),
    }
}

fn classify_connect_error(error: io::Error) -> io::Error {
    match error.raw_os_error().map(i32::cast_unsigned) {
        Some(ERROR_FILE_NOT_FOUND) => io::Error::new(
            io::ErrorKind::NotFound,
            "Windows named-pipe endpoint is absent",
        ),
        Some(ERROR_PIPE_BUSY) => io::Error::new(
            io::ErrorKind::WouldBlock,
            "Windows named-pipe endpoint is busy",
        ),
        Some(ERROR_ACCESS_DENIED) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows named-pipe endpoint denied access",
        ),
        _ => error,
    }
}

struct PipeSecurity {
    _descriptor: LocalAllocation,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn for_current_user() -> io::Result<Self> {
        let user = current_user_sid()?;
        let system = well_known_sid(WinLocalSystemSid)?;
        let user_sddl = user.to_sddl()?;
        let dacl = if user.equals(&system) {
            format!("O:{user_sddl}D:P(A;;GA;;;{user_sddl})")
        } else {
            format!("O:{user_sddl}D:P(A;;GA;;;SY)(A;;GA;;;{user_sddl})")
        };
        Self::from_sddl(&dacl)
    }

    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let encoded = wide_nul(OsStr::new(sddl));
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            if !descriptor.is_null() {
                unsafe {
                    LocalFree(descriptor);
                }
            }
            return Err(last_error(
                "failed to build Windows named-pipe security descriptor",
            ));
        }

        let descriptor = LocalAllocation(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| io::Error::other("SECURITY_ATTRIBUTES size overflow"))?,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        Ok(Self {
            _descriptor: descriptor,
            attributes,
        })
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug)]
struct OwnedSid {
    words: Box<[usize]>,
    byte_len: usize,
}

impl OwnedSid {
    fn copy_from(sid: PSID) -> io::Result<Self> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(io::Error::other("Windows token returned an invalid SID"));
        }
        let byte_len = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| io::Error::other("SID length overflow"))?;
        let word_len = byte_len.div_ceil(size_of::<usize>());
        let mut words = vec![0_usize; word_len].into_boxed_slice();
        let copied = unsafe {
            windows_sys::Win32::Security::CopySid(
                u32::try_from(byte_len).map_err(|_| io::Error::other("SID length overflow"))?,
                words.as_mut_ptr().cast(),
                sid,
            )
        };
        if copied == 0 {
            return Err(last_error("failed to copy Windows token SID"));
        }
        Ok(Self { words, byte_len })
    }

    fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.byte_len) }
    }

    fn equals(&self, other: &Self) -> bool {
        unsafe { EqualSid(self.as_psid(), other.as_psid()) != 0 }
    }

    fn to_sddl(&self) -> io::Result<String> {
        let mut text = ptr::null_mut();
        let converted = unsafe { ConvertSidToStringSidW(self.as_psid(), &raw mut text) };
        if converted == 0 || text.is_null() {
            return Err(last_error("failed to format Windows token SID"));
        }
        let allocation = LocalAllocation(text.cast());
        let mut len = 0_usize;
        unsafe {
            while *text.add(len) != 0 {
                len = len
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("SID string length overflow"))?;
            }
        }
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
            .map_err(|_| io::Error::other("Windows formatted an invalid UTF-16 SID"))?;
        drop(allocation);
        Ok(value)
    }
}

fn current_user_sid() -> io::Result<OwnedSid> {
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
    if opened == 0 || token.is_null() {
        return Err(last_error("failed to open current process token"));
    }
    token_user_sid(&OwnedHandle(token))
}

fn token_user_sid(token: &OwnedHandle) -> io::Result<OwnedSid> {
    let mut required = 0_u32;
    let first =
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut required) };
    if first != 0 || required == 0 {
        return Err(io::Error::other(
            "Windows token user query returned no required buffer size",
        ));
    }
    let first_error = io::Error::last_os_error();
    if first_error.raw_os_error().map(i32::cast_unsigned) != Some(ERROR_INSUFFICIENT_BUFFER) {
        return Err(first_error);
    }

    let bytes = usize::try_from(required)
        .map_err(|_| io::Error::other("token information length overflow"))?;
    let mut storage = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
    let read = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    };
    if read == 0 {
        return Err(last_error("failed to read Windows token user"));
    }
    let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    OwnedSid::copy_from(token_user.User.Sid)
}

fn well_known_sid(kind: i32) -> io::Result<OwnedSid> {
    let byte_len = usize::try_from(SECURITY_MAX_SID_SIZE)
        .map_err(|_| io::Error::other("well-known SID size overflow"))?;
    let mut words = vec![0_usize; byte_len.div_ceil(size_of::<usize>())].into_boxed_slice();
    let mut actual = SECURITY_MAX_SID_SIZE;
    let created = unsafe {
        CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            words.as_mut_ptr().cast(),
            &raw mut actual,
        )
    };
    if created == 0 {
        return Err(last_error("failed to create well-known Windows SID"));
    }
    Ok(OwnedSid {
        words,
        byte_len: usize::try_from(actual)
            .map_err(|_| io::Error::other("well-known SID length overflow"))?,
    })
}

fn validate_pipe_security(handle: HANDLE) -> io::Result<()> {
    let current = current_user_sid()?;
    let system = well_known_sid(WinLocalSystemSid)?;
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    if descriptor.is_null() {
        return Err(io::Error::other(
            "Windows returned no named-pipe security descriptor",
        ));
    }
    let descriptor_allocation = LocalAllocation(descriptor);

    // SAFETY: GetSecurityInfo returned this non-null descriptor, and
    // `descriptor_allocation` keeps it live through validation.
    unsafe { validate_descriptor_control(descriptor) }?;

    if owner.is_null() || unsafe { EqualSid(owner, current.as_psid()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe owner is not the current operating-system user",
        ));
    }
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe has a null or missing DACL",
        ));
    }

    // SAFETY: `dacl` points into the descriptor allocation returned by
    // GetSecurityInfo, which remains live and unmodified through
    // `descriptor_allocation`. The parser validates and bounds the ACL before
    // exposing any borrowed ACE or SID.
    let dacl = unsafe {
        ValidatedAcl::from_raw(
            dacl,
            &descriptor_allocation,
            "named-pipe security descriptor",
        )
    }?;
    let expected_aces = if current.equals(&system) { 1 } else { 2 };
    let ace_count = dacl.ace_count();
    if ace_count != expected_aces {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("named-pipe DACL has {ace_count} entries; expected exactly {expected_aces}"),
        ));
    }

    let mut saw_current = false;
    let mut saw_system = current.equals(&system);
    for index in 0..ace_count {
        let ValidatedAce::Allow { flags, mask, sid } = dacl.ace(index)? else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "named-pipe DACL contains a non-canonical access entry",
            ));
        };
        if flags != 0 || mask != GENERIC_ALL {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "named-pipe DACL contains a non-canonical access entry",
            ));
        }
        if unsafe { EqualSid(sid.as_ptr(), current.as_psid()) } != 0 && !saw_current {
            saw_current = true;
        } else if unsafe { EqualSid(sid.as_ptr(), system.as_psid()) } != 0 && !saw_system {
            saw_system = true;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "named-pipe DACL grants an unexpected or duplicate principal",
            ));
        }
    }

    if !saw_current || !saw_system {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe DACL omits the current user or Local System",
        ));
    }
    Ok(())
}

fn wide_nul(value: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(context: &str) -> io::Error {
    let source = io::Error::last_os_error();
    io::Error::new(source.kind(), format!("{context}: {source}"))
}

#[cfg(test)]
#[path = "windows/tests.rs"]
mod tests;
