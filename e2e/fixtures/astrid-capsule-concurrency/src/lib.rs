//! Runtime E2E fixture for `astrid#1231` — concurrent run-loop workers.
//!
//! Binds a loopback TCP port and answers each request after a fixed delay,
//! standing in for a capsule blocked on upstream I/O. The delay is the point:
//! a fast handler cannot distinguish a serial run loop from a concurrent one.
//!
//! Every worker Store runs this same `run()` export against the ONE shared
//! bound listener, so the OS accept queue hands each connection to whichever
//! worker is idle. The response carries the worker's own view of its identity
//! so the harness can count how many distinct workers served a burst.
//!
//! Deliberately minimal: no framing, no keep-alive, no parsing. It reads
//! nothing and writes a fixed line, because the only thing under test is
//! whether two connections can be in flight at once.

use std::time::Duration;

use astrid_sdk::net::{self, Shutdown, TcpStream};
use astrid_sdk::prelude::*;
use astrid_sdk::{log, runtime, time};

/// Must match `net_bind` in `Capsule.toml`. A concrete port, not 0 — sharing is
/// only defined for a concrete port, since 0 means "any ephemeral port" and two
/// such requests are different addresses.
const PORT: u16 = 18231;

/// How long each request occupies its worker. Long enough that serial handling
/// is unmistakable at five concurrent clients (5 × 500ms = 2.5s vs ~500ms), and
/// short enough that the suite stays quick.
const WORK_MS: u64 = 500;

/// Accept poll timeout. Bounded so a cancelled worker reaches a yield point and
/// the run loop can be torn down promptly rather than blocking forever.
const ACCEPT_TIMEOUT_MS: u64 = 500;

#[derive(Default)]
pub struct ConcurrencyFixture;

#[capsule]
impl ConcurrencyFixture {
    #[astrid::run]
    pub fn run(&self) -> Result<(), SysError> {
        // Every worker calls this. The first to arrive binds the socket; the
        // rest dedupe onto its `Arc<TcpListener>` inside the host and block on
        // accept() against the same OS queue.
        let listener = match net::bind_tcp("127.0.0.1", PORT) {
            Ok(listener) => listener,
            Err(e) => {
                log::warn(format!("concurrency fixture: bind failed: {e:?}"));
                return Err(e);
            },
        };
        let _ = runtime::signal_ready();
        log::info(format!("concurrency fixture: serving 127.0.0.1:{PORT}"));

        loop {
            match listener.try_accept(ACCEPT_TIMEOUT_MS) {
                Ok(Some(stream)) => serve(&stream),
                // Accept timeout — loop so cancellation is observable.
                Ok(None) => {},
                Err(e) => {
                    log::warn(format!("concurrency fixture: accept error: {e:?}"));
                    return Err(e);
                },
            }
        }
    }
}

/// Occupy this worker for `WORK_MS`, then answer.
///
/// `runtime::sleep` blocks the worker's single guest thread, which is exactly
/// the condition being reproduced: the guest is single-threaded with blocking
/// host I/O, so one in-flight request holds its whole Store.
fn serve(stream: &TcpStream) {
    let _ = time::sleep(Duration::from_millis(WORK_MS));

    let body = b"served\n";
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if let Err(e) = write_all(stream, head.as_bytes()).and_then(|()| write_all(stream, body)) {
        log::warn(format!("concurrency fixture: write failed: {e:?}"));
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn write_all(stream: &TcpStream, mut bytes: &[u8]) -> Result<(), SysError> {
    while !bytes.is_empty() {
        let written = stream.write_bytes(bytes)? as usize;
        if written == 0 {
            return Err(SysError::ApiError("write_bytes wrote 0".into()));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}
