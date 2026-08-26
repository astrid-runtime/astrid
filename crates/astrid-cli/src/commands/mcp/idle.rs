//! Idle-EOF ceiling for gateway attach readers.
//!
//! This is a protocol leak guard, not an operator config knob. Codex keeps a
//! stdio child per conversation and does not always drop it when the thread
//! ends; a reader without a deadline would pin a broker slot forever. Same
//! class as `MAX_ATTACHES` and `REGISTRATION_TIMEOUT`.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Production attach sockets that go silent are reaped after two minutes.
#[cfg(not(test))]
pub(crate) const ATTACH_IDLE_EOF: Duration = Duration::from_mins(2);
/// Tests use a tight bound so idle-EOF is deterministic in milliseconds.
#[cfg(test)]
pub(crate) const ATTACH_IDLE_EOF: Duration = Duration::from_millis(80);

pub(crate) struct IdleEof<R> {
    inner: R,
    idle: Duration,
    sleep: Pin<Box<Sleep>>,
    last_activity: Arc<Mutex<Instant>>,
}

impl<R> IdleEof<R> {
    pub(crate) fn new(inner: R, idle: Duration, last_activity: Arc<Mutex<Instant>>) -> Self {
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            last_activity,
        }
    }

    fn bump(&mut self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = now;
        }
        self.sleep
            .as_mut()
            .reset(now.checked_add(self.idle).unwrap_or(now));
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for IdleEof<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > filled_before {
                    this.bump();
                }
                Poll::Ready(Ok(()))
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MCP attach idle-EOF",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

pub(crate) fn is_idle(last_activity: &Mutex<Instant>, idle: Duration) -> bool {
    last_activity
        .lock()
        .is_ok_and(|instant| instant.elapsed() >= idle)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::time::Instant;

    use super::{ATTACH_IDLE_EOF, IdleEof, is_idle};

    #[tokio::test]
    async fn idle_reader_times_out_without_bytes() {
        let (_peer, stream) = tokio::io::duplex(32);
        let last = Arc::new(Mutex::new(Instant::now()));
        let mut reader = IdleEof::new(BufReader::new(stream), ATTACH_IDLE_EOF, last);
        let started = Instant::now();
        let error = reader
            .read_u8()
            .await
            .expect_err("silent attach must idle-EOF");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("idle-EOF"), "{error}");
        assert!(started.elapsed() >= ATTACH_IDLE_EOF);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn idle_reader_survives_traffic_inside_the_window() {
        let (mut peer, stream) = tokio::io::duplex(32);
        let last = Arc::new(Mutex::new(Instant::now()));
        let mut reader = IdleEof::new(BufReader::new(stream), ATTACH_IDLE_EOF, Arc::clone(&last));
        tokio::spawn(async move {
            tokio::time::sleep(ATTACH_IDLE_EOF / 2).await;
            peer.write_u8(b'x').await.expect("traffic");
        });
        assert_eq!(reader.read_u8().await.expect("byte"), b'x');
        assert!(!is_idle(&last, ATTACH_IDLE_EOF));
    }
}
