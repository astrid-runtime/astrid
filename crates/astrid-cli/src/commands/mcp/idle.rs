//! Activity tracking for capacity-bound gateway admission.
//!
//! Silence is not EOF: a connected host can spend minutes thinking or waiting
//! for user input. Track traffic for the existing capacity-pressure eviction
//! policy, but close ordinary connections only when their transport closes.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::Instant;

/// Quiet slots become eviction candidates only when admission reaches its cap.
#[cfg(not(test))]
pub(crate) const ATTACH_IDLE_THRESHOLD: Duration = Duration::from_mins(2);
/// Tests exercise the same quiet period with a shorter bound.
#[cfg(test)]
pub(crate) const ATTACH_IDLE_THRESHOLD: Duration = Duration::from_millis(80);

pub(crate) struct ActivityReader<R> {
    inner: R,
    last_activity: Arc<Mutex<Instant>>,
}

impl<R> ActivityReader<R> {
    pub(crate) fn new(inner: R, last_activity: Arc<Mutex<Instant>>) -> Self {
        Self {
            inner,
            last_activity,
        }
    }

    fn bump(&mut self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = now;
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ActivityReader<R> {
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
            Poll::Pending => Poll::Pending,
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

    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::time::Instant;

    use super::{ATTACH_IDLE_THRESHOLD, ActivityReader, is_idle};

    #[tokio::test]
    async fn connected_reader_survives_quiet_period_then_accepts_request() {
        let (mut peer, stream) = tokio::io::duplex(32);
        let last = Arc::new(Mutex::new(Instant::now()));
        let mut reader = ActivityReader::new(BufReader::new(stream), last);
        assert!(
            tokio::time::timeout(ATTACH_IDLE_THRESHOLD * 2, reader.read_u8())
                .await
                .is_err(),
            "silence is not a client disconnect"
        );
        peer.write_u8(b'x')
            .await
            .expect("request after quiet period");
        assert_eq!(reader.read_u8().await.expect("request byte"), b'x');
        drop(peer);
        assert_eq!(
            reader.read_u8().await.expect_err("real EOF").kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn traffic_refreshes_capacity_eviction_activity() {
        let (mut peer, stream) = tokio::io::duplex(32);
        let last = Arc::new(Mutex::new(Instant::now()));
        let mut reader = ActivityReader::new(BufReader::new(stream), Arc::clone(&last));
        tokio::spawn(async move {
            tokio::time::sleep(ATTACH_IDLE_THRESHOLD / 2).await;
            peer.write_u8(b'x').await.expect("traffic");
            tokio::time::sleep(ATTACH_IDLE_THRESHOLD * 7 / 8).await;
            let _ = peer.write_u8(b'y').await;
        });
        assert_eq!(reader.read_u8().await.expect("byte"), b'x');
        assert!(!is_idle(&last, ATTACH_IDLE_THRESHOLD));
        assert_eq!(reader.read_u8().await.expect("reset byte"), b'y');
    }
}
