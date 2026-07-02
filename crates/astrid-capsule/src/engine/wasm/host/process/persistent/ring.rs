//! Per-stream log ring + opaque cursor for the persistent tier.
//!
//! One ring backs BOTH the draining `read-logs` path and the non-draining,
//! cursor-addressed `read-since` path (the WIT's "single shared ring per
//! `process-id`": whoever drains first consumes those bytes).

use std::collections::VecDeque;

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{ErrorCode, LogCursor};

/// Ring overflow behaviour for one stream.
#[derive(Clone, Copy)]
pub(super) enum Overflow {
    /// Drop oldest bytes to make room; loss surfaces as `bytes-dropped`.
    DropOldest,
    /// Stop draining the pipe when full so the child blocks on write.
    Backpressure,
}

/// Which stream a reader task feeds.
#[derive(Clone, Copy)]
pub(super) enum Stream {
    Out,
    Err,
}

/// A single stream's retained output.
///
/// `front_offset` is the absolute byte offset of `buf[0]`. It advances on
/// overflow eviction AND on drain, so a stale `read-since` cursor below it
/// reports the gap as `bytes-dropped` rather than ever returning another
/// range's bytes. `overflow_dropped` counts ONLY involuntary eviction (for
/// `process-info.bytes-dropped`), never intentional drain.
pub(super) struct LogRing {
    buf: VecDeque<u8>,
    front_offset: u64,
    pub(super) overflow_dropped: u64,
    cap: usize,
    overflow: Overflow,
}

impl LogRing {
    pub(super) fn new(cap: usize, overflow: Overflow) -> Self {
        Self {
            buf: VecDeque::new(),
            front_offset: 0,
            overflow_dropped: 0,
            cap,
            overflow,
        }
    }

    /// Bytes currently retained (drainable).
    pub(super) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Absolute offset one past the newest byte.
    pub(super) fn end_offset(&self) -> u64 {
        self.front_offset + self.buf.len() as u64
    }

    /// Append reader-task bytes. `drop-oldest` always accepts (evicting the
    /// oldest bytes on overflow). `backpressure` is **all-or-nothing**: it
    /// accepts only if the whole chunk fits, else returns `false` and stores
    /// nothing — so it NEVER evicts (no byte loss / framing corruption); the
    /// reader holds the chunk and retries, the OS pipe fills, and the child
    /// blocks on write. The caller must size reads `<= cap` so a chunk can
    /// always fit in an empty ring (otherwise backpressure would never accept
    /// it); see `entry::READER_CHUNK_BYTES`.
    pub(super) fn push(&mut self, bytes: &[u8]) -> bool {
        match self.overflow {
            Overflow::Backpressure => {
                if self.buf.len() + bytes.len() > self.cap {
                    return false;
                }
                self.buf.extend(bytes);
                true
            },
            Overflow::DropOldest => {
                self.buf.extend(bytes);
                if self.buf.len() > self.cap {
                    let excess = self.buf.len() - self.cap;
                    self.buf.drain(..excess);
                    self.front_offset += excess as u64;
                    self.overflow_dropped += excess as u64;
                }
                true
            },
        }
    }

    /// Drain ALL retained bytes (`read-logs` semantics). Advances
    /// `front_offset` so later `read-since` cursors see the gap.
    pub(super) fn drain(&mut self) -> Vec<u8> {
        let out: Vec<u8> = self.buf.drain(..).collect();
        self.front_offset += out.len() as u64;
        out
    }

    /// Non-draining cursor read. `cursor` is an absolute offset (`None` =
    /// from the oldest retained byte). Returns `(data, next_offset,
    /// dropped_for_this_cursor)`.
    pub(super) fn read_since(&self, cursor: Option<u64>, max: usize) -> (Vec<u8>, u64, u64) {
        let requested = cursor.unwrap_or(self.front_offset);
        let dropped = self.front_offset.saturating_sub(requested);
        let start = requested.max(self.front_offset).min(self.end_offset());
        let rel = (start - self.front_offset) as usize;
        let take = (self.buf.len() - rel).min(max);
        let data: Vec<u8> = self.buf.iter().skip(rel).take(take).copied().collect();
        (data, start + take as u64, dropped)
    }
}

/// Encode an absolute byte offset as an opaque cursor token (hex of the u64).
pub(super) fn encode_cursor(offset: u64) -> LogCursor {
    LogCursor {
        token: Some(format!("{offset:016x}")),
    }
}

/// Decode a cursor token to an absolute offset. `none` => from the oldest
/// retained byte. A malformed token is a structural oracle, so it collapses
/// to `no-such-process` (never `invalid-input`).
pub(super) fn decode_cursor(cursor: &LogCursor) -> Result<Option<u64>, ErrorCode> {
    match &cursor.token {
        None => Ok(None),
        Some(t) => u64::from_str_radix(t, 16)
            .map(Some)
            .map_err(|_| ErrorCode::NoSuchProcess),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_oldest_evicts_and_counts() {
        let mut ring = LogRing::new(4, Overflow::DropOldest);
        assert!(ring.push(b"abcdef")); // 6 into cap 4 → evict 2
        assert_eq!(ring.overflow_dropped, 2);
        assert_eq!(ring.front_offset, 2);
        let (data, next, dropped) = ring.read_since(None, 100);
        assert_eq!(data, b"cdef");
        assert_eq!(next, 6);
        assert_eq!(dropped, 0); // None starts at front, missed nothing
    }

    #[test]
    fn cursor_below_front_reports_drop() {
        let mut ring = LogRing::new(4, Overflow::DropOldest);
        ring.push(b"abcdef"); // front_offset now 2
        let (data, next, dropped) = ring.read_since(Some(0), 100);
        assert_eq!(dropped, 2);
        assert_eq!(data, b"cdef");
        assert_eq!(next, 6);
    }

    #[test]
    fn drain_advances_front() {
        let mut ring = LogRing::new(100, Overflow::DropOldest);
        ring.push(b"hello");
        assert_eq!(ring.drain(), b"hello");
        assert_eq!(ring.front_offset, 5);
        let (data, _next, dropped) = ring.read_since(Some(0), 100);
        assert!(data.is_empty());
        assert_eq!(dropped, 5);
    }

    #[test]
    fn read_since_respects_max() {
        let mut ring = LogRing::new(100, Overflow::DropOldest);
        ring.push(b"abcdefghij");
        let (data, next, _) = ring.read_since(Some(0), 4);
        assert_eq!(data, b"abcd");
        assert_eq!(next, 4);
        let (data2, next2, _) = ring.read_since(Some(next), 100);
        assert_eq!(data2, b"efghij");
        assert_eq!(next2, 10);
    }

    #[test]
    fn backpressure_rejects_when_full() {
        let mut ring = LogRing::new(4, Overflow::Backpressure);
        assert!(ring.push(b"abcd"));
        assert!(!ring.push(b"e")); // full → reader parks
        assert_eq!(ring.overflow_dropped, 0);
    }

    #[test]
    fn backpressure_never_evicts_on_crossing_push() {
        // A push that would cross the cap from below is rejected WHOLE —
        // backpressure must never drop bytes (the bug: it used to evict).
        let mut ring = LogRing::new(10, Overflow::Backpressure);
        assert!(ring.push(b"abcdef")); // 6 <= 10 → accepted
        assert!(!ring.push(b"ghijkl")); // 6+6=12 > 10 → rejected, nothing stored
        assert_eq!(ring.len(), 6);
        assert_eq!(ring.overflow_dropped, 0);
        let (data, _next, dropped) = ring.read_since(None, 100);
        assert_eq!(data, b"abcdef"); // exactly what was accepted, contiguous
        assert_eq!(dropped, 0);
    }

    #[test]
    fn cursor_roundtrip_and_reject_garbage() {
        let c = encode_cursor(0x1234_5678_9abc_def0);
        assert_eq!(decode_cursor(&c).unwrap(), Some(0x1234_5678_9abc_def0));
        assert_eq!(decode_cursor(&LogCursor { token: None }).unwrap(), None);
        assert!(
            decode_cursor(&LogCursor {
                token: Some("zzz".into())
            })
            .is_err()
        );
    }
}
