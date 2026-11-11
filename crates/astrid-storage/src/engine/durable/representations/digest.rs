//! Bounded BLAKE3 digests over representation journal bytes.
//!
//! Checkpoint publication and recovery must fingerprint raw journal bytes with
//! the frozen domain below. Streaming through the shared 64 `KiB` transfer size
//! keeps ordinary commit-time maintenance from allocating a whole-generation
//! `Vec` while preserving digest bytes, authentication order, and the append
//! cursor at end-of-file on success.

use std::io::{ErrorKind, SeekFrom};

use super::format::JOURNAL_BYTES_DIGEST_CONTEXT;
use super::{DurableError, DurableIo, io_error};

pub(super) use super::super::format::TRANSFER_BUFFER_BYTES;

/// Digest the entire journal file with the frozen journal-bytes domain.
///
/// Seeks to the start, streams through [`TRANSFER_BUFFER_BYTES`] reads (retrying
/// `Interrupted`), then seeks to end so callers can continue appending.
pub(super) fn digest_journal_file<F: DurableIo>(
    file: &mut F,
    operation: &'static str,
) -> Result<[u8; 32], DurableError> {
    digest_journal_range(file, None, operation)
}

/// Digest exactly the prefix `[0, end)` and ignore any later bytes.
///
/// Fails closed if the file ends before `end`. Leaves the cursor at end-of-file
/// on success, matching [`digest_journal_file`].
pub(super) fn digest_journal_prefix<F: DurableIo>(
    file: &mut F,
    end: u64,
    operation: &'static str,
) -> Result<[u8; 32], DurableError> {
    digest_journal_range(file, Some(end), operation)
}

/// Authoritative journal length for tail budgets without a second full read.
///
/// Cross-checks durable metadata length against `SeekFrom::End(0)` and leaves
/// the sequential cursor at EOF for appenders.
pub(super) fn journal_byte_len<F: DurableIo>(
    file: &mut F,
    operation: &'static str,
) -> Result<u64, DurableError> {
    let meta_len = file
        .durable_metadata()
        .map_err(|source| io_error(operation, source))?
        .len();
    let end = file
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error(operation, source))?;
    if meta_len != end {
        return Err(DurableError::InvalidRepresentationState(
            "representation journal metadata length disagrees with end offset",
        ));
    }
    Ok(end)
}

fn digest_journal_range<F: DurableIo>(
    file: &mut F,
    end: Option<u64>,
    operation: &'static str,
) -> Result<[u8; 32], DurableError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error(operation, source))?;
    let mut hasher = blake3::Hasher::new_derive_key(JOURNAL_BYTES_DIGEST_CONTEXT);
    let mut buffer = vec![0_u8; TRANSFER_BUFFER_BYTES].into_boxed_slice();
    let mut consumed = 0_u64;
    loop {
        let want = match end {
            None => buffer.len(),
            Some(limit) => {
                let remaining = limit.saturating_sub(consumed);
                if remaining == 0 {
                    break;
                }
                let capped = remaining.min(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
                usize::try_from(capped).unwrap_or(buffer.len())
            },
        };
        let read = read_retry(file, &mut buffer[..want], operation)?;
        if read == 0 {
            if matches!(end, Some(limit) if consumed < limit) {
                return Err(DurableError::InvalidRepresentationState(
                    "representation journal digest prefix is truncated",
                ));
            }
            break;
        }
        hasher.update(&buffer[..read]);
        let read_u64 = u64::try_from(read).map_err(|_| DurableError::EncodingOverflow)?;
        consumed = consumed
            .checked_add(read_u64)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error(operation, source))?;
    Ok(*hasher.finalize().as_bytes())
}

fn read_retry<F: DurableIo>(
    file: &mut F,
    buffer: &mut [u8],
    operation: &'static str,
) -> Result<usize, DurableError> {
    loop {
        match file.read(buffer) {
            Ok(read) => return Ok(read),
            Err(source) if source.kind() == ErrorKind::Interrupted => {},
            Err(source) => return Err(io_error(operation, source)),
        }
    }
}

#[cfg(test)]
mod tests;
