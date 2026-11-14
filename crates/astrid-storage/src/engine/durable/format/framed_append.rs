//! Bounded framed append stream for tip rewrites.
//!
//! Seeks once, then writes frame headers and payloads through a fixed-size
//! transfer buffer. This is an I/O coalescing mechanism (same class as the
//! object-index snapshot and WAL write buffers), not an operator retention or
//! admission limit.

use std::io::{BufWriter, SeekFrom, Write};

use super::{DurableError, DurableIo, frame_checksum_hasher, frame_header, io_error};

/// Transfer buffer for coalescing many small framed writes.
pub(in crate::engine::durable) const TRANSFER_BUFFER_BYTES: usize = 64 * 1024;

pub(in crate::engine::durable) struct FramedAppendStream<'a, F: DurableIo> {
    writer: BufWriter<&'a mut F>,
    magic: [u8; 8],
}

impl<'a, F: DurableIo> FramedAppendStream<'a, F> {
    /// Seek to end once and begin buffered framed appends.
    pub(in crate::engine::durable) fn begin(
        file: &'a mut F,
        magic: [u8; 8],
    ) -> Result<Self, DurableError> {
        file.seek(SeekFrom::End(0))
            .map_err(|source| io_error("seek framed append stream", source))?;
        Ok(Self {
            writer: BufWriter::with_capacity(TRANSFER_BUFFER_BYTES, file),
            magic,
        })
    }

    /// Append one already-encoded payload with the standard frame header/checksum.
    pub(in crate::engine::durable) fn append_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<(), DurableError> {
        self.append_payload_parts(&[payload])
    }

    /// Append borrowed payload slices as one frame.
    ///
    /// Checksum and length cover the concatenation; the slices are written in
    /// order and never copied into a temporary payload Vec. Adoption can pass
    /// a metadata prefix plus a live node body as `[&prefix, body]`.
    pub(in crate::engine::durable) fn append_payload_parts(
        &mut self,
        parts: &[&[u8]],
    ) -> Result<(), DurableError> {
        let payload_len = payload_parts_len(parts)?;
        let checksum = payload_parts_checksum(self.magic, payload_len, parts);
        let header = frame_header(self.magic, payload_len, checksum);
        self.writer
            .write_all(&header)
            .map_err(|source| io_error("append framed stream header", source))?;
        write_payload_parts(&mut self.writer, parts)
    }

    /// Flush the transfer buffer before the caller syncs or re-reads the file.
    pub(in crate::engine::durable) fn finish(mut self) -> Result<(), DurableError> {
        self.writer
            .flush()
            .map_err(|source| io_error("flush framed append stream", source))
    }
}

fn payload_parts_len(parts: &[&[u8]]) -> Result<u64, DurableError> {
    parts.iter().try_fold(0_u64, |total, part| {
        u64::try_from(part.len())
            .ok()
            .and_then(|len| total.checked_add(len))
            .ok_or(DurableError::EncodingOverflow)
    })
}

fn payload_parts_checksum(magic: [u8; 8], payload_len: u64, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = frame_checksum_hasher(magic, payload_len);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn write_payload_parts<W: Write>(writer: &mut W, parts: &[&[u8]]) -> Result<(), DurableError> {
    for part in parts {
        writer
            .write_all(part)
            .map_err(|source| io_error("append framed stream payload", source))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Seek as _, SeekFrom};

    use super::super::{
        ARENA_MAGIC, DurableError, File, RecoveryLimits, append_frame, scan_frames,
    };
    use super::FramedAppendStream;

    fn open_file(hosted: bool) -> (tempfile::TempDir, File) {
        let dir = tempfile::tempdir().unwrap();
        let file = if hosted {
            File::volume(
                crate::volume::HostedFileVolume::open(dir.path().join("astrid.volume")).unwrap(),
                "frames",
                true,
            )
            .unwrap()
        } else {
            File::native(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(dir.path().join("frames"))
                    .unwrap(),
            )
        };
        (dir, file)
    }

    fn append_then_bytes(
        file: &mut File,
        write: impl FnOnce(&mut FramedAppendStream<'_, File>) -> Result<(), DurableError>,
    ) -> Vec<u8> {
        {
            let mut stream = FramedAppendStream::begin(file, ARENA_MAGIC).unwrap();
            write(&mut stream).unwrap();
            stream.finish().unwrap();
        }
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn scanned_payloads(file: &mut File) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        scan_frames(
            file,
            "frames",
            ARENA_MAGIC,
            RecoveryLimits::process_addressable(),
            |_, payload| {
                payloads.push(payload.to_vec());
                Ok(())
            },
        )
        .unwrap();
        payloads
    }

    #[test]
    fn append_payload_parts_matches_concatenated_payload_on_native_and_volume() {
        let prefix = [0xA5_u8; 49];
        let body = b"canonical-node-body";
        let cases: &[&[&[u8]]] = &[
            &[],
            &[&[]],
            &[b"single"],
            &[&prefix, body],
            &[b"ab", b"", b"cd", b"ef"],
        ];
        for hosted in [false, true] {
            for parts in cases {
                let concat = parts.concat();
                let (_dir_parts, mut parts_file) = open_file(hosted);
                let (_dir_concat, mut concat_file) = open_file(hosted);
                let parts_bytes =
                    append_then_bytes(&mut parts_file, |stream| stream.append_payload_parts(parts));
                // Compare against the independent ordinary writer rather than
                // append_payload, which now delegates to the multipart writer.
                append_frame(&mut concat_file, ARENA_MAGIC, &concat).unwrap();
                concat_file.seek(SeekFrom::Start(0)).unwrap();
                let mut concat_bytes = Vec::new();
                concat_file.read_to_end(&mut concat_bytes).unwrap();
                assert_eq!(parts_bytes, concat_bytes, "hosted={hosted}");
                assert_eq!(
                    scanned_payloads(&mut parts_file),
                    vec![concat.clone()],
                    "hosted={hosted}"
                );
                assert_eq!(
                    scanned_payloads(&mut concat_file),
                    vec![concat],
                    "hosted={hosted}"
                );
            }
        }
    }
}
