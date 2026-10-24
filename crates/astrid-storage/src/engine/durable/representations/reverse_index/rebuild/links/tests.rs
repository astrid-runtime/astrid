use super::*;
use crate::engine::durable::locations::LocationIndexMemoryBudget;
use crate::engine::durable::representations::reverse_index::chain::PAYLOAD_BYTES;
use crate::engine::durable::{File, format::append_frame};
use std::io::{self, Read};

fn output_capacity() -> usize {
    LocationIndexMemoryBudget::default().buffered_output_bytes()
}

#[derive(Default)]
struct Counted {
    cursor: io::Cursor<Vec<u8>>,
    writes: usize,
    fail: bool,
}
impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail {
            return Err(io::Error::other("injected scratch write failure"));
        }
        self.writes = self.writes.strict_add(1);
        self.cursor.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for Counted {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.cursor.seek(at)
    }
}

#[test]
fn buffered_links_keep_identical_frames_offsets_and_reduce_inner_writes() {
    for capacity in [
        usize::try_from(LocationIndexMemoryBudget::MIN_BYTES).unwrap() / 4,
        output_capacity(),
    ] {
        let mut output = BufferedLinks::new(Counted::default(), capacity).unwrap();
        let mut baseline = File::native(tempfile::tempfile().unwrap());
        for index in 0..256_u64 {
            let payload = [u8::try_from(index).unwrap(); PAYLOAD_BYTES];
            assert_eq!(
                output.append(&payload).unwrap(),
                append_frame(&mut baseline, MAGIC, &payload).unwrap()
            );
        }
        let actual = output.finish().unwrap();
        let mut expected = Vec::new();
        baseline.seek(SeekFrom::Start(0)).unwrap();
        baseline.read_to_end(&mut expected).unwrap();
        assert_eq!(actual.cursor.into_inner(), expected);
        if capacity
            > usize::try_from(FRAME_HEADER_LEN)
                .unwrap()
                .strict_add(PAYLOAD_BYTES)
        {
            assert!(actual.writes < 256, "inner writes: {}", actual.writes);
        }
    }
}

#[test]
fn buffered_links_propagate_readback_and_final_flush_failures() {
    let target = Counted {
        fail: true,
        ..Counted::default()
    };
    let mut output = BufferedLinks::new(target, output_capacity()).unwrap();
    output.append(&[0; PAYLOAD_BYTES]).unwrap();
    assert!(output.flush().is_err());
    let target = Counted {
        fail: true,
        ..Counted::default()
    };
    let mut output = BufferedLinks::new(target, output_capacity()).unwrap();
    output.append(&[0; PAYLOAD_BYTES]).unwrap();
    assert!(output.finish().is_err());
}

#[test]
fn buffered_links_reject_offset_overflow_before_writing() {
    let mut output = BufferedLinks::new(Counted::default(), output_capacity()).unwrap();
    output.offset = u64::MAX;
    assert!(matches!(
        output.append(&[0; PAYLOAD_BYTES]),
        Err(DurableError::EncodingOverflow)
    ));
    assert_eq!(output.finish().unwrap().writes, 0);
}
