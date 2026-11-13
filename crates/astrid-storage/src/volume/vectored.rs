//! Borrowed concatenation for a single checksummed volume write.

use std::io::{self, IoSlice, Read};

pub(super) struct Reader<'a, 'b> {
    slices: std::slice::Iter<'a, IoSlice<'b>>,
    current: &'a [u8],
}

impl<'a, 'b> Reader<'a, 'b> {
    pub(super) fn new(slices: &'a [IoSlice<'b>]) -> Self {
        Self {
            slices: slices.iter(),
            current: &[],
        }
    }
}

impl Read for Reader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.current.is_empty() {
            let Some(slice) = self.slices.next() else {
                return Ok(0);
            };
            self.current = slice;
        }
        self.current.read(output)
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;
    use crate::volume::{HostedFileVolume, VolumeFile, VolumeRegion};
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn borrowed_slices_preserve_empty_reads_and_partial_boundaries() {
        let slices = [
            IoSlice::new(b""),
            IoSlice::new(b"abc"),
            IoSlice::new(b""),
            IoSlice::new(b"defgh"),
            IoSlice::new(b""),
        ];
        let mut reader = Reader::new(&slices);
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        let mut first = [0; 2];
        reader.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"ab");
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"cdefgh");
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn vectored_volume_write_is_one_record_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("astrid.volume");
        let region = VolumeRegion::new("objects").unwrap();
        let expected = [b"prefix".as_slice(), &vec![0xa5; 70_000], b"suffix"].concat();
        {
            let volume = HostedFileVolume::open(&path).unwrap();
            let mut file = VolumeFile::create_new(volume.clone(), region.clone()).unwrap();
            let slices = [
                IoSlice::new(&expected[..6]),
                IoSlice::new(b""),
                IoSlice::new(&expected[6..70_006]),
                IoSlice::new(&expected[70_006..]),
            ];
            assert_eq!(file.write_vectored(&slices).unwrap(), expected.len());
            assert_eq!(file.stream_position().unwrap(), expected.len() as u64);
            let records = volume.write_record_payloads().unwrap();
            assert_eq!(records, vec![("objects".to_owned(), expected.len() as u64)]);
            file.sync_all().unwrap();
        }
        let volume = HostedFileVolume::open(&path).unwrap();
        let mut file = VolumeFile::open(volume, region, false).unwrap();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        file.seek(SeekFrom::Start(3)).unwrap();
        assert_eq!(
            file.write_vectored(&[IoSlice::new(b"12"), IoSlice::new(b"34")])
                .unwrap(),
            4,
        );
        file.seek(SeekFrom::Start(0)).unwrap();
        actual.clear();
        file.read_to_end(&mut actual).unwrap();
        let mut overwritten = expected;
        overwritten[3..7].copy_from_slice(b"1234");
        assert_eq!(actual, overwritten);
    }

    #[test]
    fn empty_vectored_write_does_not_append_or_move_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
        let mut file =
            VolumeFile::create_new(volume.clone(), VolumeRegion::new("objects").unwrap()).unwrap();
        file.seek(SeekFrom::Start(19)).unwrap();
        assert_eq!(file.write_vectored(&[]).unwrap(), 0);
        assert_eq!(file.write_vectored(&[IoSlice::new(b"")]).unwrap(), 0);
        assert_eq!(file.stream_position().unwrap(), 19);
        assert!(volume.write_record_payloads().unwrap().is_empty());
    }

    #[test]
    fn cursor_overflow_rejects_before_any_volume_write() {
        let directory = tempfile::tempdir().unwrap();
        let volume = HostedFileVolume::open(directory.path().join("astrid.volume")).unwrap();
        let mut file =
            VolumeFile::create_new(volume.clone(), VolumeRegion::new("objects").unwrap()).unwrap();
        file.seek(SeekFrom::Start(u64::MAX)).unwrap();
        assert!(
            file.write_vectored(&[IoSlice::new(b"a"), IoSlice::new(b"b")])
                .is_err()
        );
        assert!(file.write_from(1, &mut &b"a"[..]).is_err());
        assert_eq!(file.stream_position().unwrap(), u64::MAX);
        assert!(volume.write_record_payloads().unwrap().is_empty());
    }
}
