//! Compare projected bytes without retaining a second file-sized allocation.

use std::fs::File;
use std::io::{self, Read};

pub(crate) fn matches_file_from(
    file: &mut File,
    length: u64,
    expected: &mut dyn Read,
) -> io::Result<bool> {
    if file.metadata()?.len() != length {
        return Ok(false);
    }
    matches_readers(file, length, expected)
}

fn matches_readers(
    host: &mut dyn Read,
    mut remaining: u64,
    expected: &mut dyn Read,
) -> io::Result<bool> {
    // Transfer buffers, not admission limits. Neither side retains a file body.
    let mut actual = [0; 8192];
    let mut wanted = [0; 8192];
    while remaining > 0 {
        let count = usize::try_from(remaining.min(8192)).map_err(io::Error::other)?;
        // Expected-content failures must remain hard errors even when host
        // privacy/namespace failures are classified as an ordinary non-match.
        expected
            .read_exact(&mut wanted[..count])
            .map_err(io::Error::other)?;
        match host.read_exact(&mut actual[..count]) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(error) => return Err(error),
        }
        if actual[..count] != wanted[..count] {
            return Ok(false);
        }
        remaining = remaining.strict_sub(u64::try_from(count).map_err(io::Error::other)?);
    }
    if has_extra(host)? {
        return Ok(false);
    }
    if has_extra(expected).map_err(io::Error::other)? {
        return Err(io::Error::other(
            "expected content exceeds its admitted length",
        ));
    }
    Ok(true)
}

fn has_extra(reader: &mut dyn Read) -> io::Result<bool> {
    loop {
        match reader.read(&mut [0; 1]) {
            Ok(count) => return Ok(count != 0),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
fn matches_reader(reader: &mut impl Read, expected: &[u8]) -> io::Result<bool> {
    matches_readers(
        reader,
        u64::try_from(expected.len()).map_err(io::Error::other)?,
        &mut io::Cursor::new(expected),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ShortReads<'a>(&'a [u8]);

    impl Read for ShortReads<'_> {
        fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
            assert!(
                destination.len() <= 8192,
                "comparison requested an unbounded read"
            );
            let count = destination.len().min(self.0.len()).min(37);
            destination[..count].copy_from_slice(&self.0[..count]);
            self.0 = &self.0[count..];
            Ok(count)
        }
    }

    #[test]
    fn comparison_handles_short_reads_and_exact_length() {
        let expected = vec![0x5a; 20003];
        assert!(matches_reader(&mut ShortReads(&expected), &expected).unwrap());
        assert!(!matches_reader(&mut ShortReads(&expected[..20002]), &expected).unwrap());
        assert!(!matches_reader(&mut ShortReads(&expected), &expected[..20002]).unwrap());
        let mut different = expected.clone();
        different[8193] ^= 1;
        assert!(!matches_reader(&mut ShortReads(&different), &expected).unwrap());
        assert!(matches_reader(&mut ShortReads(&[]), &[]).unwrap());
        assert!(!matches_reader(&mut ShortReads(&[1]), &[]).unwrap());
    }

    #[test]
    fn comparison_propagates_read_errors() {
        struct Failed;
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
        assert_eq!(
            matches_reader(&mut Failed, b"x").unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            matches_reader(&mut Failed, b"").unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn expected_stream_length_and_read_failures_are_hard_errors() {
        struct Failed(io::ErrorKind);
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(self.0, "authenticated source failed"))
            }
        }
        for kind in [io::ErrorKind::InvalidData, io::ErrorKind::PermissionDenied] {
            for length in [0, 1] {
                let error = matches_readers(&mut &b"x"[..length], length as u64, &mut Failed(kind))
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert!(error.to_string().contains("authenticated source failed"));
            }
        }
        for expected in [b"".as_slice(), b"xx".as_slice()] {
            assert_eq!(
                matches_readers(&mut &b"x"[..], 1, &mut &expected[..])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Other
            );
        }
        assert!(matches_readers(&mut &b"x"[..], 1, &mut ShortReads(b"x")).unwrap());
    }
}
