//! Compare projected bytes without retaining a second file-sized allocation.

use std::fs::File;
use std::io::{self, Read};

pub(super) fn matches_file(file: &mut File, expected: &[u8]) -> io::Result<bool> {
    if u64::try_from(expected.len()).ok() != Some(file.metadata()?.len()) {
        return Ok(false);
    }
    matches_reader(file, expected)
}

fn matches_reader(reader: &mut impl Read, expected: &[u8]) -> io::Result<bool> {
    // A bounded transfer buffer, not a file-size or admission limit.
    let mut buffer = [0; 8192];
    for chunk in expected.chunks(buffer.len()) {
        match reader.read_exact(&mut buffer[..chunk.len()]) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(error) => return Err(error),
        }
        if buffer[..chunk.len()] != *chunk {
            return Ok(false);
        }
    }
    // Detect growth after the initial metadata check, including empty files.
    match reader.read_exact(&mut buffer[..1]) {
        Ok(()) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(true),
        Err(error) => Err(error),
    }
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
}
