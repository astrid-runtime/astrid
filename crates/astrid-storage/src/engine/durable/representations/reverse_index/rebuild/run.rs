//! Private sorted runs: fixed-width rows, exact count, order and whole-run digest.
use super::{DurableError, ObjectId, RepresentationRecordId};
use crate::engine::durable::io_error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};

const ROW_BYTES: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Row {
    pub(super) object: ObjectId,
    pub(super) ordinal: u64,
    pub(super) representation: RepresentationRecordId,
}

impl Row {
    fn encode(self) -> [u8; ROW_BYTES] {
        let mut bytes = [0; ROW_BYTES];
        bytes[..32].copy_from_slice(self.object.as_bytes());
        bytes[32..40].copy_from_slice(&self.ordinal.to_le_bytes());
        bytes[40..].copy_from_slice(self.representation.as_bytes());
        bytes
    }

    fn decode(bytes: [u8; ROW_BYTES]) -> Self {
        Self {
            object: ObjectId::new(bytes[..32].try_into().expect("fixed object width")),
            ordinal: u64::from_le_bytes(bytes[32..40].try_into().expect("fixed ordinal width")),
            representation: RepresentationRecordId::new(
                bytes[40..].try_into().expect("fixed record width"),
            ),
        }
    }

    fn key(self) -> (ObjectId, u64) {
        (self.object, self.ordinal)
    }
}

pub(super) struct Run {
    file: File,
    count: u64,
    digest: blake3::Hash,
}

pub(super) struct Writer {
    file: BufWriter<File>,
    count: u64,
    digest: blake3::Hasher,
    previous: Option<Row>,
}

impl Writer {
    pub(super) fn new() -> Result<Self, DurableError> {
        Ok(Self {
            file: BufWriter::new(
                tempfile::tempfile().map_err(|e| io_error("create reverse sort run", e))?,
            ),
            count: 0,
            digest: blake3::Hasher::new(),
            previous: None,
        })
    }

    pub(super) fn push(&mut self, row: Row) -> Result<(), DurableError> {
        require_order(self.previous, row)?;
        let bytes = row.encode();
        self.file
            .write_all(&bytes)
            .map_err(|e| io_error("write reverse sort run", e))?;
        self.digest.update(&bytes);
        self.count = self
            .count
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        self.previous = Some(row);
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Run, DurableError> {
        let mut file = self
            .file
            .into_inner()
            .map_err(|e| io_error("flush reverse sort run", e.into_error()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| io_error("rewind reverse sort run", e))?;
        Ok(Run {
            file,
            count: self.count,
            digest: self.digest.finalize(),
        })
    }
}

pub(super) struct Reader {
    file: BufReader<File>,
    remaining: u64,
    expected: blake3::Hash,
    digest: blake3::Hasher,
    previous: Option<Row>,
}

impl Run {
    pub(super) fn reader(self) -> Reader {
        Reader {
            file: BufReader::new(self.file),
            remaining: self.count,
            expected: self.digest,
            digest: blake3::Hasher::new(),
            previous: None,
        }
    }

    pub(super) fn merge(self, newer: Self) -> Result<Self, DurableError> {
        let expected = self
            .count
            .checked_add(newer.count)
            .ok_or(DurableError::EncodingOverflow)?;
        let mut left = self.reader();
        let mut right = newer.reader();
        let mut a = left.next()?;
        let mut b = right.next()?;
        let mut output = Writer::new()?;
        while a.is_some() || b.is_some() {
            if a.is_some_and(|row| b.is_none_or(|other| row < other)) {
                output.push(a.take().expect("left selected"))?;
                a = left.next()?;
            } else {
                output.push(b.take().expect("right selected"))?;
                b = right.next()?;
            }
        }
        if output.count != expected {
            return Err(corrupt("reverse sort merge lost rows"));
        }
        output.finish()
    }
}

impl Reader {
    pub(super) fn next(&mut self) -> Result<Option<Row>, DurableError> {
        if self.remaining == 0 {
            self.verify_end()?;
            return Ok(None);
        }
        let mut bytes = [0; ROW_BYTES];
        self.file
            .read_exact(&mut bytes)
            .map_err(|e| io_error("read reverse sort run", e))?;
        self.digest.update(&bytes);
        let row = Row::decode(bytes);
        require_order(self.previous, row)?;
        self.previous = Some(row);
        self.remaining = self.remaining.strict_sub(1);
        if self.remaining == 0 {
            self.verify_end()?;
        }
        Ok(Some(row))
    }

    fn verify_end(&mut self) -> Result<(), DurableError> {
        let mut tail = [0];
        if self
            .file
            .read(&mut tail)
            .map_err(|e| io_error("read reverse sort tail", e))?
            != 0
            || self.digest.finalize() != self.expected
        {
            return Err(corrupt("reverse sort run digest or length changed"));
        }
        Ok(())
    }
}

fn require_order(previous: Option<Row>, row: Row) -> Result<(), DurableError> {
    if previous.is_some_and(|previous| previous.key() >= row.key()) {
        return Err(corrupt("reverse sort rows are not strictly ordered"));
    }
    Ok(())
}

fn corrupt(detail: &'static str) -> DurableError {
    DurableError::InvalidRepresentationState(detail)
}

#[cfg(test)]
mod tests;
