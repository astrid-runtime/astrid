//! Deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding).
//!
//! Only the subset the v2 audit formats use is supported: unsigned and
//! negative integers, byte and text strings, definite-length arrays and maps,
//! `false`, `true` and `null`. The encoder writes every head in its shortest
//! form and sorts map entries by the bytewise order of their encoded keys.
//! The decoder accepts exactly those encodings and rejects everything else:
//! floats, tags, other simple values, indefinite lengths, non-shortest heads,
//! unsorted or duplicate map keys, invalid UTF-8 and trailing bytes.

use std::fmt;

/// One CBOR data item from the supported subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Cbor {
    /// Major type 0: an unsigned integer.
    Uint(u64),
    /// Major type 1: the negative integer `-1 - n`, holding `n`.
    Nint(u64),
    /// Major type 2: a byte string.
    Bytes(Vec<u8>),
    /// Major type 3: a UTF-8 text string.
    Text(String),
    /// Major type 4: a definite-length array.
    Array(Vec<Cbor>),
    /// Major type 5: a definite-length map. The encoder sorts the entries;
    /// callers must not supply duplicate keys.
    Map(Vec<(Cbor, Cbor)>),
    /// `false` (`0xf4`) or `true` (`0xf5`).
    Bool(bool),
    /// `null` (`0xf6`).
    Null,
}

/// A decoding failure: the input is not a canonical item of the subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CborError(&'static str);

impl fmt::Display for CborError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "non-canonical or unsupported CBOR: {}", self.0)
    }
}

impl std::error::Error for CborError {}

// Major types, already shifted into the top three bits of the initial byte.
const MAJOR_UINT: u8 = 0x00;
const MAJOR_NINT: u8 = 0x20;
const MAJOR_BYTES: u8 = 0x40;
const MAJOR_TEXT: u8 = 0x60;
const MAJOR_ARRAY: u8 = 0x80;
const MAJOR_MAP: u8 = 0xa0;
const MAJOR_SIMPLE: u8 = 0xe0;
const MAJOR_MASK: u8 = 0xe0;
const INFO_MASK: u8 = 0x1f;
// Additional-information values announcing a 1-, 2-, 4- or 8-byte argument.
const INFO_ONE_BYTE: u8 = 0x18;
const INFO_TWO_BYTES: u8 = 0x19;
const INFO_FOUR_BYTES: u8 = 0x1a;
const INFO_EIGHT_BYTES: u8 = 0x1b;
const INFO_INDEFINITE: u8 = 0x1f;
const SIMPLE_FALSE: u8 = 0xf4;
const SIMPLE_TRUE: u8 = 0xf5;
const SIMPLE_NULL: u8 = 0xf6;
/// Nesting bound for the decoder; the v2 formats nest a few levels deep.
const MAX_DEPTH: usize = 64;

impl Cbor {
    /// A text item.
    #[must_use]
    pub(crate) fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// A byte-string item.
    #[must_use]
    pub(crate) fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// Encode this item deterministically.
    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Uint(value) => head(out, MAJOR_UINT, *value),
            Self::Nint(value) => head(out, MAJOR_NINT, *value),
            Self::Bytes(bytes) => {
                head(out, MAJOR_BYTES, len_u64(bytes.len()));
                out.extend_from_slice(bytes);
            },
            Self::Text(text) => {
                head(out, MAJOR_TEXT, len_u64(text.len()));
                out.extend_from_slice(text.as_bytes());
            },
            Self::Array(items) => {
                head(out, MAJOR_ARRAY, len_u64(items.len()));
                for item in items {
                    item.encode_into(out);
                }
            },
            Self::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(key, value)| (key.encode(), value.encode()))
                    .collect();
                encoded.sort_by(|left, right| left.0.cmp(&right.0));
                head(out, MAJOR_MAP, len_u64(encoded.len()));
                for (key, value) in encoded {
                    out.extend_from_slice(&key);
                    out.extend_from_slice(&value);
                }
            },
            Self::Bool(false) => out.push(SIMPLE_FALSE),
            Self::Bool(true) => out.push(SIMPLE_TRUE),
            Self::Null => out.push(SIMPLE_NULL),
        }
    }

    /// Decode exactly one canonical item that spans all of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`CborError`] when `bytes` is not the deterministic encoding of
    /// a single item from the supported subset.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let mut reader = Reader { bytes, pos: 0 };
        let item = reader.item(0)?;
        if reader.pos != bytes.len() {
            return Err(CborError("trailing bytes after the item"));
        }
        Ok(item)
    }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Write the shortest head for `major` with argument `value`.
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    match value {
        0..=23 => out.push(major | u8::try_from(value).unwrap_or(0)),
        24..=0xff => {
            out.push(major | INFO_ONE_BYTE);
            out.push(u8::try_from(value).unwrap_or(0));
        },
        0x100..=0xffff => {
            out.push(major | INFO_TWO_BYTES);
            out.extend_from_slice(&u16::try_from(value).unwrap_or(0).to_be_bytes());
        },
        0x1_0000..=0xffff_ffff => {
            out.push(major | INFO_FOUR_BYTES);
            out.extend_from_slice(&u32::try_from(value).unwrap_or(0).to_be_bytes());
        },
        _ => {
            out.push(major | INFO_EIGHT_BYTES);
            out.extend_from_slice(&value.to_be_bytes());
        },
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .pos
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(CborError("item runs past the end of the input"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(CborError("item runs past the end of the input"))?;
        self.pos = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Read an initial byte and its argument, enforcing shortest form.
    fn head(&mut self) -> Result<(u8, u8, u64), CborError> {
        let initial = *self
            .take(1)?
            .first()
            .ok_or(CborError("missing initial byte"))?;
        let major = initial & MAJOR_MASK;
        let info = initial & INFO_MASK;
        let value = match info {
            0..=23 => u64::from(info),
            INFO_ONE_BYTE => {
                let value = u64::from(self.take(1)?.first().copied().unwrap_or(0));
                if value < 24 {
                    return Err(CborError("non-shortest one-byte argument"));
                }
                value
            },
            INFO_TWO_BYTES => {
                let value = u64::from(u16::from_be_bytes(array(self.take(2)?)?));
                if value <= 0xff {
                    return Err(CborError("non-shortest two-byte argument"));
                }
                value
            },
            INFO_FOUR_BYTES => {
                let value = u64::from(u32::from_be_bytes(array(self.take(4)?)?));
                if value <= 0xffff {
                    return Err(CborError("non-shortest four-byte argument"));
                }
                value
            },
            INFO_EIGHT_BYTES => {
                let value = u64::from_be_bytes(array(self.take(8)?)?);
                if value <= 0xffff_ffff {
                    return Err(CborError("non-shortest eight-byte argument"));
                }
                value
            },
            INFO_INDEFINITE => return Err(CborError("indefinite-length item")),
            _ => return Err(CborError("reserved additional information")),
        };
        Ok((major, info, value))
    }

    fn length(&self, value: u64) -> Result<usize, CborError> {
        let length = usize::try_from(value).map_err(|_| CborError("length overflows"))?;
        // Every element takes at least one byte, so a count beyond the
        // remaining input is malformed and must not drive an allocation.
        if length > self.remaining() {
            return Err(CborError("length exceeds the remaining input"));
        }
        Ok(length)
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError("nesting too deep"));
        }
        let (major, info, value) = self.head()?;
        match major {
            MAJOR_UINT => Ok(Cbor::Uint(value)),
            MAJOR_NINT => Ok(Cbor::Nint(value)),
            MAJOR_BYTES => {
                let length = self.length(value)?;
                Ok(Cbor::Bytes(self.take(length)?.to_vec()))
            },
            MAJOR_TEXT => {
                let length = self.length(value)?;
                let text = std::str::from_utf8(self.take(length)?)
                    .map_err(|_| CborError("text is not valid UTF-8"))?;
                Ok(Cbor::Text(text.to_owned()))
            },
            MAJOR_ARRAY => {
                let count = self.length(value)?;
                let next = depth.saturating_add(1);
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.item(next)?);
                }
                Ok(Cbor::Array(items))
            },
            MAJOR_MAP => self.map(value, depth),
            MAJOR_SIMPLE => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(CborError("unsupported simple value or float")),
            },
            _ => Err(CborError("tags are not supported")),
        }
    }

    fn map(&mut self, value: u64, depth: usize) -> Result<Cbor, CborError> {
        let count = self.length(value)?;
        let next = depth.saturating_add(1);
        let input = self.bytes;
        let mut entries = Vec::with_capacity(count);
        let mut previous_key: Option<&[u8]> = None;
        for _ in 0..count {
            let start = self.pos;
            let key = self.item(next)?;
            let encoded_key = input
                .get(start..self.pos)
                .ok_or(CborError("map key runs past the end of the input"))?;
            if previous_key.is_some_and(|previous| previous >= encoded_key) {
                return Err(CborError("map keys are unsorted or duplicated"));
            }
            previous_key = Some(encoded_key);
            let value = self.item(next)?;
            entries.push((key, value));
        }
        Ok(Cbor::Map(entries))
    }
}

fn array<const N: usize>(slice: &[u8]) -> Result<[u8; N], CborError> {
    <[u8; N]>::try_from(slice).map_err(|_| CborError("short argument"))
}
