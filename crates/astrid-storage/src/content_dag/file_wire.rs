//! Persisted fields of a version-one file descriptor.
use super::{ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord};
use crate::storage_words::{little_endian, little_endian_u32, read_u32};
use vstd::prelude::*;

verus! {
pub(super) const LENGTH: usize = 40;
pub(super) const TAG: &[u8; 4] = &[1, 1, 0, 1];

pub(super) struct Header {
    pub(super) minimum: u32,
    pub(super) average: u32,
    pub(super) maximum: u32,
    pub(super) seed: u64,
    pub(super) logical: u64,
    pub(super) chunks: u64,
}

impl Header {
    pub(super) open spec fn wire(&self) -> Seq<u8> {
        TAG@ + crate::storage_words::word32(self.minimum)
            + crate::storage_words::word32(self.average)
            + crate::storage_words::word32(self.maximum)
            + vstd::bytes::spec_u64_to_le_bytes(self.seed)
            + vstd::bytes::spec_u64_to_le_bytes(self.logical)
            + vstd::bytes::spec_u64_to_le_bytes(self.chunks)
    }

    pub(super) fn encode(&self) -> (bytes: Vec<u8>)
        ensures bytes@ == self.wire(),
    {
        let mut bytes = Vec::with_capacity(LENGTH);
        bytes.extend_from_slice(TAG);
        bytes.extend_from_slice(&little_endian_u32(self.minimum));
        bytes.extend_from_slice(&little_endian_u32(self.average));
        bytes.extend_from_slice(&little_endian_u32(self.maximum));
        bytes.extend_from_slice(&little_endian(self.seed));
        bytes.extend_from_slice(&little_endian(self.logical));
        bytes.extend_from_slice(&little_endian(self.chunks));
        bytes
    }
}

fn fixed<const N: usize>(bytes: &[u8], at: usize) -> (out: [u8; N])
    requires at + N <= bytes.len(),
    ensures out@ == bytes@.subrange(at as int, at + N),
{
    let mut word = [0; N];
    word.copy_from_slice(&bytes[at..at.saturating_add(N)]);
    word
}

pub(super) fn decode(bytes: &[u8]) -> (out: Option<Header>)
    ensures out.is_some() == (bytes.len() == LENGTH && bytes@.take(4) == TAG@),
        out matches Some(h) ==> h.wire() == bytes@ &&
            h.logical == vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(24,32)) &&
            h.chunks == vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(32,40)),
{
    if bytes.len() != LENGTH { return None; }
    if &bytes[..4] != TAG { return None; }
    assert(bytes@.take(4) =~= TAG@);
    let header = Header {
        minimum: read_u32(fixed(bytes, 4)),
        average: read_u32(fixed(bytes, 8)),
        maximum: read_u32(fixed(bytes, 12)),
        seed: u64::from_le_bytes(fixed(bytes, 16)),
        logical: u64::from_le_bytes(fixed(bytes, 24)),
        chunks: u64::from_le_bytes(fixed(bytes, 32)),
    };
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    }
    assert(header.wire() =~= bytes@);
    Some(header)
}

pub(super) const CONTENT: &[u8; 7] = b"content";

pub(super) open spec fn file_record(record: ObjectRecord, version: ObjectFormatVersion) -> bool {
    let r = record.contents();
    r.0 == ObjectKind::File && r.1 == version.number() && r.4 == 0 && r.5 == ObjectClass::Metadata
}

pub(crate) enum Error<E> { Invalid(&'static str), Profile(E) }

pub(super) fn parse<P,E,F>(record: &ObjectRecord, version: ObjectFormatVersion, profile: F)
    -> (out: Result<(P,u64,u64,Option<ObjectId>), Error<E>>)
    where F: FnOnce(u32,u32,u32,u64) -> Result<P,E>,
    requires forall|a:u32,b:u32,c:u32,d:u64| #[trigger] profile.requires((a,b,c,d)),
    ensures out matches Ok((p,length,count,root)) ==> {
        let r = record.contents();
        &&& file_record(*record,version)
        &&& exists|h:Header| #[trigger] h.wire() == r.2 && h.logical == length && h.chunks == count
            && profile.ensures((h.minimum,h.average,h.maximum,h.seed),Ok(p))
            && (length > 0 ==> (count == 1) == (length <= h.maximum))
        &&& if length == 0 { count == 0 && root.is_none() && r.3.len() == 0 }
            else { count > 0 && r.3.len() == 1 && (root matches Some(id)
                && r.3[0].fields() == (CONTENT@,id,super::ReferenceKind::Owns)) }
    },
{
    if !matches!(record.kind(),ObjectKind::File) || record.format_version().get() != version.get()
        || !matches!(record.class(),ObjectClass::Metadata) || record.logical_bytes() != 0 {
        return Err(Error::Invalid("invalid file object type or accounting"));
    }
    let Some(h) = decode(record.canonical_bytes()) else {
        return Err(Error::Invalid("unsupported file chunking profile"));
    };
    let p = match profile(h.minimum,h.average,h.maximum,h.seed) {
        Ok(p) => p,
        Err(e) => return Err(Error::Profile(e)),
    };
    if h.logical != 0 && (h.chunks == 1) != (h.logical <= u64::from(h.maximum)) {
        return Err(Error::Invalid("file chunk count violates the whole-object threshold"));
    }
    let refs = record.references();
    if h.logical == 0 {
        if h.chunks != 0 || !refs.is_empty() {
            return Err(Error::Invalid("empty file has chunks or content"));
        }
        return Ok((p,0,0,None));
    }
    if h.chunks == 0 { return Err(Error::Invalid("non-empty file has no chunks")); }
    let invalid_edge = Error::Invalid("invalid file content reference");
    let [edge] = refs else { return Err(invalid_edge); };
    if edge.label_bytes() != CONTENT { return Err(invalid_edge); }
    assert(edge.fields().0 =~= CONTENT@);
    let id = edge.owning_target().ok_or(invalid_edge)?;
    Ok((p,h.logical,h.chunks,Some(id)))
}

pub(crate) enum LengthError<L,E> { Load(L), Decode(Error<E>), Mismatch }

/// Check the declared catalog charge against the immutable file selected by the leaf.
pub(crate) fn check_length<P,L,E,F,R>(file: ObjectId, declared: u64, version: ObjectFormatVersion,
    load: R, profile: F) -> (out: Result<(),LengthError<L,E>>)
    where R: FnOnce(ObjectId) -> Result<ObjectRecord,L>, F: FnOnce(u32,u32,u32,u64) -> Result<P,E>,
    requires load.requires((file,)),
        forall|a:u32,b:u32,c:u32,d:u64| #[trigger] profile.requires((a,b,c,d)),
    ensures out.is_ok() ==> exists|r:ObjectRecord,h:Header,p:P|
        #[trigger] load.ensures((file,),Ok(r)) && file_record(r,version)
        && #[trigger] h.wire() == r.contents().2 && h.logical == declared
        && #[trigger] profile.ensures((h.minimum,h.average,h.maximum,h.seed),Ok(p)),
        out matches Err(LengthError::Load(e)) ==> load.ensures((file,),Err(e)),
        out matches Err(LengthError::Mismatch) ==> exists|r:ObjectRecord,h:Header|
            #[trigger] load.ensures((file,),Ok(r)) && #[trigger] h.wire() == r.contents().2 && h.logical != declared,
{
    let record = match load(file) { Ok(r) => r, Err(e) => return Err(LengthError::Load(e)) };
    let decoded = match parse(&record, version, profile) {
        Ok(d) => d,
        Err(e) => return Err(LengthError::Decode(e)),
    };
    if decoded.1 != declared {
        proof {
            let h = choose|h:Header| #[trigger] h.wire() == record.contents().2 &&
                h.logical == decoded.1 && h.chunks == decoded.2 &&
                profile.ensures((h.minimum,h.average,h.maximum,h.seed),Ok(decoded.0)) &&
                (decoded.1 > 0 ==> (decoded.2 == 1) == (decoded.1 <= h.maximum));
            assert(h.logical != declared);
        }
        return Err(LengthError::Mismatch);
    }
    Ok(())
}
}
