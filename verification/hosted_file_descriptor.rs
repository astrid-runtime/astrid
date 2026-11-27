//! A persisted file descriptor retains the charge and chunk count at distinct offsets.
use crate::file_wire::{Header, decode};
use vstd::prelude::*;

verus! {
fn persisted_header(h: Header) -> (read: Option<Header>)
    ensures read matches Some(r) && r.logical == h.logical && r.chunks == h.chunks
        && r.minimum == h.minimum && r.average == h.average && r.maximum == h.maximum && r.seed == h.seed,
{
    let bytes = h.encode();
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(bytes@.take(4) =~= seq![1u8,1u8,0u8,1u8]);
    }
    let r = decode(&bytes);
    proof {
        if let Some(got) = &r {
            assert(got.wire().subrange(4,8) =~= crate::storage_words::word32(got.minimum));
            assert(got.wire().subrange(8,12) =~= crate::storage_words::word32(got.average));
            assert(got.wire().subrange(12,16) =~= crate::storage_words::word32(got.maximum));
            assert(got.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(got.seed));
            assert(h.wire().subrange(4,8) =~= crate::storage_words::word32(h.minimum));
            assert(h.wire().subrange(8,12) =~= crate::storage_words::word32(h.average));
            assert(h.wire().subrange(12,16) =~= crate::storage_words::word32(h.maximum));
            assert(h.wire().subrange(16,24) =~= vstd::bytes::spec_u64_to_le_bytes(h.seed));
            assert(h.wire().subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(h.logical));
            crate::storage_words::unique_word32(h.minimum, got.minimum);
            crate::storage_words::unique_word32(h.average, got.average);
            crate::storage_words::unique_word32(h.maximum, got.maximum);
            assert(h.wire().subrange(32,40) =~= vstd::bytes::spec_u64_to_le_bytes(h.chunks));
        }
    }
    r
}

/// The catalog's logical charge must match the encoded length of the named file.
fn checked_catalog_file<P,L,E,F,R>(file: crate::ObjectId, declared: u64,
    version: crate::ObjectFormatVersion, load: R, profile: F,
    table: Ghost<spec_fn(crate::ObjectId) -> Result<crate::ObjectRecord,L>>)
    -> (out: Result<(),crate::file_wire::LengthError<L,E>>)
    where R: FnOnce(crate::ObjectId) -> Result<crate::ObjectRecord,L>,
        F: FnOnce(u32,u32,u32,u64) -> Result<P,E>,
    requires load.requires((file,)),
        forall|id:crate::ObjectId,x:Result<crate::ObjectRecord,L>| #[trigger] load.ensures((id,),x) ==> x == (table@)(id),
        forall|a:u32,b:u32,c:u32,d:u64| #[trigger] profile.requires((a,b,c,d)),
    ensures out.is_ok() ==> ((table@)(file) matches Ok(r) &&
        r.contents().0 == crate::ObjectKind::File && r.contents().1 == version.number()
        && r.contents().4 == 0 && r.contents().5 == crate::ObjectClass::Metadata
        && r.contents().2.len() == 40
        && r.contents().2.subrange(24,32) == vstd::bytes::spec_u64_to_le_bytes(declared)),
        out matches Err(crate::file_wire::LengthError::Load(e)) ==> (table@)(file) == Err(e),
        out matches Err(crate::file_wire::LengthError::Mismatch) ==> ((table@)(file) matches Ok(r)
            && vstd::bytes::spec_u64_from_le_bytes(r.contents().2.subrange(24,32)) != declared),
{
    let out = crate::file_wire::check_length(file,declared,version,load,profile);
    proof {
        if out.is_ok() {
            let (r,h,p) = choose|r:crate::ObjectRecord,h:Header,p:P|
                #[trigger] load.ensures((file,),Ok(r)) && crate::file_wire::file_record(r,version)
                && #[trigger] h.wire() == r.contents().2 && h.logical == declared
                && #[trigger] profile.ensures((h.minimum,h.average,h.maximum,h.seed),Ok(p));
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(h.wire().subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(h.logical));
        }
        if out matches Err(crate::file_wire::LengthError::Mismatch) {
            let (r,h) = choose|r:crate::ObjectRecord,h:Header|
                #[trigger] load.ensures((file,),Ok(r)) && #[trigger] h.wire() == r.contents().2 && h.logical != declared;
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(r.contents().2.subrange(24,32) =~= vstd::bytes::spec_u64_to_le_bytes(h.logical));
        }
    }
    out
}

/// A nonempty file can expose only the target of its single owning content edge.
fn content_edge<P,E,F>(record: &crate::ObjectRecord, version: crate::ObjectFormatVersion, profile: F)
    -> (out: Result<(P,u64,u64,Option<crate::ObjectId>),crate::file_wire::Error<E>>)
    where F: FnOnce(u32,u32,u32,u64) -> Result<P,E>,
    requires forall|a:u32,b:u32,c:u32,d:u64| #[trigger] profile.requires((a,b,c,d)),
    ensures out matches Ok((_,n,k,root)) ==> if n == 0 {
        k == 0 && root.is_none() && record.contents().3.len() == 0
    } else {
        k > 0 && record.contents().3.len() == 1 && (root matches Some(id) &&
            record.contents().3[0].fields() == (b"content"@,id,crate::ReferenceKind::Owns))
    },
{
    crate::file_wire::parse(record,version,profile)
}

/// A request contained in one chunk reconstructs the specified record bytes.
/// Both native output modes must retain all previously emitted data.
fn read_chunk(record: &crate::ObjectRecord, version: crate::ObjectFormatVersion,
    base:u64, offset:u64, end:u64, output:&mut crate::chunk_range::RangeOutput)
    -> (out:Result<usize,crate::chunk_range::Error>)
    requires
        crate::chunk_range::valid(*record,version,record.contents().2.len() as u64,1,0),
        base + record.contents().2.len() <= u64::MAX,
        base <= offset <= end <= base + record.contents().2.len(),
    ensures ({
        let data = record.contents().2;
        let selected = data.subrange(offset-base,end-base);
        let prior = old(output).snapshot();
        let after = final(output).snapshot();
        &&& out.is_ok() == match prior {
            crate::chunk_range::Output::Count(k) => k + end-offset <= usize::MAX,
            crate::chunk_range::Output::Bytes(_) => true,
        }
        &&& out matches Ok(n) ==> n == end-offset && match (prior,after) {
            (crate::chunk_range::Output::Bytes(a), crate::chunk_range::Output::Bytes(b)) => b == a+selected,
            (crate::chunk_range::Output::Count(a), crate::chunk_range::Output::Count(b)) => b == a+selected.len(),
            _ => false,
        }
        &&& out.is_err() ==> prior == after
    }),
{
    let length = record.canonical_bytes().len() as u64;
    let chunk = crate::chunk_range::Chunk::from_record(record, version, length, 1, 0).unwrap();
    crate::chunk_range::emit(&chunk,base,offset,end,output)
}
}
