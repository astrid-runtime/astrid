//! Transition payload shared by the root journal and the write-ahead log.
use vstd::prelude::*;

verus! {

#[derive(Clone, Copy)]
pub(super) struct Scheme {
    pub(super) algorithm: [u8; 2],
    pub(super) construction: [u8; 2],
}

#[derive(Clone, Copy)]
pub(super) struct Root {
    pub(super) generation: [u8; 8],
    pub(super) commit: [u8; 32],
}

impl Root {
    pub(super) open spec fn wire(self, scheme: Scheme) -> Seq<u8> {
        self.generation@ + scheme.algorithm@ + scheme.construction@ + seq![32u8,0,0,0] + self.commit@
    }

    pub(super) fn append(self, bytes: &mut Vec<u8>, scheme: Scheme)
        ensures final(bytes)@ == old(bytes)@ + self.wire(scheme),
    {
        bytes.extend_from_slice(&self.generation);
        bytes.extend_from_slice(&scheme.algorithm);
        bytes.extend_from_slice(&scheme.construction);
        bytes.extend_from_slice(&[32u8,0,0,0]);
        bytes.extend_from_slice(&self.commit);
        assert(bytes@ =~= old(bytes)@ + self.wire(scheme));
    }
}

pub(super) open spec fn prior(root: Option<Root>, scheme: Scheme) -> Seq<u8> {
    match root { None => seq![0u8], Some(root) => seq![1u8] + root.wire(scheme) }
}

pub(super) fn encode(owner: &[u8], scheme: Scheme, expected: Option<Root>, replacement: Root)
    -> (result: Option<Vec<u8>>)
    ensures
        result.is_some() == (owner.len() < u64::MAX),
        result matches Some(bytes) ==> bytes@ == vstd::bytes::spec_u64_to_le_bytes(owner.len() as u64)
            + owner@ + prior(expected,scheme) + replacement.wire(scheme),
{
    let Ok(length) = u64::try_from(owner.len()) else { return None; };
    if length == u64::MAX { return None; }
    let mut bytes = vstd::bytes::u64_to_le_bytes(length);
    bytes.extend_from_slice(owner);
    match expected {
        None => bytes.push(0),
        Some(root) => {
            bytes.push(1);
            root.append(&mut bytes, scheme);
        },
    }
    assert(bytes@ =~= vstd::bytes::spec_u64_to_le_bytes(length) + owner@ + prior(expected,scheme));
    replacement.append(&mut bytes, scheme);
    Some(bytes)
}

#[derive(Clone, Copy)]
pub(super) enum ReadError { Overflow(usize), Truncated }

/// Advance the cursor only when the entire requested field was present.
pub(super) fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize)
    -> (read: Result<&'a [u8],ReadError>)
    ensures
        read.is_ok() == (*old(cursor) as int + len <= bytes.len()),
        read matches Ok(field) ==> *final(cursor) as int == *old(cursor) as int + len &&
            field@ == bytes@.subrange(*old(cursor) as int,*final(cursor) as int),
        read.is_err() ==> *final(cursor) == *old(cursor),
        (read matches Err(ReadError::Overflow(_))) == (*old(cursor) as int + len > usize::MAX),
{
    let Some(end) = cursor.checked_add(len) else { return Err(ReadError::Overflow(len)); };
    if end > bytes.len() { return Err(ReadError::Truncated); }
    let field = &bytes[*cursor..end];
    *cursor = end;
    Ok(field)
}

pub(super) open spec fn at(bytes: Seq<u8>, offset: int, field: Seq<u8>) -> bool {
    0 <= offset && offset + field.len() <= bytes.len() &&
        bytes.subrange(offset, offset + field.len()) == field
}

proof fn subfield(bytes: Seq<u8>, start: int, whole: Seq<u8>, pos: int, len: int)
    requires at(bytes,start,whole), 0 <= pos, 0 <= len, pos+len <= whole.len(),
    ensures bytes.subrange(start+pos,start+pos+len) == whole.subrange(pos,pos+len),
{
    assert(bytes.subrange(start+pos,start+pos+len) =~= whole.subrange(pos,pos+len)) by {
        assert forall|i: int| 0 <= i < len implies bytes[start+pos+i] == #[trigger] whole[pos+i] by {
            assert(bytes.subrange(start,start+whole.len())[pos+i] == bytes[start+pos+i]);
        }
    }
}

fn fixed<const N: usize>(bytes: &[u8], cursor: &mut usize) -> (value: Result<[u8;N],ReadError>)
    ensures value.is_ok() == (*old(cursor) as int + N <= bytes.len()),
        value matches Ok(array) ==> *final(cursor) as int == *old(cursor) as int + N
            && at(bytes@,*old(cursor) as int,array@),
        value.is_err() ==> *final(cursor) == *old(cursor),
{
    let field = take(bytes, cursor, N)?;
    let mut array = [0u8;N];
    array.copy_from_slice(field);
    Ok(array)
}

pub(super) enum OwnerError { Read(ReadError), Length(u64) }

pub(super) open spec fn owner_length(bytes: Seq<u8>) -> u64 {
    vstd::bytes::spec_u64_from_le_bytes(bytes.take(8))
}

pub(super) fn read_owner(bytes: &[u8]) -> (result: Result<(&[u8],usize),OwnerError>)
    ensures
        result.is_ok() == (bytes.len() >= 8 && 8 + owner_length(bytes@) as int <= bytes.len()),
        result matches Ok((owner,end)) ==> {
            &&& end as int == 8 + owner_length(bytes@) as int
            &&& owner@ == bytes@.subrange(8,end as int)
        },
{
    let mut cursor = 0;
    let field = match fixed::<8>(bytes,&mut cursor) {
        Ok(field) => field,
        Err(e) => return Err(OwnerError::Read(e)),
    };
    assert(field@ =~= bytes@.take(8));
    let length = u64::from_le_bytes(field);
    let Ok(len) = usize::try_from(length) else { return Err(OwnerError::Length(length)); };
    match take(bytes,&mut cursor,len) {
        Ok(owner) => Ok((owner,cursor)),
        Err(e) => Err(OwnerError::Read(e)),
    }
}

#[derive(Clone, Copy)]
pub(super) enum RootError {
    Read(ReadError),
    Scheme { algorithm: [u8;2], construction: [u8;2], size: [u8;4] },
}

/// Decode the fixed root fields used by write-ahead log transitions.
pub(super) fn read_root(bytes: &[u8], cursor: &mut usize, scheme: Scheme)
    -> (result: Result<Root, RootError>)
    ensures
        result matches Ok(r) ==> at(bytes@,*old(cursor) as int,r.wire(scheme))
            && *final(cursor) as int == *old(cursor) as int + 48,
        forall|r: Root| #[trigger] at(bytes@,*old(cursor) as int,r.wire(scheme)) ==> result.is_ok(),
{
    let ghost start = *cursor as int;
    let generation = match fixed::<8>(bytes,cursor) { Ok(v) => v, Err(e) => return Err(RootError::Read(e)) };
    let algorithm = match fixed::<2>(bytes,cursor) { Ok(v) => v, Err(e) => return Err(RootError::Read(e)) };
    let construction = match fixed::<2>(bytes,cursor) { Ok(v) => v, Err(e) => return Err(RootError::Read(e)) };
    let size = match fixed::<4>(bytes,cursor) { Ok(v) => v, Err(e) => return Err(RootError::Read(e)) };
    if algorithm.as_slice() != scheme.algorithm.as_slice()
        || construction.as_slice() != scheme.construction.as_slice() || size.as_slice() != [32u8,0,0,0].as_slice() {
        assert forall|r: Root| !#[trigger] at(bytes@, start, r.wire(scheme)) by {
            if at(bytes@,start,r.wire(scheme)) {
                subfield(bytes@,start,r.wire(scheme),8,2);
                subfield(bytes@,start,r.wire(scheme),10,2);
                subfield(bytes@,start,r.wire(scheme),12,4);
                assert(r.wire(scheme).subrange(8,10) =~= scheme.algorithm@);
                assert(r.wire(scheme).subrange(10,12) =~= scheme.construction@);
                assert(r.wire(scheme).subrange(12,16) =~= seq![32u8,0,0,0]);
                assert(algorithm@ =~= scheme.algorithm@);
                assert(construction@ =~= scheme.construction@);
                assert(size@ =~= seq![32u8,0,0,0]);
            }
        }
        return Err(RootError::Scheme { algorithm, construction, size });
    }
    assert(algorithm@ =~= scheme.algorithm@);
    assert(construction@ =~= scheme.construction@);
    assert(size@ =~= seq![32u8,0,0,0]);
    let commit = match fixed::<32>(bytes,cursor) { Ok(v) => v, Err(e) => return Err(RootError::Read(e)) };
    let root = Root { generation, commit };
    assert(bytes@.subrange(start, start+48) =~= root.wire(scheme));
    Ok(root)
}

pub(super) open spec fn tail(bytes: Seq<u8>, start: int, scheme: Scheme, expected: Option<Root>, replacement: Root) -> bool {
    0 <= start <= bytes.len() && bytes.skip(start) == prior(expected,scheme) + replacement.wire(scheme)
}

proof fn tail_fields(bytes: Seq<u8>, start: int, scheme: Scheme, expected: Option<Root>, replacement: Root)
    requires tail(bytes,start,scheme,expected,replacement),
    ensures start < bytes.len(), bytes[start] == (if expected.is_some() {1u8} else {0u8}),
        expected matches Some(r) ==> at(bytes,start+1,r.wire(scheme)),
        at(bytes,start+prior(expected,scheme).len(),replacement.wire(scheme)),
        start+prior(expected,scheme).len()+48 == bytes.len(),
{
    let whole = prior(expected,scheme) + replacement.wire(scheme);
    assert(bytes.subrange(start,bytes.len() as int) =~= whole);
    assert(at(bytes,start,whole));
    assert(bytes.skip(start)[0] == bytes[start]);
    assert(whole[0] == prior(expected,scheme)[0]);
    if let Some(r) = expected {
        subfield(bytes,start,whole,1,48);
        assert(whole.subrange(1,49) =~= r.wire(scheme));
    }
    let prefix = prior(expected,scheme).len() as int;
    subfield(bytes,start,whole,prefix,48);
    assert(whole.subrange(prefix,prefix+48) =~= replacement.wire(scheme));
}

pub(super) open spec fn same(a: Root,b: Root) -> bool {
    a.generation@ == b.generation@ && a.commit@ == b.commit@
}

pub(super) open spec fn same_expected(a: Option<Root>,b: Option<Root>) -> bool {
    match (a,b) { (None,None) => true, (Some(x),Some(y)) => same(x,y), _ => false }
}

proof fn same_field(bytes: Seq<u8>, start: int, scheme: Scheme, a: Root, b: Root)
    requires at(bytes,start,a.wire(scheme)), at(bytes,start,b.wire(scheme)),
    ensures same(a,b),
{
    assert(a.wire(scheme) == b.wire(scheme));
    assert(a.wire(scheme).take(8) =~= a.generation@);
    assert(b.wire(scheme).take(8) =~= b.generation@);
    assert(a.wire(scheme).skip(16) =~= a.commit@);
    assert(b.wire(scheme).skip(16) =~= b.commit@);
}

pub(super) proof fn unique_tail(bytes: Seq<u8>, start: int, scheme: Scheme, e: Option<Root>, r: Root,
    other_e: Option<Root>, other_r: Root)
    requires tail(bytes,start,scheme,e,r), tail(bytes,start,scheme,other_e,other_r),
    ensures same_expected(e,other_e), same(r,other_r),
{
    tail_fields(bytes,start,scheme,e,r);
    tail_fields(bytes,start,scheme,other_e,other_r);
    if let Some(x) = e {
        same_field(bytes,start+1,scheme,x,other_e.unwrap());
    }
    same_field(bytes,start+prior(e,scheme).len(),scheme,r,other_r);
}

pub(super) enum TailError { Read(ReadError), Root(RootError), ExpectedTag, Trailing }

/// Parse the remainder of one WAL transition after its owner has been validated.
pub(super) fn read_tail(bytes: &[u8], cursor: &mut usize, scheme: Scheme)
    -> (decoded: Result<(Option<Root>,Root),TailError>)
    ensures forall|e: Option<Root>, r: Root| #[trigger] tail(bytes@,*old(cursor) as int,scheme,e,r) ==> decoded.is_ok(),
        decoded matches Ok((expected,replacement)) ==> {
        &&& bytes@.skip(*old(cursor) as int) == prior(expected,scheme) + replacement.wire(scheme)
        &&& *final(cursor) == bytes.len()
    },
{
    let ghost start = *cursor as int;
    assert forall|e: Option<Root>,r: Root| #[trigger] tail(bytes@,start,scheme,e,r) implies {
        &&& start < bytes.len()
        &&& bytes@[start] == (if e.is_some() {1u8} else {0u8})
        &&& (e matches Some(p) ==> at(bytes@,start+1,p.wire(scheme)))
        &&& at(bytes@,start+prior(e,scheme).len(),r.wire(scheme))
        &&& start+prior(e,scheme).len()+48 == bytes.len()
    } by { tail_fields(bytes@,start,scheme,e,r); }
    let tag = match fixed::<1>(bytes,cursor) { Ok(tag) => tag[0], Err(e) => return Err(TailError::Read(e)) };
    let expected = match tag {
        0 => None,
        1 => match read_root(bytes,cursor,scheme) {
            Ok(root) => Some(root),
            Err(e) => return Err(TailError::Root(e)),
        },
        _ => return Err(TailError::ExpectedTag),
    };
    assert(bytes@.subrange(start,*cursor as int) =~= prior(expected,scheme));
    let replacement = match read_root(bytes,cursor,scheme) {
        Ok(root) => root,
        Err(e) => return Err(TailError::Root(e)),
    };
    if *cursor != bytes.len() { return Err(TailError::Trailing); }
    assert(bytes@.skip(start) =~= prior(expected,scheme) + replacement.wire(scheme));
    Ok((expected,replacement))
}

}
