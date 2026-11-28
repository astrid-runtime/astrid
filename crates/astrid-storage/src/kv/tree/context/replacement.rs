//! Bind each point-write result to the key and bytes observed for this attempt.
use vstd::prelude::*;

verus! {
pub(crate) struct Replacement {
    pub(super) key: Vec<u8>,
    pub(super) previous: PreviousValue,
    pub(super) value: Option<Vec<u8>>,
}

pub(super) enum PreviousValue {
    Unread,
    Loaded { previous_len: Option<usize>, unchanged: bool },
}

pub(crate) open spec fn bytes(value:Option<Vec<u8>>) -> Option<Seq<u8>> {
    match value {Some(v) => Some(v@),None => None}
}

fn same(previous:Option<&Vec<u8>>,expected:Option<&[u8]>) -> (equal:bool)
    ensures equal == ((match previous {Some(v) => Some(v@),None => None}) == match expected {Some(v) => Some(v@),None => None}),
{
    match (previous,expected) {
        (Some(a),Some(b)) => {
            let same = a.as_slice() == b;
            assert(same == (a@ =~= b@));
            same
        },
        (None,None) => true,
        _ => false,
    }
}

impl Replacement {
    pub(crate) closed spec fn fields(&self) -> (Seq<u8>,Option<Seq<u8>>,Option<(Option<usize>,bool)>) {
        (self.key@,bytes(self.value),match self.previous {
            PreviousValue::Unread => None,
            PreviousValue::Loaded {previous_len,unchanged} => Some((previous_len,unchanged)),
        })
    }

    pub(super) fn into_parts(self) -> (out:(Vec<u8>,PreviousValue,Option<Vec<u8>>))
        ensures out.0@ == self.fields().0, bytes(out.2) == self.fields().1,
            self.fields().2 == match out.1 {
                PreviousValue::Unread => None,
                PreviousValue::Loaded {previous_len,unchanged} => Some((previous_len,unchanged)),
            },
    {
        (self.key,self.previous,self.value)
    }

    #[cfg(any(test, all(feature = "legacy-surrealkv", not(target_family = "wasm"))))]
    pub(crate) fn new(key:Vec<u8>,value:Option<Vec<u8>>) -> Self {
        Self {key,previous:PreviousValue::Unread,value}
    }

    pub(crate) fn observed(key:Vec<u8>,previous:Option<Vec<u8>>,value:Option<Vec<u8>>) -> (out:Self)
        ensures out.fields() == (key@,bytes(value),Some((match previous {Some(v) => Some(v.len()),None => None},
            bytes(previous) == bytes(value)))),
    {
        let unchanged = same(previous.as_ref(),match &value {Some(v) => Some(v.as_slice()),None => None});
        let previous_len = previous.map(|v:Vec<u8>| -> (n:usize) ensures n == v.len(), {v.len()});
        Self {key,previous:PreviousValue::Loaded {previous_len,unchanged},value}
    }

    pub(crate) open spec fn decision(out:(bool,Vec<Self>,bool),key:Seq<u8>,prior:Option<Seq<u8>>,
        expected:Option<Seq<u8>>,new:Seq<u8>) -> bool {
        &&& out.0 == (prior == expected)
        &&& out.2 == (prior == expected && prior != Some(new))
        &&& out.1.len() == if out.2 {1int} else {0int}
        &&& out.2 ==> out.1@[0].fields() == (key,Some(new),Some((match prior {Some(v) => Some(v.len() as usize),None => None},false)))
    }

    pub(crate) fn compare_at<H,E,F:FnOnce(&H,&[u8])->Result<Option<Vec<u8>>,E>>(
        header:&H,key:&[u8],expected:Option<&[u8]>,new:&[u8],read:F)
        -> (out:Result<(bool,Vec<Self>,bool),E>)
        requires read.requires((header,key)),
        ensures match out {
            Err(e) => read.ensures((header,key),Err(e)),
            Ok(r) => exists|old:Option<Vec<u8>>| #[trigger] read.ensures((header,key),Ok(old)) &&
                Self::decision(r,key@,bytes(old),match expected {Some(v) => Some(v@),None => None},new@),
        },
    {
        let previous = read(header,key)?;
        Ok(Self::compare_exchange(key,previous,expected,new))
    }

    /// Read the addressed value at this attempt's header before choosing a replacement.
    pub(crate) fn set_at<H,E,F:FnOnce(&H,&[u8])->Result<Option<Vec<u8>>,E>>(
        header:&H,key:&[u8],new:&[u8],read:F,
    ) -> (out:Result<((),Vec<Self>,bool),E>)
        requires read.requires((header,key)),
        ensures match out {
            Err(e)=>read.ensures((header,key),Err(e)),
            Ok((_,rows,changed))=>exists|observed:Option<Vec<u8>>| #[trigger] read.ensures((header,key),Ok(observed)) &&
                Self::assignment(rows@,changed,key@,bytes(observed),new@),
        },
    {
        let previous=read(header,key)?;
        let (rows,changed)=Self::assign(key,previous,new);
        Ok(((),rows,changed))
    }

    pub(crate) open spec fn assignment(rows:Seq<Self>,changed:bool,key:Seq<u8>,prior:Option<Seq<u8>>,new:Seq<u8>) -> bool {
        &&& changed==(prior!=Some(new))
        &&& rows.len()==if changed {1int} else {0int}
        &&& changed ==> rows[0].fields()==(key,Some(new),Some((match prior {Some(v)=>Some(v.len() as usize),None=>None},false)))
    }

    /// The enclosing writer retries on a root conflict. This decision uses only
    /// the value read at the current attempt's immutable header.
    fn compare_exchange(key:&[u8],previous:Option<Vec<u8>>,expected:Option<&[u8]>,new:&[u8])
        -> (out:(bool,Vec<Self>,bool))
        ensures Self::decision(out,key@,bytes(previous),match expected {Some(v) => Some(v@),None => None},new@),
    {
        if !same(previous.as_ref(),expected) {return (false,Vec::new(),false);}
        let (rows,changed)=Self::assign(key,previous,new);
        (true,rows,changed)
    }

    fn assign(key:&[u8],previous:Option<Vec<u8>>,new:&[u8]) -> (out:(Vec<Self>,bool))
        ensures Self::assignment(out.0@,out.1,key@,bytes(previous),new@),
    {
        if same(previous.as_ref(),Some(new)) {return (Vec::new(),false);}
        let previous_len = previous.map(|v:Vec<u8>| -> (n:usize) ensures n == v.len(), {v.len()});
        let mut address = Vec::with_capacity(key.len());
        address.extend_from_slice(key);
        let mut value = Vec::with_capacity(new.len());
        value.extend_from_slice(new);
        assert(address@ =~= key@);
        assert(value@ =~= new@);
        assert(previous_len == match bytes(previous) {Some(v) => Some(v.len() as usize),None => None});
        let row = Self {key:address,previous:PreviousValue::Loaded {previous_len,unchanged:false},
            value:Some(value)};
        (vec![row],true)
    }
}
}
