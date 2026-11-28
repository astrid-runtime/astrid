//! Bind a content commit's lineage and state references to the root used for CAS.
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel, RootState, transaction_records,
};
use std::collections::BTreeMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::{
    laws_cmp::{obeys_cmp, obeys_cmp_concrete_eq},
    laws_eq::obeys_concrete_eq,
    std_specs::btree::btree_map_inv,
};

verus! {

pub(super) const PARENT: &[u8;6] = b"parent";
pub(super) const STATE: &[u8;5] = super::header_graph::STATE;

pub(super) open spec fn references(before:Seq<ObjectReference>, after:Seq<ObjectReference>,
    expected:Option<RootState>, state:ObjectId) -> bool {
    &&& after.len() == before.len() + (if expected.is_some() { 2int } else { 1int })
    &&& after.take(before.len() as int) == before
    &&& after.last().fields() == (STATE@,state,ReferenceKind::Owns)
    &&& expected matches Some(root) ==> after[before.len() as int].fields() == (PARENT@,root.commit,ReferenceKind::Lineage)
}

pub(super) enum MetadataError {
    NonCanonicalReferences,
    Collision(ObjectId),
}

pub(super) open spec fn metadata(record:ObjectRecord, kind:ObjectKind, version:ObjectFormatVersion,
    refs:Seq<ObjectReference>) -> bool {
    record.contents() == (kind,version.number(),Seq::empty(),refs,0,ObjectClass::Metadata)
}

/// Validate the sorted references and stage exactly the record used to derive its identity.
pub(super) fn stage_metadata<F:FnOnce(&ObjectRecord)->ObjectId>(
    records:&mut BTreeMap<ObjectId,ObjectRecord>, kind:ObjectKind, version:ObjectFormatVersion,
    refs:Vec<ObjectReference>, identify:F) -> (out:Result<ObjectId,MetadataError>)
    requires btree_map_inv(old(records)), obeys_cmp::<ObjectId>(), obeys_cmp_concrete_eq::<ObjectId>(),
        obeys_concrete_eq::<ObjectRecord>(), forall|r:&ObjectRecord| #[trigger] identify.requires((r,)),
    ensures btree_map_inv(final(records)),
        match out {
            Err(MetadataError::NonCanonicalReferences) => !ObjectRecord::labels_ordered(refs@) && final(records)@ == old(records)@,
            Err(MetadataError::Collision(id)) => ObjectRecord::labels_ordered(refs@) && final(records)@ == old(records)@ &&
                old(records)@.contains_key(id) && exists|r:ObjectRecord| metadata(r,kind,version,refs@) &&
                    old(records)@[id] != r && #[trigger] identify.ensures((&r,),id),
            Ok(id) => ObjectRecord::labels_ordered(refs@) && final(records)@.contains_key(id) && ({
                let r = final(records)@[id];
                &&& metadata(r,kind,version,refs@)
                &&& identify.ensures((&r,),id)
                &&& final(records)@ == old(records)@.insert(id,r)
                &&& !old(records)@.contains_key(id) || old(records)@[id] == r
            }),
        },
{
    let record = ObjectRecord::from_fields(kind,version,Vec::new(),refs,0,ObjectClass::Metadata)
        .ok_or(MetadataError::NonCanonicalReferences)?;
    assert(metadata(record,kind,version,refs@));
    match transaction_records::stage(records,record,identify) {
        Ok(id) => {
            assert(records@[id] == record);
            Ok(id)
        },
        Err(id) => {
            assert(exists|r:ObjectRecord| metadata(r,kind,version,refs@) &&
                old(records)@[id] != r && #[trigger] identify.ensures((&r,),id)) by {
                assert(identify.ensures((&record,),id));
            }
            Err(MetadataError::Collision(id))
        },
    }
}

pub(super) struct Candidate<P> {
    owner: P,
    expected: Option<RootState>,
    refs: Vec<ObjectReference>,
}

fn label(bytes:&[u8]) -> (out:ReferenceLabel)
    ensures out.value()@ == bytes@,
{
    let mut owned = Vec::with_capacity(bytes.len());
    owned.extend_from_slice(bytes);
    ReferenceLabel::new(owned)
}

impl<P> Candidate<P> {
    pub(super) closed spec fn parts(&self) -> (P,Option<RootState>,Vec<ObjectReference>) {
        (self.owner,self.expected,self.refs)
    }

    pub(super) fn new(owner:P, expected:Option<RootState>, prior:Vec<ObjectReference>, state:ObjectId)
        -> (out:Self)
        ensures out.parts().0 == owner, out.parts().1 == expected,
            references(prior@,out.parts().2@,expected,state),
    {
        let mut refs = prior;
        if let Some(previous) = expected {
            refs.push(ObjectReference::new(label(PARENT),previous.commit,ReferenceKind::Lineage));
        }
        refs.push(ObjectReference::owns(label(STATE),state));
        assert(refs@.take(prior@.len() as int) =~= prior@);
        Self {owner,expected,refs}
    }

    pub(super) fn seal<B,E,S>(self,seal:S) -> (out:Result<(P,Option<RootState>,ObjectId,B),E>)
        where S:FnOnce(Vec<ObjectReference>) -> Result<(ObjectId,B),E>,
        requires seal.requires((self.parts().2,)),
        ensures out matches Err(e) ==> seal.ensures((self.parts().2,),Err(e)),
            out matches Ok((p,r,id,b)) ==> p == self.parts().0 && r == self.parts().1
                && seal.ensures((self.parts().2,),Ok((id,b))),
    {
        let (commit,records) = seal(self.refs)?;
        Ok((self.owner,self.expected,commit,records))
    }
}
}
