//! Type, tag and payload admission for a physical KV projection record.
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceLabel, checkpoint_totals::NodeTotals, delta_chain::Head, delta_recovery as delta,
};
use crate::storage_fields::fixed;
use crate::storage_words::little_endian;
use vstd::prelude::*;

verus! {
pub(super) const ROOT_LABEL:&[u8;4]=b"root";

pub(super) const CHECKPOINT:u8 = 0;
pub(super) const DELTA:u8 = 1;

pub(super) open spec fn checkpoint_bytes(t:NodeTotals) -> Seq<u8> {
    seq![CHECKPOINT] + vstd::bytes::spec_u64_to_le_bytes(t.entries) + vstd::bytes::spec_u64_to_le_bytes(t.quota_bytes)
}

pub(super) fn checkpoint(version:ObjectFormatVersion,label:&[u8],tree:Option<ObjectId>,totals:NodeTotals) -> (r:ObjectRecord)
    ensures ({
        let f = r.contents();
        &&& f.0 is NamespaceMap && f.1 == version.number() && f.5 is Metadata
        &&& f.2 == checkpoint_bytes(totals) && f.4 == totals.logical_bytes
        &&& match tree {
            None => f.3.len() == 0,
            Some(id) => f.3.len() == 1 && f.3[0].fields() == (label@,id,super::ReferenceKind::Owns),
        }
    }),
{
    let mut bytes = Vec::with_capacity(17);
    bytes.push(CHECKPOINT);
    bytes.extend_from_slice(&little_endian(totals.entries));
    bytes.extend_from_slice(&little_endian(totals.quota_bytes));
    assert(bytes@ =~= checkpoint_bytes(totals));
    let mut refs = Vec::new();
    if let Some(id) = tree {
        let mut name = Vec::with_capacity(label.len());
        name.extend_from_slice(label);
        refs.push(ObjectReference::owns(ReferenceLabel::new(name),id));
    }
    ObjectRecord::from_fields(ObjectKind::NamespaceMap,version,bytes,refs,totals.logical_bytes,ObjectClass::Metadata)
        .expect("a checkpoint has at most one owning reference")
}

pub(super) enum Error<E> { Type,Truncated,Tag,Trailing,Root,Delta(delta::Error<E>) }

pub(super) open spec fn base_tree(refs:Seq<ObjectReference>,label:Seq<u8>,tree:Option<ObjectId>) -> bool {
    match tree {None => refs.len() == 0,Some(id) => refs.len() == 1 && refs[0].fields() == (label,id,super::ReferenceKind::Owns)}
}

pub(super) open spec fn valid<E,F:Fn(&[u8])->Option<E>>(record:&ObjectRecord,version:ObjectFormatVersion,
    label:&[u8],check:F,out:Result<Head,Error<E>>) -> bool {
    let f = record.contents();
    let bytes = f.2;
    if !(f.0 is NamespaceMap) || f.1 != version.number() || !(f.5 is Metadata) {out == Err(Error::Type)}
    else if bytes.len() == 0 {out == Err(Error::Truncated)}
    else if bytes[0] == CHECKPOINT {
        if bytes.len() < 17 {out == Err(Error::Truncated)}
        else if bytes.len() > 17 {out == Err(Error::Trailing)}
        else {match out {
            Ok(Head::Checkpoint {tree,totals}) => base_tree(f.3,label@,tree) && totals.logical_bytes == f.4 && checkpoint_bytes(totals) == bytes,
            Err(Error::Root) => forall|tree:Option<ObjectId>| !#[trigger] base_tree(f.3,label@,tree),
            _ => false,
        }}
    } else if bytes[0] == DELTA {match out {
        Ok(Head::Delta {previous,depth,delta_bytes,mutations,totals}) => {
            let r = delta::Recovered {previous,depth,delta_bytes,rows:mutations,totals};
            exists|b:&[u8],refs:&[ObjectReference],p:Seq<usize>| #[trigger] delta::admitted(record,check,r,b,refs,p)
        },
        Err(Error::Delta(e)) => match e {delta::Error::Truncated=>bytes.len() < 37,_=>
            exists|h:super::delta_header::Header,b:&[u8],refs:&[ObjectReference]| b@ == bytes && refs@ == f.3 && #[trigger] delta::refused(b,refs,check,h,e)},
        _ => false,
    }} else {out == Err(Error::Tag)}
}

pub(super) fn decode<E,F:Fn(&[u8])->Option<E>+Copy>(record:&ObjectRecord,version:ObjectFormatVersion,label:&[u8],check:F)
    -> (out:Result<Head,Error<E>>)
    requires forall|key:&[u8]| #[trigger] check.requires((key,)),
    ensures valid(record,version,label,check,out),
{
    if !matches!(record.kind(),ObjectKind::NamespaceMap) || record.format_version().get() != version.get() ||
        !matches!(record.class(),ObjectClass::Metadata) {return Err(Error::Type);}
    let bytes = record.canonical_bytes();
    let Some(tag) = bytes.first() else {return Err(Error::Truncated);};
    match *tag {
        CHECKPOINT => {
            let mut cursor = 1usize;
            let Ok(entries) = fixed::<8>(bytes,&mut cursor) else {return Err(Error::Truncated);};
            let Ok(quota) = fixed::<8>(bytes,&mut cursor) else {return Err(Error::Truncated);};
            if cursor != bytes.len() {return Err(Error::Trailing);}
            let totals = NodeTotals {entries:u64::from_le_bytes(entries),logical_bytes:record.logical_bytes(),quota_bytes:u64::from_le_bytes(quota)};
            proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();assert(bytes@ =~= checkpoint_bytes(totals));}
            let refs = record.references();
            let tree = match refs.len() {
                0 => None,
                1 => {
                    let name = refs[0].label_bytes();
                    if name != label {return Err(Error::Root);}
                    assert(name@ =~= label@);
                    let Some(id) = refs[0].owning_target() else {return Err(Error::Root);};
                    Some(id)
                },
                _ => return Err(Error::Root),
            };
            Ok(Head::Checkpoint {tree,totals})
        },
        DELTA => match delta::decode(record,check) {
            Ok(r)=>Ok(Head::Delta {previous:r.previous,depth:r.depth,delta_bytes:r.delta_bytes,mutations:r.rows,totals:r.totals}),
            Err(e)=>Err(Error::Delta(e)),
        },
        _ => Err(Error::Tag),
    }
}

pub(super) enum LoadError<E,K> { Source(E), Record(ObjectId,Error<K>) }

/// Decode exactly the record obtained from the owner and object requested by the walk.
pub(super) fn read_at<P,E,K,L:FnOnce(&P,ObjectId)->Result<std::sync::Arc<ObjectRecord>,E>,F:Fn(&[u8])->Option<K>+Copy>(
    owner:&P,id:ObjectId,version:ObjectFormatVersion,label:&[u8],load:L,check:F,
) -> (out:Result<Head,LoadError<E,K>>)
    requires load.requires((owner,id)),forall|k:&[u8]| #[trigger] check.requires((k,)),
    ensures match out {
        Err(LoadError::Source(e)) => load.ensures((owner,id),Err(e)),
        Err(LoadError::Record(bad,e)) => bad == id && exists|r:std::sync::Arc<ObjectRecord>|
            #[trigger] load.ensures((owner,id),Ok(r)) && valid(&*r,version,label,check,Err(e)),
        Ok(h) => exists|r:std::sync::Arc<ObjectRecord>| #[trigger] load.ensures((owner,id),Ok(r)) &&
            valid(&*r,version,label,check,Ok(h)),
    },
{
    let record = match load(owner,id) {Ok(r)=>r,Err(e)=>return Err(LoadError::Source(e))};
    match decode(&record,version,label,check) {
        Ok(h) => Ok(h),Err(e) => Err(LoadError::Record(id,e)),
    }
}
}
