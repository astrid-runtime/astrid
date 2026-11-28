//! Encode a KV delta with canonical mutation bytes and ordered owning references.
#[cfg(verus_keep_ghost)]
use super::ObjectReference;
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    checkpoint_totals::NodeTotals,
    delta_batch, delta_header,
    delta_mutation::{Mutation, WriteError},
    projection_record::DELTA,
};
use vstd::prelude::*;

verus! {
pub(super) enum EncodeError { Keys, Overflow, References, Row(WriteError) }

pub(super) open spec fn body_prefix(rows:Seq<Mutation>,n:nat) -> Seq<u8>
    decreases n,
{
    if n==0 {seq![]} else {body_prefix(rows,(n-1) as nat)+rows[n-1].payload()}
}

pub(super) open spec fn edge_prefix(previous:Option<ObjectId>,rows:Seq<Mutation>,n:nat)
    -> Seq<(Seq<u8>,ObjectId,super::ReferenceKind)> decreases n,
{
    if n==0 {match previous {None=>seq![],Some(id)=>seq![(delta_header::PREVIOUS@,id,super::ReferenceKind::Owns)]}}
    else {
        let prior=edge_prefix(previous,rows,(n-1) as nat);
        match rows[n-1].value {
            Some(super::checkpoint_value::ValueSlot::Spilled{object,..})=>
                prior.push((super::delta_mutation::label_bytes((n-1) as u32),object,super::ReferenceKind::Owns)),
            _=>prior,
        }
    }
}

pub(super) open spec fn invalid_row(row:Mutation,e:WriteError) -> bool {
    match e {
            WriteError::Overflow=>row.key.len()>u32::MAX,
            WriteError::Oversized=>row.value matches Some(super::checkpoint_value::ValueSlot::Inline(data)) && data.len()>super::checkpoint_value::INLINE_VALUE_MAX,
            WriteError::SmallSpill=>row.value matches Some(super::checkpoint_value::ValueSlot::Spilled{length,..}) && length<=super::checkpoint_value::INLINE_VALUE_MAX,
        }
}

pub(super) open spec fn ref_fields() -> spec_fn(ObjectReference)->(Seq<u8>,ObjectId,super::ReferenceKind) {|r:ObjectReference| r.fields()}

proof fn ordinal_before(a:u32,b:u32)
    requires a<b,
    ensures ObjectRecord::label_before(super::delta_mutation::label_bytes(a),super::delta_mutation::label_bytes(b)),
{
    let x=super::delta_mutation::label_bytes(a);
    let y=super::delta_mutation::label_bytes(b);
    assert(a<b ==> ((((a >> 24) & 255) as u8) < (((b >> 24) & 255) as u8) || ((((a >> 24) & 255) as u8) == (((b >> 24) & 255) as u8) &&
        ((((a >> 16) & 255) as u8) < (((b >> 16) & 255) as u8) || ((((a >> 16) & 255) as u8) == (((b >> 16) & 255) as u8) &&
        ((((a >> 8) & 255) as u8) < (((b >> 8) & 255) as u8) || ((((a >> 8) & 255) as u8) == (((b >> 8) & 255) as u8) &&
        (((a & 255) as u8) < ((b & 255) as u8))))))))) by (bit_vector);
    let i=if x[6]!=y[6] {6int} else if x[7]!=y[7] {7int} else if x[8]!=y[8] {8int} else {9int};
    assert(x[i]<y[i]);
    assert(x.take(i) =~= y.take(i));
}

pub(super) fn record(version:ObjectFormatVersion,previous:Option<ObjectId>,depth:u64,bytes:u64,rows:&[Mutation],totals:NodeTotals)
    -> (out:Result<ObjectRecord,EncodeError>)
    ensures out matches Ok(r) ==> {
        let f=r.contents();
        let charge=delta_batch::usage(rows@,rows.len() as nat).0;
        let header=delta_header::Header{depth:(depth+1) as u64,delta_bytes:(bytes+charge) as u64,entries:totals.entries,
            quota_bytes:totals.quota_bytes,count:rows.len() as u32};
        &&& 0<rows.len()<=u32::MAX && delta_batch::ordered(rows@) && depth<u64::MAX && bytes+charge<=u64::MAX
        &&& f.0==ObjectKind::NamespaceMap && f.1==version.number() && f.4==totals.logical_bytes && f.5==ObjectClass::Metadata
        &&& f.2==seq![DELTA]+header.wire()+body_prefix(rows@,rows.len() as nat)
        &&& ObjectRecord::labels_ordered(f.3)
        &&& f.3.map_values(ref_fields())==edge_prefix(previous,rows@,rows.len() as nat)
    },
        !(out matches Err(EncodeError::References)),
        (out matches Err(EncodeError::Keys)) == (rows.len()==0 || !delta_batch::ordered(rows@)),
        out matches Err(EncodeError::Overflow) ==> depth==u64::MAX || bytes+delta_batch::usage(rows@,rows.len() as nat).0>u64::MAX || rows.len()>u32::MAX,
        out matches Err(EncodeError::Row(e)) ==> exists|i:int| 0<=i<rows.len() && #[trigger] invalid_row(rows@[i],e),
{
    if rows.is_empty() || !delta_batch::keys_ordered(rows) {return Err(EncodeError::Keys);}
    let Some(next)=depth.checked_add(1) else {return Err(EncodeError::Overflow);};
    let Some((charge,_))=delta_batch::measure(rows) else {return Err(EncodeError::Overflow);};
    let Some(total)=bytes.checked_add(charge) else {return Err(EncodeError::Overflow);};
    let Ok(count)=u32::try_from(rows.len()) else {return Err(EncodeError::Overflow);};
    let h=delta_header::Header{depth:next,delta_bytes:total,entries:totals.entries,quota_bytes:totals.quota_bytes,count};
    let mut body=vec![DELTA];
    h.append(&mut body);
    let mut refs=delta_header::predecessor_edges(previous);
    assert(refs@.map_values(ref_fields()) =~= edge_prefix(previous,rows@,0));
    let mut i=0usize;
    while i<rows.len()
        invariant 0<rows.len()<=u32::MAX,i<=rows.len(),delta_batch::ordered(rows@),depth<u64::MAX,
            h.depth==depth+1,h.delta_bytes==bytes+delta_batch::usage(rows@,rows.len() as nat).0,
            h.entries==totals.entries,h.quota_bytes==totals.quota_bytes,h.count==rows.len(),
            body@==seq![DELTA]+h.wire()+body_prefix(rows@,i as nat),
            ObjectRecord::labels_ordered(refs@),
            refs.len()==0 || refs@.last().fields().0==delta_header::PREVIOUS@ ||
                exists|j:u32| j<i && #[trigger] super::delta_mutation::label_bytes(j)==refs@.last().fields().0,
            refs@.map_values(ref_fields())==edge_prefix(previous,rows@,i as nat),
        decreases rows.len()-i,
    {
        let ghost before=refs@;
        if let Err(e)=rows[i].append(i,&mut body,&mut refs) {assert(invalid_row(rows@[i as int],e));return Err(EncodeError::Row(e));}
        assert(body@ =~= seq![DELTA]+h.wire()+body_prefix(rows@,i as nat+1));
        assert(refs@.map_values(ref_fields()) =~= edge_prefix(previous,rows@,i as nat+1)) by {
            reveal_with_fuel(edge_prefix,2);
            if let Some(super::checkpoint_value::ValueSlot::Spilled{object,..})=rows@[i as int].value {
                assert(refs@.last().fields()==(super::delta_mutation::label_bytes(i as u32),object,super::ReferenceKind::Owns));
                assert(refs@.map_values(ref_fields()).last()==refs@.last().fields());
                assert(edge_prefix(previous,rows@,i as nat+1)==edge_prefix(previous,rows@,i as nat).push(refs@.last().fields()));
                assert(refs@.drop_last()==before);
                assert(refs@.map_values(ref_fields()).drop_last() =~= before.map_values(ref_fields()));
            } else {assert(refs@==before);}
        }
        proof {
            if refs.len()>before.len() {
                let name=super::delta_mutation::label_bytes(i as u32);
                assert(refs@.last().fields().0==name);
                if before.len()>0 {
                    let prior=before.last().fields().0;
                    if prior==delta_header::PREVIOUS@ {
                        assert(prior.take(0) =~= name.take(0));
                        assert(prior[0]<name[0]);
                    } else {
                        let j=choose|j:u32| j<i && #[trigger] super::delta_mutation::label_bytes(j)==prior;
                        ordinal_before(j,i as u32);
                    }
                    assert(ObjectRecord::label_before(prior,name));
                }
                assert forall|j:int| 0<j<refs.len() implies #[trigger] ObjectRecord::label_before(refs@[j-1].fields().0,refs@[j].fields().0) by {
                    if j<before.len() {assert(refs@[j]==before[j] && refs@[j-1]==before[j-1]);}
                }
            }
        }
        i=i.saturating_add(1);
    }
    match ObjectRecord::from_fields(ObjectKind::NamespaceMap,version,body,refs,totals.logical_bytes,ObjectClass::Metadata) {
        Some(record)=>Ok(record),None=>Err(EncodeError::References),
    }
}

}
