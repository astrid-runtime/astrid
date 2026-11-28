//! Bind a persistent checkpoint to an owner-scoped replay ending at its physical record.
use crate::{ObjectId,ObjectFormatVersion,ObjectRecord,ObjectKind,ObjectClass,checkpoint_totals::NodeTotals,
    projection_record::{self as format,Error,LoadError},delta_chain::{self as chain,Head}};
use std::sync::Arc;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq}};

verus! {
proof fn equal_totals(a:NodeTotals,b:NodeTotals)
    requires format::checkpoint_bytes(a) == format::checkpoint_bytes(b),a.logical_bytes == b.logical_bytes,
    ensures a == b,
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    assert(format::checkpoint_bytes(a).subrange(1,9) =~= vstd::bytes::spec_u64_to_le_bytes(a.entries));
    assert(format::checkpoint_bytes(b).subrange(1,9) =~= vstd::bytes::spec_u64_to_le_bytes(b.entries));
    assert(format::checkpoint_bytes(a).subrange(9,17) =~= vstd::bytes::spec_u64_to_le_bytes(a.quota_bytes));
    assert(format::checkpoint_bytes(b).subrange(9,17) =~= vstd::bytes::spec_u64_to_le_bytes(b.quota_bytes));
}

fn base(owner:u64,id:ObjectId,tree:Option<ObjectId>,totals:NodeTotals,available:bool,observed_root:Option<ObjectId>,measured:NodeTotals)
    requires obeys_cmp::<ObjectId>(),obeys_cmp_concrete_eq::<ObjectId>(),
{
    let version = ObjectFormatVersion::new(4).unwrap();
    let label = [114u8,111,111,116];
    let record = Arc::new(format::checkpoint(version,&label,tree,totals));
    let source = &record;
    let read = |p:&u64,k:ObjectId| -> (out:Result<Head,u8>)
        ensures if *p == owner && k == id && available {out == Ok(Head::Checkpoint {tree,totals})} else {out == Err(3u8)} {
        let ghost f = source.contents();
    let fetch = |p:&u64,k:ObjectId| -> (out:Result<Arc<ObjectRecord>,u8>)
        ensures if *p == owner && k == id && available {out matches Ok(r) && r.contents() == f}
            else {out == Err(3u8)} {
        if *p == owner && k.same(&id) && available {Ok(Arc::clone(source))} else {Err(3u8)}
    };
        let check = |_key:&[u8]| -> (e:Option<u8>) ensures e == None {None};
        let result = format::read_at(p,k,version,&label,fetch,check);
        proof {
            vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
            assert(format::checkpoint_bytes(totals).len() == 17 && f.2[0] == format::CHECKPOINT);
            assert(format::base_tree(f.3,label@,tree));
            if result is Ok {
                let h = result->Ok_0;
                let r = choose|r:Arc<ObjectRecord>| #[trigger] fetch.ensures((p,k),Ok(r)) && format::valid(&*r,version,&label,check,Ok(h));
                assert(h is Checkpoint);
                equal_totals(h->Checkpoint_totals,totals);
                assert(h == Head::Checkpoint {tree,totals});
            } else if result->Err_0 is Record {
                let e = result->Err_0->Record_1;
                let r = choose|r:Arc<ObjectRecord>| #[trigger] fetch.ensures((p,k),Ok(r)) && format::valid(&*r,version,&label,check,Err(e));
                assert(false);
            }
        }
        match result {Ok(h)=>Ok(h),Err(LoadError::Source(e))=>Err(e),Err(LoadError::Record(..))=>Err(4u8)}
    };
    let got = chain::walk(&owner,id,read);
    let ghost verdict = got;
    proof {
        match verdict {
            Ok(c) => {
                let end = choose|end:Option<ObjectId>| #[trigger] chain::complete(&owner,id,c,end,read);
                if c.newest_first.len() > 0 {chain::at(&owner,id,c.newest_first@,end,read,0);}
                assert(available && c.newest_first.len() == 0 && c.tree == tree && c.totals == totals);
            },
            Err(e) => {
                let (s,k) = choose|s:Seq<chain::Step>,k:ObjectId| #[trigger] chain::stopped(&owner,id,s,k,read,e);
                if s.len() > 0 {chain::at(&owner,id,s,Some(k),read,0);}
                assert(chain::ids(s) =~= Seq::<ObjectId>::empty());
                assert(!available && e == chain::Error::Source(3u8));
            },
        }
    }
    if let Ok(c) = got {
        use crate::{checkpoint_replay as checkpoint,delta_replay as replay,delta_mutation::Mutation};
        let start = || -> (s:u64) ensures s == owner {owner};
        let apply = |_s:u64,_tree:Option<ObjectId>,_k:ObjectId,_r:&Vec<Mutation>,_totals:NodeTotals|
            -> (out:Result<(u64,NodeTotals),u8>) ensures out == Err(9u8) {Err(9u8)};
        let ghost selected = c;
        let result = checkpoint::recover(c,observed_root,measured,start,apply,Ghost(|_| true));
        let ghost out = result;
        proof {
            assert(selected.newest_first.len() == 0);
            match out {
                Err(checkpoint::Error::Root) => assert(observed_root != tree),
                Err(checkpoint::Error::Totals) => assert(tree == observed_root && measured != totals),
                Err(checkpoint::Error::Replay(e)) => {
                    let s = choose|s:u64| #[trigger] start.ensures((),s) &&
                        replay::failed(s,measured,observed_root,selected.newest_first@,apply,e);
                    assert(false);
                },
                Ok(end) => {
                    let s = choose|s:u64| #[trigger] start.ensures((),s) &&
                        replay::replayed(s,measured,observed_root,selected.newest_first@,0,apply,end);
                    let h = choose|h:Seq<replay::Cursor<u64>>| #[trigger] replay::history(s,measured,observed_root,selected.newest_first@,0,apply,h)
                        && h.last() == end;
                    assert(h.len() == 1);
                    assert(tree == observed_root && measured == totals && end.state == owner && end.totals == totals && end.depth == 0 && end.bytes == 0);
                },
            }
        }
    }
}

fn tag_errors(tag:u8,correct_type:bool) {
    let version = ObjectFormatVersion::new(4).unwrap();
    let kind = if correct_type {ObjectKind::NamespaceMap} else {ObjectKind::File};
    let record = ObjectRecord::from_fields(kind,version,vec![tag],Vec::new(),0,ObjectClass::Metadata).unwrap();
    let check = |_key:&[u8]| -> (e:Option<u8>) ensures e == None {None};
    let result = format::decode(&record,version,&[],check);
    assert(result == if !correct_type {Err(Error::Type)} else if tag == 0 {Err(Error::Truncated)}
        else if tag == 1 {Err(Error::Delta(crate::delta_recovery::Error::Truncated))} else {Err(Error::Tag)});
}

fn invalid_checkpoint(tree:ObjectId,wrong_label:bool,trailing:bool) {
    let version = ObjectFormatVersion::new(4).unwrap();
    let valid = [114u8,111,111,116];
    let mut name = Vec::new();
    name.extend_from_slice(&valid);
    assert(name@ =~= valid@);
    if wrong_label {name.push(0);}
    let edge = crate::ObjectReference::new(crate::ReferenceLabel::new(name),tree,crate::ReferenceKind::Evidence);
    let mut bytes = vec![0u8;17];
    if trailing {bytes.push(0);}
    let record = ObjectRecord::from_fields(ObjectKind::NamespaceMap,version,bytes,vec![edge],0,ObjectClass::Metadata).unwrap();
    let check = |_key:&[u8]| -> (e:Option<u8>) ensures e == None {None};
    let out = format::decode(&record,version,&valid,check);
    assert(out == if trailing {Err(Error::Trailing)} else {Err(Error::Root)});
}
}
