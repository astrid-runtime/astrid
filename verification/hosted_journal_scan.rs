//! Bind frame authentication and principal history to the same physical scan.
use crate::{RootState,arena_frame::{ROOT_MAGIC,FRAME_VERSION},frame_repair::FrameReader,
    frame_scan::{self,Call,Stop,Visitor,Window},journal_apply::{self,VisitError},journal_visitor::RootHistory,root_wire};
use std::collections::BTreeMap;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq}};

verus! {
pub(crate) open spec fn reconstructs<P,D,C,H>(calls:Seq<Call>,states:Seq<Map<P,(RootState,u64)>>,
    table:Map<P,(RootState,u64)>,image:Seq<u8>,end:u64,limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H) -> bool
    where D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,H:Fn([u8;8],u64,&[u8])->[u8;32],
{
    &&& frame_scan::traversed(calls,0,end as int,image,ROOT_MAGIC,FRAME_VERSION,limit,hash)
    &&& states.len()==calls.len()+1 && states[0]==Map::<P,(RootState,u64)>::empty() && states.last()==table
    &&& forall|i:int| 0<=i<calls.len() ==> #[trigger] journal_apply::step(calls[i].1,calls[i].0,scheme,states[i],states[i+1],decode,recode)
}

pub(crate) closed spec fn recovered<P,D,C,H>(table:Map<P,(RootState,u64)>,image:Seq<u8>,end:u64,limit:u64,
    scheme:root_wire::Scheme,decode:D,recode:C,hash:H) -> bool
    where D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,H:Fn([u8;8],u64,&[u8])->[u8;32],
{
    exists|calls,states| #[trigger] reconstructs(calls,states,table,image,end,limit,scheme,decode,recode,hash)
}

/// A framing error is reached only after replaying the entire authenticated prefix.
pub(crate) closed spec fn stopped<R:FrameReader,P,D,C,H>(reader:&R,at:u64,end:u64,error:crate::frame_repair::FrameError<R::Error>,
    limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H) -> bool
    where D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,H:Fn([u8;8],u64,&[u8])->[u8;32],
{
    &&& at<end && frame_scan::frame_failure(reader,at,end,ROOT_MAGIC,FRAME_VERSION,limit,hash,error)
    &&& exists|table| #[trigger] recovered(table,reader.image(),at,limit,scheme,decode,recode,hash)
}

/// All earlier frames have advanced history. The final authenticated payload
/// was offered once and refused, leaving the previous root map intact.
pub(crate) closed spec fn refused<P,D,C,H>(calls:Seq<Call>,states:Seq<Map<P,(RootState,u64)>>,table:Map<P,(RootState,u64)>,
    image:Seq<u8>,end:u64,limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H,error:VisitError) -> bool
    where D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,H:Fn([u8;8],u64,&[u8])->[u8;32],
{
    let cursor=frame_scan::boundary(calls,calls.len(),0);
    &&& calls.len()>0 && cursor<=end && frame_scan::traversed(calls,0,cursor,image,ROOT_MAGIC,FRAME_VERSION,limit,hash)
    &&& states.len()==calls.len() && states[0]==Map::<P,(RootState,u64)>::empty() && states.last()==table
    &&& forall|i:int| 0<=i<calls.len()-1 ==> #[trigger] journal_apply::step(calls[i].1,calls[i].0,scheme,states[i],states[i+1],decode,recode)
    &&& journal_apply::refusal(calls.last().1,scheme,error)
}

pub(crate) fn recover<R:FrameReader,P:Ord,D,C,H>(reader:&mut R,end:u64,limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H)
    -> (result:Result<BTreeMap<P,(RootState,u64)>,Stop<R::Error,VisitError>>)
    where D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires old(reader).position()==0,end<=old(reader).image().len(),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((ROOT_MAGIC,n,b)),
    ensures result matches Err(Stop::Visitor(e)) ==> exists|calls,states,table|
            #[trigger] refused(calls,states,table,old(reader).image(),end,limit,scheme,decode,recode,hash,e),
        result matches Err(Stop::Frame(at,e)) ==> stopped(final(reader),at,end,e,limit,scheme,decode,recode,hash),
        final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        result.is_ok() ==> final(reader).position()==end,
        result matches Ok(t) ==> recovered(t@,old(reader).image(),end,limit,scheme,decode,recode,hash),
{
    let mut visitor=RootHistory::new(scheme,decode,recode);
    let window=Window{start:0,end,magic:ROOT_MAGIC,version:FRAME_VERSION,limit};
    match frame_scan::scan(reader,&mut visitor,window,hash) {
        Err(Stop::Frame(at,e))=>{
            proof {
                visitor.certificate();
                let m=visitor.model();
                assert(m.calls.skip(0) =~= m.calls);
                assert(reconstructs(m.calls,m.states,m.table,reader.image(),at,limit,scheme,decode,recode,hash));
                assert(recovered(m.table,reader.image(),at,limit,scheme,decode,recode,hash));
                assert(stopped(reader,at,end,e,limit,scheme,decode,recode,hash));
            }
            Err(Stop::Frame(at,e))
        },
        Err(Stop::Visitor(e))=>{
            proof {
                let m=visitor.model();
                assert(m.calls.skip(0) =~= m.calls);
                let prior=choose|p:RootHistory<P,D,C>| p.valid() && p.model().scheme==m.scheme &&
                    p.model().decode==m.decode && p.model().recode==m.recode && p.model().calls==m.calls.drop_last() &&
                    #[trigger] <RootHistory<P,D,C> as Visitor<R>>::refused(&visitor,&p,m.calls.last().1,e);
                prior.certificate();
                assert forall|i:int| 0<=i<m.calls.len()-1 implies #[trigger] journal_apply::step(m.calls[i].1,m.calls[i].0,scheme,
                    m.states[i],m.states[i+1],decode,recode) by {
                    assert(prior.model().calls[i]==m.calls[i]);
                }
                assert(refused(m.calls,m.states,m.table,old(reader).image(),end,limit,scheme,decode,recode,hash,e));
            }
            return Err(Stop::Visitor(e));
        },
        Ok(())=>{
            proof {visitor.certificate();}
            let ghost m=visitor.model();
            let table=visitor.finish();
            assert(m.calls.skip(0) =~= m.calls);
            assert(reconstructs(m.calls,m.states,table@,reader.image(),end,limit,scheme,decode,recode,hash));
            assert(reconstructs(m.calls,m.states,table@,old(reader).image(),end,limit,scheme,decode,recode,hash));
            assert(exists|calls,states| #[trigger] reconstructs(calls,states,table@,old(reader).image(),end,limit,scheme,decode,recode,hash));
            assert(recovered(table@,old(reader).image(),end,limit,scheme,decode,recode,hash));
            Ok(table)
        },
    }
}
}
