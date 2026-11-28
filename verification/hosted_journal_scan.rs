//! Bind frame authentication and principal history to the same physical scan.
use crate::{RootState,arena_frame::{ROOT_MAGIC,FRAME_VERSION},frame_repair::FrameReader,
    frame_scan::{self,Call,Stop,Visitor},journal_apply::{self,VisitError},journal_visitor::RootHistory,root_wire};
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
    &&& journal_apply::refusal(calls.last().1,calls.last().0,scheme,table,decode,recode,error)
}

pub(crate) enum ScanError<P,E> {
    Frame(u64,crate::frame_repair::FrameError<E>,BTreeMap<P,(RootState,u64)>),
    Visitor(VisitError),
}

pub(crate) fn recover<R:FrameReader,P:Ord,D,C,H>(reader:&mut R,end:u64,limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H)
    -> (result:Result<BTreeMap<P,(RootState,u64)>,ScanError<P,R::Error>>)
    where D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires old(reader).position()==0,end<=old(reader).image().len(),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((ROOT_MAGIC,n,b)),
    ensures result matches Err(ScanError::Visitor(e)) ==> exists|calls,states,table|
            #[trigger] refused(calls,states,table,old(reader).image(),end,limit,scheme,decode,recode,hash,e),
        result matches Err(ScanError::Frame(at,e,t)) ==> stopped(final(reader),at,end,e,limit,scheme,decode,recode,hash) &&
            recovered(t@,old(reader).image(),at,limit,scheme,decode,recode,hash),
        final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        result.is_ok() ==> final(reader).position()==end,
        result matches Ok(t) ==> recovered(t@,old(reader).image(),end,limit,scheme,decode,recode,hash),
{
    let mut visitor=RootHistory::new(scheme,decode,recode);
    match frame_scan::scan_root(reader,&mut visitor,end,limit,hash) {
        Err(Stop::Frame(at,e))=>{
            proof {
                visitor.certificate();
                let m=visitor.model();
                assert(m.calls.skip(0) =~= m.calls);
                assert(reconstructs(m.calls,m.states,m.table,reader.image(),at,limit,scheme,decode,recode,hash));
                assert(recovered(m.table,reader.image(),at,limit,scheme,decode,recode,hash));
                assert(stopped(reader,at,end,e,limit,scheme,decode,recode,hash));
            }
            let ghost m=visitor.model();
            let table=visitor.finish();
            assert(table@==m.table);
            Err(ScanError::Frame(at,e,table))
        },
        Err(Stop::Visitor(_,_,e))=>{
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
            return Err(ScanError::Visitor(e));
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

/// Physical boundaries grow strictly at every callback (including an empty payload).
proof fn within(calls:Seq<Call>,i:nat,n:nat)
    requires i<=n<=calls.len(),
        forall|j:int| 0<=j<calls.len() ==> (#[trigger] calls[j]).0==frame_scan::boundary(calls,j as nat,0),
    ensures frame_scan::boundary(calls,i,0)<=frame_scan::boundary(calls,n,0),
    decreases n-i,
{
    if i<n {
        within(calls,i,(n-1) as nat);
        assert(calls[n-1].0==frame_scan::boundary(calls,(n-1) as nat,0));
    }
}

proof fn retain_prefix<P,D,C,H>(table:Map<P,(RootState,u64)>,image:Seq<u8>,end:u64,limit:u64,scheme:root_wire::Scheme,
    decode:D,recode:C,hash:H)
    where D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,H:Fn([u8;8],u64,&[u8])->[u8;32],
    requires end<=image.len(),recovered(table,image,end,limit,scheme,decode,recode,hash),
    ensures recovered(table,image.take(end as int),end,limit,scheme,decode,recode,hash),
{
    let (calls,states)=choose|calls:Seq<Call>,states:Seq<Map<P,(RootState,u64)>>| #[trigger] reconstructs(calls,states,table,image,end,limit,scheme,decode,recode,hash);
    let retained=image.take(end as int);
    assert forall|i:int| 0<=i<calls.len() implies (#[trigger] calls[i]).0==frame_scan::boundary(calls,i as nat,0) &&
        frame_scan::authentic(retained,calls[i].0,calls[i].1,ROOT_MAGIC,FRAME_VERSION,limit,hash) by {
        within(calls,(i+1) as nat,calls.len());
        let (at,body)=calls[i];
        let next=at as int+52+body.len();
        assert(retained.subrange(at as int,next) =~= image.subrange(at as int,next));
    }
    assert(reconstructs(calls,states,table,retained,end,limit,scheme,decode,recode,hash));
}

pub(crate) enum Live<P,E,ME> {
    Complete(BTreeMap<P,(RootState,u64)>),
    Repaired(u64,crate::frame_repair::TailError,BTreeMap<P,(RootState,u64)>),
    Frame(u64,crate::frame_repair::FrameError<E>),
    Visitor(VisitError),
    Media(u64,crate::frame_repair::TailError,crate::frame_repair::Error<ME>),
}

/// Model native aliasing with two views of the same measured file. A repair
/// publishes the accumulated map only after resize and flush both succeed.
pub(crate) fn recover_live<R:FrameReader,M:crate::frame_repair::Medium,P:Ord,D,C,H>(reader:&mut R,media:&mut M,
    end:u64,protected:u64,limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H)
    -> (out:Live<P,R::Error,M::Error>)
    where D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires old(reader).target()==old(media).target(),old(reader).image()==old(media).bytes(),
        old(reader).position()==0,protected<=end==old(reader).image().len(),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((ROOT_MAGIC,n,b)),
    ensures final(media).syncs_file()==old(media).syncs_file(),final(media).target()==old(reader).target(),
        out matches Live::Complete(t) ==> *final(media)==*old(media) && recovered(t@,final(media).bytes(),end,limit,scheme,decode,recode,hash),
        out matches Live::Repaired(at,e,t) ==> protected<=at<end && !crate::frame_repair::has_later::<M>(old(media).bytes(),at,end,ROOT_MAGIC,limit) &&
            stopped(final(reader),at,end,crate::frame_repair::FrameError::Tail(e),limit,scheme,decode,recode,hash) &&
            (match e.classification() {
                crate::frame_repair::Damage::Incomplete=>final(media).calls()==old(media).calls().push(crate::frame_repair::Event::Resize(at)).push(crate::frame_repair::Event::Flush),
                crate::frame_repair::Damage::Suspect {known_interior}=>!known_interior && !crate::frame_repair::has_later::<M>(old(media).bytes(),at,end,ROOT_MAGIC,limit) &&
                    final(media).calls()==old(media).calls().push(crate::frame_repair::Event::Probe(at)).push(crate::frame_repair::Event::Resize(at)).push(crate::frame_repair::Event::Flush),
            }) && final(media).bytes()==old(reader).image().take(at as int) &&
            (final(media).syncs_file() ==> final(media).durable()==final(media).bytes()) &&
            recovered(t@,final(media).bytes(),at,limit,scheme,decode,recode,hash),
        out matches Live::Frame(at,e) ==> stopped(final(reader),at,end,e,limit,scheme,decode,recode,hash) &&
            final(media).bytes()==old(media).bytes() && final(media).durable()==old(media).durable(),
        out matches Live::Media(at,e,failure) ==> protected<=at<end &&
            stopped(final(reader),at,end,crate::frame_repair::FrameError::Tail(e),limit,scheme,decode,recode,hash) && (
                failure is Probe ==> final(media).bytes()==old(media).bytes() && final(media).durable()==old(media).durable()),
        out is Visitor ==> *final(media)==*old(media),
{
    use crate::frame_repair::{FrameError,Outcome};
    match recover(reader,end,limit,scheme,decode,recode,hash) {
        Ok(table)=>Live::Complete(table),
        Err(ScanError::Visitor(e))=>Live::Visitor(e),
        Err(ScanError::Frame(at,FrameError::Tail(e),table))=>{
            match crate::frame_repair::repair(media,at,end,protected,e.damage(),ROOT_MAGIC,limit) {
                Ok(Outcome::Repaired)=>{
                    proof {
                        if e is HeaderShort {
                            let r=choose|r:R| r.target()==reader.target() && r.image()==reader.image() && r.position()==at &&
                                #[trigger] crate::frame_repair::classified(&r,reader,at,end,ROOT_MAGIC,FRAME_VERSION,limit,hash,Err(FrameError::Tail(e)));
                            assert(end<at as int+52);
                            assert forall|next:u64| at<next implies !(#[trigger] crate::frame_probe::protects::<M>(r.image(),ROOT_MAGIC,end,limit,next)) by {};
                        }
                        retain_prefix(table@,reader.image(),at,limit,scheme,decode,recode,hash);
                    }
                    Live::Repaired(at,e,table)
                },
                Ok(Outcome::Reject)=>Live::Frame(at,FrameError::Tail(e)),
                Err(failure)=>Live::Media(at,e,failure),
            }
        },
        Err(ScanError::Frame(at,e,_))=>Live::Frame(at,e),
    }
}

/// A container-backed region has only a staged prefix after its file-level
/// flush. Capture the matching region *after* repair, then persist the backing
/// container before exporting the recovered map as a durable result.
pub(crate) enum VolumeRecovery<P,E,ME,C:crate::frontier::JournalContainer> {
    Unmodified(BTreeMap<P,(RootState,u64)>),
    Persisted(u64,BTreeMap<P,(RootState,u64)>,C),
    Frame(u64,crate::frame_repair::FrameError<E>),
    Visitor(VisitError),
    Repair(u64,ME),
    Container(u64,C::Error),
}

pub(crate) closed spec fn container_failure<V:crate::frontier::JournalContainer>(target:(int,Seq<u8>),bytes:Seq<u8>,error:V::Error) -> bool {
    exists|v:V| (v.container_id(),v.region_id())==target && v.journal_image()==bytes && #[trigger] v.sync_failed(error)
}

pub(crate) fn recover_volume<R:FrameReader,M:crate::frame_repair::Medium,P:Ord,D,C,H,V:crate::frontier::JournalContainer,F:FnOnce(&M)->V>(
    reader:&mut R,media:&mut M,end:u64,protected:u64,limit:u64,scheme:root_wire::Scheme,decode:D,recode:C,hash:H,capture:F)
    -> (out:VolumeRecovery<P,R::Error,crate::frame_repair::Error<M::Error>,V>)
    where D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,
    requires !old(media).syncs_file(),old(reader).target()==old(media).target(),old(reader).image()==old(media).bytes(),
        old(reader).position()==0,protected<=end==old(reader).image().len(),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((ROOT_MAGIC,n,b)),
        forall|m:&M| m.target()==old(media).target() && !m.syncs_file() ==> #[trigger] capture.requires((m,)),
        forall|m:&M,v:V| #[trigger] capture.ensures((m,),v) ==> (v.container_id(),v.region_id())==m.target() && v.journal_image()==m.bytes(),
    ensures out matches VolumeRecovery::Persisted(at,t,v) ==> protected<=at<end && (v.container_id(),v.region_id())==old(reader).target() &&
            v.durable_image()==old(reader).image().take(at as int) && recovered(t@,v.durable_image(),at,limit,scheme,decode,recode,hash),
        out matches VolumeRecovery::Unmodified(t) ==> *final(media)==*old(media) && recovered(t@,final(media).bytes(),end,limit,scheme,decode,recode,hash),
        out matches VolumeRecovery::Container(at,e) ==> protected<=at<end && final(media).bytes()==old(reader).image().take(at as int) &&
            container_failure::<V>(old(reader).target(),final(media).bytes(),e),
{
    match recover_live(reader,media,end,protected,limit,scheme,decode,recode,hash) {
        Live::Complete(t)=>VolumeRecovery::Unmodified(t),
        Live::Repaired(at,_,table)=>{
            let mut region=capture(media);
            let ghost before=region;
            match region.sync_container() {
                Ok(())=>VolumeRecovery::Persisted(at,table,region),
                Err(e)=>{
                    assert(before.sync_failed(e));
                    assert(container_failure::<V>(old(reader).target(),media.bytes(),e));
                    VolumeRecovery::Container(at,e)
                },
            }
        },
        Live::Frame(at,e)=>VolumeRecovery::Frame(at,e),
        Live::Visitor(e)=>VolumeRecovery::Visitor(e),
        Live::Media(at,_,e)=>VolumeRecovery::Repair(at,e),
    }
}
}
