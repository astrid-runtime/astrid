//! Reconstruct root-journal transitions using only the physical reader and codec.
use crate::{ArenaLocation,RootState,arena_frame as frame,frame_repair as scan,journal_history as history,
    journal_transition as journal,root_wire};
use std::collections::BTreeMap;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};

verus! {
pub(crate) struct Row<P> {
    name:Seq<u8>,key:P,prior:Option<RootState>,root:RootState,
    prior_wire:Option<root_wire::Root>,root_wire:root_wire::Root,loc:ArenaLocation,
}

impl<P> Row<P> {
    spec fn payload(self,scheme:root_wire::Scheme) -> Seq<u8> {
        journal::wire(self.name,scheme,self.prior,self.root)
    }
    spec fn frames<H:Fn([u8;8],u64,&[u8])->[u8;32]>(self,image:Seq<u8>,scheme:root_wire::Scheme,limit:u64,hash:H) -> bool {
        let raw=self.payload(scheme);let at=self.loc.offset as int;
        &&& self.name.len()<u64::MAX && history::represents(self.root_wire,self.root)
        &&& match (self.prior_wire,self.prior) {(None,None)=>true,(Some(w),Some(r))=>history::represents(w,r),_=>false}
        &&& self.loc.payload_len==raw.len() && raw.len()<=limit && at+52+raw.len()<=image.len()
        &&& image.subrange(at,at+52+raw.len())==frame::header_bytes(frame::ROOT_MAGIC,frame::FRAME_VERSION,self.loc.payload_len,self.loc.checksum)+raw
        &&& frame::hashed(hash,frame::ROOT_MAGIC,raw,self.loc.checksum)
    }
    spec fn admitted(self,prior:Map<P,(RootState,u64)>) -> bool {
        let actual=if prior.contains_key(self.key) {Some(prior[self.key].0)} else {None};
        actual==self.prior && self.root.generation.value()==match actual {None=>0int,Some(r)=>r.generation.value() as int+1}
    }
}

pub(crate) enum Failure<E> {Frame(scan::FrameError<E>),Transition(journal::Error)}

#[verifier::spinoff_prover]
fn replay<R:scan::FrameReader,P:Ord,H,D,C>(reader:&mut R,offset:u64,end:u64,history:&mut BTreeMap<P,(RootState,u64)>,
    scheme:root_wire::Scheme,limit:u64,hash:H,decode:D,recode:C,Ghost(row):Ghost<Row<P>>) -> (out:Result<u64,Failure<R::Error>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,
    requires row.frames(old(reader).image(),scheme,limit,hash),old(reader).position()==offset==row.loc.offset,
        end==old(reader).image().len(),btree_map_inv(old(history)),obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((frame::ROOT_MAGIC,n,b)),
        forall|a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ &&
            #[trigger] hash.ensures((frame::ROOT_MAGIC,row.loc.payload_len,a),d) &&
            #[trigger] hash.ensures((frame::ROOT_MAGIC,row.loc.payload_len,b),e) ==> d==e,
        forall|n:&[u8]| n@==row.name ==> #[trigger] decode.requires((n,)),
        forall|n:&[u8],p:Option<P>| n@==row.name && #[trigger] decode.ensures((n,),p) ==> p==Some(row.key),
        recode.requires((&row.key,)),forall|v:Vec<u8>| #[trigger] recode.ensures((&row.key,),v) ==> v@==row.name,
    ensures btree_map_inv(final(history)),final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        match out {
            Ok(next)=>row.admitted(old(history)@) && next==offset as int+52+row.loc.payload_len &&
                final(reader).position()==next && final(history)@==old(history)@.insert(row.key,(row.root,offset)),
            Err(Failure::Frame(scan::FrameError::Io(e)))=>final(history)@==old(history)@ && (
                old(reader).failed(offset as int,52,e) || exists|r:R| r.image()==old(reader).image() && r.target()==old(reader).target() &&
                    r.position()==offset as int+52 && #[trigger] r.failed(offset as int+52,row.loc.payload_len,e)),
            Err(Failure::Transition(journal::Error::History(_)))=>!row.admitted(old(history)@) && final(history)@==old(history)@,
            _=>false,
        },
{
    let f=match crate::hosted_acknowledged_root::scan_written(reader,offset,end,limit,frame::ROOT_MAGIC,hash,Ghost(row.loc),Ghost(row.payload(scheme))) {
        Ok(f)=>f,Err(e)=>return Err(Failure::Frame(e)),
    };
    let r=crate::hosted_acknowledged_root::parse_transition(&f.body,scheme,Ghost(row.name),Ghost(row.prior_wire),Ghost(row.root_wire));
    proof {
        history::unique(row.root_wire,row.root,r.replacement);
        if let Some(w)=row.prior_wire {history::unique(w,row.prior.unwrap(),r.expected.unwrap());}
    }
    match r.replay(history,scheme,offset,&f.body,decode,recode) {
        Ok(())=>Ok(f.end),Err(e)=>Err(Failure::Transition(e)),
    }
}

spec fn extent<P>(rows:Seq<Row<P>>,n:nat) -> int {
    if n==0 {0} else {let loc=rows[n-1].loc;loc.offset as int+52+loc.payload_len}
}

pub(crate) closed spec fn prefix<P>(rows:Seq<Row<P>>,n:nat) -> Map<P,(RootState,u64)>
    decreases n,
{
    if n==0 {Map::empty()} else {let r=rows[n-1];prefix(rows,(n-1) as nat).insert(r.key,(r.root,r.loc.offset))}
}

pub(crate) closed spec fn consecutive<P>(rows:Seq<Row<P>>,n:nat) -> bool {
    forall|i:int| 0<=i<n ==> (#[trigger] rows[i]).admitted(prefix(rows,i as nat))
}

spec fn refused_at<R:scan::FrameReader,P>(image:Seq<u8>,target:(int,Seq<u8>),r:Row<P>,prior:Map<P,(RootState,u64)>,f:Failure<R::Error>) -> bool {
    let at=r.loc.offset as int;
    match f {
        Failure::Transition(journal::Error::History(_))=>!r.admitted(prior),
        Failure::Frame(scan::FrameError::Io(e))=>
            (exists|c:R| c.image()==image && c.target()==target && c.position()==at && #[trigger] c.failed(at,52,e)) ||
            (exists|c:R| c.image()==image && c.target()==target && c.position()==at+52 && #[trigger] c.failed(at+52,r.loc.payload_len,e)),
        _=>false,
    }
}

pub(crate) closed spec fn readable<P:Ord,H,D,C>(rows:Seq<Row<P>>,image:Seq<u8>,end:u64,scheme:root_wire::Scheme,limit:u64,hash:H,decode:D,recode:C) -> bool
    where H:Fn([u8;8],u64,&[u8])->[u8;32],D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,
{
        &&& extent(rows,rows.len())==end
        &&& forall|i:int| 0<=i<rows.len() ==> (#[trigger] rows[i]).frames(image,scheme,limit,hash) &&
            rows[i].loc.offset==extent(rows,i as nat)
        &&& obeys_cmp::<P>() && obeys_cmp_concrete_eq::<P>()
        &&& forall|n:u64,b:&[u8]| #[trigger] hash.requires((frame::ROOT_MAGIC,n,b))
        &&& forall|n:u64,a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ && #[trigger] hash.ensures((frame::ROOT_MAGIC,n,a),d) &&
            #[trigger] hash.ensures((frame::ROOT_MAGIC,n,b),e) ==> d==e
        &&& forall|n:&[u8]| #[trigger] decode.requires((n,))
        &&& forall|i:int,n:&[u8],p:Option<P>| 0<=i<rows.len() && n@==(#[trigger] rows[i]).name && #[trigger] decode.ensures((n,),p) ==> p==Some(rows[i].key)
        &&& forall|p:&P| #[trigger] recode.requires((p,))
        &&& forall|i:int,v:Vec<u8>| 0<=i<rows.len() && #[trigger] recode.ensures((&rows[i].key,),v) ==> v@==rows[i].name
}

pub(crate) closed spec fn failed<R:scan::FrameReader,P>(rows:Seq<Row<P>>,image:Seq<u8>,target:(int,Seq<u8>),at:u64,f:Failure<R::Error>) -> bool {
    exists|i:int| 0<=i<rows.len() && (#[trigger] rows[i]).loc.offset==at && consecutive(rows,i as nat) &&
                refused_at::<R,P>(image,target,rows[i],prefix(rows,i as nat),f)
}

#[verifier::spinoff_prover]
#[verifier::loop_isolation(false)]
#[verifier::rlimit(30)]
pub(crate) fn recover<R:scan::FrameReader,P:Ord,H,D,C>(reader:&mut R,end:u64,scheme:root_wire::Scheme,limit:u64,
    hash:H,decode:D,recode:C,Ghost(rows):Ghost<Seq<Row<P>>>) -> (out:Result<BTreeMap<P,(RootState,u64)>,(u64,Failure<R::Error>)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,
    requires old(reader).position()==0,end==old(reader).image().len(),readable(rows,old(reader).image(),end,scheme,limit,hash,decode,recode),
    ensures final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        match out {
            Ok(history)=>btree_map_inv(&history) && history@==prefix(rows,rows.len()) && consecutive(rows,rows.len()) && final(reader).position()==end,
            Err((at,f))=>failed::<R,P>(rows,old(reader).image(),old(reader).target(),at,f),
        },
{
    let mut history=BTreeMap::new();
    let mut at=0u64;
    let ghost mut n:nat=0;
    while at<end
        invariant at<=end,n<=rows.len(),at==extent(rows,n),reader.position()==at,reader.image()==old(reader).image(),
            reader.target()==old(reader).target(),btree_map_inv(&history),history@==prefix(rows,n),consecutive(rows,n),
        decreases end-at,
    {
        assert(n<rows.len());
        let ghost row=rows[n as int];
        let ghost cursor=*reader;
        match replay(reader,at,end,&mut history,scheme,limit,hash,decode,recode,Ghost(row)) {
            Ok(next)=>{
                assert(history@==prefix(rows,n+1));
                assert forall|i:int| 0<=i<n+1 implies (#[trigger] rows[i]).admitted(prefix(rows,i as nat)) by {
                    if i<n {assert(rows[i].admitted(prefix(rows,i as nat)));}
                }
                at=next;
                proof {n=n+1;}
            },
            Err(e)=>{
                proof {
                    if let Failure::Frame(scan::FrameError::Io(io))=&e {
                        let ghost witness=if cursor.failed(at as int,52,*io) {cursor} else {
                            choose|r:R| r.image()==cursor.image() && r.target()==cursor.target() && r.position()==at as int+52 &&
                                #[trigger] r.failed(at as int+52,row.loc.payload_len,*io)
                        };
                        assert(witness.image()==old(reader).image());
                    }
                }
                assert(refused_at::<R,P>(cursor.image(),cursor.target(),row,prefix(rows,n),e));
                assert(exists|i:int| 0<=i<rows.len() && (#[trigger] rows[i]).loc.offset==at && consecutive(rows,i as nat) &&
                    refused_at::<R,P>(cursor.image(),cursor.target(),rows[i],prefix(rows,i as nat),e));
                return Err((at,e));
            }
        }
    }
    proof {
        if n<rows.len() {assert(rows[n as int].frames(reader.image(),scheme,limit,hash));}
        assert(n==rows.len());
    }
    Ok(history)
}
}
