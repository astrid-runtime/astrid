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

pub(crate) closed spec fn boundary<P>(start:u64,rows:Seq<Row<P>>,n:nat) -> int {
    if n==0 {start as int} else {let loc=rows[n-1].loc;loc.offset as int+52+loc.payload_len}
}

spec fn extent<P>(rows:Seq<Row<P>>,n:nat) -> int {
    boundary(0,rows,n)
}

pub(crate) closed spec fn applied<P>(base:Map<P,(RootState,u64)>,rows:Seq<Row<P>>,n:nat) -> Map<P,(RootState,u64)>
    decreases n,
{
    if n==0 {base} else {let r=rows[n-1];applied(base,rows,(n-1) as nat).insert(r.key,(r.root,r.loc.offset))}
}

pub(crate) closed spec fn prefix<P>(rows:Seq<Row<P>>,n:nat) -> Map<P,(RootState,u64)> {
    applied(Map::empty(),rows,n)
}

pub(crate) closed spec fn accepted<P>(base:Map<P,(RootState,u64)>,rows:Seq<Row<P>>,n:nat) -> bool {
    forall|i:int| 0<=i<n ==> (#[trigger] rows[i]).admitted(applied(base,rows,i as nat))
}

pub(crate) closed spec fn consecutive<P>(rows:Seq<Row<P>>,n:nat) -> bool {
    accepted(Map::empty(),rows,n)
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

pub(crate) closed spec fn describes_suffix<P,H:Fn([u8;8],u64,&[u8])->[u8;32]>(start:u64,rows:Seq<Row<P>>,image:Seq<u8>,scheme:root_wire::Scheme,limit:u64,hash:H) -> bool {
        &&& boundary(start,rows,rows.len())==image.len()
        &&& forall|i:int| 0<=i<rows.len() ==> (#[trigger] rows[i]).frames(image,scheme,limit,hash) &&
            rows[i].loc.offset==boundary(start,rows,i as nat)
}

pub(crate) closed spec fn describes<P,H:Fn([u8;8],u64,&[u8])->[u8;32]>(rows:Seq<Row<P>>,image:Seq<u8>,scheme:root_wire::Scheme,limit:u64,hash:H) -> bool {
    describes_suffix(0,rows,image,scheme,limit,hash)
}

pub(crate) closed spec fn appended<P,H:Fn([u8;8],u64,&[u8])->[u8;32]>(
    prior_image:Seq<u8>,image:Seq<u8>,scheme:root_wire::Scheme,hash:H,
    key:P,name:Seq<u8>,expected:Option<RootState>,next:RootState) -> bool {
    exists|r:Row<P>| r.key==key && r.name==name && r.prior==expected && r.root==next &&
        r.loc.offset==prior_image.len() && r.loc.payload_len==r.payload(scheme).len() &&
        forall|rows:Seq<Row<P>>,limit:u64| #[trigger] describes(rows,prior_image,scheme,limit,hash) && r.loc.payload_len<=limit ==>
            describes(rows.push(r),image,scheme,limit,hash)
}

pub(crate) fn attest_append<P,H:Fn([u8;8],u64,&[u8])->[u8;32]>(Ghost(prior_image):Ghost<Seq<u8>>,Ghost(image):Ghost<Seq<u8>>,
    scheme:root_wire::Scheme,hash:H,key:P,name:&[u8],expected:Option<RootState>,next:RootState,body:&[u8],Ghost(sum):Ghost<[u8;32]>)
    requires prior_image.len()<=u64::MAX,name.len()<u64::MAX,body@==journal::wire(name@,scheme,expected,next),
        image==prior_image+frame::header_bytes(frame::ROOT_MAGIC,frame::FRAME_VERSION,body.len() as u64,sum)+body@,
        frame::hashed(hash,frame::ROOT_MAGIC,body@,sum),
    ensures appended(prior_image,image,scheme,hash,key,name@,expected,next),
{
    let prior=match expected {Some(r)=>Some(history::to_wire(r)),None=>None};
    let root=history::to_wire(next);
    proof {
        let loc=ArenaLocation {offset:prior_image.len() as u64,payload_len:body.len() as u64,checksum:sum};
        let row=Row {name:name@,key,prior:expected,root:next,prior_wire:prior,root_wire:root,loc};
        let hdr=frame::header_bytes(frame::ROOT_MAGIC,frame::FRAME_VERSION,loc.payload_len,sum);
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(hdr.len()==52);
        assert(image.subrange(prior_image.len() as int,image.len() as int) =~= hdr+body@);
        assert forall|rows:Seq<Row<P>>,limit:u64| #[trigger] describes(rows,prior_image,scheme,limit,hash) && row.loc.payload_len<=limit implies
            describes(rows.push(row),image,scheme,limit,hash) by {
            let result=rows.push(row);
            assert(row.frames(image,scheme,limit,hash));
            assert forall|i:int| 0<=i<result.len() implies (#[trigger] result[i]).frames(image,scheme,limit,hash) &&
                result[i].loc.offset==extent(result,i as nat) by {
                if i<rows.len() {
                    let old=rows[i];
                    assert(old.frames(prior_image,scheme,limit,hash));
                    let at=old.loc.offset as int;let end=at+52+old.loc.payload_len;
                    assert(image.subrange(at,end) =~= prior_image.subrange(at,end));
                }
                if i>0 {assert(result[i-1]==rows[i-1]);}
            }
        }
    }
}

pub(crate) closed spec fn readable_suffix<P:Ord,H,D,C>(start:u64,rows:Seq<Row<P>>,image:Seq<u8>,end:u64,scheme:root_wire::Scheme,limit:u64,hash:H,decode:D,recode:C) -> bool
    where H:Fn([u8;8],u64,&[u8])->[u8;32],D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,
{
        &&& describes_suffix(start,rows,image,scheme,limit,hash)
        &&& end==image.len()
        &&& obeys_cmp::<P>() && obeys_cmp_concrete_eq::<P>()
        &&& forall|n:u64,b:&[u8]| #[trigger] hash.requires((frame::ROOT_MAGIC,n,b))
        &&& forall|n:u64,a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ && #[trigger] hash.ensures((frame::ROOT_MAGIC,n,a),d) &&
            #[trigger] hash.ensures((frame::ROOT_MAGIC,n,b),e) ==> d==e
        &&& forall|n:&[u8]| #[trigger] decode.requires((n,))
        &&& forall|i:int,n:&[u8],p:Option<P>| 0<=i<rows.len() && n@==(#[trigger] rows[i]).name && #[trigger] decode.ensures((n,),p) ==> p==Some(rows[i].key)
        &&& forall|p:&P| #[trigger] recode.requires((p,))
        &&& forall|i:int,v:Vec<u8>| 0<=i<rows.len() && #[trigger] recode.ensures((&rows[i].key,),v) ==> v@==rows[i].name
}

pub(crate) closed spec fn readable<P:Ord,H,D,C>(rows:Seq<Row<P>>,image:Seq<u8>,end:u64,scheme:root_wire::Scheme,limit:u64,hash:H,decode:D,recode:C) -> bool
    where H:Fn([u8;8],u64,&[u8])->[u8;32],D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,
{
    readable_suffix(0,rows,image,end,scheme,limit,hash,decode,recode)
}

proof fn prefix_push<P>(rows:Seq<Row<P>>,row:Row<P>,n:nat)
    requires n<=rows.len(),
    ensures prefix(rows.push(row),n)==prefix(rows,n),
    decreases n,
{
    if n>0 {
        prefix_push(rows,row,(n-1) as nat);
        assert(rows.push(row)[n-1]==rows[n-1]);
    }
}

/// A WAL-applied transition extends the scan contract for every certified
/// prefix, including a journal containing other owners and earlier generations.
pub(crate) proof fn extend_readable<P:Ord,H,D,C>(rows:Seq<Row<P>>,old_image:Seq<u8>,image:Seq<u8>,
    scheme:root_wire::Scheme,limit:u64,hash:H,decode:D,recode:C,
    key:P,name:Seq<u8>,expected:Option<RootState>,next:RootState)
    where H:Fn([u8;8],u64,&[u8])->[u8;32],D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,
    requires readable(rows,old_image,old_image.len() as u64,scheme,limit,hash,decode,recode),
        consecutive(rows,rows.len()),image.len()<=u64::MAX,journal::wire(name,scheme,expected,next).len()<=limit,
        appended(old_image,image,scheme,hash,key,name,expected,next),
        expected==(if prefix(rows,rows.len()).contains_key(key) {Some(prefix(rows,rows.len())[key].0)} else {None}),
        next.generation.value()==match expected {None=>0int,Some(r)=>r.generation.value() as int+1},
        forall|n:&[u8],p:Option<P>| n@==name && #[trigger] decode.ensures((n,),p) ==> p==Some(key),
        forall|v:Vec<u8>| #[trigger] recode.ensures((&key,),v) ==> v@==name,
    ensures exists|extended:Seq<Row<P>>| #[trigger] readable(extended,image,image.len() as u64,scheme,limit,hash,decode,recode) &&
        consecutive(extended,extended.len()) && prefix(extended,extended.len())==prefix(rows,rows.len()).insert(key,(next,old_image.len() as u64)),
{
    let row=choose|r:Row<P>| r.key==key && r.name==name && r.prior==expected && r.root==next &&
        r.loc.offset==old_image.len() && r.loc.payload_len==r.payload(scheme).len() &&
        forall|rs:Seq<Row<P>>,lim:u64| #[trigger] describes(rs,old_image,scheme,lim,hash) && r.loc.payload_len<=lim ==>
            describes(rs.push(r),image,scheme,lim,hash);
    let extended=rows.push(row);
    assert(describes(rows,old_image,scheme,limit,hash));
    assert(row.loc.payload_len<=limit);
    assert(describes(extended,image,scheme,limit,hash));
    assert forall|i:int,n:&[u8],p:Option<P>| 0<=i<extended.len() && n@==(#[trigger] extended[i]).name && #[trigger] decode.ensures((n,),p) implies p==Some(extended[i].key) by {
        if i<rows.len() {assert(extended[i]==rows[i]);}
    }
    assert forall|i:int,v:Vec<u8>| 0<=i<extended.len() && #[trigger] recode.ensures((&extended[i].key,),v) implies v@==extended[i].name by {
        if i<rows.len() {assert(extended[i]==rows[i]);}
    }
    assert(readable(extended,image,image.len() as u64,scheme,limit,hash,decode,recode));
    assert forall|i:int| 0<=i<extended.len() implies (#[trigger] extended[i]).admitted(prefix(extended,i as nat)) by {
        prefix_push(rows,row,i as nat);
        if i<rows.len() {assert(rows[i].admitted(prefix(rows,i as nat)));}
    }
    prefix_push(rows,row,rows.len());
    assert(prefix(extended,extended.len())==prefix(rows,rows.len()).insert(key,(next,old_image.len() as u64)));
}

pub(crate) closed spec fn failed_suffix<R:scan::FrameReader,P>(base:Map<P,(RootState,u64)>,rows:Seq<Row<P>>,image:Seq<u8>,target:(int,Seq<u8>),at:u64,f:Failure<R::Error>) -> bool {
    exists|i:int| 0<=i<rows.len() && (#[trigger] rows[i]).loc.offset==at && accepted(base,rows,i as nat) &&
                refused_at::<R,P>(image,target,rows[i],applied(base,rows,i as nat),f)
}

pub(crate) closed spec fn failed<R:scan::FrameReader,P>(rows:Seq<Row<P>>,image:Seq<u8>,target:(int,Seq<u8>),at:u64,f:Failure<R::Error>) -> bool {
    failed_suffix::<R,P>(Map::empty(),rows,image,target,at,f)
}

#[verifier::spinoff_prover]
#[verifier::loop_isolation(false)]
#[verifier::rlimit(70)]
pub(crate) fn scan_suffix<R:scan::FrameReader,P:Ord,H,D,C>(reader:&mut R,start:u64,end:u64,mut history:BTreeMap<P,(RootState,u64)>,scheme:root_wire::Scheme,limit:u64,
    hash:H,decode:D,recode:C,Ghost(rows):Ghost<Seq<Row<P>>>) -> (out:Result<BTreeMap<P,(RootState,u64)>,(u64,Failure<R::Error>)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,
    requires btree_map_inv(&history),start<=end,old(reader).position()==start,end==old(reader).image().len(),readable_suffix(start,rows,old(reader).image(),end,scheme,limit,hash,decode,recode),
    ensures final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        match out {
            Ok(table)=>btree_map_inv(&table) && table@==applied(history@,rows,rows.len()) && accepted(history@,rows,rows.len()) && final(reader).position()==end,
            Err((at,f))=>failed_suffix::<R,P>(history@,rows,old(reader).image(),old(reader).target(),at,f),
        },
{
    assert(boundary(start,rows,rows.len())==end);
    assert forall|i:int| 0<=i<rows.len() implies (#[trigger] rows[i]).frames(reader.image(),scheme,limit,hash) &&
        rows[i].loc.offset==boundary(start,rows,i as nat) by {}
    let ghost base=history@;
    let mut at=start;
    let ghost mut n:nat=0;
    while at<end
        invariant at<=end,n<=rows.len(),at==boundary(start,rows,n),reader.position()==at,reader.image()==old(reader).image(),
            reader.target()==old(reader).target(),btree_map_inv(&history),history@==applied(base,rows,n),accepted(base,rows,n),
        decreases end-at,
    {
        assert(n<rows.len());
        let ghost row=rows[n as int];
        assert(row.frames(reader.image(),scheme,limit,hash));
        assert(row.loc.offset==at);
        let ghost cursor=*reader;
        match replay(reader,at,end,&mut history,scheme,limit,hash,decode,recode,Ghost(row)) {
            Ok(next)=>{
                assert(history@==applied(base,rows,n+1));
                assert forall|i:int| 0<=i<n+1 implies (#[trigger] rows[i]).admitted(applied(base,rows,i as nat)) by {
                    if i<n {assert(rows[i].admitted(applied(base,rows,i as nat)));}
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
                assert(refused_at::<R,P>(cursor.image(),cursor.target(),row,applied(base,rows,n),e));
                assert(exists|i:int| 0<=i<rows.len() && (#[trigger] rows[i]).loc.offset==at && accepted(base,rows,i as nat) &&
                    refused_at::<R,P>(cursor.image(),cursor.target(),rows[i],applied(base,rows,i as nat),e));
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
    scan_suffix(reader,0,end,BTreeMap::new(),scheme,limit,hash,decode,recode,Ghost(rows))
}

/// Reopen the complete file after one accepted publication on a certified
/// prefix. Key and root witnesses are erased; decoding starts at physical zero.
#[verifier::spinoff_prover]
fn recover_appended<R:scan::FrameReader,P:Ord,H,D,C>(reader:&mut R,end:u64,scheme:root_wire::Scheme,limit:u64,hash:H,decode:D,recode:C,
    Ghost(rows):Ghost<Seq<Row<P>>>,Ghost(before):Ghost<Seq<u8>>,Ghost(key):Ghost<P>,Ghost(name):Ghost<Seq<u8>>,
    Ghost(expected):Ghost<Option<RootState>>,Ghost(next):Ghost<RootState>)
    -> (out:Result<BTreeMap<P,(RootState,u64)>,(u64,Failure<R::Error>)>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,
    requires old(reader).position()==0,end==old(reader).image().len(),
        readable(rows,before,before.len() as u64,scheme,limit,hash,decode,recode),consecutive(rows,rows.len()),
        appended(before,old(reader).image(),scheme,hash,key,name,expected,next),
        journal::wire(name,scheme,expected,next).len()<=limit,
        expected==(if prefix(rows,rows.len()).contains_key(key) {Some(prefix(rows,rows.len())[key].0)} else {None}),
        next.generation.value()==match expected {None=>0int,Some(r)=>r.generation.value() as int+1},
        forall|n:&[u8],p:Option<P>| n@==name && #[trigger] decode.ensures((n,),p) ==> p==Some(key),
        forall|v:Vec<u8>| #[trigger] recode.ensures((&key,),v) ==> v@==name,
    ensures final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        match out {
            Ok(table)=>btree_map_inv(&table) && final(reader).position()==end &&
                table@==prefix(rows,rows.len()).insert(key,(next,before.len() as u64)),
            Err((at,Failure::Frame(scan::FrameError::Io(e))))=>at<end &&
                exists|r:R,n:u64| r.image()==old(reader).image() && r.target()==old(reader).target() &&
                    (r.position()==at && n==52 || r.position()==at as int+52 && r.position()+n<=end) &&
                    #[trigger] r.failed(r.position(),n,e),
            _=>false,
        },
{
    let ghost image=reader.image();
    proof {extend_readable(rows,before,image,scheme,limit,hash,decode,recode,key,name,expected,next);}
    let ghost full=choose|rs:Seq<Row<P>>| #[trigger] readable(rs,image,end,scheme,limit,hash,decode,recode) && consecutive(rs,rs.len()) &&
        prefix(rs,rs.len())==prefix(rows,rows.len()).insert(key,(next,before.len() as u64));
    let out=recover(reader,end,scheme,limit,hash,decode,recode,Ghost(full));
    proof {
        if let Err((at,e))=&out {
            let i=choose|i:int| 0<=i<full.len() && (#[trigger] full[i]).loc.offset==*at && consecutive(full,i as nat) &&
                refused_at::<R,P>(image,reader.target(),full[i],prefix(full,i as nat),*e);
            let row=full[i];
            assert(row.admitted(prefix(full,i as nat)));
            assert(row.frames(image,scheme,limit,hash));
            if let Failure::Frame(scan::FrameError::Io(io))=e {
                if exists|r:R| r.image()==image && r.target()==reader.target() && r.position()==*at && #[trigger] r.failed(*at as int,52,*io) {
                    let r=choose|r:R| r.image()==image && r.target()==reader.target() && r.position()==*at && #[trigger] r.failed(*at as int,52,*io);
                    assert(r.failed(r.position(),52,*io));
                } else {
                    let r=choose|r:R| r.image()==image && r.target()==reader.target() && r.position()==*at as int+52 && #[trigger] r.failed(*at as int+52,row.loc.payload_len,*io);
                    assert(r.failed(r.position(),row.loc.payload_len,*io));
                }
            }
        }
    }
    out
}
}
