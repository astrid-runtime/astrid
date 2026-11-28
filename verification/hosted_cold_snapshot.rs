//! Bind the production compaction decoder and restore fold to one root file.
use crate::{ArenaLocation,RootState,arena_frame as frame,frame_repair as scan,journal_history as history,
    journal_payload as payload,journal_snapshot as snapshot,root_wire};
use crate::hosted_cold_journal as transitions;
use std::collections::BTreeMap;
use vstd::{prelude::*,laws_cmp::{obeys_cmp,obeys_cmp_concrete_eq},std_specs::btree::btree_map_inv};
verus! {
type Row=(Vec<u8>,RootState);

/// An accepted snapshot can be re-encoded byte-for-byte from its decoded rows.
proof fn reencode(bytes:Seq<u8>,rows:Seq<Row>,ends:Seq<usize>,scheme:root_wire::Scheme,n:nat)
    requires n<=rows.len(),payload::snapshot_header(bytes,rows.len() as usize),rows.len()<=usize::MAX,
        ends[0]==17,snapshot::spans(bytes,rows,ends,scheme),
    ensures snapshot::prefix(rows,n,scheme)==bytes.take(ends[n as int] as int),
    decreases n,
{
    if n>0 {
        reencode(bytes,rows,ends,scheme,(n-1) as nat);
        let p=ends[n-1] as int;let q=ends[n as int] as int;
        let wire=snapshot::row_bytes(rows[n-1],scheme);
        assert(root_wire::at(bytes,p,wire));
        assert(bytes.take(q) =~= bytes.take(p)+bytes.subrange(p,q));
    }
}

pub(crate) struct Image<P> {
    pub(crate) bytes:Seq<u8>,
    pub(crate) wire:snapshot::WireRows,
    pub(crate) ends:Seq<usize>,
    pub(crate) keys:Seq<P>,
    pub(crate) loc:ArenaLocation,
}

impl<P> Image<P> {
    spec fn canonical(self,scheme:root_wire::Scheme) -> bool {
        &&& self.wire.len()<=usize::MAX && self.keys.len()==self.wire.len() && self.keys.no_duplicates()
        &&& payload::snapshot_header(self.bytes,self.wire.len() as usize)
        &&& snapshot::layout(self.bytes,17,self.wire.len() as usize,scheme,self.wire,self.ends)
        &&& self.ends.last()==self.bytes.len()
        &&& forall|i:int| 1<=i<self.wire.len() ==> #[trigger] crate::byte_order::below(self.wire[i-1].0,self.wire[i].0)
    }
    pub(crate) closed spec fn restored(self,table:Map<P,(RootState,u64)>) -> bool {
        &&& table.dom()==self.keys.to_set()
        &&& forall|i:int| 0<=i<self.keys.len() ==> (#[trigger] table[self.keys[i]]).1==0 &&
            history::represents(self.wire[i].1,table[self.keys[i]].0)
    }
}

pub(crate) enum Failure<E> { Frame(scan::FrameError<E>), Capacity }

pub(crate) closed spec fn readable<P:Ord,H,D,C>(img:Image<P>,image:Seq<u8>,end:u64,scheme:root_wire::Scheme,limit:u64,hash:H,decode:D,recode:C) -> bool
    where H:Fn([u8;8],u64,&[u8])->[u8;32],D:Fn(&[u8])->Option<P>,C:Fn(&P)->Vec<u8>,
{
        &&& img.canonical(scheme) && img.loc.offset==0
        &&& img.loc.payload_len==img.bytes.len() && img.bytes.len()<=limit && 52+img.bytes.len()<=end
        &&& image.take(52+img.bytes.len() as int)==frame::header_bytes(frame::ROOT_MAGIC,frame::FRAME_VERSION,img.loc.payload_len,img.loc.checksum)+img.bytes
        &&& frame::hashed(hash,frame::ROOT_MAGIC,img.bytes,img.loc.checksum)
        &&& forall|n:u64,b:&[u8]| #[trigger] hash.requires((frame::ROOT_MAGIC,n,b))
        &&& forall|a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ &&
            #[trigger] hash.ensures((frame::ROOT_MAGIC,img.loc.payload_len,a),d) &&
            #[trigger] hash.ensures((frame::ROOT_MAGIC,img.loc.payload_len,b),e) ==> d==e
        &&& obeys_cmp::<P>() && obeys_cmp_concrete_eq::<P>() && forall|b:&[u8]| #[trigger] decode.requires((b,))
        &&& forall|p:&P| #[trigger] recode.requires((p,))
        &&& forall|i:int,n:&[u8],p:Option<P>| 0<=i<img.keys.len() && n@==(#[trigger] img.wire[i]).0 &&
            #[trigger] decode.ensures((n,),p) ==> p==Some(img.keys[i])
        &&& forall|i:int,v:Vec<u8>| 0<=i<img.keys.len() && #[trigger] recode.ensures((&img.keys[i],),v) ==> v@==img.wire[i].0
}

/// Start with empty history. A snapshot is legal only as the first frame.
#[verifier::spinoff_prover]
fn recover<R:scan::FrameReader,P:Ord,H,D,C>(reader:&mut R,end:u64,scheme:root_wire::Scheme,limit:u64,
    hash:H,decode:D,recode:C,Ghost(img):Ghost<Image<P>>)
    -> (out:Result<(BTreeMap<P,(RootState,u64)>,u64),Failure<R::Error>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,
    requires old(reader).position()==0,end==old(reader).image().len(),readable(img,old(reader).image(),end,scheme,limit,hash,decode,recode),
    ensures final(reader).target()==old(reader).target(),final(reader).image()==old(reader).image(),
        match out {
            Ok((table,at))=>btree_map_inv(&table) && img.restored(table@) && final(reader).position()==at==52+img.bytes.len(),
            Err(Failure::Capacity)=>img.keys.len()>0 && final(reader).position()==52+img.bytes.len(),
            Err(Failure::Frame(scan::FrameError::Io(e)))=>old(reader).failed(0,52,e) || exists|r:R| r.target()==old(reader).target() &&
                r.image()==old(reader).image() && r.position()==52 && #[trigger] r.failed(52,img.loc.payload_len,e),
            _=>false,
        },
{
    let f=match crate::hosted_acknowledged_root::scan_written(reader,0,end,limit,frame::ROOT_MAGIC,hash,Ghost(img.loc),Ghost(img.bytes)) {
        Ok(f)=>f,Err(e)=>return Err(Failure::Frame(e)),
    };
    let mut cursor=0;
    let parsed=payload::decode(&f.body,&mut cursor,scheme);
    proof {
        let count=img.wire.len() as usize;
        assert(snapshot::layout(f.body@,17,count,scheme,img.wire,img.ends));
        if let Err(payload::Error::Snapshot(snapshot::CompleteError::End(e)))=&parsed {
            let v=choose|v:Seq<Row>| v.len()==count && #[trigger] snapshot::matches_rows(v,img.wire) &&
                match e {snapshot::EndError::Order=>!snapshot::ordered(v),snapshot::EndError::Trailing=>snapshot::ordered(v) && cursor!=f.body.len()};
            assert forall|i:int| 1<=i<v.len() implies #[trigger] crate::byte_order::below(v[i-1].0@,v[i].0@) by {
                assert(snapshot::row_matches(v[i-1],img.wire[i-1]));assert(snapshot::row_matches(v[i],img.wire[i]));
            }
        }
    }
    let rows=match parsed {
        Ok(payload::Record::Snapshot(rows))=>rows,
        Err(payload::Error::Snapshot(snapshot::CompleteError::Capacity))=>return Err(Failure::Capacity),
        _=>{assert(false);unreached()},
    };
    let ghost original=rows@;
    proof {
        let ends=choose|ends:Seq<usize>| ends[0]==17 && ends[rows.len() as int]==f.body.len() && #[trigger] snapshot::spans(f.body@,rows@,ends,scheme);
        reencode(f.body@,rows@,ends,scheme,rows.len() as nat);
        assert(f.body@.take(f.body.len() as int) =~= f.body@);
    }
    let encode=|entries:&Vec<Row>| -> (out:Result<Vec<u8>,()>)
        ensures match out {Ok(v)=>v@==snapshot::prefix(entries@,entries.len() as nat,scheme),Err(())=>!snapshot::ordered(entries@)},
    {snapshot::encode_ordered(entries,scheme).ok_or(())};
    let wire=Ghost(img.wire);let keys=Ghost(img.keys);
    let owner=|bytes:&Vec<u8>| -> (out:Result<P,()>)
        ensures forall|i:int| 0<=i<keys@.len() && bytes@==(#[trigger] wire@[i]).0 ==> out==Ok(keys@[i]),
    {
        let name=bytes.as_slice();
        let o=history::principal(name,decode,recode);
        proof {
            assert forall|i:int| 0<=i<keys@.len() && bytes@==(#[trigger] wire@[i]).0 implies o==Some(keys@[i]) by {
                if o.is_none() && !decode.ensures((name,),None) {
                    let (p,v)=choose|p:P,v:Vec<u8>| #[trigger] decode.ensures((name,),Some(p)) &&
                        #[trigger] recode.ensures((&p,),v) && v@!=name@;
                    assert(p==keys@[i]);
                }
            }
        }
        o.ok_or(())
    };
    let mut table=BTreeMap::new();
    let result=snapshot::restore(&mut table,0,&f.body,rows,encode,owner);
    proof {
        assert forall|i:int,p:Result<P,()>| 0<=i<original.len() && #[trigger] owner.ensures((&original[i].0,),p) implies p==Ok(img.keys[i]) by {
            assert(snapshot::row_matches(original[i],img.wire[i]));
        }
        assert(result.is_ok());
        let ids=choose|ids:Seq<P>| ids.len()==original.len() && snapshot::decoded(original,ids,owner) && #[trigger] snapshot::image(original,ids,table@);
        assert(ids =~= img.keys) by {
            assert forall|i:int| 0<=i<ids.len() implies #[trigger] ids[i]==img.keys[i] by {assert(owner.ensures((&original[i].0,),Ok(ids[i])));}
        }
        assert forall|i:int| 0<=i<img.keys.len() implies (#[trigger] table@[img.keys[i]]).1==0 &&
            history::represents(img.wire[i].1,table@[img.keys[i]].0) by {
            assert(snapshot::row_matches(original[i],img.wire[i]));
            assert(table@.get(ids[i])==Some((original[i].1,0u64)));
        }
    }
    Ok((table,f.end))
}

pub(crate) enum JournalFailure<E> { Snapshot(Failure<E>), Transition(u64,transitions::Failure<E>) }

pub(crate) closed spec fn matches_history<P>(img:Image<P>,rows:Seq<transitions::Row<P>>,table:Map<P,(RootState,u64)>) -> bool {
    exists|base:Map<P,(RootState,u64)>| img.restored(base) &&
        #[trigger] transitions::accepted(base,rows,rows.len()) && table==transitions::applied(base,rows,rows.len())
}

pub(crate) closed spec fn transition_failure<P,R:scan::FrameReader>(img:Image<P>,rows:Seq<transitions::Row<P>>,image:Seq<u8>,target:(int,Seq<u8>),at:u64,e:transitions::Failure<R::Error>) -> bool {
    exists|base:Map<P,(RootState,u64)>| img.restored(base) && #[trigger] transitions::failed_suffix::<R,P>(base,rows,image,target,at,e)
}

/// The remainder of a compacted journal starts at the exact physical cursor
/// returned for its snapshot and folds into those recovered owners.
#[verifier::spinoff_prover]
pub(crate) fn recover_compacted<R:scan::FrameReader,P:Ord,H,D,C>(reader:&mut R,end:u64,scheme:root_wire::Scheme,limit:u64,
    hash:H,decode:D,recode:C,Ghost(img):Ghost<Image<P>>,Ghost(rows):Ghost<Seq<transitions::Row<P>>>)
    -> (out:Result<BTreeMap<P,(RootState,u64)>,JournalFailure<R::Error>>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,
    requires old(reader).position()==0,end==old(reader).image().len(),readable(img,old(reader).image(),end,scheme,limit,hash,decode,recode),
        transitions::readable_suffix((52+img.bytes.len()) as u64,rows,old(reader).image(),end,scheme,limit,hash,decode,recode),
    ensures final(reader).image()==old(reader).image(),final(reader).target()==old(reader).target(),
        match out {
            Ok(table)=>final(reader).position()==end && btree_map_inv(&table) && matches_history(img,rows,table@),
            Err(JournalFailure::Snapshot(Failure::Capacity))=>img.keys.len()>0 && final(reader).position()==52+img.bytes.len(),
            Err(JournalFailure::Snapshot(Failure::Frame(scan::FrameError::Io(e))))=>old(reader).failed(0,52,e) || exists|r:R| r.target()==old(reader).target() &&
                r.image()==old(reader).image() && r.position()==52 && #[trigger] r.failed(52,img.loc.payload_len,e),
            Err(JournalFailure::Transition(at,e))=>transition_failure::<P,R>(img,rows,old(reader).image(),old(reader).target(),at,e),
            _=>false,
        },
{
    let (base,start)=match recover(reader,end,scheme,limit,hash,decode,recode,Ghost(img)) {
        Ok(pair)=>pair,Err(e)=>return Err(JournalFailure::Snapshot(e)),
    };
    let ghost saved=base@;
    assert(img.restored(saved));
    let out=transitions::scan_suffix(reader,start,end,base,scheme,limit,hash,decode,recode,Ghost(rows));
    match out {
        Ok(table)=>{assert(transitions::accepted(saved,rows,rows.len()));assert(matches_history(img,rows,table@));Ok(table)},
        Err((at,e))=>{assert(transitions::failed_suffix::<R,P>(saved,rows,reader.image(),reader.target(),at,e));assert(transition_failure::<P,R>(img,rows,reader.image(),reader.target(),at,e));Err(JournalFailure::Transition(at,e))},
    }
}

enum RoundTrip<P,WE,RE> {
    Write(payload::WriteError<WE>), Sync(WE), AwaitingContainer,
    Read(Failure<RE>), Loaded(BTreeMap<P,(RootState,u64)>),
}

/// Write the compactor's selected, encoded rows into an empty journal. Only a
/// stable file can be reopened as this independent source of root authority.
#[verifier::spinoff_prover]
fn round_trip<S:frame::ReplayArena,R:scan::FrameReader,P:Ord,H,D,C,O>(file:&mut S,roots:&[Row],scheme:root_wire::Scheme,
    limit:u64,hash:H,decode:D,recode:C,open:O,Ghost(keys):Ghost<Seq<P>>) -> (out:RoundTrip<P,S::Error,R::Error>)
    where H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,D:Fn(&[u8])->Option<P>+Copy,C:Fn(&P)->Vec<u8>+Copy,O:FnOnce(&S)->(R,u64),
    requires old(file).image()==Seq::<u8>::empty(),keys.len()==roots.len(),keys.no_duplicates(),
        obeys_cmp::<P>(),obeys_cmp_concrete_eq::<P>(),
        forall|f:&S| f.target()==old(file).target() && f.stable()==f.image() ==> #[trigger] open.requires((f,)),
        forall|f:&S,p:(R,u64)| #[trigger] open.ensures((f,),p) ==> p.0.image()==f.stable() && p.0.target()==f.target() &&
            p.0.position()==0 && p.1==p.0.image().len(),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((frame::ROOT_MAGIC,n,b)),
        forall|n:u64,a:&[u8],b:&[u8],d:[u8;32],e:[u8;32]| a@==b@ &&
            #[trigger] hash.ensures((frame::ROOT_MAGIC,n,a),d) && #[trigger] hash.ensures((frame::ROOT_MAGIC,n,b),e) ==> d==e,
        forall|b:&[u8]| #[trigger] decode.requires((b,)),forall|p:&P| #[trigger] recode.requires((p,)),
        forall|i:int,b:&[u8],p:Option<P>| 0<=i<keys.len() && b@==(#[trigger] roots@[i]).0@ && #[trigger] decode.ensures((b,),p) ==> p==Some(keys[i]),
        forall|i:int,v:Vec<u8>| 0<=i<keys.len() && #[trigger] recode.ensures((&keys[i],),v) ==> v@==roots@[i].0@,
    ensures final(file).target()==old(file).target(),{
        let raw=snapshot::prefix(roots@,roots.len() as nat,scheme);
        match out {
            RoundTrip::Write(payload::WriteError::Order)=>!snapshot::ordered(roots@) && final(file).image()==old(file).image(),
            RoundTrip::Write(payload::WriteError::Size(n))=>n==raw.len() && n>limit && final(file).image()==old(file).image(),
            RoundTrip::Write(payload::WriteError::Frame(frame::SingleError::Length))=>raw.len()>u64::MAX,
            RoundTrip::Write(payload::WriteError::Frame(frame::SingleError::Seek(e)))=>old(file).seek_failed(e),
            RoundTrip::Write(payload::WriteError::Frame(frame::SingleError::Header(e)))|
                RoundTrip::Write(payload::WriteError::Frame(frame::SingleError::Payload(e)))=>S::write_failed(old(file).target(),e),
            RoundTrip::Sync(e)=>S::sync_failed(old(file).target(),e),
            RoundTrip::AwaitingContainer=>true,
            RoundTrip::Read(Failure::Capacity)=>keys.len()>0 && final(file).stable()==final(file).image(),
            RoundTrip::Read(Failure::Frame(scan::FrameError::Io(e)))=> final(file).stable()==final(file).image() && (
                (exists|r:R| r.target()==old(file).target() && r.image()==final(file).stable() && r.position()==0 && #[trigger] r.failed(0,52,e)) ||
                (exists|r:R| r.target()==old(file).target() && r.image()==final(file).stable() && r.position()==52 && #[trigger] r.failed(52,raw.len() as u64,e))),
            RoundTrip::Loaded(t)=>btree_map_inv(&t) && final(file).image()==final(file).stable() && t@.dom()==keys.to_set() &&
                forall|i:int| 0<=i<keys.len() ==> (#[trigger] t@[keys[i]])==(roots@[i].1,0u64),
            _=>false,
        }
    },
{
    let loc=match payload::append_snapshot(file,roots,scheme,limit,hash) {Ok(loc)=>loc,Err(e)=>return RoundTrip::Write(e)};
    match file.sync_replayed() {
        Err(e)=>return RoundTrip::Sync(e),Ok(crate::frontier::JournalFlush::AwaitingContainer(()))=>return RoundTrip::AwaitingContainer,
        Ok(crate::frontier::JournalFlush::StableFile)=>{},
    }
    let (mut reader,end)=open(file);
    let ghost initial=reader;
    let ghost raw=snapshot::prefix(roots@,roots.len() as nat,scheme);
    let ghost (wire,ends)=choose|wire:snapshot::WireRows,ends:Seq<usize>| #[trigger] snapshot::layout(raw,17,roots.len(),scheme,wire,ends) &&
        snapshot::matches_rows(roots@,wire) && ends.last()==raw.len();
    let ghost img=Image {bytes:raw,wire,ends,keys,loc};
    proof {
        vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
        assert(frame::header_bytes(frame::ROOT_MAGIC,frame::FRAME_VERSION,loc.payload_len,loc.checksum).len()==52);
        assert(reader.image().take(52+raw.len() as int) =~= reader.image());
        assert forall|i:int| 1<=i<wire.len() implies #[trigger] crate::byte_order::below(wire[i-1].0,wire[i].0) by {
            assert(snapshot::row_matches(roots@[i-1],wire[i-1]));assert(snapshot::row_matches(roots@[i],wire[i]));
        }
        assert forall|i:int,b:&[u8],p:Option<P>| 0<=i<keys.len() && b@==(#[trigger] wire[i]).0 && #[trigger] decode.ensures((b,),p) implies p==Some(keys[i]) by {
            assert(snapshot::row_matches(roots@[i],wire[i]));
        }
        assert forall|i:int,v:Vec<u8>| 0<=i<keys.len() && #[trigger] recode.ensures((&keys[i],),v) implies v@==wire[i].0 by {
            assert(snapshot::row_matches(roots@[i],wire[i]));
        }
        assert(readable(img,reader.image(),end,scheme,limit,hash,decode,recode));
    }
    match recover(&mut reader,end,scheme,limit,hash,decode,recode,Ghost(img)) {
        Ok((table,_))=>{
            assert forall|i:int| 0<=i<keys.len() implies (#[trigger] table@[keys[i]])==(roots@[i].1,0u64) by {
                assert(snapshot::row_matches(roots@[i],wire[i]));
                history::unique(wire[i].1,table@[keys[i]].0,roots@[i].1);
            }
            RoundTrip::Loaded(table)
        },
        Err(e)=>{proof {if let Failure::Frame(scan::FrameError::Io(io))=&e {
            if initial.failed(0,52,*io) {assert(initial.target()==file.target());}
        }} RoundTrip::Read(e)},
    }
}
}
