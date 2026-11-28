//! Encode physical arena frame headers and assign contiguous append locations.
use super::root_wire;
use vstd::prelude::*;

verus! {

pub(super) const ARENA_MAGIC:[u8;8] = *b"ASTOBJ1\0";
pub(super) const ROOT_MAGIC:[u8;8] = *b"ASTROOT\0";
pub(super) const FRAME_VERSION:u16 = 1;

pub(super) const WIDTH: usize = 52;
pub(super) const CHECKSUM_START:usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ArenaLocation {
    pub(super) offset: u64,
    pub(super) payload_len: u64,
    pub(super) checksum: [u8; 32],
}

impl ArenaLocation {
    pub(super) const ENCODED_LEN:usize = 8 + 8 + 32;

    pub(super) open spec fn wire(self) -> Seq<u8> {
        vstd::bytes::spec_u64_to_le_bytes(self.offset) +
            vstd::bytes::spec_u64_to_le_bytes(self.payload_len) + self.checksum@
    }

    pub(super) fn encode(&self, bytes:&mut Vec<u8>)
        ensures final(bytes)@ == old(bytes)@ + self.wire(),
    {
        bytes.extend_from_slice(&root_wire::little_endian(self.offset));
        bytes.extend_from_slice(&root_wire::little_endian(self.payload_len));
        bytes.extend_from_slice(&self.checksum);
        assert(bytes@ =~= old(bytes)@ + self.wire());
    }

    pub(super) fn decode(bytes:&[u8]) -> (out:Option<Self>)
        ensures out.is_some() == (bytes.len() == Self::ENCODED_LEN),
            out matches Some(loc) ==> loc.wire() == bytes@,
    {
        if bytes.len() != Self::ENCODED_LEN {return None;}
        let mut offset = [0;8];
        let mut size = [0;8];
        let mut checksum = [0;32];
        offset.copy_from_slice(&bytes[..8]);
        size.copy_from_slice(&bytes[8..16]);
        checksum.copy_from_slice(&bytes[16..]);
        let loc = Self {offset:u64::from_le_bytes(offset),payload_len:u64::from_le_bytes(size),checksum};
        proof {vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();}
        assert(loc.wire() =~= bytes@);
        Some(loc)
    }

    pub(super) fn end(&self) -> (end:Option<u64>)
        ensures ({
            let e = self.offset as int + WIDTH + self.payload_len;
            end.is_some() == (e <= u64::MAX) && (end matches Some(value) ==> value == e)
        }),
    {
        self.offset.checked_add(WIDTH as u64)?.checked_add(self.payload_len)
    }
}

pub(super) open spec fn header_bytes(magic:[u8;8],version:u16,size:u64,sum:[u8;32]) -> Seq<u8> {
    magic@ + seq![version as u8,(version >> 8) as u8,0u8,0u8] +
        vstd::bytes::spec_u64_to_le_bytes(size) + sum@
}

pub(super) fn header(magic:[u8;8],version:u16,size:u64,sum:[u8;32]) -> (out:[u8;52])
    ensures out@ == header_bytes(magic,version,size,sum),
{
    let mut out = [0u8;52];
    out[..8].copy_from_slice(&magic);
    assert(((version & 255) as u8) == version as u8 && (version & 255) <= 255 && (version >> 8) <= 255) by(bit_vector);
    out[8] = (version & 255) as u8;
    out[9] = (version >> 8) as u8;
    out[12..20].copy_from_slice(&root_wire::little_endian(size));
    out[20..].copy_from_slice(&sum);
    assert(out@ =~= header_bytes(magic,version,size,sum));
    out
}

#[derive(Clone,Copy)]
pub(super) struct DecodedFrameHeader {
    pub(super) payload_len:u64,
    pub(super) checksum:[u8;32],
}

pub(super) enum HeaderError { Version, Reserved }

pub(super) fn magic_matches(bytes:&[u8;52],magic:[u8;8]) -> (ok:bool)
    ensures ok == (bytes@.take(8) == magic@),
{
    let mut i = 0usize;
    while i < 8
        invariant i <= 8, forall|j:int| 0 <= j < i ==> #[trigger] bytes@[j] == magic@[j],
        decreases 8 - i,
    {
        if bytes[i] != magic[i] {assert(bytes@.take(8)[i as int] == bytes@[i as int]);return false;}
        i = i.saturating_add(1);
    }
    assert(bytes@.take(8) =~= magic@);
    true
}

pub(super) fn decode_header(bytes:&[u8;52],version:u16) -> (out:Result<DecodedFrameHeader,HeaderError>)
    ensures ({
        let current = bytes@[8] == version as u8 && bytes@[9] == (version >> 8) as u8;
        let clear = bytes@[10] == 0 && bytes@[11] == 0;
        &&& (out matches Err(HeaderError::Version)) == !current
        &&& (out matches Err(HeaderError::Reserved)) == (current && !clear)
        &&& out matches Ok(h) ==> h.payload_len == vstd::bytes::spec_u64_from_le_bytes(bytes@.subrange(12,20))
            && h.checksum@ == bytes@.subrange(20,52)
    }),
{
    assert(((version & 255) as u8) == version as u8 && (version & 255) <= 255) by(bit_vector);
    if bytes[8] != (version & 255) as u8 || bytes[9] != (version >> 8) as u8 {return Err(HeaderError::Version);}
    if bytes[10] != 0 || bytes[11] != 0 {return Err(HeaderError::Reserved);}
    let mut length = [0u8;8];
    length.copy_from_slice(&bytes[12..20]);
    let mut checksum = [0u8;32];
    checksum.copy_from_slice(&bytes[CHECKSUM_START..]);
    Ok(DecodedFrameHeader {payload_len:u64::from_le_bytes(length),checksum})
}

pub(super) enum PayloadError { Length, Checksum }

pub(super) fn check_payload<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(header:DecodedFrameHeader,magic:[u8;8],
    payload:&[u8],hash:H) -> (out:Result<[u8;32],PayloadError>)
    requires hash.requires((magic,header.payload_len,payload)),
    ensures (out matches Err(PayloadError::Length)) == (payload.len() != header.payload_len),
        out matches Ok(sum) ==> sum == header.checksum && hash.ensures((magic,header.payload_len,payload),sum),
        out matches Err(PayloadError::Checksum) ==> (exists|sum:[u8;32]| sum != header.checksum &&
            #[trigger] hash.ensures((magic,header.payload_len,payload),sum)),
{
    if payload.len() as u64 != header.payload_len {return Err(PayloadError::Length);}
    let actual = hash(magic,header.payload_len,payload);
    if actual.as_slice() != header.checksum.as_slice() {return Err(PayloadError::Checksum);}
    assert(actual =~= header.checksum);
    Ok(actual)
}

pub(super) struct PreparedFrame {
    header: [u8;52],
    payload: Vec<u8>,
    checksum: [u8;32],
}

pub(super) open spec fn hashed<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    hash:H, magic:[u8;8], data:Seq<u8>, sum:[u8;32],
) -> bool {
    exists|p:&[u8]| p@ == data && #[trigger] hash.ensures((magic,data.len() as u64,p),sum)
}

/// Append one borrowed payload to the coalesced batch and return its physical extent.
pub(super) fn extend_batch<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
    encoded:&mut Vec<u8>, base:u64, magic:[u8;8], version:u16, payload:&[u8], hash:H,
) -> (out:Option<ArenaLocation>)
    requires hash.requires((magic,payload.len() as u64,payload)),
    ensures out.is_some() == (base as int + old(encoded).len() <= u64::MAX && payload.len() <= u64::MAX
            && old(encoded).len() as int + WIDTH + payload.len() <= isize::MAX),
        out matches Some(loc) ==> loc.offset == base as int + old(encoded).len()
            && loc.payload_len == payload.len()
            && hash.ensures((magic,loc.payload_len,payload),loc.checksum)
            && final(encoded)@ == old(encoded)@ + header_bytes(magic,version,loc.payload_len,loc.checksum) + payload@,
        out.is_none() ==> final(encoded)@ == old(encoded)@,
{
    let length = encoded.len().checked_add(WIDTH)?.checked_add(payload.len())?;
    if length > isize::MAX as usize {return None;}
    let payload_len = u64::try_from(payload.len()).ok()?;
    let checksum = hash(magic,payload_len,payload);
    let relative = u64::try_from(encoded.len()).ok()?;
    let offset = base.checked_add(relative)?;
    encoded.extend_from_slice(&header(magic,version,payload_len,checksum));
    encoded.extend_from_slice(payload);
    assert(encoded@ =~= old(encoded)@ + header_bytes(magic,version,payload_len,checksum) + payload@);
    Some(ArenaLocation {offset,payload_len,checksum})
}

/// The locations and bytes describe the first rows of the caller's batch in order.
pub(super) open spec fn packed<'a,T:'a,F:Fn(&'a T)->&'a [u8],H:Fn([u8;8],u64,&[u8])->[u8;32]>(
    input:&'a [T],select:F,hash:H,base:u64,magic:[u8;8],version:u16,initial:Seq<u8>,encoded:Seq<u8>,rows:Seq<ArenaLocation>) -> bool
    decreases rows.len(),
{
    if rows.len()==0 {encoded==initial} else {
        let i=rows.len()-1;
        let loc=rows[i];
        let start=loc.offset as int-base;
        &&& i<input.len() && 0<=start<=encoded.len()
        &&& packed(input,select,hash,base,magic,version,initial,encoded.take(start),rows.drop_last())
        &&& exists|body:&[u8]| #[trigger] select.ensures((&input@[i],),body) &&
            body.len()==loc.payload_len && hash.ensures((magic,loc.payload_len,body),loc.checksum) &&
            encoded==encoded.take(start)+header_bytes(magic,version,loc.payload_len,loc.checksum)+body@
    }
}

pub(super) open spec fn refused_at<'a,T:'a,F:Fn(&'a T)->&'a [u8],H:Fn([u8;8],u64,&[u8])->[u8;32]>(
    input:&'a [T],select:F,hash:H,base:u64,magic:[u8;8],version:u16,initial:Seq<u8>,prior:Seq<u8>,r:Seq<ArenaLocation>,b:&[u8]) -> bool {
    &&& r.len()<input.len()
    &&& packed(input,select,hash,base,magic,version,initial,prior,r)
    &&& select.ensures((&input@[r.len() as int],),b)
    &&& base as int+prior.len()>u64::MAX || b.len()>u64::MAX || prior.len()+WIDTH+b.len()>isize::MAX
}

#[verifier::loop_isolation(false)]
pub(super) fn encode_batch<'a,T:'a,F:Fn(&'a T)->&'a [u8],H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy>(
    input:&'a [T],select:F,hash:H,base:u64,magic:[u8;8],version:u16,buffers:(Vec<u8>,Vec<ArenaLocation>))
    -> (out:Option<(Vec<u8>,Vec<ArenaLocation>)>)
    requires buffers.1.len()==0,forall|i:int| 0<=i<input.len() ==> #[trigger] select.requires((&input@[i],)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
    ensures out matches Some((v,r)) ==> r.len()==input.len() && packed(input,select,hash,base,magic,version,buffers.0@,v@,r@),
        out.is_none() ==> exists|prior:Seq<u8>,r:Seq<ArenaLocation>,b:&[u8]|
            #[trigger] refused_at(input,select,hash,base,magic,version,buffers.0@,prior,r,b),
{
    let ghost initial=buffers.0@;
    let (mut encoded,mut rows)=buffers;
    let mut i=0usize;
    while i<input.len()
        invariant i<=input.len(),rows.len()==i,packed(input,select,hash,base,magic,version,initial,encoded@,rows@),
            forall|j:int| 0<=j<input.len() ==> #[trigger] select.requires((&input@[j],)),
            forall|n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
        decreases input.len()-i,
    {
        let body=select(&input[i]);
        let ghost prior=encoded@;
        let Some(loc)=extend_batch(&mut encoded,base,magic,version,body,hash) else {
            assert(refused_at(input,select,hash,base,magic,version,initial,prior,rows@,body));
            return None;
        };
        let ghost previous=rows@;
        rows.push(loc);
        assert(rows@.drop_last() =~= previous);
        assert(encoded@.take(prior.len() as int) =~= prior);
        assert(packed(input,select,hash,base,magic,version,initial,encoded@,rows@));
        i=i.saturating_add(1);
    }
    Some((encoded,rows))
}

/// Sequential writes to an isolated canonical file or volume region.
pub(super) trait BatchFile {
    type Error;
    spec fn image(&self) -> Seq<u8>;
    spec fn target(&self) -> (int,Seq<u8>);
    spec fn cursor(&self) -> int;
    spec fn seek_failed(&self,e:Self::Error) -> bool;
    spec fn write_failed(target:(int,Seq<u8>),e:Self::Error) -> bool;
    fn seek_end(&mut self) -> (out:Result<u64,Self::Error>)
        ensures final(self).target()==old(self).target(),final(self).image()==old(self).image(),
            out matches Err(e) ==> old(self).seek_failed(e),
            out matches Ok(base) ==> base==old(self).image().len() && final(self).cursor()==base;
    fn write_bytes(&mut self,bytes:&[u8]) -> (out:Result<(),Self::Error>)
        requires old(self).cursor()==old(self).image().len(),
        ensures final(self).target()==old(self).target(),
            out matches Err(e) ==> Self::write_failed(old(self).target(),e),
            out.is_ok() ==> final(self).image()==old(self).image()+bytes@ &&
                final(self).cursor()==final(self).image().len();
}

pub(super) type FrameBatch = (Vec<u8>,Vec<ArenaLocation>);

pub(super) enum BatchError<E> { Seek(E), Overflow, Write(E) }

pub(super) fn prepare_at_end<'a,T:'a,F:Fn(&'a T)->&'a [u8],H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,S:BatchFile>(
    file:&mut S,input:&'a [T],select:F,hash:H,magic:[u8;8],version:u16,buffers:(Vec<u8>,Vec<ArenaLocation>))
    -> (out:Result<FrameBatch,BatchError<S::Error>>)
    requires buffers.0.len()==0,buffers.1.len()==0,
        forall|i:int| 0<=i<input.len() ==> #[trigger] select.requires((&input@[i],)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
    ensures final(file).target()==old(file).target(), final(file).image()==old(file).image(),
        out matches Err(BatchError::Seek(e)) ==> old(file).seek_failed(e),
        !(out matches Err(BatchError::Write(_))),
        out matches Err(BatchError::Overflow) ==> exists|prior:Seq<u8>,r:Seq<ArenaLocation>,b:&[u8]|
            #[trigger] refused_at(input,select,hash,old(file).image().len() as u64,magic,version,Seq::empty(),prior,r,b),
        out matches Ok((bytes,rows)) ==> final(file).cursor()==old(file).image().len() &&
            rows.len()==input.len() && packed(input,select,hash,old(file).image().len() as u64,magic,version,Seq::empty(),bytes@,rows@),
{
    let base=match file.seek_end() { Ok(n)=>n,Err(e)=>return Err(BatchError::Seek(e)) };
    assert(buffers.0@ =~= Seq::<u8>::empty());
    assert(base==old(file).image().len() as u64);
    match encode_batch(input,select,hash,base,magic,version,buffers) {
        Some(batch)=>Ok(batch),None=>Err(BatchError::Overflow),
    }
}

/// The locations become available only after the encoded bytes reach the same file.
pub(super) fn append_batch<'a,T:'a,F:Fn(&'a T)->&'a [u8],H:Fn([u8;8],u64,&[u8])->[u8;32]+Copy,S:BatchFile>(
    file:&mut S,input:&'a [T],select:F,hash:H,magic:[u8;8],version:u16,buffers:(Vec<u8>,Vec<ArenaLocation>))
    -> (out:Result<Vec<ArenaLocation>,BatchError<S::Error>>)
    requires buffers.0.len()==0,buffers.1.len()==0,
        forall|i:int| 0<=i<input.len() ==> #[trigger] select.requires((&input@[i],)),
        forall|n:u64,b:&[u8]| #[trigger] hash.requires((magic,n,b)),
    ensures final(file).target()==old(file).target(),
        out matches Ok(rows) ==> rows.len()==input.len() && final(file).cursor()==final(file).image().len() &&
            exists|bytes:Seq<u8>| final(file).image()==old(file).image()+bytes &&
                #[trigger] packed(input,select,hash,old(file).image().len() as u64,magic,version,Seq::empty(),bytes,rows@),
        out matches Err(BatchError::Seek(e)) ==> old(file).seek_failed(e) && final(file).image()==old(file).image(),
        out matches Err(BatchError::Write(e)) ==> S::write_failed(old(file).target(),e),
        out matches Err(BatchError::Overflow) ==> final(file).image()==old(file).image() &&
            exists|prior:Seq<u8>,r:Seq<ArenaLocation>,b:&[u8]|
                #[trigger] refused_at(input,select,hash,old(file).image().len() as u64,magic,version,Seq::empty(),prior,r,b),
{
    let (bytes,rows)=prepare_at_end(file,input,select,hash,magic,version,buffers)?;
    assert(packed(input,select,hash,old(file).image().len() as u64,magic,version,Seq::empty(),bytes@,rows@));
    match file.write_bytes(bytes.as_slice()) {
        Ok(())=>{assert(file.image()==old(file).image()+bytes@);Ok(rows)},
        Err(e)=>Err(BatchError::Write(e)),
    }
}

impl PreparedFrame {
    pub(super) closed spec fn body(self) -> Seq<u8> { self.payload@ }
    pub(super) closed spec fn sum(self) -> [u8;32] { self.checksum }
    pub(super) closed spec fn wire(self) -> Seq<u8> { self.header@ + self.payload@ }

    pub(super) fn prepare<H:FnOnce([u8;8],u64,&[u8])->[u8;32]>(
        magic:[u8;8], version:u16, payload:Vec<u8>, hash:H,
    ) -> (out:Option<Self>)
        requires forall|p:&[u8]| #[trigger] hash.requires((magic,payload.len() as u64,p)),
        ensures out.is_some() == (payload.len() <= u64::MAX),
            out matches Some(f) ==> f.body() == payload@ &&
                f.wire() == header_bytes(magic,version,payload.len() as u64,f.sum()) + payload@ &&
                hashed(hash,magic,payload@,f.sum()),
    {
        let size = u64::try_from(payload.len()).ok()?;
        let p = payload.as_slice();
        let checksum = hash(magic,size,p);
        assert(hash.ensures((magic,size,p),checksum));
        assert(hashed(hash,magic,payload@,checksum));
        let header = header(magic,version,size,checksum);
        Some(Self {header,payload,checksum})
    }

    pub(super) fn payload(&self) -> (out:&[u8]) ensures out@ == self.body() { &self.payload }
    pub(super) fn parts(&self) -> (out:(&[u8],&[u8]))
        ensures out.0@ + out.1@ == self.wire(), out.0.len() == WIDTH, out.1@ == self.body(),
    {
        (self.header.as_slice(),self.payload.as_slice())
    }
    pub(super) fn retained_bytes(&self) -> (out:usize)
        ensures out as int == if self.wire().len() <= usize::MAX {self.wire().len() as int} else {usize::MAX as int},
    {
        self.header.len().saturating_add(self.payload.len())
    }
}

pub(super) open spec fn prefix(frames:Seq<PreparedFrame>,count:nat) -> Seq<u8>
    decreases count,
{
    if count == 0 {Seq::empty()} else {prefix(frames,(count-1) as nat) + frames[count-1].wire()}
}

/// Consume an empty, preallocated output vector. No partial layout escapes on overflow.
pub(super) fn assign(frames:&[PreparedFrame],base:u64,mut locations:Vec<ArenaLocation>)
    -> (out:Option<Vec<ArenaLocation>>)
    requires locations.len() == 0,
    ensures out.is_some() == (base as int + prefix(frames@,frames@.len()).len() <= u64::MAX),
        out matches Some(rows) ==> rows.len() == frames.len() &&
            forall|i:int| 0 <= i < rows.len() ==> {
                let location = #[trigger] rows@[i];
                &&& location.offset as int == base as int + prefix(frames@,i as nat).len()
                &&& location.payload_len == frames@[i].body().len()
                &&& location.checksum == frames@[i].sum()
            },
{
    let mut offset = base;
    let mut i = 0usize;
    while i < frames.len()
        invariant i <= frames.len(), locations.len() == i,
            offset as int == base as int + prefix(frames@,i as nat).len(),
            forall|j:int| 0 <= j < i ==> {
                let location = #[trigger] locations@[j];
                &&& location.offset as int == base as int + prefix(frames@,j as nat).len()
                &&& location.payload_len == frames@[j].body().len()
                &&& location.checksum == frames@[j].sum()
            },
        decreases frames.len()-i,
    {
        let frame = &frames[i];
        let size = frame.payload.len() as u64;
        locations.push(ArenaLocation {offset,payload_len:size,checksum:frame.checksum});
        proof {prefix_monotone(frames@,(i+1) as nat,frames@.len());}
        offset = offset.checked_add(WIDTH as u64)?.checked_add(size)?;
        i = i.saturating_add(1);
    }
    Some(locations)
}

proof fn prefix_monotone(frames:Seq<PreparedFrame>,i:nat,j:nat)
    requires i <= j <= frames.len(),
    ensures prefix(frames,i).len() <= prefix(frames,j).len(),
    decreases j-i,
{
    if i < j {prefix_monotone(frames,i,(j-1) as nat);}
}

pub(super) proof fn segment(frames:Seq<PreparedFrame>,start:nat,end:nat)
    requires start <= end <= frames.len(),
    ensures prefix(frames,end) == prefix(frames,start) +
        prefix(frames.subrange(start as int,end as int),(end-start) as nat),
    decreases end-start,
{
    if end == start {
        assert(prefix(frames,start) + Seq::<u8>::empty() =~= prefix(frames,start));
    } else {
        segment(frames,start,(end-1) as nat);
        let sub = frames.subrange(start as int,end as int);
        let shorter = frames.subrange(start as int,end as int-1);
        same_prefix(shorter,sub,(end-1-start) as nat);
        assert(sub[end-1-start] == frames[end-1]);
    }
}

proof fn same_prefix(a:Seq<PreparedFrame>,b:Seq<PreparedFrame>,n:nat)
    requires n <= a.len(), n <= b.len(), forall|i:int| 0 <= i < n ==> #[trigger] a[i] == #[trigger] b[i],
    ensures prefix(a,n) == prefix(b,n),
    decreases n,
{
    if n > 0 {same_prefix(a,b,(n-1) as nat);}
}

pub(super) trait Sink {
    type Error;
    spec fn sent(&self) -> Seq<u8>;
    spec fn failed(before:Seq<u8>,batch:Seq<PreparedFrame>,error:Self::Error) -> bool;

    fn write_chunk(&mut self, batch:&[PreparedFrame]) -> (out:Result<(),Self::Error>)
        ensures out matches Err(e) ==> Self::failed(old(self).sent(),batch@,e), ({
            let bytes = prefix(batch@,batch@.len());
            if out.is_ok() {final(self).sent() == old(self).sent() + bytes}
            else {exists|n:int| 0 <= n <= bytes.len() && final(self).sent() == old(self).sent() + bytes.take(n)}
        });
}

pub(super) enum AppendError<E> { Overflow, Write(E) }

pub(super) open spec fn failed_step<S:Sink>(initial:Seq<u8>,frames:Seq<PreparedFrame>,size:usize,e:S::Error,lo:int,hi:int) -> bool {
    0 <= lo < hi <= frames.len() && hi-lo <= size &&
        S::failed(initial + prefix(frames,lo as nat),frames.subrange(lo,hi),e)
}

pub(super) open spec fn failed_chunk<S:Sink>(initial:Seq<u8>,frames:Seq<PreparedFrame>,size:usize,e:S::Error) -> bool {
    exists|lo:int,hi:int| #[trigger] failed_step::<S>(initial,frames,size,e,lo,hi)
}

/// Return locations only after every chunk has been accepted by the writer.
pub(super) fn append<S:Sink>(sink:&mut S,frames:&[PreparedFrame],base:u64,empty:Vec<ArenaLocation>,batch_size:usize)
    -> (out:Result<Vec<ArenaLocation>,AppendError<S::Error>>)
    requires empty.len() == 0, batch_size > 0,
    ensures ({
        let bytes = prefix(frames@,frames@.len());
        match out {
            Ok(rows) => {
                &&& final(sink).sent() == old(sink).sent() + bytes
                &&& rows.len() == frames.len()
                &&& forall|i:int| 0 <= i < rows.len() ==> {
                    let loc = #[trigger] rows@[i];
                    &&& loc.offset as int == base as int + prefix(frames@,i as nat).len()
                    &&& loc.payload_len == frames@[i].body().len() && loc.checksum == frames@[i].sum()
                }
            },
            Err(AppendError::Overflow) => base as int + bytes.len() > u64::MAX && final(sink).sent() == old(sink).sent(),
            Err(AppendError::Write(e)) => failed_chunk::<S>(old(sink).sent(),frames@,batch_size,e) &&
                exists|n:int| 0 <= n <= bytes.len() && final(sink).sent() == old(sink).sent() + bytes.take(n),
        }
    }),
{
    let Some(rows) = assign(frames,base,empty) else {return Err(AppendError::Overflow);};
    let mut start = 0usize;
    while start < frames.len()
        invariant batch_size > 0, start <= frames.len(), sink.sent() == old(sink).sent() + prefix(frames@,start as nat),
        decreases frames.len()-start,
    {
        let end = start.saturating_add(batch_size).min(frames.len());
        let batch = &frames[start..end];
        proof {segment(frames@,start as nat,end as nat);}
        let ghost before = sink.sent();
        if let Err(e) = sink.write_chunk(batch) {
            proof {
                assert(S::failed(old(sink).sent()+prefix(frames@,start as nat),frames@.subrange(start as int,end as int),e));
                assert(end as int-start <= batch_size);
                assert(failed_step::<S>(old(sink).sent(),frames@,batch_size,e,start as int,end as int));
                assert(failed_chunk::<S>(old(sink).sent(),frames@,batch_size,e));
                segment(frames@,end as nat,frames@.len());
                let part = prefix(batch@,batch@.len());
                let n = choose|n:int| 0 <= n <= part.len() && sink.sent() == before + part.take(n);
                let k = prefix(frames@,start as nat).len()+n;
                let bytes = prefix(frames@,frames@.len());
                assert(bytes.take(k) =~= prefix(frames@,start as nat)+part.take(n));
                assert(sink.sent() == old(sink).sent()+bytes.take(k));
            }
            return Err(AppendError::Write(e));
        }
        start = end;
    }
    Ok(rows)
}

}
