//! Identity and reference fields preserved by the durable frame decoder.
use super::ReferenceKind;
use vstd::prelude::*;

verus! {
/// Logical identity of one canonical typed object.
///
/// The model treats digest construction as an integration boundary. A
/// production implementation derives this value from a domain-separated hash
/// of the object format version, object kind, complete canonical object
/// encoding, and identity-bearing accounting fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    pub closed spec fn raw(self) -> [u8;32] {self.0}
    pub open spec fn digest(self) -> Seq<u8> {self.raw()@}

    pub(crate) proof fn same_digest(a:Self,b:Self)
        requires a.digest() == b.digest(), ensures a == b,
    {assert(a.0 =~= b.0);}
    pub(crate) fn same(&self, other:&Self) -> (equal:bool)
        ensures equal == (*self == *other),
    {
        let equal = self.0.as_slice() == other.0.as_slice();
        if equal { assert(self.0 =~= other.0); }
        equal
    }

    /// Construct an object identifier from its digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> (out:Self) ensures out.digest() == bytes@ {
        Self(bytes)
    }

    /// Borrow the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> (out:&[u8; 32]) ensures out@ == self.digest() {
        &self.0
    }
}

/// Canonical relation label within an immutable object.
///
/// Labels are opaque bytes: individual object schemas decide whether they
/// represent a directory name, KV slot, structural field, or another
/// relation. This wrapper prevents canonical payload bytes, object
/// identifiers, and relation labels from being interchanged accidentally.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferenceLabel<B = Vec<u8>>(B);

impl<B> ReferenceLabel<B> {
    pub closed spec fn value(&self) -> B {self.0}
    /// Construct a typed reference label over owned or borrowed bytes.
    #[must_use]
    pub const fn new(bytes: B) -> (out:Self) ensures out.value() == bytes {
        Self(bytes)
    }

    /// Consume the label and return its underlying byte representation.
    #[must_use]
    pub fn into_inner(self) -> (out:B) ensures out == self.value() {
        self.0
    }
}

/// A typed, labelled reference to another immutable object.
///
/// The label identifies the relation inside the source object: for example a
/// principal-state field, directory name, KV slot, or chunk position.
/// Different labels may intentionally point to the same target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectReference {
    // The parent model validates label order and replaces one target on an owned record.
    pub(super) label: ReferenceLabel,
    pub(super) target: ObjectId,
    pub(super) kind: ReferenceKind,
}

pub(crate) open spec fn before(a:Seq<u8>,b:Seq<u8>) -> bool {
    (a.len() < b.len() && a == b.take(a.len() as int)) ||
        exists|i:int| 0 <= i < a.len() && i < b.len() && a.take(i) == b.take(i) && #[trigger] a[i] < #[trigger] b[i]
}

proof fn first_difference(a:Seq<u8>,b:Seq<u8>,i:int)
    requires 0 <= i < a.len(),i < b.len(),a.take(i) == b.take(i),a[i] != b[i],
    ensures before(a,b) == (a[i] < b[i]),
{
    if a[i] < b[i] {
        assert(exists|j:int| 0 <= j < a.len() && j < b.len() && a.take(j) == b.take(j) && #[trigger] a[j] < #[trigger] b[j]) by {assert(a[i] < b[i]);}
    } else {
        if a.len() < b.len() {assert(b.take(a.len() as int)[i] == b[i]);}
        assert forall|j:int| 0 <= j < a.len() && j < b.len() && a.take(j) == b.take(j) implies !(#[trigger] a[j] < #[trigger] b[j]) by {
            if j < i {assert(a.take(i)[j] == a[j]);assert(b.take(i)[j] == b[j]);}
            if j > i {assert(a.take(j)[i] == a[i]);assert(b.take(j)[i] == b[i]);}
        }
    }
}

/// The first differing byte, or the end of the shorter prefix.
proof fn order_witness(a: Seq<u8>, b: Seq<u8>) -> (i: int)
    requires before(a,b),
    ensures 0 <= i <= a.len(), i < b.len(), a.take(i) == b.take(i),
        i < a.len() ==> a[i] < b[i],
{
    if a.len() < b.len() && a == b.take(a.len() as int) {
        assert(a.take(a.len() as int) =~= a);
        a.len() as int
    } else {
        choose|i:int| 0 <= i < a.len() && i < b.len() && a.take(i) == b.take(i)
            && #[trigger] a[i] < #[trigger] b[i]
    }
}

pub(crate) proof fn order_transitive(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires before(a,b), before(b,c),
    ensures before(a,c),
{
    let i = order_witness(a,b);
    let j = order_witness(b,c);
    let k = if i < j { i } else { j };
    assert forall|h:int| 0 <= h < k implies #[trigger] a.take(k)[h] == c.take(k)[h] by {
        assert(a.take(i)[h] == a[h] && b.take(i)[h] == b[h]);
        assert(b.take(j)[h] == b[h] && c.take(j)[h] == c[h]);
    }
    assert(a.take(k) =~= c.take(k));
    if k == a.len() {
        assert(a.take(k) =~= a);
    } else {
        if i < j { assert(b.take(j)[i] == b[i] && c.take(j)[i] == c[i]); }
        if j < i { assert(a.take(i)[j] == a[j] && b.take(i)[j] == b[j]); }
        assert(a[k] < c[k]);
    }
}

impl ObjectId {
    pub(crate) open spec fn digest_before(a:Seq<u8>, b:Seq<u8>) -> bool {before(a,b)}

    pub(crate) proof fn digest_order_transitive(a:Seq<u8>,b:Seq<u8>,c:Seq<u8>)
        requires a.len() == b.len() == c.len(),before(a,b),before(b,c),
        ensures before(a,c),
    {
        order_transitive(a,b,c);
    }

    pub(crate) fn strictly_before(&self, other:&Self) -> (yes:bool)
        ensures yes == Self::digest_before(self.digest(),other.digest()),
    {
        bytes_before(self.as_bytes(),other.as_bytes())
    }
}

fn bytes_before(a:&[u8], b:&[u8]) -> (yes:bool)
    ensures yes == before(a@,b@),
{
    let end = a.len().min(b.len());
    let mut i = 0usize;
    while i < end
        invariant i <= end,end == (if a.len() <= b.len() {a.len()} else {b.len()}),a@.take(i as int) == b@.take(i as int),
        decreases end-i,
    {
        if a[i] != b[i] {
            proof {first_difference(a@,b@,i as int);}
            return a[i] < b[i];
        }
        // Skip common label prefixes in fixed-width slices so long
        // directory or KV labels do not require one branch per byte.
        if end.saturating_sub(i) >= 16 {
            let next = i.saturating_add(16);
            let left = &a[i..next];
            let right = &b[i..next];
            if left == right {
                assert(left@ =~= right@);
                assert forall|j:int| 0 <= j < next implies a@[j] == b@[j] by {
                    if j < i {assert(a@.take(i as int)[j] == b@.take(i as int)[j]);}
                    else {assert(left@[j-i] == a@[j]);assert(right@[j-i] == b@[j]);}
                }
                assert(a@.take(next as int) =~= b@.take(next as int));
                i = next;
                continue;
            }
        }
        assert(a@.take(i as int+1) =~= b@.take(i as int+1));
        i = i.saturating_add(1);
    }
    assert forall|j:int| 0 <= j < end implies a@[j] == b@[j] by {assert(a@.take(end as int)[j] == a@[j]);}
    if a.len() <= b.len() {assert(a@ =~= a@.take(end as int));}
    a.len() < b.len()
}

impl ObjectReference {
    pub closed spec fn fields(&self) -> (Seq<u8>,ObjectId,ReferenceKind) {
        (self.label.value()@,self.target,self.kind)
    }

    pub(crate) proof fn label_fits(&self)
        ensures self.fields().0.len() <= usize::MAX,
    {assert(self.label.0.len() <= usize::MAX);}

    /// Return the stored target only for a strong ownership relation.
    pub(crate) fn owning_target(&self) -> (out:Option<ObjectId>)
        ensures out == if self.fields().2 is Owns {Some(self.fields().1)} else {None},
    {
        self.kind.owned_target(self.target)
    }

    pub(crate) fn label_bytes(&self) -> (bytes:&[u8]) ensures bytes@ == self.fields().0 {
        self.label.0.as_slice()
    }

    pub(crate) fn duplicate(&self) -> (r:Self) ensures r.fields() == self.fields() {
        let label = self.label.0.clone();
        assert(label@ =~= self.label.0@);
        Self { label:ReferenceLabel(label), target:self.target, kind:self.kind }
    }

    pub(crate) fn label_less_than(&self, label:&[u8]) -> (yes:bool)
        ensures yes == before(self.fields().0,label@),
    {
        bytes_before(self.label.0.as_slice(),label)
    }

    pub(super) fn label_before(&self,next:&Self) -> (yes:bool)
        ensures yes == before(self.fields().0,next.fields().0),
    {
        bytes_before(self.label.0.as_slice(),next.label.0.as_slice())
    }

    /// Construct a typed object reference.
    #[must_use]
    pub const fn new(label: ReferenceLabel, target: ObjectId, kind: ReferenceKind) -> (out:Self)
        ensures out.fields() == (label.value()@,target,kind),
    {
        Self {
            label,
            target,
            kind,
        }
    }

    /// Construct a strong ownership reference.
    #[must_use]
    pub const fn owns(label: ReferenceLabel, target: ObjectId) -> (out:Self)
        ensures out.fields() == (label.value()@,target,ReferenceKind::Owns),
    {
        Self::new(label, target, ReferenceKind::Owns)
    }

    /// Borrow the canonical relation label.
    #[must_use]
    pub const fn label(&self) -> (out:&ReferenceLabel) ensures out.value()@ == self.fields().0 {
        &self.label
    }

    /// Return the referenced object identifier.
    #[must_use]
    pub const fn target(&self) -> (out:ObjectId) ensures out == self.fields().1 {
        self.target
    }

    /// Return the reference's reachability meaning.
    #[must_use]
    pub const fn kind(&self) -> (out:ReferenceKind) ensures out == self.fields().2 {
        self.kind
    }
}

}

impl<B: AsRef<[u8]>> ReferenceLabel<B> {
    /// Borrow the canonical label bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for ReferenceLabel<Vec<u8>> {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for ReferenceLabel<B> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
