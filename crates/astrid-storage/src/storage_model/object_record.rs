//! Fields of a canonical record admitted by the durable reader and closure walk.
use super::{ObjectClass, ObjectKind, ObjectReference};
use core::num::NonZeroU16;
use vstd::prelude::*;

verus! {
/// Non-zero schema version of one [`ObjectKind`].
///
/// Versions are scoped to a kind so unrelated object families can evolve
/// without rewriting every identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectFormatVersion(NonZeroU16);

impl ObjectFormatVersion {
    pub closed spec fn number(self) -> u16 {self.0@}

    /// Construct a non-zero object-format version.
    #[must_use]
    pub const fn new(value: u16) -> (out:Option<Self>)
        ensures out.is_some() == (value != 0),out matches Some(v) ==> v.number() == value,
    {
        match NonZeroU16::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the numeric schema version.
    #[must_use]
    pub const fn get(self) -> (out:u16) ensures out == self.number() && out != 0 {
        proof {vstd::std_specs::nonzero::axiom_nonzero_is_not_zero(self.0);}
        self.0.get()
    }
}

/// Canonical object bytes and their typed child references.
///
/// `logical_bytes` is the number of user-visible bytes contributed by this
/// object. Structural objects normally contribute zero. The complete canonical
/// record—including payload and references—remains part of retained accounting
/// regardless of class.
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    pub(super) kind: ObjectKind,
    pub(super) format_version: ObjectFormatVersion,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) references: Vec<ObjectReference>,
    pub(super) logical_bytes: u64,
    pub(super) class: ObjectClass,
}


impl Clone for ObjectRecord {
    fn clone(&self) -> Self { self.owned_record() }
}

impl ObjectRecord {
    // Stable widths in the logical canonical record encoding. Durable engines
    // may add framing, checksums, algorithm tags, and indexes; those belong to
    // physical-store accounting rather than a principal's retained quota.
    pub(crate) const FIXED_RETAINED_BYTES: u64 = 2 // object kind
        + 2 // format version
        + 1 // accounting class
        + 8 // logical byte contribution
        + 8 // canonical payload length
        + 8; // reference count
    pub(crate) const FIXED_REFERENCE_BYTES: u64 = 8 // label length
        + 32 // target ObjectId
        + 1; // reference kind

    pub(crate) open spec fn reference_charge(refs: Seq<ObjectReference>, count: nat) -> nat
        decreases count,
    {
        if count == 0 { 0 } else {
            Self::reference_charge(refs, (count - 1) as nat)
                + Self::FIXED_REFERENCE_BYTES as nat + refs[count - 1].fields().0.len()
        }
    }

    proof fn prefix_charge_le(refs: Seq<ObjectReference>, prefix: nat, count: nat)
        requires prefix <= count <= refs.len(),
        ensures Self::reference_charge(refs, prefix) <= Self::reference_charge(refs, count),
        decreases count - prefix,
    {
        if prefix < count { Self::prefix_charge_le(refs, prefix, (count - 1) as nat); }
    }

    pub(crate) open spec fn retained_cost(&self) -> nat {
        Self::FIXED_RETAINED_BYTES as nat + self.contents().2.len()
            + Self::reference_charge(self.contents().3, self.contents().3.len())
    }

    pub(crate) fn retained_usage(&self) -> (out: Option<u64>)
        ensures out.is_some() == (self.retained_cost() <= u64::MAX),
            out matches Some(n) ==> n == self.retained_cost(),
    {
        let bytes = u64::try_from(self.canonical_bytes.len()).ok()?;
        let mut retained = Self::FIXED_RETAINED_BYTES.checked_add(bytes)?;
        let refs = self.references.as_slice();
        let mut i = 0usize;
        while i < refs.len()
            invariant i <= refs.len(), refs@ == self.contents().3,
                retained == Self::FIXED_RETAINED_BYTES as nat + self.contents().2.len()
                    + Self::reference_charge(refs@, i as nat),
            decreases refs.len() - i,
        {
            proof { Self::prefix_charge_le(refs@, i as nat + 1, refs@.len()); }
            let label = u64::try_from(refs[i].label_bytes().len()).ok()?;
            retained = retained.checked_add(Self::FIXED_REFERENCE_BYTES)?.checked_add(label)?;
            i = i.saturating_add(1);
        }
        Some(retained)
    }

pub(crate) open spec fn label_before(a:Seq<u8>,b:Seq<u8>) -> bool {super::object_reference::before(a,b)}

pub(crate) open spec fn labels_ordered(refs:Seq<ObjectReference>) -> bool {
    forall|i:int| 0 < i < refs.len() ==> #[trigger] Self::label_before(refs[i-1].fields().0,refs[i].fields().0)
}

    pub(crate) proof fn ordered_pair(refs: Seq<ObjectReference>, i: int, j: int)
        requires Self::labels_ordered(refs), 0 <= i < j < refs.len(),
        ensures Self::label_before(refs[i].fields().0, refs[j].fields().0),
            !Self::label_before(refs[j].fields().0, refs[i].fields().0),
            refs[i].fields().0 != refs[j].fields().0,
        decreases j - i,
    {
        let a = refs[i].fields().0;
        let b = refs[j].fields().0;
        assert(Self::label_before(refs[j-1].fields().0,b));
        if i < j-1 {
            Self::ordered_pair(refs,i,j-1);
            super::object_reference::order_transitive(a,refs[j-1].fields().0,b);
        }
        if Self::label_before(b,a) {
            super::object_reference::order_transitive(a,b,a);
            assert(!Self::label_before(a,a));
        }
    }

    pub closed spec fn contents(&self) -> (ObjectKind,u16,Seq<u8>,Seq<ObjectReference>,u64,ObjectClass) {
        (self.kind,self.format_version.number(),self.canonical_bytes@,self.references@,self.logical_bytes,self.class)
    }

    pub(crate) proof fn version_nonzero(&self)
        ensures self.contents().1 != 0,
    {
        vstd::std_specs::nonzero::axiom_nonzero_is_not_zero(self.format_version.0);
    }

    pub(crate) open spec fn same_contents(&self,other:&Self) -> bool {
        let a = self.contents();
        let b = other.contents();
        &&& a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.4 == b.4 && a.5 == b.5
        &&& a.3.len() == b.3.len()
        &&& forall|i:int| 0 <= i < a.3.len() ==> (#[trigger] a.3[i]).fields() == (#[trigger] b.3[i]).fields()
    }

    pub(crate) fn owned_record(&self) -> (copy:Self)
        ensures copy.same_contents(self),
    {
        let bytes = self.canonical_bytes.clone();
        assert(bytes@ =~= self.canonical_bytes@);
        let mut refs = Vec::<ObjectReference>::with_capacity(self.references.len());
        let mut i = 0usize;
        while i < self.references.len()
            invariant i <= self.references.len(), refs.len() == i,
                forall|j:int| 0 <= j < i ==> (#[trigger] refs@[j]).fields() == self.references@[j].fields(),
            decreases self.references.len()-i,
        {
            refs.push(self.references[i].duplicate());
            i = i.saturating_add(1);
        }
        Self {kind:self.kind,format_version:self.format_version,canonical_bytes:bytes,
            references:refs,logical_bytes:self.logical_bytes,class:self.class}
    }

    pub(crate) fn from_fields(kind:ObjectKind,format_version:ObjectFormatVersion,canonical_bytes:Vec<u8>,
        references:Vec<ObjectReference>,logical_bytes:u64,class:ObjectClass) -> (out:Option<Self>)
        ensures out.is_some() == Self::labels_ordered(references@),
            out matches Some(r) ==> r.contents() == (kind,format_version.number(),canonical_bytes@,references@,logical_bytes,class),
    {
        let mut i = 1usize;
        while i < references.len()
            invariant i >= 1, forall|j:int| 0 < j < i && j < references.len() ==>
                #[trigger] Self::label_before(references@[j-1].fields().0,references@[j].fields().0),
            decreases references.len()-i,
        {
            let previous = i.saturating_sub(1);
            if !references[previous].label_before(&references[i]) {
                assert(!Self::label_before(references@[i as int-1].fields().0,references@[i as int].fields().0));
                return None;
            }
            assert(Self::label_before(references@[i as int-1].fields().0,references@[i as int].fields().0));
            i = i.saturating_add(1);
        }
        Some(Self{kind,format_version,canonical_bytes,references,logical_bytes,class})
    }

    /// Return the semantic object kind.
    #[must_use]
    pub const fn kind(&self) -> (k:ObjectKind) ensures k == self.contents().0 {self.kind}
    /// Return the kind-scoped schema version.
    #[must_use]
    pub const fn format_version(&self) -> (v:ObjectFormatVersion) ensures v.number() == self.contents().1 {self.format_version}
    /// Borrow the canonical bytes used for collision checking.
    #[must_use]
    pub fn canonical_bytes(&self) -> (b:&[u8]) ensures b@ == self.contents().2 {&self.canonical_bytes}
    /// Borrow the object's child references.
    #[must_use]
    pub fn references(&self) -> (r:&[ObjectReference]) ensures r@ == self.contents().3 {&self.references}
    /// Return the user-visible byte contribution.
    #[must_use]
    pub const fn logical_bytes(&self) -> (n:u64) ensures n == self.contents().4 {self.logical_bytes}
    /// Return the accounting class.
    #[must_use]
    pub const fn class(&self) -> (c:ObjectClass) ensures c == self.contents().5 {self.class}
}
}

impl ObjectFormatVersion {
    /// First schema version for a kind.
    pub const V1: Self = Self(NonZeroU16::MIN);
}
