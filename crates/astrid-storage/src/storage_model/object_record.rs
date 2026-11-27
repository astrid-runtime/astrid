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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    pub(super) kind: ObjectKind,
    pub(super) format_version: ObjectFormatVersion,
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) references: Vec<ObjectReference>,
    pub(super) logical_bytes: u64,
    pub(super) class: ObjectClass,
}


impl ObjectRecord {
pub(crate) open spec fn label_before(a:Seq<u8>,b:Seq<u8>) -> bool {super::object_reference::before(a,b)}

pub(crate) open spec fn labels_ordered(refs:Seq<ObjectReference>) -> bool {
    forall|i:int| 0 < i < refs.len() ==> #[trigger] Self::label_before(refs[i-1].fields().0,refs[i].fields().0)
}

    pub closed spec fn contents(&self) -> (ObjectKind,u16,Seq<u8>,Seq<ObjectReference>,u64,ObjectClass) {
        (self.kind,self.format_version.number(),self.canonical_bytes@,self.references@,self.logical_bytes,self.class)
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
