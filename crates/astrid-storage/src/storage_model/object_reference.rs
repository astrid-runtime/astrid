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
    pub closed spec fn digest(self) -> Seq<u8> { self.0@ }
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

impl ObjectReference {
    pub closed spec fn fields(&self) -> (Seq<u8>,ObjectId,ReferenceKind) {
        (self.label.value()@,self.target,self.kind)
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
