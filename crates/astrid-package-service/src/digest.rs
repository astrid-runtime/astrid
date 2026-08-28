use blake3::Hasher;
use std::fmt::{Display, Formatter};

macro_rules! digest_alias {
    ($name:ident, $doc:literal, $kind:literal) => {
        #[doc = $doc]
        pub type $name = TypedDigest<$kind>;
    };
}

/// A fixed-size digest tagged by its semantic type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedDigest<const KIND: u8>([u8; 32]);

impl<const KIND: u8> TypedDigest<KIND> {
    /// Creates a digest from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns ownership of the digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

digest_alias!(ContextDigest, "Canonical operation-context digest.", 1);
digest_alias!(StateDigest, "Canonical installed-state digest.", 2);
digest_alias!(PlanDigest, "Canonical lifecycle-plan digest.", 3);
digest_alias!(BudgetDigest, "Canonical resource-budget digest.", 4);
digest_alias!(RequestDigest, "Canonical authenticated-request digest.", 5);
digest_alias!(
    ProvenanceDigest,
    "Canonical attribution-evidence digest.",
    6
);
digest_alias!(Sha256Digest, "Exact SHA-256 artifact digest.", 7);
digest_alias!(Blake3Digest, "Exact BLAKE3 evidence digest.", 8);
digest_alias!(
    AuthorityDecisionDigest,
    "Canonical authenticated-authority decision digest.",
    9
);
digest_alias!(ReceiptDigest, "Canonical operation-receipt digest.", 12);

/// Canonical, field-length-delimited digest input.
#[derive(Default)]
pub struct DigestWriter {
    bytes: Vec<u8>,
}

impl DigestWriter {
    /// Creates empty canonical input.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes a fixed variant or field tag.
    pub fn tag(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Writes a bounded unsigned integer.
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a boolean as exactly one canonical byte.
    pub fn bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    /// Writes a digest as its exact bytes.
    pub fn digest<const KIND: u8>(&mut self, value: &TypedDigest<KIND>) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    /// Length-prefixes canonical bytes.
    pub fn bytes(&mut self, value: &[u8]) {
        self.u64(cast_length(value.len()));
        self.bytes.extend_from_slice(value);
    }

    fn digest_bytes(&self, domain: &'static str) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        hasher.update(&(self.bytes.len() as u64).to_le_bytes());
        hasher.update(&self.bytes);
        *hasher.finalize().as_bytes()
    }

    pub(crate) fn finish<const KIND: u8>(&self, domain: &'static str) -> TypedDigest<KIND> {
        TypedDigest::from_bytes(self.digest_bytes(domain))
    }
}

impl Display for Sha256Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "sha256:{}", hex_lower(self.as_bytes()))
    }
}

impl Display for Blake3Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "blake3:{}", hex_lower(self.as_bytes()))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cast_length(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}
