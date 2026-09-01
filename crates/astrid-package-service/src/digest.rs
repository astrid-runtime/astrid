//! Canonical, domain-separated hashing for the private package contract.

use blake3::Hasher;

macro_rules! digest_alias {
    ($name:ident, $doc:literal, $kind:literal) => {
        #[doc = $doc]
        pub type $name = TypedDigest<$kind>;
    };
}

/// A fixed-size digest tagged by its semantic domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedDigest<const KIND: u8>([u8; 32]);

impl<const KIND: u8> TypedDigest<KIND> {
    /// Constructs a digest from its exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns whether the digest is non-zero.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.0.iter().any(|byte| *byte != 0)
    }

    /// Returns whether two semantically distinct digests have identical bytes.
    #[must_use]
    pub fn eq_bytes<const OTHER: u8>(&self, other: &TypedDigest<OTHER>) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .all(|(left, right)| left == right)
    }
}

digest_alias!(
    ProvenanceDigest,
    "Canonical digest of validated artifact and manifest provenance.",
    1
);
digest_alias!(StateDigest, "Canonical digest of one installed state.", 2);
digest_alias!(PlanDigest, "Canonical digest of a lifecycle plan.", 3);
digest_alias!(
    BudgetDigest,
    "Canonical digest of the operation resource budget.",
    4
);
digest_alias!(
    ContextDigest,
    "Canonical digest of one complete operation context.",
    5
);
digest_alias!(
    AuthorityDigest,
    "Canonical digest of an authenticated authority decision.",
    6
);
digest_alias!(
    ReceiptDigest,
    "Canonical digest of a terminal operation receipt.",
    7
);
digest_alias!(
    RuntimeReceiptDigest,
    "Exact runtime receipt digest supplied by the execution boundary.",
    8
);

/// Length-delimited canonical digest input.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DigestWriter {
    chunks: Vec<Vec<u8>>,
    bytes_len: usize,
}

impl DigestWriter {
    /// Creates an empty canonical input.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes a closed variant or field tag.
    pub fn tag(&mut self, value: u8) {
        self.push(&[value]);
    }

    /// Writes a little-endian unsigned integer.
    pub fn u64(&mut self, value: u64) {
        self.push(&value.to_le_bytes());
    }

    /// Writes one canonical boolean byte.
    pub fn bool(&mut self, value: bool) {
        self.push(&[u8::from(value)]);
    }

    /// Length-prefixes arbitrary bytes.
    pub fn bytes(&mut self, value: &[u8]) {
        let mut framed = u64::try_from(value.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes()
            .to_vec();
        framed.extend_from_slice(value);
        self.push_vec(framed);
    }

    /// Writes a digest as its exact bytes.
    pub fn digest<const KIND: u8>(&mut self, value: &TypedDigest<KIND>) {
        self.push(value.as_bytes());
    }

    /// Completes a digest under the supplied unique semantic domain.
    #[must_use]
    pub fn finish<const KIND: u8>(&self, domain: &'static str) -> TypedDigest<KIND> {
        let mut hasher = Hasher::new();
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        hasher.update(
            &(u64::try_from(self.bytes_len)
                .unwrap_or(u64::MAX)
                .to_le_bytes()),
        );
        // Fields remain separate so fixed canonical framing is not combined
        // with operation nonce bytes before hashing.
        for chunk in &self.chunks {
            hasher.update(chunk);
        }
        TypedDigest::from_bytes(*hasher.finalize().as_bytes())
    }

    fn push(&mut self, bytes: &[u8]) {
        self.push_vec(bytes.to_vec());
    }

    fn push_vec(&mut self, bytes: Vec<u8>) {
        self.bytes_len = self.bytes_len.saturating_add(bytes.len());
        self.chunks.push(bytes);
    }
}
