//! Validated opaque package identities and artifact evidence.

use crate::digest::{DigestWriter, ProvenanceDigest};
use crate::error::{PackageServiceError, PackageServiceResult};
use core::num::NonZeroU64;

macro_rules! opaque_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs the identity, rejecting all-zero bytes.
            ///
            /// # Errors
            /// Returns [`PackageServiceError::ZeroValue`] for a zero identity.
            pub fn from_bytes(bytes: [u8; 32]) -> PackageServiceResult<Self> {
                if bytes == [0; 32] {
                    return Err(PackageServiceError::ZeroValue);
                }
                Ok(Self(bytes))
            }

            /// Returns the exact canonical bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

opaque_id!(
    ServiceIdentity,
    "Opaque identity of the admitted package service generation."
);
opaque_id!(
    PackageObject,
    "Registry-neutral immutable identity of one package object."
);
opaque_id!(
    ArtifactIdentity,
    "Trusted exact-byte artifact identity from the staging boundary."
);
opaque_id!(
    ManifestIdentity,
    "Trusted exact-byte manifest identity from the staging boundary."
);
opaque_id!(
    AuthorityIssuerIdentity,
    "Opaque authority policy or issuer identity."
);
opaque_id!(
    BudgetIdentity,
    "Opaque identity of the budget charged by an operation."
);
opaque_id!(Nonce, "Unique unguessable operation nonce.");

/// The only protocol version understood by this private model.
pub const PROTOCOL_VERSION: u32 = 1;

/// Validated artifact and manifest evidence for one content root.
///
/// The host staging boundary must establish byte identity and content-root
/// semantics before constructing this type. This crate performs no parsing,
/// extraction, transport, or storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedArtifact {
    artifact: ArtifactIdentity,
    manifest: ManifestIdentity,
    artifact_size: NonZeroU64,
    content_root: [u8; 32],
}

impl ValidatedArtifact {
    /// Binds validated artifact, manifest, and exact content-root identities.
    ///
    /// # Errors
    /// Returns [`PackageServiceError::ZeroValue`] for any zero identity or root.
    pub fn new(
        artifact: ArtifactIdentity,
        manifest: ManifestIdentity,
        artifact_size: NonZeroU64,
        content_root: [u8; 32],
    ) -> PackageServiceResult<Self> {
        if content_root == [0; 32] {
            return Err(PackageServiceError::ZeroValue);
        }
        Ok(Self {
            artifact,
            manifest,
            artifact_size,
            content_root,
        })
    }

    /// Returns the exact artifact identity.
    #[must_use]
    pub const fn artifact(&self) -> &ArtifactIdentity {
        &self.artifact
    }

    /// Returns the exact manifest identity.
    #[must_use]
    pub const fn manifest(&self) -> &ManifestIdentity {
        &self.manifest
    }

    /// Returns the exact immutable content root.
    #[must_use]
    pub const fn content_root(&self) -> &[u8; 32] {
        &self.content_root
    }

    /// Returns the exact artifact byte size.
    #[must_use]
    pub const fn artifact_size(&self) -> u64 {
        self.artifact_size.get()
    }

    /// Derives the public canonical provenance digest.
    ///
    /// Consumers use this method instead of duplicating hidden canonical
    /// hashing when constructing an [`crate::OperationContext`].
    #[must_use]
    pub fn provenance_digest(&self) -> ProvenanceDigest {
        let mut writer = DigestWriter::new();
        writer.bytes(self.artifact.as_bytes());
        writer.bytes(self.manifest.as_bytes());
        writer.u64(self.artifact_size.get());
        writer.bytes(&self.content_root);
        writer.finish("astrid.package.provenance.v1")
    }
}
