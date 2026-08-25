//! Explicit trusted inputs and the result of successful admission.

use crate::error::GenerationError;
use crate::types::{
    ComponentSet, ContentId, Generation, ManifestIdentity, ManifestSizes, SignedSystemGeneration,
};

/// Inert input DTO for constructing the trusted policy boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedInputData {
    pub signer: [u8; 32],
    pub kernel_identity: ContentId,
    pub plan_digest: ContentId,
    pub components: ComponentSet,
    pub object_root: ContentId,
    pub closure_root: ContentId,
    pub generation_floor: Generation,
    pub now_unix_seconds: u64,
    pub sizes: ManifestSizes,
}

/// Facts supplied by an already trusted boot-policy source.
///
/// Nothing in the manifest can replace these expected identities, signer, or
/// rollback floor. The timestamp is also supplied by the verifier rather than
/// read from the manifest's untrusted bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedInput {
    signer: [u8; 32],
    kernel_identity: ContentId,
    plan_digest: ContentId,
    components: ComponentSet,
    object_root: ContentId,
    closure_root: ContentId,
    generation_floor: Generation,
    now_unix_seconds: u64,
    sizes: ManifestSizes,
}

impl TrustedInput {
    pub fn try_new(input: TrustedInputData) -> Result<Self, GenerationError> {
        if input.signer.iter().all(|byte| *byte == 0) {
            return Err(GenerationError::InvalidSigner);
        }
        Ok(Self {
            signer: input.signer,
            kernel_identity: input.kernel_identity,
            plan_digest: input.plan_digest,
            components: input.components,
            object_root: input.object_root,
            closure_root: input.closure_root,
            generation_floor: input.generation_floor,
            now_unix_seconds: input.now_unix_seconds,
            sizes: input.sizes,
        })
    }

    pub const fn signer(self) -> [u8; 32] {
        self.signer
    }

    pub const fn kernel_identity(self) -> ContentId {
        self.kernel_identity
    }

    pub const fn plan_digest(self) -> ContentId {
        self.plan_digest
    }

    pub const fn components(self) -> ComponentSet {
        self.components
    }

    pub const fn object_root(self) -> ContentId {
        self.object_root
    }

    pub const fn closure_root(self) -> ContentId {
        self.closure_root
    }

    pub const fn generation_floor(self) -> Generation {
        self.generation_floor
    }

    pub const fn now_unix_seconds(self) -> u64 {
        self.now_unix_seconds
    }

    pub const fn sizes(self) -> ManifestSizes {
        self.sizes
    }
}

/// An accepted generation whose manifest is now bound to trusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedGeneration {
    signed: SignedSystemGeneration,
    manifest_identity: ManifestIdentity,
}

impl VerifiedGeneration {
    pub(crate) const fn new(
        signed: SignedSystemGeneration,
        manifest_identity: ManifestIdentity,
    ) -> Self {
        Self {
            signed,
            manifest_identity,
        }
    }

    pub const fn manifest(self) -> crate::SystemGenerationManifest {
        self.signed.manifest()
    }

    pub const fn signer(self) -> [u8; 32] {
        self.signed.signer()
    }

    /// Returns the stable identity of the exact canonical signed bytes that
    /// passed verification.
    pub const fn manifest_identity(self) -> ManifestIdentity {
        self.manifest_identity
    }
}
