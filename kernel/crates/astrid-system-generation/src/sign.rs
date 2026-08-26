//! Host/fixture signing. The native verifier does not call this module.

use ed25519_dalek::{Signer, SigningKey};

use crate::codec::{encode_manifest, signature_message};
use crate::types::{MANIFEST_LEN, SignedSystemGeneration, SystemGenerationManifest};

pub(crate) fn sign_manifest(
    signing_key: &SigningKey,
    manifest: crate::SystemGenerationManifest,
) -> SignedSystemGeneration {
    let signature = signing_key.sign(&signature_message(&manifest));
    SignedSystemGeneration {
        manifest,
        signer: signing_key.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
    }
}

/// Canonically encode a host-signed fixture manifest for verifier tests and
/// image tooling. The native verifier never calls this helper.
pub fn signed_bytes(
    signing_key: &SigningKey,
    manifest: SystemGenerationManifest,
) -> [u8; MANIFEST_LEN] {
    encode_manifest(&sign_manifest(signing_key, manifest))
}
