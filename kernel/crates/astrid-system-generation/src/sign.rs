//! Host/fixture signing. The native verifier does not call this module.

use ed25519_dalek::{Signer, SigningKey};

use crate::codec::signature_message;
use crate::types::SignedSystemGeneration;

#[allow(dead_code)]
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
