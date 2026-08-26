//! Host/loader signing. Kernel never calls this path.

use ed25519_dalek::{Signer, SigningKey};

use crate::types::{
    ClosureArtifact, ClosureKind, DualClosureKeys, DualClosureTable, GenerationFloor,
    MeasuredIdentity, signed_message,
};

pub fn sign_artifact(
    signing_key: &SigningKey,
    kind: ClosureKind,
    floor: GenerationFloor,
    identity: MeasuredIdentity,
) -> ClosureArtifact {
    let msg = signed_message(kind, floor, identity);
    let signature = signing_key.sign(&msg);
    ClosureArtifact {
        kind,
        floor,
        identity,
        signer: signing_key.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
    }
}

pub fn sign_kernel_bootstrap(
    signing_key: &SigningKey,
    floor: GenerationFloor,
    kernel_elf: &[u8],
) -> ClosureArtifact {
    sign_artifact(
        signing_key,
        ClosureKind::KernelBootstrap,
        floor,
        MeasuredIdentity::from_payload(kernel_elf),
    )
}

pub fn sign_empty_sysgen(signing_key: &SigningKey, floor: GenerationFloor) -> ClosureArtifact {
    sign_artifact(
        signing_key,
        ClosureKind::SystemGeneration,
        floor,
        MeasuredIdentity::empty_sysgen(),
    )
}

pub fn signed_table(
    kernel_key: &SigningKey,
    sysgen_key: &SigningKey,
    kernel_floor: GenerationFloor,
    sysgen_floor: GenerationFloor,
    kernel_elf: &[u8],
    sysgen_payload: &[u8],
) -> DualClosureTable {
    DualClosureTable {
        min_floor: core::cmp::min(kernel_floor, sysgen_floor),
        keys: DualClosureKeys {
            kernel_bootstrap: kernel_key.verifying_key().to_bytes(),
            system_generation: sysgen_key.verifying_key().to_bytes(),
        },
        kernel: sign_kernel_bootstrap(kernel_key, kernel_floor, kernel_elf),
        sysgen: sign_artifact(
            sysgen_key,
            ClosureKind::SystemGeneration,
            sysgen_floor,
            MeasuredIdentity::from_payload(sysgen_payload),
        ),
    }
}
