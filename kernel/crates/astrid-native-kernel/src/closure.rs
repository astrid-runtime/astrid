//! Ring-0 acceptance of one authenticated policy handoff and dual-closure
//! table. The loader ramdisk is a fixed memory bundle, never a guest
//! filesystem. This remains an emulator fixture: no firmware root, bootloader
//! authentication, relocated-image measurement, or physical-ownership claim.

use astrid_native_closure::{
    AuthenticatedPolicyHandoff, BootContextBinding, BoundIdentities, CURRENT_FLOOR, ClosureError,
    HANDOFF_LEN, HandoffContext, LoaderIdentity, LoaderMeasurement, MeasuredIdentity,
    PolicyGeneration, RootVerifier, TABLE_LEN, TrustedPolicy, verify_policy_handoff, verify_table,
};
use bootloader_api::BootInfo;
use bootloader_api::info::LoaderHandoffVerification;

// Keep ring 0's view of the loader receipt pinned to the vendored
// bootloader/common producer. A layout drift would otherwise turn the
// evidence fields into a differently interpreted byte stream.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<LoaderHandoffVerification>() == 328);
    assert!(align_of::<LoaderHandoffVerification>() == 8);
    assert!(offset_of!(LoaderHandoffVerification, magic) == 0);
    assert!(offset_of!(LoaderHandoffVerification, envelope_digest) == 16);
    assert!(offset_of!(LoaderHandoffVerification, kernel_image) == 48);
    assert!(offset_of!(LoaderHandoffVerification, closure_table) == 80);
    assert!(offset_of!(LoaderHandoffVerification, root_verify) == 208);
    assert!(offset_of!(LoaderHandoffVerification, policy_generation) == 304);
    assert!(offset_of!(LoaderHandoffVerification, kernel_floor) == 312);
    assert!(offset_of!(LoaderHandoffVerification, sysgen_floor) == 320);
};

/// The exact ramdisk contract is `[ASTRIDPH; 379][ASTRIDDC; 355]`.
pub const RAMDISK_BUNDLE_LEN: usize = HANDOFF_LEN + TABLE_LEN;

/// Emulator fixture root public key corresponding to the explicit root seed
/// in `tools/kimage/fixtures/root.key.hex`. The envelope's root-key field is
/// informational and never selects this verifier.
pub const EMULATOR_ROOT_VERIFY_KEY: [u8; 32] = [
    237, 73, 40, 198, 40, 209, 194, 198, 234, 233, 3, 56, 144, 89, 149, 97, 41, 89, 39, 58, 92, 99,
    249, 54, 54, 193, 70, 20, 172, 135, 55, 209,
];

const LOADER_MEASUREMENT_DOMAIN: &[u8] = b"astrid.kimage.loader.measurement.v1";
const LOADER_IDENTITY_DOMAIN: &[u8] = b"astrid.kimage.loader.identity.v1";
const BOOT_CONTEXT_DOMAIN: &[u8] = b"astrid.boot.q35.uefi.tcg.v1";

/// Values accepted only after both the root handoff and closure table verify.
#[derive(Clone, Copy)]
pub struct AcceptedClosure {
    pub handoff: AuthenticatedPolicyHandoff,
    pub bound: BoundIdentities,
    pub kernel_image: MeasuredIdentity,
    pub closure_table: MeasuredIdentity,
}

pub fn accept(boot_info: &BootInfo) -> Result<AcceptedClosure, ClosureError> {
    let mut bundle = [0u8; RAMDISK_BUNDLE_LEN];
    copy_ramdisk(boot_info, &mut bundle)?;

    let receipt = boot_info
        .loader_handoff
        .into_option()
        .ok_or(ClosureError::Missing)?;
    if receipt.magic != *b"ASTRIDLV"
        || receipt.version != 1
        || receipt.status != 1
        || receipt.reserved != [0; 6]
    {
        return Err(ClosureError::Malformed);
    }

    // The loader measured the original Kernel.elf.input before writable
    // PT_LOAD mappings existed. Ring 0 never hashes BootInfo::kernel_addr:
    // those pages may alias the relocated image and can change after entry.
    let kernel_image = MeasuredIdentity::from_bytes(receipt.kernel_image);
    let table_bytes = &bundle[HANDOFF_LEN..];
    let closure_table = MeasuredIdentity::from_bytes(receipt.closure_table);
    if MeasuredIdentity::from_payload(&bundle[..HANDOFF_LEN]).as_bytes() != receipt.envelope_digest
        || MeasuredIdentity::from_payload(table_bytes).as_bytes() != receipt.closure_table
    {
        return Err(ClosureError::BindingMismatch);
    }
    let expected = expected_context(kernel_image, closure_table);
    if receipt.loader_measurement != expected.loader_measurement.as_bytes()
        || receipt.loader_identity != expected.loader_identity.as_bytes()
        || receipt.boot_context != expected.boot_context.as_bytes()
    {
        return Err(ClosureError::BindingMismatch);
    }
    let root = RootVerifier::try_new(
        EMULATOR_ROOT_VERIFY_KEY,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        PolicyGeneration::new(1),
    )?;
    let handoff = verify_policy_handoff(&bundle[..HANDOFF_LEN], &root, &expected)?;
    let policy_handoff = handoff.policy();
    if handoff.root_verify() != receipt.root_verify
        || policy_handoff.kernel_verify() != receipt.kernel_verify
        || policy_handoff.sysgen_verify() != receipt.sysgen_verify
        || policy_handoff.policy_generation().get() != receipt.policy_generation
        || policy_handoff.kernel_floor().get() != receipt.kernel_floor
        || policy_handoff.sysgen_floor().get() != receipt.sysgen_floor
    {
        return Err(ClosureError::BindingMismatch);
    }
    let policy = TrustedPolicy::try_new(
        policy_handoff.kernel_verify(),
        policy_handoff.sysgen_verify(),
        policy_handoff.kernel_floor(),
        policy_handoff.sysgen_floor(),
    )?;
    let bound = verify_table(table_bytes, &policy)?;
    Ok(AcceptedClosure {
        handoff,
        bound,
        kernel_image,
        closure_table,
    })
}

fn expected_context(
    kernel_image: MeasuredIdentity,
    closure_table: MeasuredIdentity,
) -> HandoffContext {
    HandoffContext::new(
        kernel_image,
        closure_table,
        LoaderMeasurement::from_bytes(
            MeasuredIdentity::from_payload(LOADER_MEASUREMENT_DOMAIN).as_bytes(),
        ),
        LoaderIdentity::from_bytes(
            MeasuredIdentity::from_payload(LOADER_IDENTITY_DOMAIN).as_bytes(),
        ),
        BootContextBinding::from_bytes(
            MeasuredIdentity::from_payload(BOOT_CONTEXT_DOMAIN).as_bytes(),
        ),
    )
}

fn copy_ramdisk(
    boot_info: &BootInfo,
    destination: &mut [u8; RAMDISK_BUNDLE_LEN],
) -> Result<(), ClosureError> {
    let Some(addr) = boot_info.ramdisk_addr.into_option() else {
        return Err(ClosureError::Missing);
    };
    if boot_info.ramdisk_len != RAMDISK_BUNDLE_LEN as u64 {
        return Err(ClosureError::Truncated);
    }
    crate::memory::prove_readable_range(addr, boot_info.ramdisk_len)?;
    // SAFETY: the range was proven readable above; the helper also rejects
    // overlap with this kernel-owned destination before forming a source
    // slice or invoking the non-overlapping copy primitive.
    unsafe { crate::memory::copy_readable_range(addr, destination) }
}
