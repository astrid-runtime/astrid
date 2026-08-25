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

    // BootInfo::kernel_addr/kernel_len name the physical raw ELF span. The
    // proof checks the active physical mapping before forming any slice.
    let kernel_image =
        crate::memory::measure_physical_span(boot_info.kernel_addr, boot_info.kernel_len)?;
    let table_bytes = &bundle[HANDOFF_LEN..];
    let closure_table = MeasuredIdentity::from_payload(table_bytes);
    let expected = expected_context(kernel_image, closure_table);
    let root = RootVerifier::try_new(
        EMULATOR_ROOT_VERIFY_KEY,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        PolicyGeneration::new(1),
    )?;
    let handoff = verify_policy_handoff(&bundle[..HANDOFF_LEN], &root, &expected)?;
    let policy = TrustedPolicy::try_new(
        handoff.policy.kernel_verify,
        handoff.policy.sysgen_verify,
        handoff.policy.kernel_floor,
        handoff.policy.sysgen_floor,
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
    // SAFETY: the exact canonical range and every covering page were proven
    // readable immediately above; this copies only into kernel-owned storage.
    unsafe { crate::memory::copy_readable_range(addr, destination) };
    Ok(())
}
