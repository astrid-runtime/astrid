//! Pre-relocation verification for Astrid's fixture policy handoff.
//!
//! This hook runs while the bootloader still owns the original kernel ELF
//! bytes and before `set_up_mappings` can map writable PT_LOAD pages.  It
//! returns bounded evidence for `BootInfo`; ring 0 must bind that evidence to
//! the copied bundle and verify the signatures again.  The public key below
//! is an emulator fixture, not a firmware or production root of trust.

use astrid_native_closure::{
    BootContextBinding, CURRENT_FLOOR, HANDOFF_LEN, HandoffContext, LoaderIdentity,
    LoaderMeasurement, MeasuredIdentity, PolicyGeneration, RootVerifier, TABLE_LEN, TrustedPolicy,
    verify_policy_handoff, verify_table,
};

// Keep this loader-local framing constant in sync with the canonical
// astrid-system-generation manifest length. The bootloader vendor intentionally
// depends only on the closure crate, so changing the descriptor wire layout is
// a deliberate review point rather than an accidental transitive update.
const MANIFEST_LEN: usize = 548;
use bootloader_api::info::LoaderHandoffVerification;

// Keep the bootloader's receipt layout pinned to the ring-0 consumer. These
// assertions fail at compile time if a field is inserted, reordered, or
// receives a different alignment in the vendored ABI.
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

pub const RECEIPT_MAGIC: [u8; 8] = *b"ASTRIDLV";
pub const RECEIPT_VERSION: u8 = 1;
pub const RECEIPT_STATUS_VERIFIED: u8 = 1;

pub const EMULATOR_ROOT_VERIFY_KEY: [u8; 32] = [
    237, 73, 40, 198, 40, 209, 194, 198, 234, 233, 3, 56, 144, 89, 149, 97, 41, 89, 39, 58, 92, 99,
    249, 54, 54, 193, 70, 20, 172, 135, 55, 209,
];

const LOADER_MEASUREMENT_DOMAIN: &[u8] = b"astrid.kimage.loader.measurement.v1";
const LOADER_IDENTITY_DOMAIN: &[u8] = b"astrid.kimage.loader.identity.v1";
const BOOT_CONTEXT_DOMAIN: &[u8] = b"astrid.boot.q35.uefi.tcg.v1";

/// Verify the exact handoff while the loader still owns the original files.
///
/// `kernel_elf` is the original `Kernel.elf.input` byte slice, not a
/// relocated image. `bundle` must be exactly
/// `[ASTRIDPH][ASTRIDDC][ASTRIDSG]`. The resulting receipt contains evidence
/// only; it is not sufficient authority for ring 0 without the second
/// verification there.
pub fn verify_before_mapping(
    kernel_elf: &[u8],
    bundle: &[u8],
) -> Result<LoaderHandoffVerification, &'static str> {
    if bundle.len() != HANDOFF_LEN + TABLE_LEN + MANIFEST_LEN {
        return Err("handoff_length");
    }
    if kernel_elf.is_empty() {
        return Err("kernel_empty");
    }

    let kernel_image = MeasuredIdentity::from_payload(kernel_elf);
    let table_end = HANDOFF_LEN + TABLE_LEN;
    let closure_table = MeasuredIdentity::from_payload(&bundle[HANDOFF_LEN..table_end]);
    let sysgen_payload = &bundle[table_end..];
    let expected = expected_context(kernel_image, closure_table);
    let root = RootVerifier::try_new(
        EMULATOR_ROOT_VERIFY_KEY,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        PolicyGeneration::new(1),
    )
    .map_err(|err| err.as_reason())?;
    let handoff = verify_policy_handoff(&bundle[..HANDOFF_LEN], &root, &expected)
        .map_err(|err| err.as_reason())?;
    let policy = TrustedPolicy::try_new(
        handoff.policy().kernel_verify(),
        handoff.policy().sysgen_verify(),
        handoff.policy().kernel_floor(),
        handoff.policy().sysgen_floor(),
    )
    .map_err(|err| err.as_reason())?;
    let bound =
        verify_table(&bundle[HANDOFF_LEN..table_end], &policy).map_err(|err| err.as_reason())?;
    if bound.sysgen_identity() != MeasuredIdentity::from_payload(sysgen_payload) {
        return Err("binding");
    }

    Ok(LoaderHandoffVerification {
        magic: RECEIPT_MAGIC,
        version: RECEIPT_VERSION,
        status: RECEIPT_STATUS_VERIFIED,
        reserved: [0; 6],
        envelope_digest: MeasuredIdentity::from_payload(&bundle[..HANDOFF_LEN]).as_bytes(),
        kernel_image: kernel_image.as_bytes(),
        closure_table: closure_table.as_bytes(),
        loader_measurement: handoff.policy().context().loader_measurement.as_bytes(),
        loader_identity: handoff.policy().context().loader_identity.as_bytes(),
        boot_context: handoff.policy().context().boot_context.as_bytes(),
        root_verify: handoff.root_verify(),
        kernel_verify: handoff.policy().kernel_verify(),
        sysgen_verify: handoff.policy().sysgen_verify(),
        policy_generation: handoff.policy().policy_generation().get(),
        kernel_floor: handoff.policy().kernel_floor().get(),
        sysgen_floor: handoff.policy().sysgen_floor().get(),
    })
}

pub fn expected_context(
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

#[cfg(test)]
mod tests {
    use super::verify_before_mapping;
    use astrid_native_closure::{HANDOFF_LEN, TABLE_LEN};

    #[test]
    fn legacy_and_noncanonical_ramdisk_lengths_fail_closed() {
        let legacy = vec![0u8; HANDOFF_LEN + TABLE_LEN];
        assert_eq!(
            verify_before_mapping(b"kernel", &legacy),
            Err("handoff_length")
        );

        let truncated = vec![0u8; HANDOFF_LEN + TABLE_LEN + super::MANIFEST_LEN - 1];
        assert_eq!(
            verify_before_mapping(b"kernel", &truncated),
            Err("handoff_length")
        );

        let extended = vec![0u8; HANDOFF_LEN + TABLE_LEN + super::MANIFEST_LEN + 1];
        assert_eq!(
            verify_before_mapping(b"kernel", &extended),
            Err("handoff_length")
        );
    }

    #[test]
    fn exact_length_reaches_content_validation() {
        let exact = vec![0u8; HANDOFF_LEN + TABLE_LEN + super::MANIFEST_LEN];
        assert_eq!(
            verify_before_mapping(&[], &exact),
            Err("kernel_empty"),
            "the canonical length must not be rejected as a legacy bundle"
        );
    }
}
