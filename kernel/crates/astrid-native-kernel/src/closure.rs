//! Ring-0 acceptance of one authenticated policy handoff and dual-closure
//! table. The loader ramdisk is a fixed memory bundle, never a guest
//! filesystem. This remains an emulator fixture: no firmware root, bootloader
//! authentication, relocated-image measurement, or physical-ownership claim.

use astrid_native_closure::{
    AuthenticatedPolicyHandoff, BootContextBinding, BoundIdentities, CURRENT_FLOOR, ClosureError,
    EMULATOR_COMPONENT_LEN, HANDOFF_LEN, HandoffContext, LoaderIdentity, LoaderMeasurement,
    MeasuredIdentity, PolicyGeneration, RootVerifier, TABLE_LEN, TrustedPolicy,
    verify_policy_handoff, verify_table,
};
use astrid_system_generation::emulator_fixture::{
    EMULATOR_CLOSURE_ROOT, EMULATOR_GENERATION_FLOOR, EMULATOR_MANIFEST_SIZES,
    EMULATOR_NOW_UNIX_SECONDS, EMULATOR_OBJECT_ROOT, EMULATOR_PLAN_DIGEST, emulator_components,
};
use astrid_system_generation::{
    ContentId, Generation, GenerationError, MANIFEST_LEN, TrustedInput, TrustedInputData,
    VerifiedGeneration,
};
use bootloader_api::BootInfo;
use bootloader_api::info::LoaderHandoffVerification;
use spin::Mutex;

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

/// The exact ramdisk contract adds the measured native-domain component.
pub const RAMDISK_BUNDLE_LEN: usize =
    HANDOFF_LEN + TABLE_LEN + MANIFEST_LEN + EMULATOR_COMPONENT_LEN;

const _: () = assert!(EMULATOR_COMPONENT_LEN == 517);

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

type ComponentBytes = [u8; EMULATOR_COMPONENT_LEN];

static AUTHENTICATED_COMPONENT: Mutex<Option<ComponentBytes>> = Mutex::new(None);

/// Values accepted only after both the root handoff and closure table verify.
#[derive(Clone, Copy)]
pub struct AcceptedClosure {
    handoff: AuthenticatedPolicyHandoff,
    bound: BoundIdentities,
    kernel_image: MeasuredIdentity,
    closure_table: MeasuredIdentity,
    /// Exact descriptor bytes copied from the loader-owned ramdisk. This is
    /// still untrusted until the caller binds its identity and verifies it.
    sysgen_payload: [u8; MANIFEST_LEN],
    /// Non-empty executable input independently matched to a signed digest.
    component_payload: [u8; EMULATOR_COMPONENT_LEN],
}

/// A verified generation and the one component admitted from its component
/// set. This is the only ring-0 bridge between manifest verification and
/// native-domain admission; its fields stay private so a handle can never be
/// relabeled after admission.
#[derive(Clone, Copy)]
pub struct AdmittedGeneration {
    verified: VerifiedGeneration,
    component: ComponentBytes,
    component_id: ContentId,
}

impl AdmittedGeneration {
    pub const fn verified_generation(&self) -> VerifiedGeneration {
        self.verified
    }

    pub const fn manifest_identity(&self) -> astrid_system_generation::ManifestIdentity {
        self.verified.manifest_identity()
    }

    pub const fn component(&self) -> &ComponentBytes {
        &self.component
    }

    pub const fn component_id(&self) -> ContentId {
        self.component_id
    }
}

impl AcceptedClosure {
    pub const fn handoff(&self) -> AuthenticatedPolicyHandoff {
        self.handoff
    }

    pub const fn bound(&self) -> BoundIdentities {
        self.bound
    }

    pub const fn kernel_image(&self) -> MeasuredIdentity {
        self.kernel_image
    }

    pub const fn closure_table(&self) -> MeasuredIdentity {
        self.closure_table
    }

    pub const fn component(&self) -> &[u8; EMULATOR_COMPONENT_LEN] {
        &self.component_payload
    }
}

pub fn admit_component(
    verified: VerifiedGeneration,
    bytes: &[u8; EMULATOR_COMPONENT_LEN],
) -> Result<AdmittedGeneration, ClosureError> {
    let identity = ContentId::from_payload(bytes);
    let components = verified.manifest().components();
    if components.count() != 1 || components.digest(0) != Some(identity) {
        return Err(ClosureError::BindingMismatch);
    }
    *AUTHENTICATED_COMPONENT.lock() = Some(*bytes);
    Ok(AdmittedGeneration {
        verified,
        component: *bytes,
        component_id: identity,
    })
}

pub fn authenticated_component() -> ComponentBytes {
    AUTHENTICATED_COMPONENT
        .lock()
        .expect("authenticated component is present")
}

pub fn authenticated_component_id() -> ContentId {
    ContentId::from_payload(&authenticated_component())
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
    let table_end = HANDOFF_LEN + TABLE_LEN;
    let table_bytes = &bundle[HANDOFF_LEN..table_end];
    let sysgen_end = table_end + MANIFEST_LEN;
    let sysgen_payload = &bundle[table_end..sysgen_end];
    let component_payload = &bundle[sysgen_end..];
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
    let mut descriptor = [0u8; MANIFEST_LEN];
    descriptor.copy_from_slice(sysgen_payload);
    Ok(AcceptedClosure {
        handoff,
        bound,
        kernel_image,
        closure_table,
        sysgen_payload: descriptor,
        component_payload: component_payload
            .try_into()
            .map_err(|_| ClosureError::Truncated)?,
    })
}

/// Copy the accepted descriptor into a caller-owned kernel buffer before any
/// manifest parsing. The source was already copied out of loader memory by
/// [`accept`], and the destination remains independent of the ramdisk alias.
pub fn copy_system_generation(accepted: &AcceptedClosure, destination: &mut [u8; MANIFEST_LEN]) {
    destination.copy_from_slice(&accepted.sysgen_payload);
}

/// Build the ring-0 trusted input exclusively from authenticated handoff data
/// and compiled emulator fixture values. Manifest fields never populate this
/// policy boundary.
pub fn trusted_system_generation_input(
    accepted: &AcceptedClosure,
) -> Result<TrustedInput, GenerationError> {
    let kernel_identity = ContentId::try_from_bytes(accepted.kernel_image.as_bytes())?;
    let plan_digest = ContentId::try_from_bytes(EMULATOR_PLAN_DIGEST)?;
    let object_root = ContentId::try_from_bytes(EMULATOR_OBJECT_ROOT)?;
    let closure_root = ContentId::try_from_bytes(EMULATOR_CLOSURE_ROOT)?;
    TrustedInput::try_new(TrustedInputData {
        signer: accepted.handoff.policy().sysgen_verify(),
        kernel_identity,
        plan_digest,
        components: emulator_components(),
        object_root,
        closure_root,
        generation_floor: Generation::new(EMULATOR_GENERATION_FLOOR),
        now_unix_seconds: EMULATOR_NOW_UNIX_SECONDS,
        sizes: EMULATOR_MANIFEST_SIZES,
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
