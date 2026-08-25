//! Fixed-size authenticated loader policy handoff.
//!
//! This is a private, no-std contract fixture. It deliberately stops at a
//! root-signed statement and does not wire a firmware loader, production root,
//! or kernel boot path.

use crate::error::ClosureError;
use crate::types::{
    BootContextBinding, GenerationFloor, LoaderIdentity, LoaderMeasurement, MeasuredIdentity,
    PolicyGeneration,
};

pub const HANDOFF_MAGIC: &[u8; 8] = b"ASTRIDPH";
pub const HANDOFF_VERSION: u8 = 1;
pub const HANDOFF_DOMAIN: &[u8; 24] = b"astrid.policy.handoff.v1";

const MAGIC_LEN: usize = 8;
const VERSION_LEN: usize = 1;
const DOMAIN_LEN: usize = 24;
const LENGTH_LEN: usize = 2;
const KEY_LEN: usize = 32;
const FLOOR_LEN: usize = 8;
const GENERATION_LEN: usize = 8;
const DIGEST_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// Prefix carries a root key identifier that must match the explicit verifier
/// input; it never selects the verifier.
pub const HANDOFF_PREFIX_LEN: usize = MAGIC_LEN + VERSION_LEN + DOMAIN_LEN + LENGTH_LEN + KEY_LEN;
pub const HANDOFF_BODY_LEN: usize = KEY_LEN * 2 + FLOOR_LEN * 2 + GENERATION_LEN + DIGEST_LEN * 5;
pub const HANDOFF_SIGNED_LEN: usize = HANDOFF_PREFIX_LEN + HANDOFF_BODY_LEN;
pub const HANDOFF_LEN: usize = HANDOFF_SIGNED_LEN + SIGNATURE_LEN;

/// Runtime values that prevent replay into another boot context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandoffContext {
    pub kernel_image: MeasuredIdentity,
    pub closure_table: MeasuredIdentity,
    pub loader_measurement: LoaderMeasurement,
    pub loader_identity: LoaderIdentity,
    pub boot_context: BootContextBinding,
}

impl HandoffContext {
    pub const fn new(
        kernel_image: MeasuredIdentity,
        closure_table: MeasuredIdentity,
        loader_measurement: LoaderMeasurement,
        loader_identity: LoaderIdentity,
        boot_context: BootContextBinding,
    ) -> Self {
        Self {
            kernel_image,
            closure_table,
            loader_measurement,
            loader_identity,
            boot_context,
        }
    }
}

/// Root-authorized subordinate policy and its bound boot context.
///
/// The fields are intentionally opaque outside this crate. Host signing uses
/// [`PolicyHandoff::for_signing`] only when the explicit `sign` feature is
/// enabled; runtime callers can obtain a value only from verification.
///
/// ```compile_fail
/// use astrid_native_closure::PolicyHandoff;
/// fn cannot_forge(value: PolicyHandoff) {
///     let _ = value.kernel_verify;
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyHandoff {
    kernel_verify: [u8; 32],
    sysgen_verify: [u8; 32],
    kernel_floor: GenerationFloor,
    sysgen_floor: GenerationFloor,
    policy_generation: PolicyGeneration,
    context: HandoffContext,
}

impl PolicyHandoff {
    pub(crate) const fn from_parts(
        kernel_verify: [u8; 32],
        sysgen_verify: [u8; 32],
        kernel_floor: GenerationFloor,
        sysgen_floor: GenerationFloor,
        policy_generation: PolicyGeneration,
        context: HandoffContext,
    ) -> Self {
        Self {
            kernel_verify,
            sysgen_verify,
            kernel_floor,
            sysgen_floor,
            policy_generation,
            context,
        }
    }

    /// Construct a host-only statement for signing.
    ///
    /// Runtime verification never exposes a public raw constructor. This
    /// entry point exists only for the explicit `sign` feature (and tests),
    /// which is used by the fixture image builder.
    #[cfg(any(test, feature = "sign"))]
    pub fn for_signing(
        kernel_verify: [u8; 32],
        sysgen_verify: [u8; 32],
        kernel_floor: GenerationFloor,
        sysgen_floor: GenerationFloor,
        policy_generation: PolicyGeneration,
        context: HandoffContext,
    ) -> Self {
        Self::from_parts(
            kernel_verify,
            sysgen_verify,
            kernel_floor,
            sysgen_floor,
            policy_generation,
            context,
        )
    }

    pub const fn kernel_verify(self) -> [u8; 32] {
        self.kernel_verify
    }

    pub const fn sysgen_verify(self) -> [u8; 32] {
        self.sysgen_verify
    }

    pub const fn kernel_floor(self) -> GenerationFloor {
        self.kernel_floor
    }

    pub const fn sysgen_floor(self) -> GenerationFloor {
        self.sysgen_floor
    }

    pub const fn policy_generation(self) -> PolicyGeneration {
        self.policy_generation
    }

    pub const fn context(self) -> HandoffContext {
        self.context
    }
}

/// Values returned only after the root signature and all bindings pass.
///
/// ```compile_fail
/// use astrid_native_closure::AuthenticatedPolicyHandoff;
/// fn cannot_forge(value: AuthenticatedPolicyHandoff) {
///     let _ = value.policy;
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedPolicyHandoff {
    root_verify: [u8; 32],
    policy: PolicyHandoff,
}

impl AuthenticatedPolicyHandoff {
    pub(crate) const fn from_verified(root_verify: [u8; 32], policy: PolicyHandoff) -> Self {
        Self {
            root_verify,
            policy,
        }
    }

    pub const fn root_verify(self) -> [u8; 32] {
        self.root_verify
    }

    pub const fn policy(self) -> PolicyHandoff {
        self.policy
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DecodedHandoff {
    pub root_verify: [u8; 32],
    pub policy: PolicyHandoff,
    pub signature: [u8; 64],
}

pub(crate) fn decode_handoff(bytes: &[u8]) -> Result<DecodedHandoff, ClosureError> {
    if bytes.is_empty() {
        return Err(ClosureError::Missing);
    }
    if bytes.len() != HANDOFF_LEN {
        return Err(ClosureError::Truncated);
    }
    if bytes[..MAGIC_LEN] != HANDOFF_MAGIC[..]
        || bytes[MAGIC_LEN] != HANDOFF_VERSION
        || bytes[MAGIC_LEN + VERSION_LEN..MAGIC_LEN + VERSION_LEN + DOMAIN_LEN]
            != HANDOFF_DOMAIN[..]
    {
        return Err(ClosureError::Malformed);
    }

    let length_offset = MAGIC_LEN + VERSION_LEN + DOMAIN_LEN;
    let encoded_len = u16::from_le_bytes([bytes[length_offset], bytes[length_offset + 1]]);
    if usize::from(encoded_len) != HANDOFF_LEN {
        return Err(ClosureError::Truncated);
    }

    let mut root_verify = [0u8; KEY_LEN];
    root_verify.copy_from_slice(&bytes[HANDOFF_PREFIX_LEN - KEY_LEN..HANDOFF_PREFIX_LEN]);
    let body = &bytes[HANDOFF_PREFIX_LEN..HANDOFF_SIGNED_LEN];
    let mut offset = 0;
    let kernel_verify = take_key(body, &mut offset);
    let sysgen_verify = take_key(body, &mut offset);
    let kernel_floor = take_floor(body, &mut offset);
    let sysgen_floor = take_floor(body, &mut offset);
    let policy_generation = take_generation(body, &mut offset);
    let kernel_image = take_identity(body, &mut offset);
    let closure_table = take_identity(body, &mut offset);
    let loader_measurement = LoaderMeasurement::from_bytes(take_binding(body, &mut offset));
    let loader_identity = LoaderIdentity::from_bytes(take_binding(body, &mut offset));
    let boot_context = BootContextBinding::from_bytes(take_binding(body, &mut offset));
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(&bytes[HANDOFF_SIGNED_LEN..HANDOFF_LEN]);

    Ok(DecodedHandoff {
        root_verify,
        policy: PolicyHandoff::from_parts(
            kernel_verify,
            sysgen_verify,
            kernel_floor,
            sysgen_floor,
            policy_generation,
            HandoffContext::new(
                kernel_image,
                closure_table,
                loader_measurement,
                loader_identity,
                boot_context,
            ),
        ),
        signature,
    })
}

pub(crate) fn encode_unsigned(
    root_verify: &[u8; KEY_LEN],
    policy: &PolicyHandoff,
) -> [u8; HANDOFF_SIGNED_LEN] {
    let mut out = [0u8; HANDOFF_SIGNED_LEN];
    out[..MAGIC_LEN].copy_from_slice(HANDOFF_MAGIC);
    out[MAGIC_LEN] = HANDOFF_VERSION;
    out[MAGIC_LEN + VERSION_LEN..MAGIC_LEN + VERSION_LEN + DOMAIN_LEN]
        .copy_from_slice(HANDOFF_DOMAIN);
    let length_offset = MAGIC_LEN + VERSION_LEN + DOMAIN_LEN;
    out[length_offset..length_offset + LENGTH_LEN]
        .copy_from_slice(&(HANDOFF_LEN as u16).to_le_bytes());
    out[HANDOFF_PREFIX_LEN - KEY_LEN..HANDOFF_PREFIX_LEN].copy_from_slice(root_verify);

    let body = &mut out[HANDOFF_PREFIX_LEN..HANDOFF_SIGNED_LEN];
    let mut offset = 0;
    put_key(body, &mut offset, &policy.kernel_verify());
    put_key(body, &mut offset, &policy.sysgen_verify());
    put_floor(body, &mut offset, policy.kernel_floor());
    put_floor(body, &mut offset, policy.sysgen_floor());
    put_generation(body, &mut offset, policy.policy_generation());
    let context = policy.context();
    put_identity(body, &mut offset, context.kernel_image);
    put_identity(body, &mut offset, context.closure_table);
    put_binding(body, &mut offset, context.loader_measurement);
    put_binding(body, &mut offset, context.loader_identity);
    put_binding(body, &mut offset, context.boot_context);
    out
}

#[cfg(any(test, feature = "sign"))]
pub fn sign_policy_handoff(
    root_key: &ed25519_dalek::SigningKey,
    policy: &PolicyHandoff,
) -> [u8; HANDOFF_LEN] {
    use ed25519_dalek::Signer;

    let root_verify = root_key.verifying_key().to_bytes();
    let unsigned = encode_unsigned(&root_verify, policy);
    let signature = root_key.sign(&unsigned).to_bytes();
    let mut out = [0u8; HANDOFF_LEN];
    out[..HANDOFF_SIGNED_LEN].copy_from_slice(&unsigned);
    out[HANDOFF_SIGNED_LEN..].copy_from_slice(&signature);
    out
}

fn take_key(body: &[u8], offset: &mut usize) -> [u8; KEY_LEN] {
    let mut value = [0u8; KEY_LEN];
    value.copy_from_slice(&body[*offset..*offset + KEY_LEN]);
    *offset += KEY_LEN;
    value
}

fn take_floor(body: &[u8], offset: &mut usize) -> GenerationFloor {
    let mut value = [0u8; FLOOR_LEN];
    value.copy_from_slice(&body[*offset..*offset + FLOOR_LEN]);
    *offset += FLOOR_LEN;
    GenerationFloor::from_le_bytes(value)
}

fn take_generation(body: &[u8], offset: &mut usize) -> PolicyGeneration {
    let mut value = [0u8; GENERATION_LEN];
    value.copy_from_slice(&body[*offset..*offset + GENERATION_LEN]);
    *offset += GENERATION_LEN;
    PolicyGeneration::from_le_bytes(value)
}

fn take_identity(body: &[u8], offset: &mut usize) -> MeasuredIdentity {
    let mut value = [0u8; DIGEST_LEN];
    value.copy_from_slice(&body[*offset..*offset + DIGEST_LEN]);
    *offset += DIGEST_LEN;
    MeasuredIdentity::from_bytes(value)
}

fn take_binding(body: &[u8], offset: &mut usize) -> [u8; DIGEST_LEN] {
    let mut value = [0u8; DIGEST_LEN];
    value.copy_from_slice(&body[*offset..*offset + DIGEST_LEN]);
    *offset += DIGEST_LEN;
    value
}

fn put_key(body: &mut [u8], offset: &mut usize, value: &[u8; KEY_LEN]) {
    body[*offset..*offset + KEY_LEN].copy_from_slice(value);
    *offset += KEY_LEN;
}

fn put_floor(body: &mut [u8], offset: &mut usize, value: GenerationFloor) {
    body[*offset..*offset + FLOOR_LEN].copy_from_slice(&value.to_le_bytes());
    *offset += FLOOR_LEN;
}

fn put_generation(body: &mut [u8], offset: &mut usize, value: PolicyGeneration) {
    body[*offset..*offset + GENERATION_LEN].copy_from_slice(&value.to_le_bytes());
    *offset += GENERATION_LEN;
}

fn put_identity(body: &mut [u8], offset: &mut usize, value: MeasuredIdentity) {
    body[*offset..*offset + DIGEST_LEN].copy_from_slice(&value.as_bytes());
    *offset += DIGEST_LEN;
}

fn put_binding<T: BindingBytes>(body: &mut [u8], offset: &mut usize, value: T) {
    body[*offset..*offset + DIGEST_LEN].copy_from_slice(&value.binding_bytes());
    *offset += DIGEST_LEN;
}

trait BindingBytes {
    fn binding_bytes(self) -> [u8; DIGEST_LEN];
}

impl BindingBytes for LoaderMeasurement {
    fn binding_bytes(self) -> [u8; DIGEST_LEN] {
        LoaderMeasurement::as_bytes(self)
    }
}

impl BindingBytes for LoaderIdentity {
    fn binding_bytes(self) -> [u8; DIGEST_LEN] {
        LoaderIdentity::as_bytes(self)
    }
}

impl BindingBytes for BootContextBinding {
    fn binding_bytes(self) -> [u8; DIGEST_LEN] {
        BootContextBinding::as_bytes(self)
    }
}
