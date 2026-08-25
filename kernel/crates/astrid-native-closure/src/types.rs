//! Domain types for the dual-closure stub.

/// Canonical empty System Generation payload. No services.
pub const EMPTY_SYSGEN: &[u8] = b"astrid.sysgen.empty.v1";

/// Current emulator-stub generation floor. Not an A/B selector.
///
/// This value is the emulator [`crate::TrustedPolicy`] minimum for both
/// closures. Verification uses the policy minima, never the table header.
pub const CURRENT_FLOOR: GenerationFloor = GenerationFloor(1);

pub const MAGIC: &[u8; 8] = b"ASTRIDDC";
pub const VERSION: u8 = 1;
pub const DOMAIN: &[u8; 17] = b"astrid.closure.v1";
pub const KIND_LEN: usize = 1;
pub const FLOOR_LEN: usize = 8;
pub const ID_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const ARTIFACT_LEN: usize = KIND_LEN + FLOOR_LEN + ID_LEN + KEY_LEN + SIG_LEN;
pub const HEADER_LEN: usize = 8 + 1 + 8 + KEY_LEN + KEY_LEN;
pub const TABLE_LEN: usize = HEADER_LEN + ARTIFACT_LEN * 2;
pub const SIGNED_LEN: usize = 17 + KIND_LEN + FLOOR_LEN + ID_LEN;

/// Which signed artifact this is. The two kinds must stay distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClosureKind {
    KernelBootstrap = 1,
    SystemGeneration = 2,
}

impl ClosureKind {
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::KernelBootstrap),
            2 => Some(Self::SystemGeneration),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelBootstrap => "kernel-bootstrap",
            Self::SystemGeneration => "system-generation",
        }
    }
}

/// Monotonic generation floor. Below-min artifacts are stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GenerationFloor(u64);

impl GenerationFloor {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(bytes))
    }
}

/// Monotonic generation of an authenticated loader policy.
///
/// This is separate from the two artifact floors: a policy can advance its
/// generation while retaining independent rollback floors for kernel and
/// System Generation artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyGeneration(u64);

impl PolicyGeneration {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(bytes))
    }
}

/// A fixed-size loader measurement binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoaderMeasurement([u8; 32]);

impl LoaderMeasurement {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A fixed-size loader identity binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoaderIdentity([u8; 32]);

impl LoaderIdentity {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A fixed-size boot-context binding supplied independently by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootContextBinding([u8; 32]);

impl BootContextBinding {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// blake3 measurement of a closure payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasuredIdentity([u8; 32]);

impl MeasuredIdentity {
    pub fn from_payload(payload: &[u8]) -> Self {
        Self(*blake3::hash(payload).as_bytes())
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn write_hex(self, out: &mut [u8; 64]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, byte) in self.0.iter().enumerate() {
            out[i * 2] = HEX[(byte >> 4) as usize];
            out[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
        }
    }

    pub fn empty_sysgen() -> Self {
        Self::from_payload(EMPTY_SYSGEN)
    }
}

/// One signed closure artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosureArtifact {
    pub kind: ClosureKind,
    pub floor: GenerationFloor,
    pub identity: MeasuredIdentity,
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

/// Untrusted key advertisement in the table header. Verification ignores this
/// and uses [`crate::TrustedPolicy`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DualClosureKeys {
    pub kernel_bootstrap: [u8; 32],
    pub system_generation: [u8; 32],
}

/// Decoded table before cryptographic acceptance.
///
/// `min_floor` and `keys` are untrusted header copies. They must not choose
/// verifying keys or rollback policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DualClosureTable {
    pub min_floor: GenerationFloor,
    pub keys: DualClosureKeys,
    pub kernel: ClosureArtifact,
    pub sysgen: ClosureArtifact,
}

/// Identities accepted after verification. Floors stay independent.
///
/// The accepted facts are opaque so an untrusted caller cannot forge a bound
/// selector result by constructing or mutating the record directly.
///
/// ```compile_fail
/// use astrid_native_closure::BoundIdentities;
/// fn cannot_forge(value: BoundIdentities) {
///     let _ = value.kernel_bootstrap;
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundIdentities {
    kernel_bootstrap: MeasuredIdentity,
    system_generation: MeasuredIdentity,
    kernel_floor: GenerationFloor,
    sysgen_floor: GenerationFloor,
}

impl BoundIdentities {
    pub(crate) const fn from_verified(
        kernel_bootstrap: MeasuredIdentity,
        system_generation: MeasuredIdentity,
        kernel_floor: GenerationFloor,
        sysgen_floor: GenerationFloor,
    ) -> Self {
        Self {
            kernel_bootstrap,
            system_generation,
            kernel_floor,
            sysgen_floor,
        }
    }

    pub const fn kernel_identity(self) -> MeasuredIdentity {
        self.kernel_bootstrap
    }

    pub const fn sysgen_identity(self) -> MeasuredIdentity {
        self.system_generation
    }

    pub const fn kernel_floor(self) -> GenerationFloor {
        self.kernel_floor
    }

    pub const fn sysgen_floor(self) -> GenerationFloor {
        self.sysgen_floor
    }

    pub fn distinct(self) -> bool {
        self.kernel_identity() != self.sysgen_identity()
    }
}

pub fn signed_message(
    kind: ClosureKind,
    floor: GenerationFloor,
    identity: MeasuredIdentity,
) -> [u8; SIGNED_LEN] {
    let mut msg = [0u8; SIGNED_LEN];
    msg[..17].copy_from_slice(DOMAIN);
    msg[17] = kind.to_u8();
    msg[18..26].copy_from_slice(&floor.to_le_bytes());
    msg[26..58].copy_from_slice(&identity.as_bytes());
    msg
}
