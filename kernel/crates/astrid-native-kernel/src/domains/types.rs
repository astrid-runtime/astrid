//! Authority-bearing types and bounded parsing for native-domain fixtures.

use astrid_system_generation::ContentId;
use astrid_system_generation::emulator_fixture::EMULATOR_COMPONENT_CODE_LEN;

#[cfg(test)]
const FRAME_SIZE: u64 = 4096;
#[cfg(not(test))]
use crate::memory::FRAME_SIZE;

pub const PAGE_SIZE: usize = FRAME_SIZE as usize;
pub const MAX_COMPONENT_BYTES: usize = PAGE_SIZE;
pub const HEADER_LEN: usize = 64;
const HEADER_MAGIC: [u8; 10] = *b"ASTRIDCOMP";
pub const CODE_OFFSET: u64 = HEADER_LEN as u64;
pub const ENTRYPOINT: u64 = 0;
pub const fn stack_base() -> u64 {
    STACK_BASE
}
pub const fn peer_probe(slot: usize) -> u64 {
    PEER_PROBE + slot as u64 * FRAME_SIZE
}
pub const QUOTA_TICKS_LIMIT: u32 = 64;
pub const MAX_STACK_PAGES: usize = 2;
pub const RESOURCE_CAPACITY: usize = 64;
pub const SLOT_CAPACITY: usize = 2;

/// Keep user mappings in a private low-half PML4 subtree, away from the
/// subtree occupied by the supervisor-only kernel-image copy.
const DOMAIN_P4: u64 = 100;
pub const CODE_BASE: u64 = DOMAIN_P4 << 39;
pub const STACK_BASE: u64 = CODE_BASE + 0x4000_0000;
pub const PEER_PROBE: u64 = (DOMAIN_P4 + 1) << 39;
pub const KERNEL_STACK: u64 = CODE_BASE + 0x001f_f000;
pub const KERNEL_STACK_TOP: u64 = KERNEL_STACK + PAGE_SIZE as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    NotInstalled,
    Empty,
    Oversized,
    Malformed,
    HashMismatch,
}

impl BindError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::Empty => "empty",
            Self::Oversized => "oversized",
            Self::Malformed => "malformed",
            Self::HashMismatch => "hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainPagingError {
    FrameExhausted,
    FrameCapacity,
    AccountingMismatch,
    AliasRejected,
    PolicyViolation,
}

impl DomainPagingError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::FrameExhausted => "frame_exhausted",
            Self::FrameCapacity => "frame_capacity",
            Self::AccountingMismatch => "accounting_mismatch",
            Self::AliasRejected => "alias_rejected",
            Self::PolicyViolation => "policy_violation",
        }
    }
}

fn read_u64(bytes: &[u8], range: core::ops::Range<usize>) -> Result<u64, BindError> {
    bytes[range]
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| BindError::Malformed)
}

fn read_u32(bytes: &[u8], range: core::ops::Range<usize>) -> Result<u32, BindError> {
    bytes[range]
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| BindError::Malformed)
}

#[derive(Clone, Copy)]
pub struct ComponentImage {
    bytes: [u8; MAX_COMPONENT_BYTES],
    len: usize,
    code_len: usize,
    stack_pages: usize,
    max_frames: usize,
    quota_ticks: u32,
}

impl ComponentImage {
    pub fn parse(raw: &[u8]) -> Result<Self, BindError> {
        if raw.is_empty() {
            return Err(BindError::Empty);
        }
        if raw.len() > MAX_COMPONENT_BYTES {
            return Err(BindError::Oversized);
        }
        if raw.len() < HEADER_LEN || raw[..HEADER_MAGIC.len()] != HEADER_MAGIC || raw[10] != 1 {
            return Err(BindError::Malformed);
        }
        if raw[11..16] != [0; 5] || read_u64(raw, 48..56)? != 0 || read_u64(raw, 56..64)? != 0 {
            return Err(BindError::Malformed);
        }

        let entrypoint = read_u64(raw, 16..24)?;
        let code_offset = read_u64(raw, 24..32)?;
        let code_len_value = u64::from(read_u32(raw, 32..36)?);
        let stack_pages = read_u32(raw, 36..40)? as usize;
        let max_frames = read_u32(raw, 40..44)? as usize;
        let quota_ticks = read_u32(raw, 44..48)?;
        if entrypoint >= code_len_value
            || entrypoint != ENTRYPOINT
            || code_offset != CODE_OFFSET
            || code_len_value == 0
            || code_len_value > (MAX_COMPONENT_BYTES - HEADER_LEN) as u64
            || raw.len() as u64 != CODE_OFFSET + code_len_value
            || quota_ticks == 0
            || quota_ticks > QUOTA_TICKS_LIMIT
        {
            return Err(BindError::Malformed);
        }
        let code_len = code_len_value as usize;
        if stack_pages == 0
            || stack_pages > MAX_STACK_PAGES
            || max_frames != expected_owned_frames(code_len, stack_pages)
        {
            return Err(BindError::Malformed);
        }

        let mut canonical = [0u8; MAX_COMPONENT_BYTES];
        canonical[..raw.len()].copy_from_slice(raw);
        Ok(Self {
            len: raw.len(),
            code_len,
            stack_pages,
            max_frames,
            quota_ticks,
            bytes: canonical,
        })
    }

    pub fn slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn identity(&self) -> ContentId {
        ContentId::from_payload(self.slice())
    }

    pub fn code(&self) -> &[u8] {
        &self.bytes[HEADER_LEN..HEADER_LEN + self.code_len]
    }

    pub const fn code_len(&self) -> usize {
        self.code_len
    }

    pub const fn stack_pages(&self) -> usize {
        self.stack_pages
    }

    pub const fn owned_frames(&self) -> usize {
        self.max_frames
    }

    pub const fn quota_ticks(&self) -> u32 {
        self.quota_ticks
    }
}

pub const fn expected_owned_frames(code_len: usize, stack_pages: usize) -> usize {
    // One root; independent L3/L2/L1 paths for code, stack, and probe; one
    // guarded transition leaf; and the three APIC path tables. The APIC
    // leaf is backing MMIO, not domain-owned RAM, so it is absent.
    1 + 3 + code_pages_for_len(code_len) + 3 * stack_pages + 3 + 1 + 1 + 3
}

const _: () = assert!(expected_owned_frames(EMULATOR_COMPONENT_CODE_LEN, 1) == 16);

const fn code_pages_for_len(len: usize) -> usize {
    let pages = len.div_ceil(PAGE_SIZE);
    if pages == 0 { 1 } else { pages }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    Exit = 0,
    PageFault = 1,
    Quota = 2,
    PeerProbe = 3,
    CancelOnly = 4,
    // Keep the established fixture scenario values stable while adding the
    // second deliberate fault path.
    InvalidInstruction = 5,
    IpcServer = 6,
    IpcClient = 7,
    IpcPeerFault = 8,
    #[allow(dead_code)]
    IpcCancelServer = 9,
    IpcCancelGuest = 10,
    RunningStop = 11,
}

impl Scenario {
    pub const fn value(self) -> u64 {
        self as u64
    }
}

impl TryFrom<u64> for Scenario {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Exit),
            1 => Ok(Self::PageFault),
            2 => Ok(Self::Quota),
            3 => Ok(Self::PeerProbe),
            4 => Ok(Self::CancelOnly),
            5 => Ok(Self::InvalidInstruction),
            6 => Ok(Self::IpcServer),
            7 => Ok(Self::IpcClient),
            8 => Ok(Self::IpcPeerFault),
            9 => Ok(Self::IpcCancelServer),
            10 => Ok(Self::IpcCancelGuest),
            11 => Ok(Self::RunningStop),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    CleanExit,
    PageFault,
    InvalidInstruction,
    QuotaExhausted,
    Cancelled,
    UnexpectedFault,
}

impl Outcome {
    pub const fn name(self) -> &'static str {
        match self {
            Self::CleanExit => "clean_exit",
            Self::PageFault => "page_fault",
            Self::InvalidInstruction => "invalid_instruction",
            Self::QuotaExhausted => "quota_exhausted",
            Self::Cancelled => "cancelled",
            Self::UnexpectedFault => "unexpected_fault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainGeneration(pub u64);

impl DomainId {
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl DomainGeneration {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainHandle {
    id: DomainId,
    generation: DomainGeneration,
}

impl DomainHandle {
    pub const fn new(id: DomainId, generation: DomainGeneration) -> Self {
        Self { id, generation }
    }

    pub const fn id(self) -> DomainId {
        self.id
    }

    pub const fn generation(self) -> DomainGeneration {
        self.generation
    }
}
