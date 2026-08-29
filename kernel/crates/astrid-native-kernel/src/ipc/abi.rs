//! Frozen private v0 user/kernel wire format and protocol ceilings.

use super::capability::Rights;
use super::error::IpcError;

pub(super) const CAP_SLOTS_PER_DOMAIN: usize = 8;
pub(super) const ENDPOINT_POOL: usize = 4;
pub(super) const CAP_OBJECT_POOL: usize = 16;
pub(super) const QUEUE_DEPTH: usize = 1;
pub(super) const MAX_PAYLOAD_BYTES: usize = 64;
pub const MAX_BUFFER_BYTES: usize = 96;
pub(super) const TRANSFERS_PER_MESSAGE: usize = 1;

pub(super) const OP_ENDPOINT_CREATE: u64 = 1;
pub(super) const OP_SEND: u64 = 2;
pub(super) const OP_RECV: u64 = 3;
pub(super) const OP_CANCEL: u64 = 4;
pub(super) const OP_CAP_REVOKE: u64 = 5;
pub(super) const OP_CAP_IDENTIFY: u64 = 6;

pub(super) const FLAG_TRANSFER: u32 = 1;
const WIRE_RESERVED_OFFSET: usize = 14;
const WIRE_SENDER_DOMAIN_OFFSET: usize = 16;
const WIRE_SENDER_GENERATION_OFFSET: usize = 24;
const WIRE_PAYLOAD_OFFSET: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    EndpointCreate,
    Send,
    Recv,
    Cancel,
    CapRevoke,
    CapIdentify,
}

impl Operation {
    pub(crate) const fn decode(value: u64) -> Option<Self> {
        match value {
            OP_ENDPOINT_CREATE => Some(Self::EndpointCreate),
            OP_SEND => Some(Self::Send),
            OP_RECV => Some(Self::Recv),
            OP_CANCEL => Some(Self::Cancel),
            OP_CAP_REVOKE => Some(Self::CapRevoke),
            OP_CAP_IDENTIFY => Some(Self::CapIdentify),
            _ => None,
        }
    }

    pub(crate) const fn as_name(self) -> &'static str {
        match self {
            Self::EndpointCreate => "endpoint_create",
            Self::Send => "send",
            Self::Recv => "recv",
            Self::Cancel => "cancel",
            Self::CapRevoke => "cap_revoke",
            Self::CapIdentify => "cap_identify",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MessageBuffer {
    tag: u32,
    flags: u32,
    cap_slot: u16,
    requested_rights: u16,
    payload_len: u16,
    payload: [u8; MAX_PAYLOAD_BYTES],
}

impl MessageBuffer {
    pub(super) const fn zeroed() -> Self {
        Self {
            tag: 0,
            flags: 0,
            cap_slot: 0,
            requested_rights: 0,
            payload_len: 0,
            payload: [0; MAX_PAYLOAD_BYTES],
        }
    }

    fn from_wire(wire: &[u8; MAX_BUFFER_BYTES], validate_sender: bool) -> Result<Self, IpcError> {
        if wire[WIRE_RESERVED_OFFSET..WIRE_RESERVED_OFFSET + 2] != [0; 2] {
            return Err(IpcError::Malformed);
        }
        if validate_sender
            && (wire[WIRE_SENDER_DOMAIN_OFFSET..WIRE_SENDER_DOMAIN_OFFSET + 8] != [0; 8]
                || wire[WIRE_SENDER_GENERATION_OFFSET..WIRE_SENDER_GENERATION_OFFSET + 8] != [0; 8])
        {
            return Err(IpcError::Malformed);
        }
        let payload_len = u16::from_le_bytes(fixed(&wire[12..14])?);
        if payload_len as usize > MAX_PAYLOAD_BYTES {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            tag: u32::from_le_bytes(fixed(&wire[0..4])?),
            flags: u32::from_le_bytes(fixed(&wire[4..8])?),
            cap_slot: u16::from_le_bytes(fixed(&wire[8..10])?),
            requested_rights: u16::from_le_bytes(fixed(&wire[10..12])?),
            payload_len,
            payload: fixed(&wire[WIRE_PAYLOAD_OFFSET..WIRE_PAYLOAD_OFFSET + MAX_PAYLOAD_BYTES])?,
        })
    }

    pub(super) fn parse_send(wire: &[u8; MAX_BUFFER_BYTES]) -> Result<Self, IpcError> {
        Self::from_wire(wire, true)
    }

    pub(super) fn parse_recv(wire: &[u8; MAX_BUFFER_BYTES]) -> Result<Self, IpcError> {
        Self::from_wire(wire, false)
    }

    pub(super) fn into_wire(
        self,
        sender: super::capability::DomainToken,
    ) -> [u8; MAX_BUFFER_BYTES] {
        let mut wire = [0u8; MAX_BUFFER_BYTES];
        wire[0..4].copy_from_slice(&self.tag.to_le_bytes());
        wire[4..8].copy_from_slice(&self.flags.to_le_bytes());
        wire[8..10].copy_from_slice(&self.cap_slot.to_le_bytes());
        wire[10..12].copy_from_slice(&self.requested_rights.to_le_bytes());
        wire[12..14].copy_from_slice(&self.payload_len.to_le_bytes());
        wire[WIRE_SENDER_DOMAIN_OFFSET..WIRE_SENDER_DOMAIN_OFFSET + 8]
            .copy_from_slice(&u64::from(sender.slot().get()).to_le_bytes());
        wire[WIRE_SENDER_GENERATION_OFFSET..WIRE_SENDER_GENERATION_OFFSET + 8]
            .copy_from_slice(&sender.generation().get().to_le_bytes());
        wire[WIRE_PAYLOAD_OFFSET..WIRE_PAYLOAD_OFFSET + MAX_PAYLOAD_BYTES]
            .copy_from_slice(&self.payload);
        wire
    }

    pub(super) const fn tag(self) -> u32 {
        self.tag
    }

    pub(super) const fn flags(self) -> u32 {
        self.flags
    }

    pub(super) const fn payload_len(self) -> usize {
        self.payload_len as usize
    }

    pub(super) const fn payload(self) -> [u8; MAX_PAYLOAD_BYTES] {
        self.payload
    }

    pub(super) const fn cap_slot(self) -> u16 {
        self.cap_slot
    }

    pub(super) const fn set_payload_len(&mut self, payload_len: u16) {
        self.payload_len = payload_len;
    }

    pub(super) fn set_message(
        &mut self,
        tag: u32,
        flags: u32,
        payload_len: u16,
        payload: [u8; MAX_PAYLOAD_BYTES],
    ) {
        self.tag = tag;
        self.flags = flags;
        self.payload_len = payload_len;
        self.payload = payload;
    }

    #[cfg(test)]
    pub(super) fn set_cap_slot(&mut self, cap_slot: u16) {
        self.cap_slot = cap_slot;
    }

    pub(super) fn payload_mut(&mut self) -> &mut [u8; MAX_PAYLOAD_BYTES] {
        &mut self.payload
    }

    pub(super) fn requested_rights(self) -> Result<Rights, IpcError> {
        Rights::from_bits(self.requested_rights).ok_or(IpcError::Denied)
    }
}

fn fixed<const LEN: usize>(bytes: &[u8]) -> Result<[u8; LEN], IpcError> {
    match bytes.try_into() {
        Ok(value) => Ok(value),
        Err(_) => Err(IpcError::Malformed),
    }
}
