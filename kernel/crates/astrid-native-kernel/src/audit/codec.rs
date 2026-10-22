//! Versioned, injective, bounded, length-delimited canonical codec.
//!
//! Every field has a frozen width or an explicit discriminant; every
//! variable region is length-bounded and strictly checked, so each frame has
//! exactly one canonical byte representation and decoding rejects any
//! non-canonical slack.

use core::mem::MaybeUninit;
use core::num::NonZeroU64;

use super::types::{
    AUDIT_MAX_PAYLOAD, AuditCapabilityInstance, AuditCheckpoint, AuditClass, AuditError,
    AuditEvent, AuditObject, AuditObjectKind, AuditRights, AuditSubject, BootSessionId,
    CheckpointAuthContext, DenialContext,
};
use super::{CODEC_VERSION, root};

/// Envelope plus every fixed-width field except payload and the
/// previous-root choice. The widest object variant is a capability instance:
/// projection token, capability slot, capability generation, object kind,
/// object token.
const FRAME_OVERHEAD_BYTES: usize = 4   // total length
    + 2 // codec version
    + 16 // boot/session identity
    + 8 // audit_seq
    + 2 // class
    + 1 + 8 // subject slot + generation
    + 1 // object tag
    + (8 + 1 + 8 + 1 + 8) // widest typed object
    + 2 // rights
    + 2 // payload length
    + 1; // previous-root flag

pub(crate) const MAX_FRAME_BYTES: usize = FRAME_OVERHEAD_BYTES + AUDIT_MAX_PAYLOAD + root::ROOT_LEN;

/// Fixed checkpoint wire size: envelope, codec version, boot, seq, root,
/// relay generation, authority id, kernel tag.
pub(crate) const CHECKPOINT_WIRE_BYTES: usize =
    4 + 2 + 16 + 8 + root::ROOT_LEN + 8 + 8 + root::ROOT_LEN;

/// One canonical frame: the decoded form of the frozen wire representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    boot: BootSessionId,
    seq: u64,
    class: AuditClass,
    subject: AuditSubject,
    object: Option<AuditObject>,
    rights: AuditRights,
    payload: [u8; AUDIT_MAX_PAYLOAD],
    payload_len: usize,
    prev_root: Option<[u8; root::ROOT_LEN]>,
}

impl Frame {
    /// Constructs directly in caller-owned scratch so a live audit transition
    /// does not materialize another frame-sized temporary on the small stack.
    pub(crate) fn write_new<'out>(
        out: &'out mut MaybeUninit<Self>,
        boot: BootSessionId,
        seq: u64,
        event: &AuditEvent,
        prev_root: Option<[u8; root::ROOT_LEN]>,
    ) -> Result<&'out mut Self, AuditError> {
        if event.class() == AuditClass::BoundedDenial {
            if event.object().is_some() {
                return Err(AuditError::UnauthorizedDisclosure);
            }
            if DenialContext::from_payload(event.payload()).is_none() {
                return Err(AuditError::MalformedFrame);
            }
        }
        let mut payload = [0; AUDIT_MAX_PAYLOAD];
        payload[..event.payload().len()].copy_from_slice(event.payload());
        out.write(Self {
            boot,
            seq,
            class: event.class(),
            subject: event.subject(),
            object: event.object(),
            rights: event.rights(),
            payload,
            payload_len: event.payload().len(),
            prev_root,
        });
        // `write` initialized every field, including the bounded payload tail.
        Ok(unsafe { out.assume_init_mut() })
    }

    pub(crate) fn new(
        boot: BootSessionId,
        seq: u64,
        event: &AuditEvent,
        prev_root: Option<[u8; root::ROOT_LEN]>,
    ) -> Result<Self, AuditError> {
        let mut slot = MaybeUninit::uninit();
        Self::write_new(&mut slot, boot, seq, event, prev_root)?;
        // `write_new` initialized the slot before returning success.
        Ok(unsafe { slot.assume_init() })
    }

    pub(crate) fn encode<'out>(
        &self,
        out: &'out mut [u8; MAX_FRAME_BYTES],
    ) -> Result<&'out [u8], AuditError> {
        let mut writer = Writer::new(out);
        writer.skip_total_length()?;
        writer.u16(CODEC_VERSION)?;
        writer.raw(&self.boot.bytes())?;
        writer.u64(self.seq)?;
        if self.class == AuditClass::BoundedDenial && self.object.is_some() {
            return Err(AuditError::UnauthorizedDisclosure);
        }
        writer.u16(self.class.discriminant())?;
        writer.u8(self.subject.slot())?;
        writer.u64(self.subject.generation().get())?;
        match self.object {
            None => writer.u8(0)?,
            Some(AuditObject::Domain { slot, generation }) => {
                writer.u8(1)?;
                writer.u8(slot)?;
                writer.u64(generation.get())?;
            },
            Some(AuditObject::Endpoint {
                pool_index,
                generation,
            }) => {
                writer.u8(2)?;
                writer.u8(pool_index)?;
                writer.u64(generation.get())?;
            },
            Some(AuditObject::CapabilityInstance(instance)) => {
                writer.u8(3)?;
                writer.u64(instance.projection_token().get())?;
                writer.u8(instance.capability_slot())?;
                writer.u64(instance.capability_generation().get())?;
                writer.u8(instance.object_kind().discriminant())?;
                writer.u64(instance.object_token().get())?;
            },
        }
        writer.u16(self.rights.bits())?;
        writer.u16(self.payload_len as u16)?;
        writer.raw(&self.payload[..self.payload_len])?;
        match self.prev_root {
            None => writer.u8(0)?,
            Some(prev_root) => {
                writer.u8(1)?;
                writer.raw(&prev_root)?;
            },
        }
        let end = writer.finish()?;
        Ok(&out[..end])
    }

    pub(crate) fn boot(self) -> BootSessionId {
        self.boot
    }

    pub(crate) fn seq(self) -> u64 {
        self.seq
    }

    pub(crate) fn class(self) -> AuditClass {
        self.class
    }

    pub(crate) fn subject(self) -> AuditSubject {
        self.subject
    }

    pub(crate) fn object(self) -> Option<AuditObject> {
        self.object
    }

    pub(crate) fn rights(self) -> AuditRights {
        self.rights
    }

    pub(crate) fn payload(self) -> [u8; AUDIT_MAX_PAYLOAD] {
        self.payload
    }

    pub(crate) fn payload_len(self) -> usize {
        self.payload_len
    }

    pub(crate) fn prev_root(self) -> Option<[u8; root::ROOT_LEN]> {
        self.prev_root
    }
}

/// Strict canonical decode: unknown codec versions, unknown discriminants,
/// out-of-ceiling values, zero generations, a zero sequence, or any trailing
/// slack fail closed.
pub(crate) fn decode(bytes: &[u8]) -> Result<Frame, AuditError> {
    let mut reader = Reader::new(bytes)?;
    let total = reader.u32()? as usize;
    if bytes.len() - 4 != total {
        return Err(AuditError::MalformedFrame);
    }
    let codec_version = reader.u16()?;
    if codec_version != CODEC_VERSION {
        return Err(AuditError::MalformedFrame);
    }
    let mut boot = [0; 16];
    reader.fill(&mut boot)?;
    let boot = BootSessionId::new(boot).ok_or(AuditError::MalformedFrame)?;
    let seq = reader.u64()?;
    if seq == 0 {
        return Err(AuditError::MalformedFrame);
    }
    let class = AuditClass::from_discriminant(reader.u16()?).ok_or(AuditError::MalformedFrame)?;
    let slot = reader.u8()?;
    let generation = NonZeroU64::new(reader.u64()?).ok_or(AuditError::MalformedFrame)?;
    let subject = AuditSubject::from_parts(slot, generation).ok_or(AuditError::MalformedFrame)?;
    let object = match reader.u8()? {
        0 => None,
        1 => {
            let slot = reader.u8()? as usize;
            let generation = reader.u64()?;
            Some(AuditObject::domain(slot, generation).ok_or(AuditError::MalformedFrame)?)
        },
        2 => {
            let pool_index = reader.u8()? as usize;
            let generation = reader.u64()?;
            Some(AuditObject::endpoint(pool_index, generation).ok_or(AuditError::MalformedFrame)?)
        },
        3 => Some(AuditObject::CapabilityInstance(decode_capability_instance(
            &mut reader,
        )?)),
        _ => return Err(AuditError::MalformedFrame),
    };
    let rights = AuditRights::from_bits(reader.u16()?).ok_or(AuditError::MalformedFrame)?;
    let payload_len = reader.u16()? as usize;
    if payload_len > AUDIT_MAX_PAYLOAD {
        return Err(AuditError::MalformedFrame);
    }
    let mut payload = [0; AUDIT_MAX_PAYLOAD];
    reader.fill(&mut payload[..payload_len])?;
    let prev_root = match reader.u8()? {
        0 => None,
        1 => {
            let mut prev_root = [0; root::ROOT_LEN];
            reader.fill(&mut prev_root)?;
            Some(prev_root)
        },
        _ => return Err(AuditError::MalformedFrame),
    };
    if reader.remaining() != 0 {
        return Err(AuditError::MalformedFrame);
    }
    if class == AuditClass::BoundedDenial {
        // A denial must never carry a foreign object identity, and its
        // payload is exactly the bounded typed context.
        if object.is_some() {
            return Err(AuditError::UnauthorizedDisclosure);
        }
        if DenialContext::from_payload(&payload[..payload_len]).is_none() {
            return Err(AuditError::MalformedFrame);
        }
    }
    Ok(Frame {
        boot,
        seq,
        class,
        subject,
        object,
        rights,
        payload,
        payload_len,
        prev_root,
    })
}

fn decode_capability_instance(
    reader: &mut Reader<'_>,
) -> Result<AuditCapabilityInstance, AuditError> {
    let projection_token = reader.u64()?;
    let capability_slot = reader.u8()? as usize;
    let capability_generation = reader.u64()?;
    let object_kind =
        AuditObjectKind::from_discriminant(reader.u8()?).ok_or(AuditError::MalformedFrame)?;
    let object_token = reader.u64()?;
    AuditCapabilityInstance::try_new(
        projection_token,
        capability_slot,
        capability_generation,
        object_kind,
        object_token,
    )
    .ok_or(AuditError::MalformedFrame)
}

/// Canonical checkpoint wire form: bounded, versioned, and tag-bound. The
/// kernel tag is the authentication; decoding always re-verifies it.
pub(crate) fn encode_checkpoint<'out>(
    checkpoint: &AuditCheckpoint,
    context: &CheckpointAuthContext,
    out: &'out mut [u8; CHECKPOINT_WIRE_BYTES],
) -> Result<&'out [u8], AuditError> {
    if checkpoint.authority_id() != context.authority_id() || !checkpoint.verify_tag(context) {
        return Err(AuditError::CheckpointMismatch);
    }
    let mut writer = Writer::new(out);
    writer.skip_total_length()?;
    writer.u16(checkpoint.codec_version())?;
    writer.raw(&checkpoint.boot().bytes())?;
    writer.u64(checkpoint.seq())?;
    writer.raw(&checkpoint.root())?;
    writer.u64(checkpoint.relay_generation())?;
    writer.u64(checkpoint.authority_id())?;
    writer.raw(&checkpoint.tag())?;
    let end = writer.finish()?;
    Ok(&out[..end])
}

pub(crate) fn decode_checkpoint(
    bytes: &[u8],
    context: &CheckpointAuthContext,
) -> Result<AuditCheckpoint, AuditError> {
    let mut reader = Reader::new(bytes)?;
    let total = reader.u32()? as usize;
    if bytes.len() - 4 != total || bytes.len() != CHECKPOINT_WIRE_BYTES {
        return Err(AuditError::MalformedFrame);
    }
    let codec_version = reader.u16()?;
    if codec_version != CODEC_VERSION {
        return Err(AuditError::MalformedFrame);
    }
    let mut boot = [0; 16];
    reader.fill(&mut boot)?;
    let boot = BootSessionId::new(boot).ok_or(AuditError::MalformedFrame)?;
    let seq = reader.u64()?;
    let mut root_bytes = [0; root::ROOT_LEN];
    reader.fill(&mut root_bytes)?;
    let relay_generation = reader.u64()?;
    let authority_id = reader.u64()?;
    if authority_id != context.authority_id() {
        return Err(AuditError::CheckpointMismatch);
    }
    let mut tag = [0; root::ROOT_LEN];
    reader.fill(&mut tag)?;
    if reader.remaining() != 0 {
        return Err(AuditError::MalformedFrame);
    }
    if relay_generation == 0 {
        return Err(AuditError::MalformedFrame);
    }
    let expected = AuditCheckpoint::seal(boot, seq, root_bytes, relay_generation, context)?;
    if expected.codec_version() != codec_version || expected.tag() != tag {
        return Err(AuditError::CheckpointMismatch);
    }
    Ok(expected)
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn skip_total_length(&mut self) -> Result<(), AuditError> {
        self.raw(&[0; 4])
    }

    fn finish(&mut self) -> Result<usize, AuditError> {
        let total = self.pos - 4;
        let total = u32::try_from(total).map_err(|_| AuditError::EncodeOverflow)?;
        self.buf[0..4].copy_from_slice(&total.to_le_bytes());
        Ok(self.pos)
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), AuditError> {
        if self.buf.len() - self.pos < bytes.len() {
            return Err(AuditError::EncodeOverflow);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), AuditError> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), AuditError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), AuditError> {
        self.raw(&value.to_le_bytes())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, AuditError> {
        if bytes.len() < 4 {
            return Err(AuditError::MalformedFrame);
        }
        Ok(Self { bytes, pos: 0 })
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AuditError> {
        if self.remaining() < len {
            return Err(AuditError::MalformedFrame);
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.bytes[start..self.pos])
    }

    fn fill(&mut self, out: &mut [u8]) -> Result<(), AuditError> {
        out.copy_from_slice(self.take(out.len())?);
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, AuditError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AuditError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, AuditError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, AuditError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
}
