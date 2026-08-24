//! Immutable guest-image identity for the portable machine fixture.
//!
//! Images are crate-private synthetic instruction sequences. They are not a
//! Linux userspace artifact, `BusyBox` ABI, or host-file ingest.

use astrid_provider::ProviderError;
use astrid_resource_types::ApplicationGenerationRef;

use crate::machine::MachineError;

/// Maximum admitted instruction image. Larger payloads fail closed.
pub const MAX_IMAGE_BYTES: usize = 256;

/// Domain tag mixed into crate-local image identity.
const IMAGE_IDENTITY_DOMAIN: [u8; 32] = *b"astrid.realm-compat.guest-img.v1";

/// Immutable identity of one admitted guest image. Not a CAS digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuestImageId([u8; 32]);

impl GuestImageId {
    /// Raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Application-generation slot used to bind this image into a closure.
    #[must_use]
    pub const fn application_generation(self) -> ApplicationGenerationRef {
        ApplicationGenerationRef::from_bytes(self.0)
    }
}

/// Admitted instruction image. Bytes are copied into a bounded buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestImage {
    bytes: [u8; MAX_IMAGE_BYTES],
    len: u16,
    id: GuestImageId,
}

impl GuestImage {
    /// Admit a bounded instruction image and bind its identity.
    ///
    /// # Errors
    ///
    /// Empty, oversized, or unaligned images return [`MachineError::InvalidImage`].
    pub fn admit(bytes: &[u8]) -> Result<Self, MachineError> {
        if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES || !bytes.len().is_multiple_of(4) {
            return Err(MachineError::InvalidImage);
        }
        let mut image = [0_u8; MAX_IMAGE_BYTES];
        image
            .get_mut(..bytes.len())
            .ok_or(MachineError::InvalidImage)?
            .copy_from_slice(bytes);
        Ok(Self {
            bytes: image,
            len: u16::try_from(bytes.len()).map_err(|_| MachineError::InvalidImage)?,
            id: identity_of(bytes),
        })
    }

    /// Identity verified before execution.
    #[must_use]
    pub const fn id(self) -> GuestImageId {
        self.id
    }

    /// Admitted bytes. Not a host path.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// `addi a0, x0, 0; ecall` — synthetic exit status 0.
pub const SYNTHETIC_EXIT_ZERO: [u8; 8] = image8(encode_addi(10, 0, 0), ECALL);

/// `addi a0, x0, 7; ecall` — synthetic exit status 7.
pub const SYNTHETIC_EXIT_SEVEN: [u8; 8] = image8(encode_addi(10, 0, 7), ECALL);

const ECALL: u32 = 0x0000_0073;

/// Resolve a closure application slot onto a known synthetic image.
///
/// # Errors
///
/// Unknown identities are [`ProviderError::TypeMismatch`].
pub fn known_image(application: ApplicationGenerationRef) -> Result<GuestImage, ProviderError> {
    let zero = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).map_err(|_| ProviderError::InvalidLength)?;
    if application.as_bytes() == zero.id().as_bytes() {
        return Ok(zero);
    }
    let seven =
        GuestImage::admit(&SYNTHETIC_EXIT_SEVEN).map_err(|_| ProviderError::InvalidLength)?;
    if application.as_bytes() == seven.id().as_bytes() {
        return Ok(seven);
    }
    Err(ProviderError::TypeMismatch)
}

pub(crate) const fn encode_addi(rd: u32, rs1: u32, immediate: u32) -> u32 {
    ((immediate & 0x0fff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
}

#[cfg(test)]
pub(crate) const fn encode_store(rs1: u32, rs2: u32, immediate: u32, funct3: u32) -> u32 {
    (((immediate >> 5) & 0x7f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((immediate & 0x1f) << 7)
        | 0x23
}

#[cfg(test)]
pub(crate) const fn encode_load(rd: u32, rs1: u32, immediate: u32, funct3: u32) -> u32 {
    ((immediate & 0x0fff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x03
}

#[cfg(test)]
pub(crate) const fn encode_jal(rd: u32, imm: u32) -> u32 {
    let bit20 = (imm >> 20) & 1;
    let bit10_1 = (imm >> 1) & 0x3ff;
    let bit11 = (imm >> 11) & 1;
    let bit19_12 = (imm >> 12) & 0xff;
    (bit20 << 31) | (bit10_1 << 21) | (bit11 << 20) | (bit19_12 << 12) | (rd << 7) | 0x6f
}

const fn image8(word0: u32, word1: u32) -> [u8; 8] {
    let a = word0.to_le_bytes();
    let b = word1.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

fn identity_of(bytes: &[u8]) -> GuestImageId {
    let mut id = IMAGE_IDENTITY_DOMAIN;
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes();
    for (slot, byte) in len.iter().enumerate() {
        if let Some(cell) = id.get_mut(slot.saturating_add(24)) {
            *cell ^= *byte;
        }
    }
    for (index, &byte) in bytes.iter().enumerate() {
        let slot = index & 31;
        if let Some(cell) = id.get_mut(slot) {
            let salt = u8::try_from(index & 0xff).unwrap_or(u8::MAX);
            *cell = cell.wrapping_add(byte).wrapping_add(salt);
        }
    }
    GuestImageId(id)
}

#[cfg(test)]
mod tests {
    use super::{GuestImage, SYNTHETIC_EXIT_SEVEN, SYNTHETIC_EXIT_ZERO, known_image};
    use crate::machine::MachineError;
    use astrid_provider::ProviderError;
    use astrid_resource_types::ApplicationGenerationRef;

    #[test]
    fn synthetic_images_have_distinct_identities() {
        let zero = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).unwrap();
        let seven = GuestImage::admit(&SYNTHETIC_EXIT_SEVEN).unwrap();
        assert_ne!(zero.id(), seven.id());
        assert_eq!(
            known_image(zero.id().application_generation())
                .unwrap()
                .id(),
            zero.id()
        );
        assert_eq!(
            known_image(seven.id().application_generation())
                .unwrap()
                .id(),
            seven.id()
        );
        assert_eq!(
            known_image(ApplicationGenerationRef::from_bytes([0xEE; 32])),
            Err(ProviderError::TypeMismatch)
        );
    }

    #[test]
    fn malformed_images_fail_closed() {
        assert_eq!(GuestImage::admit(&[]), Err(MachineError::InvalidImage));
        assert_eq!(
            GuestImage::admit(&[0x13, 0x05, 0x00]),
            Err(MachineError::InvalidImage)
        );
        assert_eq!(
            GuestImage::admit(&[0_u8; 260]),
            Err(MachineError::InvalidImage)
        );
    }
}
