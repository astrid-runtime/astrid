//! The one executable emulator fixture bound by the #1704 semantic harness.

use crate::types::{ComponentSet, ContentId};

pub const EMULATOR_COMPONENT_HEADER_LEN: usize = 64;
pub const EMULATOR_COMPONENT_CODE_LEN: usize = 71;
pub const EMULATOR_COMPONENT_LEN: usize =
    EMULATOR_COMPONENT_HEADER_LEN + EMULATOR_COMPONENT_CODE_LEN;

const _: () = assert!(EMULATOR_COMPONENT_LEN == 135);

/// Scenario values match the harness: exit, page fault, quota, a hostile
/// probe of the adjacent peer probe, cancellation only, and an invalid opcode.
const MACHINE_CODE: [u8; EMULATOR_COMPONENT_CODE_LEN] = [
    0x83, 0xff, 0x05, 0x74, 0x40, 0x83, 0xff, 0x00, 0x74, 0x1f, 0x83, 0xff, 0x01, 0x74, 0x10, 0x83,
    0xff, 0x02, 0x74, 0x05, 0x83, 0xff, 0x03, 0x74, 0x12, 0xf3, 0x90, 0xeb, 0xfc, 0x0f, 0x0b, 0x31,
    0xc0, 0x3e, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x48, 0xb8, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x32, 0x00, 0x00, 0x48, 0x05, 0x00, 0x10, 0x00, 0x00, 0xc7, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xcc, 0x31, 0xc0, 0xcc, 0x0f, 0x0b,
];

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Canonical executable bytes with an authenticated entrypoint and limits.
pub fn emulator_component() -> [u8; EMULATOR_COMPONENT_LEN] {
    let mut out = [0u8; EMULATOR_COMPONENT_LEN];
    out[..10].copy_from_slice(b"ASTRIDCOMP");
    out[10] = 1;
    put_u64(&mut out, 16, 0);
    put_u64(&mut out, 24, EMULATOR_COMPONENT_HEADER_LEN as u64);
    put_u32(&mut out, 32, EMULATOR_COMPONENT_CODE_LEN as u32);
    put_u32(&mut out, 36, 1);
    put_u32(&mut out, 40, 16);
    put_u32(&mut out, 44, 4);
    out[EMULATOR_COMPONENT_HEADER_LEN..].copy_from_slice(&MACHINE_CODE);
    out
}

pub fn emulator_component_id() -> ContentId {
    ContentId::from_payload(&emulator_component())
}

pub fn emulator_components() -> ComponentSet {
    match ComponentSet::try_from_slice(&[emulator_component_id()]) {
        Ok(components) => components,
        Err(_) => panic!("the emulator fixture contains one valid component identity"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_fixture_binds_code_entrypoint_and_limits() {
        let component = emulator_component();
        assert_eq!(component.len(), EMULATOR_COMPONENT_LEN);
        assert_eq!(&component[..10], b"ASTRIDCOMP");
        assert_eq!(component[10], 1);
        assert!(component[11..16].iter().all(|byte| *byte == 0));

        let entrypoint = u64::from_le_bytes(component[16..24].try_into().unwrap());
        let code_offset = u64::from_le_bytes(component[24..32].try_into().unwrap());
        let code_len = u32::from_le_bytes(component[32..36].try_into().unwrap());
        let stack_pages = u32::from_le_bytes(component[36..40].try_into().unwrap());
        let max_frames = u32::from_le_bytes(component[40..44].try_into().unwrap());
        let quota_ticks = u32::from_le_bytes(component[44..48].try_into().unwrap());

        assert_eq!(entrypoint, 0);
        assert_eq!(code_offset, EMULATOR_COMPONENT_HEADER_LEN as u64);
        assert_eq!(code_len as usize, EMULATOR_COMPONENT_CODE_LEN);
        assert_eq!(stack_pages, 1);
        assert_eq!(max_frames, 16);
        assert_eq!(quota_ticks, 4);
        assert!(
            component[EMULATOR_COMPONENT_HEADER_LEN..]
                .iter()
                .any(|byte| *byte != 0)
        );
    }

    #[test]
    fn fixture_component_set_contains_exact_canonical_identity() {
        let components = emulator_components();
        assert_eq!(components.count(), 1);
        assert_eq!(components.digest(0), Some(emulator_component_id()));
        assert_eq!(components.digest(1), None);
        assert_eq!(emulator_component(), emulator_component());
    }
}
