use super::AuthorityRegistryError;

pub(super) fn domain_hash(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(canonical);
    *hasher.finalize().as_bytes()
}

pub(super) fn encode_array_len(output: &mut Vec<u8>, len: usize) {
    encode_major_len(output, 4, usize_to_u64(len));
}

pub(super) fn encode_text(output: &mut Vec<u8>, value: &str) {
    encode_major_len(output, 3, usize_to_u64(value.len()));
    output.extend_from_slice(value.as_bytes());
}

pub(super) fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    encode_major_len(output, 2, usize_to_u64(value.len()));
    output.extend_from_slice(value);
}

pub(super) fn encode_unsigned(output: &mut Vec<u8>, value: u64) {
    encode_major_len(output, 0, value);
}

pub(super) fn encode_bool(output: &mut Vec<u8>, value: bool) {
    output.push(if value { 0xf5 } else { 0xf4 });
}

fn encode_major_len(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    if let Ok(value) = u8::try_from(value) {
        if value <= 23 {
            output.push(prefix | value);
        } else {
            output.push(prefix | 0x18);
            output.push(value);
        }
    } else if let Ok(value) = u16::try_from(value) {
        output.push(prefix | 0x19);
        output.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        output.push(prefix | 0x1a);
        output.extend_from_slice(&value.to_be_bytes());
    } else {
        output.push(prefix | 0x1b);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn usize_to_u64(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => unreachable!("usize always fits into u64 on supported targets"),
    }
}

pub(super) fn validate_digest_length(
    kind: &'static str,
    value: &[u8],
) -> Result<(), AuthorityRegistryError> {
    let actual = value.len();
    if actual != 32 {
        return Err(AuthorityRegistryError::InvalidDigestLength { kind, actual });
    }
    Ok(())
}
