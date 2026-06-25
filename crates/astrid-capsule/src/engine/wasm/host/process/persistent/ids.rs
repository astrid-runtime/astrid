//! `process-id` minting and encoding.
//!
//! An id is 256 bits of OS entropy rendered as lowercase base32 (RFC 4648,
//! no padding). Lowercase base32 is a subset of the IPC topic-suffix grammar
//! (`[a-z0-9._-]+`), so the id doubles as a `watch` topic suffix without
//! sanitisation. Treat the wire form as an opaque secret.

use rand::{TryRng, rngs::SysRng};

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Mint a fresh `process-id`: 256 bits of OS CSPRNG entropy, lowercase
/// base32.
pub(super) fn mint_id() -> String {
    let mut bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG unavailable while minting process id");
    base32_lower(&bytes)
}

/// Lowercase base32 encode (RFC 4648 alphabet, no padding).
fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        acc = (acc << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 0x1f) as usize] as char);
            // Keep only the not-yet-emitted low bits so `acc` stays bounded.
            acc &= (1u64 << bits) - 1;
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_is_lowercase_topic_safe() {
        let s = base32_lower(&[0u8; 32]);
        assert_eq!(s.len(), 52); // ceil(256 / 5)
        assert!(s.chars().all(|c| B32.contains(&(c as u8))));
        // Subset of the topic-suffix grammar [a-z0-9._-]+.
        assert!(
            s.chars()
                .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        );
    }

    #[test]
    fn base32_distinct_for_distinct_input() {
        assert_ne!(base32_lower(&[1u8; 32]), base32_lower(&[2u8; 32]));
    }

    #[test]
    fn base32_known_vector() {
        // All-zero input → all 'a'.
        assert_eq!(base32_lower(&[0u8; 5]), "aaaaaaaa");
    }

    #[test]
    fn mint_id_unique_and_sized() {
        let a = mint_id();
        let b = mint_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 52);
    }
}
