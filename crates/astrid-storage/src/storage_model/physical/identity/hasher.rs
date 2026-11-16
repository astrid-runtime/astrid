//! Reuse the fixed public map domains without rehashing their context strings.

use blake3::hazmat::HasherExt;

use super::super::map::{LEGACY_MAP_NODE_IDENTITY, RADIX_MAP_NODE_IDENTITY};

// These are hash_derive_key_context of the exact versioned domains above,
// including their trailing NULs. They are public format constants, not keys
// supplied by callers. Tests bind both constants to BLAKE3's context derivation.
// new_from_context_key retains DERIVE_KEY_MATERIAL and hashes every body;
// keyed_hash or an ordinary hash of the context would change the construction.
const LEGACY_CONTEXT_KEY: [u8; 32] = [
    237, 55, 97, 187, 62, 21, 82, 136, 38, 217, 216, 169, 92, 210, 212, 245, 80, 77, 183, 96, 185,
    227, 83, 88, 67, 25, 223, 132, 129, 99, 20, 184,
];
const RADIX_CONTEXT_KEY: [u8; 32] = [
    2, 45, 151, 152, 174, 60, 23, 94, 157, 42, 205, 155, 94, 242, 191, 221, 41, 157, 17, 133, 156,
    70, 172, 164, 132, 14, 215, 248, 243, 228, 9, 153,
];

#[cfg(test)]
std::thread_local! {
    static CONTEXT_DERIVATIONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

pub(super) fn physical_hasher(context: &'static str) -> blake3::Hasher {
    match context {
        LEGACY_MAP_NODE_IDENTITY => blake3::Hasher::new_from_context_key(&LEGACY_CONTEXT_KEY),
        RADIX_MAP_NODE_IDENTITY => blake3::Hasher::new_from_context_key(&RADIX_CONTEXT_KEY),
        _ => derive_context(context),
    }
}

fn derive_context(context: &'static str) -> blake3::Hasher {
    #[cfg(test)]
    CONTEXT_DERIVATIONS.with(|count| count.set(count.get().strict_add(1)));
    blake3::Hasher::new_derive_key(context)
}

#[cfg(test)]
mod tests;
