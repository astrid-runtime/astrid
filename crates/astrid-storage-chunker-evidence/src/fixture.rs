pub fn pseudorandom_bytes(length: usize, mut state: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state.wrapping_shl(13);
        state ^= state.wrapping_shr(7);
        state ^= state.wrapping_shl(17);
        bytes.push(state.to_le_bytes()[0]);
    }
    bytes
}

pub fn periodic_bytes(length: usize) -> Vec<u8> {
    const PATTERN: &[u8] = b"astrid-content-addressed-storage\n";
    (0..length)
        .map(|index| {
            let pattern_index = index
                .checked_rem(PATTERN.len())
                .expect("the fixture pattern is non-empty");
            *PATTERN
                .get(pattern_index)
                .expect("the remainder is a valid pattern index")
        })
        .collect()
}
