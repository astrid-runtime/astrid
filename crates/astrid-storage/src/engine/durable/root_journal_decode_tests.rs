use super::*;

#[test]
fn journal_reader_preserves_field_boundaries_and_scheme_diagnostics() {
    let scheme = IdentityScheme::new(2, 3).unwrap();
    let initial = RootState {
        generation: RootGeneration::INITIAL,
        commit: ObjectId::new([19; 32]),
    };
    let next = RootState {
        generation: RootGeneration::new(1),
        commit: ObjectId::new([29; 32]),
    };
    let canonical = encode_root_record(scheme, b"x", Some(initial), next).unwrap();
    let decode = |bytes: &[u8]| decode_root_journal_record(bytes, scheme).err();
    assert_eq!(decode(&canonical), None);
    for end in 0..canonical.len() {
        assert_eq!(
            decode(&canonical[..end]),
            Some("truncated frame payload"),
            "prefix {end}"
        );
    }
    // Eight length bytes, one owner byte, one tag, then two 48-byte roots.
    for (index, byte, detail) in [
        (9, 2, "invalid expected-root tag"),
        (18, 0, "identity tag fields must be non-zero"),
        (
            20,
            4,
            "unsupported identity algorithm or construction version",
        ),
        (
            70,
            31,
            "identity digest length does not match the supported scheme",
        ),
        (70, 33, "truncated frame payload"),
    ] {
        let mut bad = canonical.clone();
        bad[index] = byte;
        assert_eq!(decode(&bad), Some(detail), "byte {index}");
    }
    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(decode(&trailing), Some("trailing root-journal bytes"));
}
