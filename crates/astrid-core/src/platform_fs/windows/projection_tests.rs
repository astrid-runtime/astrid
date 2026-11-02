use super::{
    FILE_ATTRIBUTE_REPARSE_POINT, FileIdentity, GENERIC_WRITE, MAX_LISTING_BUFFER, OpenMode, Query,
    directory_access, identity_from_file_id, is_canonical_volume_name, listing_information,
    max_listing_record_bytes, parse_directory_buffer, volume_root_access, windows_names_equal,
};
use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Wdk::Storage::FileSystem::FILE_ID_EXTD_DIR_INFORMATION;

fn file_id(low: u64, high: u64) -> [u8; 16] {
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&low.to_le_bytes());
    id[8..].copy_from_slice(&high.to_le_bytes());
    id
}

fn listing_entry(name: &str, file_id: [u8; 16], next: u32, attributes: u32) -> Vec<u8> {
    listing_entry_units(
        &OsString::from(name).encode_wide().collect::<Vec<_>>(),
        file_id,
        next,
        attributes,
    )
}

fn listing_entry_units(units: &[u16], file_id: [u8; 16], next: u32, attributes: u32) -> Vec<u8> {
    let name_bytes = std::mem::size_of_val(units);
    let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    let mut buffer = vec![0_u8; name_offset];
    let next_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, NextEntryOffset);
    buffer[next_offset..][..4].copy_from_slice(&next.to_le_bytes());
    let attr_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileAttributes);
    buffer[attr_offset..][..4].copy_from_slice(&attributes.to_le_bytes());
    let len_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength);
    buffer[len_offset..][..4].copy_from_slice(&u32::try_from(name_bytes).unwrap().to_le_bytes());
    let id_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId);
    buffer[id_offset..][..16].copy_from_slice(&file_id);
    for unit in units {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    buffer
}

fn packed_chain(first: &str, first_id: [u8; 16], second: &str, second_id: [u8; 16]) -> Vec<u8> {
    let mut first = listing_entry(first, first_id, 0, 0);
    while !first.len().is_multiple_of(8) {
        first.push(0);
    }
    let next = u32::try_from(first.len()).unwrap();
    first[0..4].copy_from_slice(&next.to_le_bytes());
    first.extend(listing_entry(second, second_id, 0, 0));
    first
}

#[test]
fn listing_parser_captures_128_bit_file_id_and_volume() {
    let id = file_id(0x0000_0002_0000_0009, 0x1111_2222_3333_4444);
    let entries = parse_directory_buffer(&listing_entry("astrid.volume", id, 0, 0), 7).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, OsString::from("astrid.volume"));
    assert_eq!(
        entries[0].identity,
        FileIdentity {
            volume: 7,
            file_id: id,
        }
    );
}

#[test]
fn file_ids_differing_only_in_upper_64_bits_remain_distinct() {
    let low = file_id(1, 0);
    let high = file_id(1, 1);
    assert_ne!(
        identity_from_file_id(1, low).unwrap(),
        identity_from_file_id(1, high).unwrap()
    );
    let entries = parse_directory_buffer(&packed_chain("a", low, "b", high), 3).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].identity.file_id, low);
    assert_eq!(entries[1].identity.file_id, high);
}

#[test]
fn one_char_listing_name_parses_below_struct_size() {
    let buffer = listing_entry("a", file_id(1, 0), 0, 0);
    let packed = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName) + 2;
    assert!(packed < size_of::<FILE_ID_EXTD_DIR_INFORMATION>());
    assert_eq!(buffer.len(), packed);
    let entries = parse_directory_buffer(&buffer, 3).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, OsString::from("a"));
    assert_eq!(entries[0].identity.file_id, file_id(1, 0));
}

#[test]
fn listing_parser_treats_wildcard_characters_as_literal_names() {
    let entries = parse_directory_buffer(&listing_entry("*", file_id(8, 0), 0, 0), 1).unwrap();
    assert_eq!(entries[0].name, OsString::from("*"));
}

#[test]
fn listing_parser_skips_dot_entries_and_keeps_siblings() {
    let buffer = packed_chain(".", file_id(2, 0), "keep", file_id(3, 0));
    let entries = parse_directory_buffer(&buffer, 1).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, OsString::from("keep"));
}

#[test]
fn listing_parser_rejects_malformed_records() {
    let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    let mut truncated_header = listing_entry("a", file_id(1, 0), 0, 0);
    truncated_header.truncate(name_offset.strict_sub(1));

    let mut odd_utf16 = listing_entry("a", file_id(1, 0), 0, 0);
    let len_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength);
    odd_utf16[len_offset..][..4].copy_from_slice(&1_u32.to_le_bytes());

    let unaligned_next = listing_entry("a", file_id(1, 0), 1, 0);
    let overlapping_name = listing_entry("a", file_id(1, 0), 8, 0);

    let mut truncated_name = listing_entry("ab", file_id(1, 0), 0, 0);
    truncated_name.truncate(name_offset.strict_add(2));
    truncated_name[len_offset..][..4].copy_from_slice(&4_u32.to_le_bytes());

    let mut next_at_end = listing_entry("a", file_id(1, 0), 0, 0);
    while !next_at_end.len().is_multiple_of(8) {
        next_at_end.push(0);
    }
    let end = u32::try_from(next_at_end.len()).unwrap();
    next_at_end[0..4].copy_from_slice(&end.to_le_bytes());

    let cases = [
        truncated_header,
        odd_utf16,
        unaligned_next,
        overlapping_name,
        truncated_name,
        next_at_end,
    ];
    for buffer in cases {
        assert_eq!(
            parse_directory_buffer(&buffer, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn listing_information_rejects_bytes_past_buffer() {
    assert!(listing_information(5, 4).is_err());
    assert_eq!(listing_information(0, 4).unwrap(), Query::Done);
    assert_eq!(listing_information(4, 4).unwrap(), Query::Entries(4));
}

#[test]
fn listing_parser_rejects_reparse_attributes() {
    let buffer = listing_entry("link", file_id(4, 0), 0, FILE_ATTRIBUTE_REPARSE_POINT);
    assert_eq!(
        parse_directory_buffer(&buffer, 1).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn listing_buffer_ceiling_covers_one_max_record() {
    assert!(MAX_LISTING_BUFFER >= max_listing_record_bytes());
}

#[test]
fn flush_write_is_not_granted_to_volume_root_or_inspect() {
    assert_eq!(volume_root_access() & GENERIC_WRITE, 0);
    assert_eq!(directory_access(OpenMode::Inspect) & GENERIC_WRITE, 0);
    assert_ne!(directory_access(OpenMode::Flush) & GENERIC_WRITE, 0);
    assert_ne!(directory_access(OpenMode::Delete) & GENERIC_WRITE, 0);
    assert_eq!(directory_access(OpenMode::Flush) & super::DELETE, 0);
}

#[test]
fn zero_file_id_is_rejected() {
    assert!(identity_from_file_id(1, [0; 16]).is_err());
}

#[test]
fn opened_volume_information_rejects_remote_unknown_and_short_results() {
    use super::{
        FILE_DEVICE_DISK, FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOTE_DEVICE_VSMB,
        validate_local_volume_info,
    };
    let mut info = FILE_FS_DEVICE_INFORMATION {
        DeviceType: FILE_DEVICE_DISK,
        Characteristics: 0,
    };
    let bytes = size_of::<FILE_FS_DEVICE_INFORMATION>();
    assert!(validate_local_volume_info(info, bytes).is_ok());
    assert!(validate_local_volume_info(info, bytes.strict_sub(1)).is_err());
    assert!(validate_local_volume_info(info, bytes.strict_add(1)).is_err());
    info.Characteristics = FILE_REMOTE_DEVICE;
    assert!(validate_local_volume_info(info, bytes).is_err());
    info.Characteristics = FILE_REMOTE_DEVICE_VSMB;
    assert!(validate_local_volume_info(info, bytes).is_err());
    info.Characteristics = 0;
    for unsupported in [0, 2, 20, u32::MAX] {
        info.DeviceType = unsupported;
        assert!(validate_local_volume_info(info, bytes).is_err());
    }
}

#[test]
fn canonical_volume_name_folds_case_and_rejects_neighbors() {
    assert!(is_canonical_volume_name(OsStr::new("ASTRID.VOLUME")).unwrap());
    assert!(is_canonical_volume_name(OsStr::new("astrid.volume")).unwrap());
    assert!(is_canonical_volume_name(OsStr::new("Astrid.Volume")).unwrap());
    assert!(!is_canonical_volume_name(OsStr::new("astrid.volume.extra")).unwrap());
    assert!(windows_names_equal(OsStr::new("*"), OsStr::new("*")).unwrap());
    assert!(!windows_names_equal(OsStr::new("*"), OsStr::new("a")).unwrap());
}

#[test]
fn exclusive_directory_delete_handle_denies_rename() {
    use super::OpenedDirectory;
    use std::fs;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("captured")).unwrap();
    fs::write(root.join("captured/state"), b"captured").unwrap();
    let parent = OpenedDirectory::open_existing(&root).unwrap();
    let held = parent.open_directory(OsStr::new("captured"), true).unwrap();
    let outside = directory.path().join("outside");
    assert!(fs::rename(root.join("captured"), &outside).is_err());
    assert!(root.join("captured/state").exists());
    assert!(!outside.exists());
    drop(held);
}

#[test]
fn delete_shared_handle_control_follows_file_renamed_outside_parent() {
    use super::{OpenedDirectory, delete_file, file_access, open_relative_file};
    use std::fs;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("captured"), b"captured").unwrap();
    let parent = OpenedDirectory::open_existing(&root).unwrap();
    // Reproduce the former FILE_SHARE_DELETE open with the real native helper,
    // not a path-based deletion surrogate. The repaired public path separately
    // proves this post-check rename is denied while delete authority is held.
    let handle = open_relative_file(
        parent.handle(),
        OsStr::new("captured"),
        file_access(OpenMode::Delete),
        false,
    )
    .unwrap();
    let outside = directory.path().join("outside");
    fs::rename(root.join("captured"), &outside).unwrap();
    assert_eq!(fs::read(&outside).unwrap(), b"captured");
    delete_file(handle.into_file()).unwrap();
    assert!(!outside.exists());
}
