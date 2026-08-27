use std::fs::File;
use std::io::{Read, Write};

const SECTOR: usize = 512;
const TOTAL_SECTORS: usize = 61_440;
const RESERVED_SECTORS: u16 = 1;
const FAT_COUNT: u16 = 2;
const ROOT_ENTRIES: u16 = 512;
const SECTORS_PER_CLUSTER: u8 = 4;
const FAT_SECTORS: u16 = 128;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let image_path = args.next().ok_or("usage: build-fat <image> <payload>")?;
    let payload_path = args.next().ok_or("usage: build-fat <image> <payload>")?;
    if args.next().is_some() {
        return Err("too many arguments".to_string());
    }

    let mut payload = Vec::new();
    File::open(payload_path)
        .and_then(|mut file| file.read_to_end(&mut payload))
        .map_err(|error| format!("read payload: {error}"))?;
    if payload.is_empty() || payload.len() % SECTOR != 0 {
        return Err("UEFI payload must be nonempty and 512-byte aligned".to_string());
    }

    let cluster_size = SECTOR * usize::from(SECTORS_PER_CLUSTER);
    payload.resize(payload.len().next_multiple_of(cluster_size), 0);
    let mut cluster_count = payload.len() / cluster_size;
    let data_start_sector = usize::from(RESERVED_SECTORS)
        + usize::from(FAT_COUNT) * usize::from(FAT_SECTORS)
        + usize::from(ROOT_ENTRIES) * 32 / SECTOR;
    let usable_clusters = (TOTAL_SECTORS - data_start_sector) / usize::from(SECTORS_PER_CLUSTER);
    if cluster_count < 1 || cluster_count > usable_clusters.saturating_sub(1) {
        return Err(format!(
            "payload needs {cluster_count} clusters; volume supports {}",
            usable_clusters.saturating_sub(1)
        ));
    }

    let uefi_payload_size = payload.len();
    let mut startup = b"BOOTX64.EFI\n".to_vec();
    startup.resize(cluster_size, 0);
    payload.append(&mut startup);
    cluster_count = payload.len() / cluster_size;
    let mut image = vec![0u8; TOTAL_SECTORS * SECTOR];
    image[0] = 0xeb;
    image[1] = 0x3c;
    image[2] = 0x90;
    image[3..11].copy_from_slice(b"ASTRIDEV");
    put_u16(&mut image, 11, SECTOR as u16);
    image[13] = SECTORS_PER_CLUSTER;
    put_u16(&mut image, 14, RESERVED_SECTORS);
    image[16] = FAT_COUNT as u8;
    put_u16(&mut image, 17, ROOT_ENTRIES);
    put_u16(&mut image, 19, TOTAL_SECTORS as u16);
    image[21] = 0xf8;
    put_u16(&mut image, 22, FAT_SECTORS);
    put_u16(&mut image, 24, 63);
    put_u16(&mut image, 26, 255);
    put_u32(&mut image, 28, 0);
    put_u32(&mut image, 32, TOTAL_SECTORS as u32);
    image[36] = 0x80;
    image[38] = 0x29;
    put_u32(&mut image, 39, 0x1691_0001);
    image[43..54].copy_from_slice(b"PIOJOURNAL ");
    image[54..62].copy_from_slice(b"FAT16   ");
    image[510..512].copy_from_slice(&[0x55, 0xaa]);

    let mut fat = vec![0u8; usize::from(FAT_SECTORS) * SECTOR];
    fat[..3].copy_from_slice(&[0xf8, 0xff, 0xff]);
    for cluster_index in 0..cluster_count {
        let entry_number = cluster_index + 2;
        let value = if cluster_index + 1 == cluster_count {
            0xffff
        } else {
            (entry_number + 1) as u16
        };
        let offset = entry_number * 2;
        fat[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    let first_fat = RESERVED_SECTORS as usize * SECTOR;
    let second_fat = first_fat + usize::from(FAT_SECTORS) * SECTOR;
    image[first_fat..second_fat].copy_from_slice(&fat);
    let second_fat_end = second_fat + fat.len();
    image[second_fat..second_fat_end].copy_from_slice(&fat);

    let mut directory = vec![0u8; usize::from(ROOT_ENTRIES) * 32];
    directory[0..11].copy_from_slice(b"BOOTX64 EFI");
    directory[11] = 0x23;
    put_u16(&mut directory, 22, 0x6000);
    put_u16(&mut directory, 24, 0x5b40);
    put_u16(&mut directory, 26, 2);
    let mut second_entry = [0u8; 32];
    second_entry[0..11].copy_from_slice(b"STARTUP NSH");
    second_entry[11] = 0x23;
    put_u16(&mut second_entry, 22, 0x6000);
    put_u16(&mut second_entry, 24, 0x5b40);
    put_u16(&mut second_entry, 26, (cluster_count + 1) as u16);
    put_u32(&mut second_entry, 28, b"BOOTX64.EFI\n".len() as u32);
    directory[32..64].copy_from_slice(&second_entry);
    put_u32(&mut directory, 28, uefi_payload_size as u32);
    let directory_offset = second_fat_end;
    image[directory_offset..directory_offset + directory.len()].copy_from_slice(&directory);

    let payload_offset = data_start_sector * SECTOR;
    image[payload_offset..payload_offset + payload.len()].copy_from_slice(&payload);
    File::create(image_path)
        .and_then(|mut file| file.write_all(&image))
        .map_err(|error| format!("write image: {error}"))?;
    Ok(())
}
