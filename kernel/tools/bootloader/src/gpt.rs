use anyhow::Context;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Seek},
    path::Path,
};
use uuid::Uuid;

/// Scheme namespace for emulator GPT identifiers (UUID v5 over DNS).
const GPT_SCHEME_DNS_NAME: &[u8] = b"astrid.kimage.gpt.v1";
const DISK_GUID_NAME: &[u8] = b"astrid.kimage.gpt.disk.v1";
const ESP_GUID_NAME: &[u8] = b"astrid.kimage.gpt.esp.v1";

/// Deterministic GPT disk GUID. Not interchangeable with [`EspPartitionGuid`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GptDiskGuid(Uuid);

/// Deterministic EFI system-partition GUID. Not interchangeable with [`GptDiskGuid`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EspPartitionGuid(Uuid);

fn gpt_scheme_namespace() -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, GPT_SCHEME_DNS_NAME)
}

impl GptDiskGuid {
    fn derive() -> Self {
        Self(Uuid::new_v5(&gpt_scheme_namespace(), DISK_GUID_NAME))
    }

    fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl EspPartitionGuid {
    fn derive() -> Self {
        Self(Uuid::new_v5(&gpt_scheme_namespace(), ESP_GUID_NAME))
    }

    fn as_uuid(self) -> Uuid {
        self.0
    }
}

fn assign_esp_guid(
    gpt: &mut gpt::GptDisk<'_>,
    partition_id: u32,
    guid: EspPartitionGuid,
) -> anyhow::Result<()> {
    let mut partitions: BTreeMap<_, _> = gpt.partitions().clone();
    let Some(partition) = partitions.get_mut(&partition_id) else {
        anyhow::bail!("boot partition {partition_id} missing after creation");
    };
    partition.part_guid = guid.as_uuid();
    gpt.update_partitions(partitions)
        .context("failed to apply deterministic ESP GUID")?;
    Ok(())
}

pub fn create_gpt_disk(fat_image: &Path, out_gpt_path: &Path) -> anyhow::Result<()> {
    // create new file
    let mut disk = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(out_gpt_path)
        .with_context(|| format!("failed to create GPT file at `{}`", out_gpt_path.display()))?;

    // set file size
    let partition_size: u64 = fs::metadata(fat_image)
        .context("failed to read metadata of fat image")?
        .len();
    let disk_size = partition_size + 1024 * 64; // for GPT headers
    disk.set_len(disk_size)
        .context("failed to set GPT image file length")?;

    // create a protective MBR at LBA0 so that disk is not considered
    // unformatted on BIOS systems
    let mbr = gpt::mbr::ProtectiveMBR::with_lb_size(
        u32::try_from((disk_size / 512) - 1).unwrap_or(0xFF_FF_FF_FF),
    );
    mbr.overwrite_lba0(&mut disk)
        .context("failed to write protective MBR")?;

    // create new GPT structure with a role-typed disk GUID (never v4).
    let block_size = gpt::disk::LogicalBlockSize::Lb512;
    let mut gpt = gpt::GptConfig::new()
        .writable(true)
        .initialized(false)
        .logical_block_size(block_size)
        .create_from_device(Box::new(&mut disk), Some(GptDiskGuid::derive().as_uuid()))
        .context("failed to create GPT structure in file")?;
    gpt.update_partitions(Default::default())
        .context("failed to update GPT partitions")?;

    // add new EFI system partition and replace the crate-generated v4 part GUID
    let partition_id = gpt
        .add_partition("boot", partition_size, gpt::partition_types::EFI, 0, None)
        .context("failed to add boot EFI partition")?;
    assign_esp_guid(&mut gpt, partition_id, EspPartitionGuid::derive())?;
    let partition = gpt
        .partitions()
        .get(&partition_id)
        .context("failed to open boot partition after creation")?;
    let start_offset = partition
        .bytes_start(block_size)
        .context("failed to get start offset of boot partition")?;

    // close the GPT structure and write out changes
    gpt.write().context("failed to write out GPT changes")?;

    // place the FAT filesystem in the newly created partition
    disk.seek(io::SeekFrom::Start(start_offset))
        .context("failed to seek to start offset")?;
    io::copy(
        &mut File::open(fat_image).context("failed to open FAT image")?,
        &mut disk,
    )
    .context("failed to copy FAT image to GPT disk")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpt::disk::LogicalBlockSize;
    use std::io::Write;
    use uuid::{Variant, Version};

    /// Pins the SHA-1 inputs independently so an accidental domain rename
    /// cannot silently mint a new, stable identifier.
    const GPT_SCHEME_NAMESPACE_HEX: &str = "d08462a2-13e1-5f24-8aef-4ade5bc98a45";
    const DISK_GUID_HEX: &str = "f0fe4d2d-e958-51f8-8ce5-a4c5c468df58";
    const ESP_GUID_HEX: &str = "f7a06508-bd91-5466-8e4c-b042a0c951c4";

    fn pinned_uuid(hex: &str) -> Uuid {
        Uuid::try_parse(hex).expect("pinned test UUID parses")
    }

    fn write_blank_fat(path: &Path, len: u64) -> anyhow::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        file.set_len(len)?;
        file.write_all(&[0u8; 512])?;
        Ok(())
    }

    #[test]
    fn disk_and_esp_guids_are_distinct_v5_roles() {
        let disk = GptDiskGuid::derive();
        let esp = EspPartitionGuid::derive();
        assert_eq!(
            gpt_scheme_namespace(),
            pinned_uuid(GPT_SCHEME_NAMESPACE_HEX)
        );
        assert_eq!(disk, GptDiskGuid::derive());
        assert_eq!(esp, EspPartitionGuid::derive());
        assert_eq!(disk.as_uuid(), pinned_uuid(DISK_GUID_HEX));
        assert_eq!(esp.as_uuid(), pinned_uuid(ESP_GUID_HEX));
        assert_ne!(disk.as_uuid(), esp.as_uuid());
        assert_ne!(disk.as_uuid(), Uuid::nil());
        assert_ne!(esp.as_uuid(), Uuid::nil());
        assert_eq!(disk.as_uuid().get_version(), Some(Version::Sha1));
        assert_eq!(esp.as_uuid().get_version(), Some(Version::Sha1));
        assert_eq!(disk.as_uuid().get_variant(), Variant::RFC4122);
        assert_eq!(esp.as_uuid().get_variant(), Variant::RFC4122);
    }

    #[test]
    fn create_gpt_disk_is_byte_identical_and_crc_valid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fat = dir.path().join("fat.bin");
        write_blank_fat(&fat, 1024 * 1024).expect("fat");
        let image_a = dir.path().join("a.img");
        let image_b = dir.path().join("b.img");
        create_gpt_disk(&fat, &image_a).expect("gpt a");
        create_gpt_disk(&fat, &image_b).expect("gpt b");
        let bytes_a = fs::read(&image_a).expect("read a");
        let bytes_b = fs::read(&image_b).expect("read b");
        assert_eq!(bytes_a, bytes_b, "GPT packaging must be deterministic");

        let mut file = File::open(&image_a).expect("open gpt");
        let opened = gpt::GptConfig::new()
            .writable(false)
            .initialized(true)
            .logical_block_size(LogicalBlockSize::Lb512)
            .open_from_device(Box::new(&mut file) as gpt::DiskDeviceObject)
            .expect("primary/backup GPT CRC must validate");
        assert_eq!(*opened.guid(), pinned_uuid(DISK_GUID_HEX));
        let esp = opened
            .partitions()
            .values()
            .find(|part| part.part_guid == pinned_uuid(ESP_GUID_HEX))
            .expect("ESP unique GUID must be present and readable");
        assert_eq!(esp.name, "boot");
        assert!(esp.bytes_start(LogicalBlockSize::Lb512).expect("start") > 0);
    }
}
