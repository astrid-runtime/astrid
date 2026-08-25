use anyhow::Context;
use std::{
    fs,
    io::{self, Seek, Write},
    path::Path,
    process::Command,
};
use thiserror::Error;

/// Creates a bootable disk image from the given bootloader executable.
pub fn create_disk_image(
    bootloader_elf_path: &Path,
    output_bin_path: &Path,
    kernel_binary: &Path,
) -> anyhow::Result<()> {
    let llvm_tools =
        llvm_tools::LlvmTools::new().map_err(|err| anyhow::anyhow!("failed to get llvm tools"))?;
    let objcopy = llvm_tools
        .tool(&llvm_tools::exe("llvm-objcopy"))
        .ok_or(DiskImageError::LlvmObjcopyNotFound)?;

    // convert first stage to binary
    let mut cmd = Command::new(objcopy);
    cmd.arg("-I").arg("elf64-x86-64");
    cmd.arg("-O").arg("binary");
    cmd.arg("--binary-architecture=i386:x86-64");
    cmd.arg(bootloader_elf_path);
    cmd.arg(output_bin_path);
    let output = cmd.output().map_err(|err| DiskImageError::Io {
        message: "failed to execute llvm-objcopy command",
        error: err,
    })?;
    if !output.status.success() {
        return Err(DiskImageError::ObjcopyFailed {
            stderr: output.stderr,
        })
        .context("objcopy failed");
    }

    use std::fs::OpenOptions;
    let mut disk_image = OpenOptions::new()
        .write(true)
        .open(&output_bin_path)
        .map_err(|err| DiskImageError::Io {
            message: "failed to open boot image",
            error: err,
        })?;
    let file_size = disk_image
        .metadata()
        .map_err(|err| DiskImageError::Io {
            message: "failed to get size of boot image",
            error: err,
        })?
        .len();
    const BLOCK_SIZE: u64 = 512;
    assert_eq!(file_size, BLOCK_SIZE);

    let kernel_size = fs::metadata(&kernel_binary)
        .context("failed to read metadata of kernel binary")?
        .len();

    // create fat partition
    const MB: u64 = 1024 * 1024;
    let fat_size = kernel_size; // TODO plus second stage size
    let fat_size_padded_and_rounded = ((fat_size + 1024 * 64 - 1) / MB + 1) * MB;
    let fat_file_path = {
        let fat_path = output_bin_path.with_extension("fat");
        let fat_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&fat_path)
            .context("Failed to create UEFI FAT file")?;
        fat_file
            .set_len(fat_size_padded_and_rounded)
            .context("failed to set UEFI FAT file length")?;

        // create new FAT partition
        let format_options = fatfs::FormatVolumeOptions::new().volume_label(*b"BOOT       ");
        fatfs::format_volume(&fat_file, format_options)
            .context("Failed to format UEFI FAT file")?;

        // copy kernel to FAT filesystem
        let partition = fatfs::FileSystem::new(&fat_file, fatfs::FsOptions::new())
            .context("Failed to open FAT file system of UEFI FAT file")?;
        let root_dir = partition.root_dir();
        let mut kernel_file = root_dir.create_file("kernel-x86_64")?;
        kernel_file.truncate()?;
        io::copy(&mut fs::File::open(&kernel_binary)?, &mut kernel_file)?;

        fat_path
    };

    disk_image.seek(io::SeekFrom::Start(446))?;
    disk_image.write_all(&[0x80, 0, 0, 0, 0x04, 0, 0, 0])?;
    let start_sector = 1u32.to_le_bytes();
    let size_sectors = u32::try_from(&fat_size_padded_and_rounded / 512)
        .unwrap()
        .to_le_bytes();
    disk_image.write_all(&start_sector)?;
    disk_image.write_all(&size_sectors)?;

    disk_image.seek(io::SeekFrom::Start(512))?;
    io::copy(&mut fs::File::open(&kernel_binary)?, &mut disk_image)?;

    pad_to_nearest_block_size(output_bin_path)?;
    Ok(())
}

fn pad_to_nearest_block_size(output_bin_path: &Path) -> Result<(), DiskImageError> {
    const BLOCK_SIZE: u64 = 512;
    use std::fs::OpenOptions;
    let file = OpenOptions::new()
        .write(true)
        .open(&output_bin_path)
        .map_err(|err| DiskImageError::Io {
            message: "failed to open boot image",
            error: err,
        })?;
    let file_size = file
        .metadata()
        .map_err(|err| DiskImageError::Io {
            message: "failed to get size of boot image",
            error: err,
        })?
        .len();
    let remainder = file_size % BLOCK_SIZE;
    let padding = if remainder > 0 {
        BLOCK_SIZE - remainder
    } else {
        0
    };
    file.set_len(file_size + padding)
        .map_err(|err| DiskImageError::Io {
            message: "failed to pad boot image to a multiple of the block size",
            error: err,
        })
}

/// Creating the disk image failed.
#[derive(Debug, Error)]
pub enum DiskImageError {
    /// The `llvm-tools-preview` rustup component was not found
    #[error(
        "Could not find the `llvm-tools-preview` rustup component.\n\n\
        You can install by executing `rustup component add llvm-tools-preview`."
    )]
    LlvmToolsNotFound,

    /// There was another problem locating the `llvm-tools-preview` rustup component
    #[error("Failed to locate the `llvm-tools-preview` rustup component: {0:?}")]
    LlvmTools(llvm_tools::Error),

    /// The llvm-tools component did not contain the required `llvm-objcopy` executable
    #[error("Could not find `llvm-objcopy` in the `llvm-tools-preview` rustup component.")]
    LlvmObjcopyNotFound,

    /// The `llvm-objcopy` command failed
    #[error("Failed to run `llvm-objcopy`: {}", String::from_utf8_lossy(.stderr))]
    ObjcopyFailed {
        /// The output of `llvm-objcopy` to standard error
        stderr: Vec<u8>,
    },

    /// An unexpected I/O error occurred
    #[error("I/O error: {message}:\n{error}")]
    Io {
        /// Description of the failed I/O operation
        message: &'static str,
        /// The I/O error that occurred
        error: io::Error,
    },
}

impl From<llvm_tools::Error> for DiskImageError {
    fn from(err: llvm_tools::Error) -> Self {
        match err {
            llvm_tools::Error::NotFound => DiskImageError::LlvmToolsNotFound,
            other => DiskImageError::LlvmTools(other),
        }
    }
}
