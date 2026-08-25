use std::path::Path;

use bootloader_boot_config::BootConfig;

use crate::DiskImageBuilder;

/// Create disk images for booting on UEFI systems.
pub struct UefiBoot {
    image_builder: DiskImageBuilder,
}

impl UefiBoot {
    /// Start creating a disk image for the given bootloader ELF executable.
    pub fn new(kernel_path: &Path) -> Self {
        Self {
            image_builder: DiskImageBuilder::new(kernel_path.to_owned()),
        }
    }

    /// Add a ramdisk file to the image
    pub fn set_ramdisk(&mut self, ramdisk_path: &Path) -> &mut Self {
        self.image_builder.set_ramdisk(ramdisk_path.to_owned());
        self
    }

    /// Creates a configuration file (boot.json) that configures the runtime behavior of the bootloader.
    pub fn set_boot_config(&mut self, config: &BootConfig) -> &mut Self {
        self.image_builder.set_boot_config(config);
        self
    }

    /// Create a bootable UEFI disk image at the given path.
    pub fn create_disk_image(&self, out_path: &Path) -> anyhow::Result<()> {
        self.image_builder.create_uefi_image(out_path)
    }

    /// Prepare a folder for use with booting over UEFI_PXE.
    ///
    /// This places the bootloader executable under the path "bootloader". The
    /// DHCP server should set the filename option to that path, otherwise the
    /// bootloader won't be found.
    pub fn create_pxe_tftp_folder(&self, out_path: &Path) -> anyhow::Result<()> {
        self.image_builder.create_uefi_tftp_folder(out_path)
    }
}
