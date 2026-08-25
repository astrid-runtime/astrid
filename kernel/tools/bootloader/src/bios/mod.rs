use std::path::Path;

use bootloader_boot_config::BootConfig;

use crate::DiskImageBuilder;

/// Create disk images for booting on legacy BIOS systems.
pub struct BiosBoot {
    image_builder: DiskImageBuilder,
}

impl BiosBoot {
    /// Start creating a disk image for the given bootloader ELF executable.
    pub fn new(kernel_path: &Path) -> Self {
        Self {
            image_builder: DiskImageBuilder::new(kernel_path.to_owned()),
        }
    }

    /// Add a ramdisk file to the image.
    pub fn set_ramdisk(&mut self, ramdisk_path: &Path) -> &mut Self {
        self.image_builder.set_ramdisk(ramdisk_path.to_owned());
        self
    }

    /// Creates a configuration file (boot.json) that configures the runtime behavior of the bootloader.
    pub fn set_boot_config(&mut self, config: &BootConfig) -> &mut Self {
        self.image_builder.set_boot_config(config);
        self
    }

    /// Create a bootable BIOS disk image at the given path.
    pub fn create_disk_image(&self, out_path: &Path) -> anyhow::Result<()> {
        self.image_builder.create_bios_image(out_path)
    }
}
