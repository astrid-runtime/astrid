//! Host tool: wrap a kernel ELF into a bootable UEFI disk image.
//!
//! Usage: `kimage <kernel-elf> <output-image>`. The boot loader is replaceable
//! scaffolding outside the covenant; its output is checked by evidence, not
//! trusted by design.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let kernel = match args.next() {
        Some(k) => PathBuf::from(k),
        None => bail!("usage: kimage <kernel-elf> <output-image>"),
    };
    let output = match args.next() {
        Some(o) => PathBuf::from(o),
        None => bail!("usage: kimage <kernel-elf> <output-image>"),
    };

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating output directory {}", parent.display()))?;
    }

    bootloader::UefiBoot::new(&kernel)
        .create_disk_image(&output)
        .with_context(|| {
            format!(
                "building UEFI disk image from {} into {}",
                kernel.display(),
                output.display()
            )
        })?;

    Ok(())
}
