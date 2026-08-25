//! Host tool: wrap a kernel ELF into a bootable UEFI disk image.
//!
//! Usage: `kimage <kernel-elf> <output-image>`. Signs a kernel/bootstrap
//! closure and a distinct empty System Generation with host-only fixture
//! *private* keys, embeds them as a bootloader ramdisk (memory table, not a
//! guest filesystem), and writes the same bytes next to the image as
//! `<output>.closures`.
//!
//! The boot loader is replaceable scaffolding outside the covenant. Ring 0
//! verifies against compiled fixture public keys. This is not firmware
//! ownership, self-measurement, or authenticated loader handoff.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use astrid_native_closure::{
    CURRENT_FLOOR, FixtureRole, encode_table, fixture_signing_key, signed_table,
};

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

    let elf = std::fs::read(&kernel)
        .with_context(|| format!("reading kernel ELF {}", kernel.display()))?;
    let table = signed_table(
        &fixture_signing_key(FixtureRole::KernelBootstrap),
        &fixture_signing_key(FixtureRole::SystemGeneration),
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        &elf,
    );
    let closures = encode_table(&table);
    let closures_path = output.with_extension("closures");
    std::fs::write(&closures_path, closures)
        .with_context(|| format!("writing dual-closure table {}", closures_path.display()))?;

    let mut boot = bootloader::UefiBoot::new(&kernel);
    boot.set_ramdisk(&closures_path);
    boot.create_disk_image(&output).with_context(|| {
        format!(
            "building UEFI disk image from {} into {}",
            kernel.display(),
            output.display()
        )
    })?;

    Ok(())
}
