//! Host tool: wrap a kernel ELF into a bootable UEFI disk image.
//!
//! Usage: `kimage <kernel-elf> <output-image> --root-key <file>
//! --kernel-key <file> --sysgen-key <file> [--tamper-handoff|--tamper-sysgen|--mismatch-sysgen-plan]`. Key files contain exactly 32 raw
//! seed bytes encoded as 64 hexadecimal characters. No signing material is
//! taken from the environment or selected by a silent default. The explicit
//! fixture files under `tools/kimage/fixtures/` are development-only inputs.
//!
//! The ramdisk is exactly `[379-byte ASTRIDPH][355-byte ASTRIDDC][548-byte
//! ASTRIDSG]`; the latter two are also written as `<output>.closures` and
//! `<output>.sysgen` for inspection. The root-signed handoff binds the raw ELF
//! measurement, table digest, and fixture loader/boot-context identities. It
//! is not firmware authentication or a production root of trust.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use astrid_native_closure::{
    BootContextBinding, CURRENT_FLOOR, HANDOFF_LEN, HandoffContext, LoaderIdentity,
    LoaderMeasurement, MeasuredIdentity, PolicyGeneration, PolicyHandoff, TABLE_LEN, encode_table,
    sign_policy_handoff, signed_table,
};
use astrid_system_generation::emulator_fixture::{
    EMULATOR_CLOSURE_ROOT, EMULATOR_COMPONENTS, EMULATOR_GENERATION_FLOOR, EMULATOR_MANIFEST_SIZES,
    EMULATOR_OBJECT_ROOT, EMULATOR_PLAN_DIGEST,
};
use astrid_system_generation::{
    ContentId, Expiration, Generation, MANIFEST_LEN, ManifestInput, Revocation, RollbackFloor,
    SystemGenerationManifest, signed_bytes,
};
use ed25519_dalek::SigningKey;

const EMULATOR_ROOT_VERIFY_KEY: [u8; 32] = [
    237, 73, 40, 198, 40, 209, 194, 198, 234, 233, 3, 56, 144, 89, 149, 97, 41, 89, 39, 58, 92, 99,
    249, 54, 54, 193, 70, 20, 172, 135, 55, 209,
];
const LOADER_MEASUREMENT_DOMAIN: &[u8] = b"astrid.kimage.loader.measurement.v1";
const LOADER_IDENTITY_DOMAIN: &[u8] = b"astrid.kimage.loader.identity.v1";
const BOOT_CONTEXT_DOMAIN: &[u8] = b"astrid.boot.q35.uefi.tcg.v1";
/// Deliberately mismatched, but valid, plan identity for the ring-0 reject
/// falsifier. The descriptor remains canonical and correctly signed; only
/// compiled TrustedInput admission should reject it.
const MISMATCH_PLAN_DIGEST: [u8; 32] = [0x99; 32];

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let kernel = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    let output = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    let root_key = required_key(&mut args, "--root-key")?;
    let kernel_key = required_key(&mut args, "--kernel-key")?;
    let sysgen_key = required_key(&mut args, "--sysgen-key")?;
    let tamper_arg = args.next();
    let tamper_handoff = match tamper_arg.as_deref() {
        None => false,
        Some("--tamper-handoff") => true,
        Some("--tamper-sysgen" | "--mismatch-sysgen-plan") => false,
        Some(_) => bail!("unexpected argument; {}", usage()),
    };
    let tamper_sysgen = tamper_arg.as_deref() == Some("--tamper-sysgen");
    let mismatch_sysgen_plan = tamper_arg.as_deref() == Some("--mismatch-sysgen-plan");
    if args.next().is_some() {
        bail!("unexpected argument; {}", usage());
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating output directory {}", parent.display()))?;
    }

    let elf = std::fs::read(&kernel)
        .with_context(|| format!("reading kernel ELF {}", kernel.display()))?;
    let root_key = read_signing_key(&root_key)?;
    let kernel_key = read_signing_key(&kernel_key)?;
    let sysgen_key = read_signing_key(&sysgen_key)?;
    if root_key.verifying_key().to_bytes() != EMULATOR_ROOT_VERIFY_KEY {
        bail!("explicit root key is not the emulator fixture root key");
    }

    let kernel_image = MeasuredIdentity::from_payload(&elf);
    let kernel_identity = ContentId::try_from_bytes(kernel_image.as_bytes()).map_err(|err| {
        anyhow::anyhow!("kernel identity fixture is invalid: {}", err.as_reason())
    })?;
    let plan_digest = if mismatch_sysgen_plan {
        MISMATCH_PLAN_DIGEST
    } else {
        EMULATOR_PLAN_DIGEST
    };
    let manifest = SystemGenerationManifest::try_new(ManifestInput {
        kernel_identity,
        plan_digest: ContentId::try_from_bytes(plan_digest)
            .map_err(|err| anyhow::anyhow!("plan fixture is invalid: {}", err.as_reason()))?,
        components: EMULATOR_COMPONENTS,
        object_root: ContentId::try_from_bytes(EMULATOR_OBJECT_ROOT)
            .map_err(|err| anyhow::anyhow!("object fixture is invalid: {}", err.as_reason()))?,
        closure_root: ContentId::try_from_bytes(EMULATOR_CLOSURE_ROOT)
            .map_err(|err| anyhow::anyhow!("closure fixture is invalid: {}", err.as_reason()))?,
        generation: Generation::new(EMULATOR_GENERATION_FLOOR),
        rollback_floor: RollbackFloor::new(EMULATOR_GENERATION_FLOOR),
        expires_at: Expiration::never(),
        revocation: Revocation::Active,
        sizes: EMULATOR_MANIFEST_SIZES,
    })
    .map_err(|err| anyhow::anyhow!("system-generation fixture is invalid: {}", err.as_reason()))?;
    let descriptor = signed_bytes(&sysgen_key, manifest);
    let table = signed_table(
        &kernel_key,
        &sysgen_key,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        &elf,
        &descriptor,
    );
    let closures = encode_table(&table);
    let closure_table = MeasuredIdentity::from_payload(&closures);
    let policy = PolicyHandoff::for_signing(
        kernel_key.verifying_key().to_bytes(),
        sysgen_key.verifying_key().to_bytes(),
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        PolicyGeneration::new(1),
        expected_context(kernel_image, closure_table),
    );
    let handoff = sign_policy_handoff(&root_key, &policy);
    let mut ramdisk = [0u8; HANDOFF_LEN + TABLE_LEN + MANIFEST_LEN];
    ramdisk[..HANDOFF_LEN].copy_from_slice(&handoff);
    ramdisk[HANDOFF_LEN..HANDOFF_LEN + TABLE_LEN].copy_from_slice(&closures);
    ramdisk[HANDOFF_LEN + TABLE_LEN..].copy_from_slice(&descriptor);
    if tamper_sysgen {
        // Test-only image mode: corrupt the signed descriptor after packing so
        // the loader must reject the table/descriptor identity binding.
        ramdisk[HANDOFF_LEN + TABLE_LEN] ^= 1;
    } else if tamper_handoff {
        // Test-only image mode: corrupt the signed envelope after signing so
        // the loader must reject it before any PT_LOAD mapping or kernel entry.
        ramdisk[0] ^= 1;
    }

    let closures_path = output.with_extension("closures");
    std::fs::write(&closures_path, closures)
        .with_context(|| format!("writing dual-closure table {}", closures_path.display()))?;
    let descriptor_path = output.with_extension("sysgen");
    std::fs::write(&descriptor_path, descriptor).with_context(|| {
        format!(
            "writing system-generation descriptor {}",
            descriptor_path.display()
        )
    })?;
    let ramdisk_path = output.with_extension("ramdisk");
    std::fs::write(&ramdisk_path, ramdisk)
        .with_context(|| format!("writing policy handoff ramdisk {}", ramdisk_path.display()))?;

    let mut boot = bootloader::UefiBoot::new(&kernel);
    boot.set_ramdisk(&ramdisk_path);
    boot.create_disk_image(&output).with_context(|| {
        format!(
            "building UEFI disk image from {} into {}",
            kernel.display(),
            output.display()
        )
    })?;

    Ok(())
}

fn usage() -> &'static str {
    "usage: kimage <kernel-elf> <output-image> --root-key <file> --kernel-key <file> --sysgen-key <file> [--tamper-handoff|--tamper-sysgen|--mismatch-sysgen-plan]"
}

fn required_key(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf> {
    match (args.next().as_deref(), args.next()) {
        (Some(value), Some(path)) if value == flag => Ok(PathBuf::from(path)),
        _ => bail!("missing {flag}; {}", usage()),
    }
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading explicit signing key {}", path.display()))?;
    let text = text.trim();
    if text.len() != 64 {
        bail!(
            "signing key {} must contain exactly 64 hex characters",
            path.display()
        );
    }
    let mut seed = [0u8; 32];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        seed[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(SigningKey::from_bytes(&seed))
}

fn hex(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("signing key contains non-hex data"),
    }
}

fn expected_context(
    kernel_image: MeasuredIdentity,
    closure_table: MeasuredIdentity,
) -> HandoffContext {
    HandoffContext::new(
        kernel_image,
        closure_table,
        LoaderMeasurement::from_bytes(
            MeasuredIdentity::from_payload(LOADER_MEASUREMENT_DOMAIN).as_bytes(),
        ),
        LoaderIdentity::from_bytes(
            MeasuredIdentity::from_payload(LOADER_IDENTITY_DOMAIN).as_bytes(),
        ),
        BootContextBinding::from_bytes(
            MeasuredIdentity::from_payload(BOOT_CONTEXT_DOMAIN).as_bytes(),
        ),
    )
}
