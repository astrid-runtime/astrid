//! Host QEMU serial-assertion harness for the M1 experimental machine
//! plus the dual-closure stub.
//!
//! Builds the ring-0 kernel, wraps it into a UEFI image twice (determinism
//! measurement), boots under explicit TCG, and asserts one combined serial
//! sequence (boot, both closure floors/identities, bound, M1, halt).
//! Determinism FAIL is reported and does not gate boot assertions.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{Context, Result, bail};
use astrid_native_closure::{CURRENT_FLOOR, MeasuredIdentity, TrustedPolicy, verify_table};
use ktest::determinism::{Determinism, compare_images};
use ktest::events::{ExpectedClosures, assert_boot, parse_events};
use ktest::firmware;
use ktest::image::{KIMAGE_NIGHTLY, KimageInvocation};
use ktest::machine::{self, EXPECT_EXIT_CODE, QEMU_BIN, TIMEOUT};
use wait_timeout::ChildExt;

fn main() -> Result<()> {
    let root = workspace_root()?;
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let kernel_target = root.join("target");
    println!("== building astrid-native-kernel (x86_64-unknown-none, release) ==");
    run_inherited(
        Command::new(&cargo)
            .current_dir(&root)
            .args([
                "build",
                "-p",
                "astrid-native-kernel",
                "--locked",
                "--target",
                "x86_64-unknown-none",
                "--release",
                "--target-dir",
            ])
            .arg(&kernel_target),
        "cargo build -p astrid-native-kernel",
    )?;

    let kernel_elf = kernel_target.join("x86_64-unknown-none/release/astrid-native-kernel");
    if !kernel_elf.exists() {
        bail!("kernel ELF not found at {}", kernel_elf.display());
    }

    let out_dir = root.join("target/kimage");
    std::fs::create_dir_all(&out_dir).context("creating kimage output dir")?;
    let image_a = out_dir.join("astrid-native-kernel-a.img");
    let image_b = out_dir.join("astrid-native-kernel-b.img");
    println!("== building UEFI disk image (x2) ==");
    build_image(&root, &kernel_elf, &image_a)?;
    build_image(&root, &kernel_elf, &image_b)?;

    let determinism = compare_images(&image_a, &image_b)?;
    let (kernel_hex, sysgen_hex) = loader_identities(&image_a, &image_b, &kernel_elf)?;

    let firmware = firmware::discover()?;
    println!(
        "== firmware: code={} vars={} ==",
        firmware.code.display(),
        firmware.vars.display()
    );
    println!(
        "== booting under QEMU (q35/UEFI/TCG explicit accel, timeout {}s) ==",
        TIMEOUT.as_secs()
    );
    let run = run_qemu(&out_dir, &firmware.code, &firmware.vars, &image_a)?;

    let events = parse_events(&run.serial);
    println!("\n== parsed {} kernel event(s) ==", events.len());
    for ev in &events {
        println!("  {ev}");
    }

    let closures = ExpectedClosures {
        kernel_id_hex: &kernel_hex,
        sysgen_id_hex: &sysgen_hex,
        kernel_floor: CURRENT_FLOOR.get(),
        sysgen_floor: CURRENT_FLOOR.get(),
    };
    let assertions_ok = assert_boot(&events, run.exit_code, EXPECT_EXIT_CODE, &closures);
    print_summary(determinism, run.exit_code, assertions_ok);

    if assertions_ok {
        Ok(())
    } else {
        bail!("boot assertions failed");
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("resolving kernel workspace root")
}

fn tools_toolchain() -> String {
    std::env::var("KTEST_TOOLCHAIN").unwrap_or_else(|_| KIMAGE_NIGHTLY.to_string())
}

fn build_image(root: &Path, kernel_elf: &Path, output: &Path) -> Result<()> {
    let inv = KimageInvocation::new(root, tools_toolchain());
    run_inherited(&mut inv.command(root, kernel_elf, output), "kimage")
}

fn identity_hex(id: MeasuredIdentity) -> String {
    let mut buf = [0u8; 64];
    id.write_hex(&mut buf);
    String::from_utf8(buf.to_vec()).expect("hex digits are ascii")
}

fn loader_identities(
    image_a: &Path,
    image_b: &Path,
    kernel_elf: &Path,
) -> Result<(String, String)> {
    let closures_a = image_a.with_extension("closures");
    let closures_b = image_b.with_extension("closures");
    let bytes_a = std::fs::read(&closures_a)
        .with_context(|| format!("reading dual-closure table {}", closures_a.display()))?;
    let bytes_b = std::fs::read(&closures_b)
        .with_context(|| format!("reading dual-closure table {}", closures_b.display()))?;
    if bytes_a != bytes_b {
        bail!("dual-closure tables differ across kimage invocations");
    }
    let bound = verify_table(&bytes_a, &TrustedPolicy::emulator_fixture())
        .map_err(|err| anyhow::anyhow!("host verify_table rejected: {}", err.as_reason()))?;
    if bound.kernel_floor != CURRENT_FLOOR || bound.sysgen_floor != CURRENT_FLOOR {
        bail!("loader floors are not the emulator CURRENT_FLOOR minima");
    }
    let elf = std::fs::read(kernel_elf)
        .with_context(|| format!("reading kernel ELF {}", kernel_elf.display()))?;
    let kernel_id = MeasuredIdentity::from_payload(&elf);
    let sysgen_id = MeasuredIdentity::empty_sysgen();
    if bound.kernel_bootstrap != kernel_id {
        bail!("loader kernel identity does not match measured ELF");
    }
    if bound.system_generation != sysgen_id {
        bail!("loader sysgen identity is not the empty System Generation");
    }
    if !bound.distinct() {
        bail!("loader identities are not distinct");
    }
    let kernel_hex = identity_hex(kernel_id);
    let sysgen_hex = identity_hex(sysgen_id);
    println!("== dual-closure host verify_table OK ==");
    println!("kernel-bootstrap id: {kernel_hex}");
    println!("system-generation id: {sysgen_hex}");
    Ok((kernel_hex, sysgen_hex))
}

fn print_summary(determinism: Determinism, exit_code: Option<i32>, assertions_ok: bool) {
    println!("\n== summary ==");
    println!("DETERMINISM: {}", determinism.as_str());
    println!(
        "QEMU exit code: {} (expected {EXPECT_EXIT_CODE})",
        exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signaled/none".to_string())
    );
    println!(
        "ASSERTIONS: {}",
        if assertions_ok { "PASS" } else { "FAIL" }
    );
    println!("ACCEL: tcg (explicit). KVM/virtio/IOMMU were not selected.");
    if determinism == Determinism::Fail {
        println!("determinism FAIL is reported, not a boot-assertion gate");
    }
}

struct QemuRun {
    serial: String,
    exit_code: Option<i32>,
}

fn run_qemu(out_dir: &Path, code: &Path, vars_template: &Path, image: &Path) -> Result<QemuRun> {
    let vars = out_dir.join("vars.fd");
    std::fs::copy(vars_template, &vars)
        .with_context(|| format!("copying vars flash from {}", vars_template.display()))?;

    let args = machine::qemu_args(code, &vars, image);
    if !machine::contains_explicit_tcg(&args) {
        bail!("internal error: QEMU argv missing explicit TCG accel");
    }
    if machine::claims_kvm(&args) {
        bail!("internal error: QEMU argv selected KVM");
    }

    let mut child = Command::new(QEMU_BIN)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {QEMU_BIN}"))?;

    let mut stdout = child.stdout.take().context("capturing qemu stdout")?;
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });

    let status = match child.wait_timeout(TIMEOUT).context("waiting on qemu")? {
        Some(status) => status,
        None => {
            eprintln!("!! QEMU exceeded {}s — killing", TIMEOUT.as_secs());
            let _ = child.kill();
            child.wait().context("reaping killed qemu")?
        },
    };

    let serial = reader.join().unwrap_or_default();
    Ok(QemuRun {
        serial: String::from_utf8_lossy(&serial).into_owned(),
        exit_code: status.code(),
    })
}

fn run_inherited(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("spawning {what}"))?;
    if !status.success() {
        bail!("{what} failed with status {status}");
    }
    Ok(())
}
