//! Host QEMU serial-assertion harness for the M1 experimental machine
//! plus the fixed authenticated handoff/dual-closure/descriptor fixture.
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
use astrid_native_closure::{
    BootContextBinding, CURRENT_FLOOR, EMULATOR_COMPONENT_LEN, HANDOFF_LEN, HandoffContext,
    LoaderIdentity, LoaderMeasurement, MeasuredIdentity, PolicyGeneration, RootVerifier, TABLE_LEN,
    TrustedPolicy, verify_policy_handoff, verify_table,
};
use astrid_system_generation::MANIFEST_LEN;
use astrid_system_generation::emulator_fixture::emulator_component;
use bootloader_api::info::LoaderHandoffVerification;
use ktest::determinism::{Determinism, compare_images};
use ktest::events::{
    ExpectedClosures, RING0_REJECT_EXIT_CODE, assert_boot, assert_ring0_plan_mismatch, parse_events,
};
use ktest::firmware;
use ktest::image::{KIMAGE_NIGHTLY, KimageInvocation};
use ktest::machine::{self, EXPECT_EXIT_CODE, QEMU_BIN, TAMPER_TIMEOUT, TIMEOUT};
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
    let tampered_image = out_dir.join("astrid-native-kernel-tampered.img");
    let mismatched_plan_image = out_dir.join("astrid-native-kernel-mismatched-plan.img");
    println!("== building UEFI disk image (x2) ==");
    build_image(&root, &kernel_elf, &image_a)?;
    build_image(&root, &kernel_elf, &image_b)?;
    build_tampered_image(&root, &kernel_elf, &tampered_image)?;
    build_mismatched_plan_image(&root, &kernel_elf, &mismatched_plan_image)?;

    let determinism = compare_images(&image_a, &image_b)?;
    let (kernel_hex, sysgen_hex, kernel_image_hex, closure_table_hex) =
        loader_identities(&image_a, &image_b, &kernel_elf)?;

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
    let run = run_qemu(&out_dir, &firmware.code, &firmware.vars, &image_a, TIMEOUT)?;

    let events = parse_events(&run.serial);
    println!("\n== parsed {} kernel event(s) ==", events.len());
    for ev in &events {
        println!("  {ev}");
    }

    let closures = ExpectedClosures {
        policy_generation: 1,
        kernel_image_hex: &kernel_image_hex,
        closure_table_hex: &closure_table_hex,
        kernel_id_hex: &kernel_hex,
        sysgen_id_hex: &sysgen_hex,
        kernel_floor: CURRENT_FLOOR.get(),
        sysgen_floor: CURRENT_FLOOR.get(),
    };
    let assertions_ok = assert_boot(&events, run.exit_code, EXPECT_EXIT_CODE, &closures);
    print_summary(determinism, run.exit_code, assertions_ok);

    if assertions_ok {
        assert_tampered_boot_rejected(&run_qemu(
            &out_dir,
            &firmware.code,
            &firmware.vars,
            &tampered_image,
            TAMPER_TIMEOUT,
        )?)?;
        let mismatched_plan_run = run_qemu(
            &out_dir,
            &firmware.code,
            &firmware.vars,
            &mismatched_plan_image,
            TAMPER_TIMEOUT,
        )?;
        let mismatched_plan_events = parse_events(&mismatched_plan_run.serial);
        println!(
            "\n== ring-0 plan-mismatch QEMU events (exit {:?}) ==",
            mismatched_plan_run.exit_code
        );
        for event in &mismatched_plan_events {
            println!("  {event}");
        }
        if !assert_ring0_plan_mismatch(&mismatched_plan_events, mismatched_plan_run.exit_code) {
            bail!(
                "ring-0 plan-mismatch rejection assertions failed (timed_out={}, serial={:?})",
                mismatched_plan_run.timed_out,
                mismatched_plan_run.serial
            );
        }
        println!(
            "ring-0 plan-mismatch rejection: PASS (QEMU exit {}, expected {})",
            mismatched_plan_run.exit_code.unwrap_or_default(),
            RING0_REJECT_EXIT_CODE
        );
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

fn build_tampered_image(root: &Path, kernel_elf: &Path, output: &Path) -> Result<()> {
    let inv = KimageInvocation::new(root, tools_toolchain());
    run_inherited(
        &mut inv.command_with_tampered_sysgen(root, kernel_elf, output),
        "kimage tampered system-generation descriptor",
    )
}

fn build_mismatched_plan_image(root: &Path, kernel_elf: &Path, output: &Path) -> Result<()> {
    let inv = KimageInvocation::new(root, tools_toolchain());
    run_inherited(
        &mut inv.command_with_mismatched_sysgen_plan(root, kernel_elf, output),
        "kimage mismatched system-generation plan",
    )
}

fn identity_hex(id: MeasuredIdentity) -> String {
    let mut buf = [0u8; 64];
    id.write_hex(&mut buf);
    String::from_utf8(buf.to_vec()).expect("hex digits are ascii")
}

const EMULATOR_ROOT_VERIFY_KEY: [u8; 32] = [
    237, 73, 40, 198, 40, 209, 194, 198, 234, 233, 3, 56, 144, 89, 149, 97, 41, 89, 39, 58, 92, 99,
    249, 54, 54, 193, 70, 20, 172, 135, 55, 209,
];
const LOADER_MEASUREMENT_DOMAIN: &[u8] = b"astrid.kimage.loader.measurement.v1";
const LOADER_IDENTITY_DOMAIN: &[u8] = b"astrid.kimage.loader.identity.v1";
const BOOT_CONTEXT_DOMAIN: &[u8] = b"astrid.boot.q35.uefi.tcg.v1";

fn loader_identities(
    image_a: &Path,
    image_b: &Path,
    kernel_elf: &Path,
) -> Result<(String, String, String, String)> {
    let ramdisk_a = image_a.with_extension("ramdisk");
    let ramdisk_b = image_b.with_extension("ramdisk");
    let bytes_a = std::fs::read(&ramdisk_a)
        .with_context(|| format!("reading policy handoff ramdisk {}", ramdisk_a.display()))?;
    let bytes_b = std::fs::read(&ramdisk_b)
        .with_context(|| format!("reading policy handoff ramdisk {}", ramdisk_b.display()))?;
    if bytes_a != bytes_b {
        bail!("policy handoff ramdisks differ across kimage invocations");
    }
    let table_end = HANDOFF_LEN + TABLE_LEN;
    let manifest_end = table_end + MANIFEST_LEN;
    let bundle_len = manifest_end + EMULATOR_COMPONENT_LEN;
    if bytes_a.len() != bundle_len {
        bail!(
            "policy handoff ramdisk length is {}, expected {}",
            bytes_a.len(),
            bundle_len
        );
    }
    let elf = std::fs::read(kernel_elf)
        .with_context(|| format!("reading kernel ELF {}", kernel_elf.display()))?;
    let kernel_id = MeasuredIdentity::from_payload(&elf);
    let table_bytes = &bytes_a[HANDOFF_LEN..table_end];
    let descriptor_bytes = &bytes_a[table_end..manifest_end];
    let component_bytes = &bytes_a[manifest_end..];
    let closure_table = MeasuredIdentity::from_payload(table_bytes);
    let expected = expected_context(kernel_id, closure_table);
    let root = RootVerifier::try_new(
        EMULATOR_ROOT_VERIFY_KEY,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        PolicyGeneration::new(1),
    )
    .map_err(|err| anyhow::anyhow!("root verifier construction failed: {}", err.as_reason()))?;
    let handoff =
        verify_policy_handoff(&bytes_a[..HANDOFF_LEN], &root, &expected).map_err(|err| {
            anyhow::anyhow!("host verify_policy_handoff rejected: {}", err.as_reason())
        })?;
    let policy_handoff = handoff.policy();
    let policy = TrustedPolicy::try_new(
        policy_handoff.kernel_verify(),
        policy_handoff.sysgen_verify(),
        policy_handoff.kernel_floor(),
        policy_handoff.sysgen_floor(),
    )
    .map_err(|err| anyhow::anyhow!("handoff policy rejected: {}", err.as_reason()))?;
    let bound = verify_table(table_bytes, &policy)
        .map_err(|err| anyhow::anyhow!("host verify_table rejected: {}", err.as_reason()))?;
    let sysgen_id = MeasuredIdentity::from_payload(descriptor_bytes);
    if bound.kernel_identity() != kernel_id {
        bail!("loader kernel identity does not match measured ELF");
    }
    if bound.sysgen_identity() != sysgen_id {
        bail!("loader sysgen identity does not match descriptor bytes");
    }
    if !bound.distinct() {
        bail!("loader identities are not distinct");
    }
    if component_bytes != emulator_component() {
        bail!("authenticated component bytes do not match the canonical fixture");
    }
    let receipt = loader_receipt(&bytes_a, &handoff, kernel_id, closure_table);
    pre_relocation_hostile_checks(&bytes_a, &elf, &expected, &policy)?;
    receipt_checks(&bytes_a, &elf, &receipt, &handoff, &expected)?;
    let kernel_hex = identity_hex(bound.kernel_identity());
    let sysgen_hex = identity_hex(sysgen_id);
    let kernel_image_hex = identity_hex(kernel_id);
    let closure_table_hex = identity_hex(closure_table);
    println!("== policy handoff + dual-closure host verification OK ==");
    println!("kernel-bootstrap id: {kernel_hex}");
    println!("system-generation id: {sysgen_hex}");
    println!("raw ELF image id: {kernel_image_hex}");
    println!("closure table id: {closure_table_hex}");
    Ok((kernel_hex, sysgen_hex, kernel_image_hex, closure_table_hex))
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

fn loader_receipt(
    bundle: &[u8],
    handoff: &astrid_native_closure::AuthenticatedPolicyHandoff,
    kernel_image: MeasuredIdentity,
    closure_table: MeasuredIdentity,
) -> LoaderHandoffVerification {
    LoaderHandoffVerification {
        magic: *b"ASTRIDLV",
        version: 1,
        status: 1,
        reserved: [0; 6],
        envelope_digest: MeasuredIdentity::from_payload(&bundle[..HANDOFF_LEN]).as_bytes(),
        kernel_image: kernel_image.as_bytes(),
        closure_table: closure_table.as_bytes(),
        loader_measurement: handoff.policy().context().loader_measurement.as_bytes(),
        loader_identity: handoff.policy().context().loader_identity.as_bytes(),
        boot_context: handoff.policy().context().boot_context.as_bytes(),
        root_verify: handoff.root_verify(),
        kernel_verify: handoff.policy().kernel_verify(),
        sysgen_verify: handoff.policy().sysgen_verify(),
        policy_generation: handoff.policy().policy_generation().get(),
        kernel_floor: handoff.policy().kernel_floor().get(),
        sysgen_floor: handoff.policy().sysgen_floor().get(),
    }
}

/// Host-side execution of the pre-relocation handoff falsifiers. These run
/// before QEMU and cover every fixed-width field authenticated by the loader.
fn pre_relocation_hostile_checks(
    bundle: &[u8],
    elf: &[u8],
    expected: &HandoffContext,
    policy: &TrustedPolicy,
) -> Result<()> {
    let root = RootVerifier::try_new(
        EMULATOR_ROOT_VERIFY_KEY,
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        PolicyGeneration::new(1),
    )
    .map_err(|err| anyhow::anyhow!(err.as_reason()))?;
    let mut extended = bundle[..HANDOFF_LEN].to_vec();
    extended.push(0);
    for (name, bytes) in [
        ("missing", bundle[..0].to_vec()),
        ("truncated", bundle[..HANDOFF_LEN - 1].to_vec()),
        ("extended", extended),
    ] {
        if verify_policy_handoff(&bytes, &root, expected).is_ok() {
            bail!("hostile {name} handoff unexpectedly accepted");
        }
    }
    let mut tampered = bundle.to_vec();
    tampered[0] ^= 1;
    if verify_policy_handoff(&tampered[..HANDOFF_LEN], &root, expected).is_ok() {
        bail!("tampered handoff unexpectedly accepted");
    }
    let mut swapped = Vec::with_capacity(bundle.len());
    swapped.extend_from_slice(&bundle[HANDOFF_LEN..]);
    swapped.extend_from_slice(&bundle[..HANDOFF_LEN]);
    if verify_policy_handoff(&swapped[..HANDOFF_LEN], &root, expected).is_ok() {
        bail!("swapped handoff/table bundle unexpectedly accepted");
    }
    let mut wrong_context = *expected;
    wrong_context.kernel_image = MeasuredIdentity::from_payload(b"wrong raw ELF");
    if verify_policy_handoff(&bundle[..HANDOFF_LEN], &root, &wrong_context).is_ok() {
        bail!("loader/context replay unexpectedly accepted");
    }
    let wrong_root = RootVerifier::try_new(
        [0xA5; 32],
        CURRENT_FLOOR,
        CURRENT_FLOOR,
        PolicyGeneration::new(1),
    )
    .map_err(|err| anyhow::anyhow!(err.as_reason()))?;
    if verify_policy_handoff(&bundle[..HANDOFF_LEN], &wrong_root, expected).is_ok() {
        bail!("wrong root unexpectedly accepted");
    }
    for (name, offset) in [
        ("subkey", 67usize),
        ("floor", 131usize),
        ("generation", 147usize),
        ("kernel_digest", 155usize),
    ] {
        let mut altered = bundle[..HANDOFF_LEN].to_vec();
        altered[offset] ^= 1;
        if verify_policy_handoff(&altered, &root, expected).is_ok() {
            bail!("pre-hook {name} mutation unexpectedly accepted");
        }
    }
    let table_end = HANDOFF_LEN + TABLE_LEN;
    let mut table = bundle[HANDOFF_LEN..table_end].to_vec();
    table[0] ^= 1;
    if verify_table(&table, policy).is_ok() {
        bail!("tampered closure table unexpectedly accepted");
    }
    let bound = verify_table(&bundle[HANDOFF_LEN..table_end], policy)
        .map_err(|err| anyhow::anyhow!(err.as_reason()))?;
    let mut descriptor = bundle[table_end..].to_vec();
    descriptor[0] ^= 1;
    if bound.sysgen_identity() == MeasuredIdentity::from_payload(&descriptor) {
        bail!("mutated ASTRIDSG descriptor unexpectedly retained its table identity");
    }
    if elf.is_empty() {
        bail!("empty raw ELF fixture");
    }
    println!("pre-relocation hostile handoff/table falsifiers: PASS");
    Ok(())
}

fn receipt_matches(
    bundle: &[u8],
    receipt: &LoaderHandoffVerification,
    handoff: &astrid_native_closure::AuthenticatedPolicyHandoff,
    expected: &HandoffContext,
) -> bool {
    receipt.magic == *b"ASTRIDLV"
        && receipt.version == 1
        && receipt.status == 1
        && receipt.reserved == [0; 6]
        && receipt.envelope_digest
            == MeasuredIdentity::from_payload(&bundle[..HANDOFF_LEN]).as_bytes()
        && receipt.closure_table
            == MeasuredIdentity::from_payload(&bundle[HANDOFF_LEN..HANDOFF_LEN + TABLE_LEN])
                .as_bytes()
        && receipt.kernel_image == expected.kernel_image.as_bytes()
        && receipt.loader_measurement == expected.loader_measurement.as_bytes()
        && receipt.loader_identity == expected.loader_identity.as_bytes()
        && receipt.boot_context == expected.boot_context.as_bytes()
        && receipt.root_verify == handoff.root_verify()
        && receipt.kernel_verify == handoff.policy().kernel_verify()
        && receipt.sysgen_verify == handoff.policy().sysgen_verify()
        && receipt.policy_generation == handoff.policy().policy_generation().get()
        && receipt.kernel_floor == handoff.policy().kernel_floor().get()
        && receipt.sysgen_floor == handoff.policy().sysgen_floor().get()
}

fn receipt_checks(
    bundle: &[u8],
    elf: &[u8],
    receipt: &LoaderHandoffVerification,
    handoff: &astrid_native_closure::AuthenticatedPolicyHandoff,
    expected: &HandoffContext,
) -> Result<()> {
    if !receipt_matches(bundle, receipt, handoff, expected) {
        bail!("valid loader receipt rejected by host evidence check");
    }
    for (name, mutate) in [
        (
            "receipt status",
            mutate_status as fn(&mut LoaderHandoffVerification),
        ),
        ("receipt envelope digest", mutate_envelope),
        ("receipt table digest", mutate_table),
    ] {
        let mut altered = *receipt;
        mutate(&mut altered);
        if receipt_matches(bundle, &altered, handoff, expected) {
            bail!("forged {name} unexpectedly accepted");
        }
    }
    let mut altered_bundle = bundle.to_vec();
    altered_bundle[HANDOFF_LEN] ^= 1;
    if receipt_matches(&altered_bundle, receipt, handoff, expected) {
        bail!("forged bundle unexpectedly accepted with old receipt");
    }
    // Once loader evidence is emitted, later mutation of its raw backing
    // cannot change ring-0 acceptance: ring 0 never hashes kernel_addr.
    let mut mutated_raw = elf.to_vec();
    mutated_raw[0] ^= 1;
    if !receipt_matches(bundle, receipt, handoff, expected) || mutated_raw == elf {
        bail!("post-verification raw backing mutation changed evidence");
    }
    println!("loader receipt tamper/raw-backing falsifiers: PASS");
    Ok(())
}

fn mutate_status(receipt: &mut LoaderHandoffVerification) {
    receipt.status ^= 1;
}

fn mutate_envelope(receipt: &mut LoaderHandoffVerification) {
    receipt.envelope_digest[0] ^= 1;
}

fn mutate_table(receipt: &mut LoaderHandoffVerification) {
    receipt.closure_table[0] ^= 1;
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
    timed_out: bool,
}

fn run_qemu(
    out_dir: &Path,
    code: &Path,
    vars_template: &Path,
    image: &Path,
    timeout: std::time::Duration,
) -> Result<QemuRun> {
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

    let (status, timed_out) = match child.wait_timeout(timeout).context("waiting on qemu")? {
        Some(status) => (status, false),
        None => {
            eprintln!("!! QEMU exceeded {}s — killing", timeout.as_secs());
            let _ = child.kill();
            (child.wait().context("reaping killed qemu")?, true)
        },
    };

    let serial = reader.join().unwrap_or_default();
    Ok(QemuRun {
        serial: String::from_utf8_lossy(&serial).into_owned(),
        exit_code: status.code(),
        timed_out,
    })
}

fn assert_tampered_boot_rejected(run: &QemuRun) -> Result<()> {
    let events = parse_events(&run.serial);
    let entered = events
        .iter()
        .any(|event| ktest::events::ev_name(event) == "boot.entry");
    let reached_kernel = events.iter().any(|event| {
        let name = ktest::events::ev_name(event);
        name == "idt.ready" || name.starts_with("closure.") || name == "mem.map"
    });
    let rejected = run.serial.contains("Astrid policy handoff rejected");
    println!(
        "tampered ASTRIDSG: timed_out={} exit={:?} events={} loader_rejection_text={}",
        run.timed_out,
        run.exit_code,
        events.len(),
        rejected
    );
    if entered || reached_kernel || !run.timed_out || !rejected {
        bail!(
            "tampered ASTRIDSG did not fail before kernel entry (entered={entered}, reached_kernel={reached_kernel}, timed_out={}, rejected_text={rejected}, serial={:?})",
            run.timed_out,
            run.serial
        );
    }
    println!("tampered ASTRIDSG fail-before-entry: PASS");
    Ok(())
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
