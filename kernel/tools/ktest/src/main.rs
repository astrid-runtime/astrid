//! Host QEMU serial-assertion harness.
//!
//! End to end: build the ring-0 kernel, wrap it into a UEFI image (twice, for a
//! determinism check), boot it under the frozen machine contract, capture the
//! JSONL serial event stream, and assert the milestone's evidence. QEMU is
//! always run under a hard wall-clock timeout and killed by this process.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use wait_timeout::ChildExt;

/// Frozen machine contract.
const FIRMWARE_CODE: &str = "/opt/homebrew/share/qemu/edk2-x86_64-code.fd";
const FIRMWARE_VARS_TEMPLATE: &str = "/opt/homebrew/share/qemu/edk2-i386-vars.fd";
const QEMU_TIMEOUT_SECS: u64 = 240;
/// isa-debug-exit success value 0x10 -> QEMU process exit code (0x10<<1)|1.
const EXPECT_EXIT_CODE: i32 = 33;
/// Toolchain used to build the host tools. The `bootloader` 0.11 builder runs
/// `cargo install ... -Zbuild-std`, which requires nightly; the ring-0 kernel
/// itself is built with the spec-pinned stable toolchain. Override via
/// `KTEST_TOOLCHAIN` if a different nightly is needed.
fn tools_toolchain() -> String {
    std::env::var("KTEST_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_string())
}

fn main() -> Result<()> {
    let root = workspace_root()?;
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    // 1. Build the ring-0 kernel for the bare-metal target.
    println!("== building astrid-native-kernel (x86_64-unknown-none, release) ==");
    run_inherited(
        Command::new(&cargo).current_dir(&root).args([
            "build",
            "-p",
            "astrid-native-kernel",
            "--target",
            "x86_64-unknown-none",
            "--release",
        ]),
        "cargo build -p astrid-native-kernel",
    )?;

    let kernel_elf = root.join("target/x86_64-unknown-none/release/astrid-native-kernel");
    if !kernel_elf.exists() {
        bail!("kernel ELF not found at {}", kernel_elf.display());
    }

    // 2. Build the UEFI image twice for the determinism check.
    let out_dir = root.join("target/kimage");
    std::fs::create_dir_all(&out_dir).context("creating kimage output dir")?;
    let image_a = out_dir.join("astrid-native-kernel-a.img");
    let image_b = out_dir.join("astrid-native-kernel-b.img");
    println!("== building UEFI disk image (x2) ==");
    build_image(&root, &kernel_elf, &image_a)?;
    build_image(&root, &kernel_elf, &image_b)?;

    // 3. Determinism verdict (reported, never a boot-assertion failure).
    let determinism_ok = report_determinism(&image_a, &image_b)?;

    // 4. Boot under QEMU, capture serial, hard-kill at the timeout.
    println!("== booting under QEMU (q35/UEFI/TCG, timeout {QEMU_TIMEOUT_SECS}s) ==");
    let run = run_qemu(&out_dir, &image_a)?;

    // 5+6. Parse JSONL (skipping non-JSON firmware noise) and assert.
    let events = parse_events(&run.serial);
    println!("\n== parsed {} kernel event(s) ==", events.len());
    for ev in &events {
        println!("  {ev}");
    }

    let assertions_ok = assert_events(&events, run.exit_code);

    println!("\n== summary ==");
    println!(
        "DETERMINISM: {}",
        if determinism_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "QEMU exit code: {} (expected {EXPECT_EXIT_CODE})",
        run.exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signaled/none".to_string())
    );
    println!(
        "ASSERTIONS: {}",
        if assertions_ok { "PASS" } else { "FAIL" }
    );

    // The determinism verdict is reported, not gating. Boot assertions gate.
    if assertions_ok {
        Ok(())
    } else {
        bail!("boot assertions failed");
    }
}

fn workspace_root() -> Result<PathBuf> {
    // CARGO_MANIFEST_DIR = <root>/tools/ktest
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("resolving kernel workspace root")
}

fn build_image(root: &Path, kernel_elf: &Path, output: &Path) -> Result<()> {
    // `rustup run <toolchain> cargo` selects the nightly explicitly, rather
    // than reusing the stable `CARGO` binary path (which would ignore
    // RUSTUP_TOOLCHAIN and fail the bootloader builder's `-Zbuild-std`).
    run_inherited(
        Command::new("rustup").current_dir(root).args([
            "run",
            &tools_toolchain(),
            "cargo",
            "run",
            "-q",
            "-p",
            "kimage",
            "--release",
            "--",
            &kernel_elf.to_string_lossy(),
            &output.to_string_lossy(),
        ]),
        "kimage",
    )
}

fn report_determinism(a: &Path, b: &Path) -> Result<bool> {
    let bytes_a = std::fs::read(a).with_context(|| format!("reading {}", a.display()))?;
    let bytes_b = std::fs::read(b).with_context(|| format!("reading {}", b.display()))?;
    let hash_a = blake3::hash(&bytes_a);
    let hash_b = blake3::hash(&bytes_b);
    if hash_a == hash_b {
        println!("determinism: identical images (blake3 {})", hash_a.to_hex());
        return Ok(true);
    }
    println!(
        "determinism: DIVERGENT (blake3 {} vs {})",
        hash_a.to_hex(),
        hash_b.to_hex()
    );
    if bytes_a.len() != bytes_b.len() {
        println!(
            "  image sizes differ: {} vs {} bytes",
            bytes_a.len(),
            bytes_b.len()
        );
    }
    // Summarize differing byte ranges (report, not a failure).
    let n = bytes_a.len().min(bytes_b.len());
    let mut ranges = 0usize;
    let mut i = 0usize;
    while i < n {
        if bytes_a[i] != bytes_b[i] {
            let start = i;
            while i < n && bytes_a[i] != bytes_b[i] {
                i += 1;
            }
            if ranges < 16 {
                println!("  differ: bytes [{start:#x}..{i:#x}) ({} bytes)", i - start);
            }
            ranges += 1;
        } else {
            i += 1;
        }
    }
    println!("  total differing ranges: {ranges}");
    Ok(false)
}

struct QemuRun {
    serial: String,
    exit_code: Option<i32>,
}

fn run_qemu(out_dir: &Path, image: &Path) -> Result<QemuRun> {
    // Per-run writable copy of the vars flash (firmware mutates it).
    let vars = out_dir.join("vars.fd");
    std::fs::copy(FIRMWARE_VARS_TEMPLATE, &vars)
        .with_context(|| format!("copying vars flash from {FIRMWARE_VARS_TEMPLATE}"))?;

    let mut child = Command::new("qemu-system-x86_64")
        .args([
            "-machine",
            "q35",
            "-cpu",
            "max",
            "-m",
            "256",
            "-smp",
            "1",
            "-drive",
            &format!("if=pflash,format=raw,readonly=on,file={FIRMWARE_CODE}"),
            "-drive",
            &format!("if=pflash,format=raw,file={}", vars.display()),
            "-drive",
            &format!("format=raw,file={}", image.display()),
            "-serial",
            "stdio",
            "-display",
            "none",
            "-monitor",
            "none",
            "-no-reboot",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning qemu-system-x86_64")?;

    // Drain serial concurrently so the pipe never blocks the guest.
    let mut stdout = child.stdout.take().context("capturing qemu stdout")?;
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });

    let status = match child
        .wait_timeout(Duration::from_secs(QEMU_TIMEOUT_SECS))
        .context("waiting on qemu")?
    {
        Some(status) => status,
        None => {
            eprintln!("!! QEMU exceeded {QEMU_TIMEOUT_SECS}s — killing");
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

fn parse_events(serial: &str) -> Vec<Value> {
    serial
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                return None;
            }
            serde_json::from_str::<Value>(trimmed)
                .ok()
                .filter(|v| v.get("ev").is_some())
        })
        .collect()
}

fn ev_name(v: &Value) -> &str {
    v.get("ev").and_then(Value::as_str).unwrap_or("")
}

fn assert_events(events: &[Value], exit_code: Option<i32>) -> bool {
    let mut ok = true;
    let mut check = |label: &str, pass: bool| {
        println!("  [{}] {label}", if pass { "PASS" } else { "FAIL" });
        ok &= pass;
    };

    println!("\n== assertions ==");

    // boot.entry is the first kernel event.
    check(
        "boot.entry is first kernel event",
        events.first().map(ev_name) == Some("boot.entry"),
    );

    // Required events appear in this relative order.
    let order = [
        "boot.entry",
        "mem.map",
        "paging.wx",
        "heap.ready",
        "idt.ready",
    ];
    let mut last = -1i64;
    let mut ordered = true;
    for name in order {
        match events.iter().position(|e| ev_name(e) == name) {
            Some(idx) if (idx as i64) > last => last = idx as i64,
            _ => ordered = false,
        }
    }
    check("boot.entry<mem.map<paging.wx<heap.ready<idt.ready", ordered);

    // paging.wx W^X booleans are correct.
    let wx = events.iter().find(|e| ev_name(e) == "paging.wx");
    let wx_ok = wx.is_some_and(|e| {
        e.get("rodata_nx_w") == Some(&Value::Bool(false))
            && e.get("text_w") == Some(&Value::Bool(false))
    });
    check("paging.wx rodata_nx_w=false && text_w=false", wx_ok);

    // At least 8 timer ticks.
    let ticks = events
        .iter()
        .filter(|e| ev_name(e) == "apic.timer.tick")
        .count();
    check(&format!(">=8 apic.timer.tick (got {ticks})"), ticks >= 8);

    // Every self-test passed (present as test.pass, and never test.fail).
    let expected_tests = [
        "int3_handled",
        "wx_rodata_write",
        "nx_data_exec",
        "heap_exhaustion",
        "frame_unique",
        "frame_exhaustion",
    ];
    for name in expected_tests {
        let passed = events.iter().any(|e| {
            ev_name(e) == "test.pass" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        let failed = events.iter().any(|e| {
            ev_name(e) == "test.fail" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        check(&format!("test.pass {name}"), passed && !failed);
    }

    // ---- M2: first ring-3 protection domain -------------------------------

    // All seven ring-3 scenarios passed (present as test.pass, never test.fail).
    let scenario_tests = [
        "ring3_happy",
        "ring3_kernel_read",
        "ring3_priv_insn",
        "ring3_bad_cap",
        "ring3_stale_cap",
        "ring3_runaway",
        "ring3_reuse",
    ];
    for name in scenario_tests {
        let passed = events.iter().any(|e| {
            ev_name(e) == "test.pass" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        let failed = events.iter().any(|e| {
            ev_name(e) == "test.fail" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        check(&format!("test.pass {name}"), passed && !failed);
    }

    // At least one domain.killed for each cause literal (the fixed 3-set).
    for cause in ["pf", "gp", "quota"] {
        let present = events.iter().any(|e| {
            ev_name(e) == "domain.killed" && e.get("cause").and_then(Value::as_str) == Some(cause)
        });
        check(&format!("domain.killed cause={cause}"), present);
    }

    // Revocation produced at least one cap.revoked record.
    let revoked = events.iter().any(|e| ev_name(e) == "cap.revoked");
    check("cap.revoked present", revoked);

    // ---- M3: bounded IPC endpoints + capability transfer by derivation ----

    // All seven M3 IPC scenarios passed (present as test.pass, never test.fail).
    let m3_scenarios = [
        "ipc_rendezvous",
        "ipc_cap_transfer",
        "ipc_no_widen",
        "ipc_scoped_revoke",
        "ipc_authority",
        "ipc_ep_full",
        "ipc_deadlock_guard",
    ];
    for name in m3_scenarios {
        let passed = events.iter().any(|e| {
            ev_name(e) == "test.pass" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        let failed = events.iter().any(|e| {
            ev_name(e) == "test.fail" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        check(&format!("test.pass {name}"), passed && !failed);
    }

    // Rendezvous suspend/resume: a domain blocked on recv, then was woken.
    let blocked_idx = events.iter().position(|e| ev_name(e) == "ipc.blocked");
    let wakeup_idx = events.iter().position(|e| ev_name(e) == "ipc.wakeup");
    check(
        "ipc.blocked before ipc.wakeup",
        matches!((blocked_idx, wakeup_idx), (Some(b), Some(w)) if b < w),
    );

    // Capability transfer by derivation: a full-rights grant (0b011 = 3) and a
    // no-widen grant (0b001 = 1) each produced a cap.transfer edge.
    let transfer_with_rights = |r: u64| {
        events.iter().any(|e| {
            ev_name(e) == "cap.transfer" && e.get("rights").and_then(Value::as_u64) == Some(r)
        })
    };
    check("cap.transfer rights=3 present", transfer_with_rights(3));
    check("cap.transfer rights=1 present", transfer_with_rights(1));

    // Scoped subtree revocation killed at least the source + child nodes.
    let revoke_tree_ok = events.iter().any(|e| {
        ev_name(e) == "cap.revoke_tree"
            && e.get("killed")
                .and_then(Value::as_u64)
                .is_some_and(|k| k >= 2)
    });
    check("cap.revoke_tree killed>=2", revoke_tree_ok);

    // Deadlock liveness guard: the all-blocked set was detected and the victim
    // killed with the new cause literal.
    let deadlock_ev = events.iter().any(|e| ev_name(e) == "ipc.deadlock");
    check("ipc.deadlock present", deadlock_ev);
    let killed_deadlock = events.iter().any(|e| {
        ev_name(e) == "domain.killed" && e.get("cause").and_then(Value::as_str) == Some("deadlock")
    });
    check("domain.killed cause=deadlock", killed_deadlock);

    // No pool leak across all scenarios: the final census equals the baseline
    // (fully-free) census captured at kernel start.
    let census: Vec<&Value> = events
        .iter()
        .filter(|e| ev_name(e) == "pools.census")
        .collect();
    let census_ok = census.len() >= 2 && {
        let base = census.first().unwrap();
        let last = census.last().unwrap();
        let f = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64);
        f(base, "objects_free") == f(last, "objects_free")
            && f(base, "endpoints_free") == f(last, "endpoints_free")
            && f(base, "deriv_free") == f(last, "deriv_free")
    };
    check("pools.census final == baseline (no leak)", census_ok);

    // Every domain that was created was reclaimed, and every reclaim balanced.
    let creates = events
        .iter()
        .filter(|e| ev_name(e) == "domain.create")
        .count();
    let reclaims: Vec<&Value> = events
        .iter()
        .filter(|e| ev_name(e) == "domain.reclaimed")
        .collect();
    check(
        &format!(
            "domain.reclaimed count == domain.create count ({})",
            creates
        ),
        creates > 0 && reclaims.len() == creates,
    );
    let all_balanced = !reclaims.is_empty()
        && reclaims
            .iter()
            .all(|e| e.get("balance_ok") == Some(&Value::Bool(true)));
    check("every domain.reclaimed balance_ok=true", all_balanced);

    // Final halt with outcome ok.
    let halt_ok = events
        .iter()
        .find(|e| ev_name(e) == "halt")
        .and_then(|e| e.get("outcome").and_then(Value::as_str))
        == Some("ok");
    check("halt outcome=ok", halt_ok);

    // QEMU exit code.
    check(
        &format!("QEMU exit code == {EXPECT_EXIT_CODE}"),
        exit_code == Some(EXPECT_EXIT_CODE),
    );

    ok
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
