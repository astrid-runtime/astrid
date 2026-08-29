#!/usr/bin/env python3
"""Repeatable evidence-only negative and crash matrix for the q35 harness."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QEMU_RUNS = ROOT / "target" / "qemu-runs"
RUNNER = ROOT / "scripts" / "run_qemu.py"
JOURNAL_SERIAL = "PIO1691-JOURNAL-0001"
CLONE_SERIAL = "PIO1691-CLONE-000001"


def serial_evidence(serial_text: str) -> list[str]:
    prefixes = (
        "CRASH-BARRIER ",
        "GUEST-ATA IDENTIFY.SERIAL.",
        "GUEST-AUTH-CANDIDATE",
        "PIO1691 ROUNDTRIP PASS",
        "PIO1691 SUCCESS",
        "PIO-GUEST-PANIC ",
        "RECOVERY=",
    )
    return [
        line
        for line in serial_text.splitlines()
        if line.startswith(prefixes)
    ]


def remove_run_dir(name: str) -> None:
    shutil.rmtree(QEMU_RUNS / name, ignore_errors=True)


def run_case(
    name: str, *, preserve_run: bool = False, **arguments: str | Path | int | bool
) -> dict[str, object]:
    command = [sys.executable, str(RUNNER), "--name", name]
    for key, value in arguments.items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            command.append(flag)
            continue
        if value is False:
            continue
        command.extend([flag, str(value)])

    completed = subprocess.run(command, cwd=ROOT, check=False)
    summary_path = QEMU_RUNS / name / "summary.json"
    serial_path = QEMU_RUNS / name / "serial.log"
    if not summary_path.exists() or not serial_path.exists():
        raise AssertionError(f"{name}: runner did not produce evidence")

    summary = json.loads(summary_path.read_text())
    result: dict[str, object] = {
        "name": name,
        "runner_rc": completed.returncode,
        "summary": summary,
        "serial_evidence": serial_evidence(serial_path.read_text(errors="replace")),
    }
    expected_serial = "" if arguments.get("no_journal_device") else JOURNAL_SERIAL
    if summary.get("journal_serial") != expected_serial:
        result["serial_error"] = [
            summary.get("journal_serial"),
            "expected",
            expected_serial,
        ]
    if not preserve_run:
        remove_run_dir(name)
    return result


def require(result: dict[str, object], *keys: str) -> None:
    summary = result["summary"]
    assert isinstance(summary, dict)
    name = result["name"]
    for key in keys:
        if not summary.get(key):
            raise AssertionError(f"{name}: missing {key}: {summary}")


def require_absent(result: dict[str, object], *keys: str) -> None:
    summary = result["summary"]
    assert isinstance(summary, dict)
    name = result["name"]
    for key in keys:
        if summary.get(key):
            raise AssertionError(f"{name}: unexpectedly set {key}: {summary}")


def main() -> int:
    if QEMU_RUNS.exists():
        QEMU_RUNS.mkdir(exist_ok=True)
    else:
        QEMU_RUNS.mkdir(parents=True)
    inputs = QEMU_RUNS / "matrix-inputs"
    inputs.mkdir(exist_ok=True)
    results: list[dict[str, object]] = []

    try:
        clean = run_case("clean-two-boot", preserve_run=True)
        require(clean, "changed", "serial_ok", "auth_candidate", "roundtrip")
        source = inputs / "clean.img"
        shutil.copyfile(QEMU_RUNS / "clean-two-boot" / "journal.img", source)
        remove_run_dir("clean-two-boot")
        results.append(clean)

        recover = run_case(
            "recover", mode="recover", reuse_journal=source, keep_journal=True
        )
        require(recover, "serial_ok", "auth_candidate")
        require_absent(recover, "changed", "panic")
        results.append(recover)

        for frame in (0, 8, 15):
            crash = run_case(
                f"crash-frame-{frame}",
                preserve_run=True,
                crash=f"frame:{frame}",
                kill_after_serial=f"CRASH-BARRIER FRAME={frame:016x}",
            )
            assert crash["runner_rc"] == 137
            require(crash, "serial_ok", "missing_commit")
            require_absent(crash, "auth_candidate", "panic")
            crashed = inputs / f"crash-frame-{frame}.img"
            shutil.copyfile(QEMU_RUNS / f"crash-frame-{frame}" / "journal.img", crashed)
            remove_run_dir(f"crash-frame-{frame}")
            results.append(crash)

            recovery = run_case(
                f"crash-frame-{frame}-recover",
                mode="recover",
                reuse_journal=crashed,
            )
            require(recovery, "serial_ok", "torn")
            require_absent(recovery, "auth_candidate", "panic")
            results.append(recovery)

        pre_commit = run_case(
            "crash-pre-commit",
            crash="before-commit",
            kill_after_serial="CRASH-BARRIER BEFORE-COMMIT\n",
        )
        assert pre_commit["runner_rc"] == 137
        require(pre_commit, "changed", "serial_ok", "missing_commit")
        require_absent(pre_commit, "auth_candidate", "panic")
        results.append(pre_commit)

        pre_flush = run_case(
            "crash-pre-flush",
            crash="commit-flush-begin",
            kill_after_serial="CRASH-BARRIER COMMIT-FLUSH-BEGIN\n",
        )
        assert pre_flush["runner_rc"] == 137
        require(pre_flush, "changed", "serial_ok")
        require_absent(pre_flush, "auth_candidate", "panic")
        results.append(pre_flush)

        forged = inputs / "forged.img"
        shutil.copyfile(source, forged)
        with forged.open("r+b") as handle:
            handle.seek(0x11 * 512)
            original = handle.read(1)
            handle.seek(0x11 * 512)
            handle.write(bytes([original[0] ^ 1]))
        forged_case = run_case(
            "negative-forged-byte",
            mode="recover",
            reuse_journal=forged,
        )
        require(forged_case, "serial_ok", "torn")
        require_absent(forged_case, "auth_candidate", "panic")
        results.append(forged_case)

        stale_floor = run_case(
            "negative-stale-floor",
            mode="recover",
            reuse_journal=source,
            floor="1002",
        )
        require(stale_floor, "serial_ok", "stale", "panic")
        require_absent(stale_floor, "auth_candidate")
        results.append(stale_floor)

        clone = run_case(
            "negative-cloned-old-media",
            mode="recover",
            reuse_journal=source,
            journal_serial=CLONE_SERIAL,
        )
        require(clone, "torn")
        require_absent(clone, "auth_candidate", "panic")
        summary = clone["summary"]
        assert isinstance(summary, dict)
        assert summary["journal_serial"] == CLONE_SERIAL
        results.append(clone)

        missing_device = run_case("negative-missing-device", no_journal_device=True)
        require(missing_device, "panic")
        require_absent(missing_device, "auth_candidate", "success_line")
        results.append(missing_device)

        wrong_size = run_case("negative-wrong-size", journal_bytes=16384)
        require(wrong_size, "panic")
        require_absent(wrong_size, "auth_candidate", "success_line")
        results.append(wrong_size)
    finally:
        report = {
            "claim_boundary": "q35/TCG emulator evidence only; not physical power-loss qualification",
            "cases": results,
        }
        (QEMU_RUNS / "matrix-results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        shutil.rmtree(inputs, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
