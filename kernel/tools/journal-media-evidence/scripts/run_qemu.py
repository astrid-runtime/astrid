#!/usr/bin/env python3
"""Evidence-only q35/isa-ide QEMU runner for issue 1691 option 2."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

OVMF = Path("/opt/homebrew/share/qemu/edk2-x86_64-code.fd")
QEMU = Path("/opt/homebrew/bin/qemu-system-x86_64")
TIMEOUT_S = 90
JOURNAL_BYTES = 1024 * 1024
JOURNAL_SERIAL = "PIO1691-JOURNAL-0001"
DEBUG_SUCCESS = 33
DEBUG_PANIC = 67


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sector_head(path: Path, lba: int, nbytes: int = 16) -> bytes:
    with path.open("rb") as handle:
        handle.seek(lba * 512)
        return handle.read(nbytes)


def nonzero_count(path: Path, lba: int) -> int:
    with path.open("rb") as handle:
        handle.seek(lba * 512)
        return sum(1 for byte in handle.read(512) if byte)


def qmp_send_ret(sock_path: Path) -> None:
    payload = json.dumps(
        {
            "execute": "send-key",
            "arguments": {"keys": [{"type": "qcode", "data": "ret"}]},
        }
    ).encode()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect(str(sock_path))
    greeting = sock.recv(4096)
    if not greeting:
        sock.close()
        raise OSError("empty qmp greeting")
    sock.sendall(b'{"execute":"qmp_capabilities"}\n')
    sock.recv(4096)
    sock.sendall(payload + b"\n")
    sock.recv(4096)
    sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--mode", default="normal")
    parser.add_argument("--crash", default="")
    parser.add_argument("--floor", default="1000")
    parser.add_argument("--reuse-journal", type=Path)
    parser.add_argument("--keep-journal", action="store_true")
    parser.add_argument("--kill-after-serial")
    parser.add_argument("--journal-serial", default=JOURNAL_SERIAL)
    parser.add_argument("--journal-bytes", type=int, default=JOURNAL_BYTES)
    parser.add_argument("--no-journal-device", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    run_dir = root / "target" / "qemu-runs" / args.name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)

    efi = root / "target" / "x86_64-unknown-uefi" / "guest" / "pio-media-guest.efi"
    fat = root / "target" / "debug" / "build-fat"
    if not efi.exists() or not fat.exists():
        raise SystemExit("guest EFI or build-fat missing")

    root_img = run_dir / "root.img"
    subprocess.check_call([str(fat), str(root_img), str(efi)])
    fw = run_dir / "fw.fd"
    shutil.copyfile(OVMF, fw)

    key = run_dir / "key.bin"
    key.write_bytes(bytes(range(32)))
    (run_dir / "floor.txt").write_bytes(args.floor.encode())
    (run_dir / "mode.txt").write_bytes(args.mode.encode() + b"\x00")
    (run_dir / "crash.txt").write_bytes(args.crash.encode() + (b"\x00" if args.crash else b""))

    journal = run_dir / "journal.img"
    if args.reuse_journal:
        shutil.copyfile(args.reuse_journal, journal)
    else:
        journal.write_bytes(b"\x00" * args.journal_bytes)

    before = sha256(journal)
    (run_dir / "journal.before.sha").write_text(f"{before}  {journal}\n")

    qmp = Path(f"/tmp/pio1691-{os.getpid()}.qmp")
    serial = run_dir / "serial.log"
    qemu_cmd = [
        str(QEMU),
        "-machine",
        "q35",
        "-cpu",
        "qemu64",
        "-m",
        "256",
        "-accel",
        "tcg",
        "-display",
        "none",
        "-no-reboot",
        "-chardev",
        f"file,id=serial0,path={serial}",
        "-serial",
        "chardev:serial0",
        "-qmp",
        f"unix:{qmp},server,nowait",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-drive",
        f"if=pflash,format=raw,unit=0,file={fw}",
        "-drive",
        f"if=none,id=root,format=raw,file={root_img}",
        "-device",
        "ide-hd,drive=root",
        "-fw_cfg",
        f"name=opt/astrid.pio.key,file={key}",
        "-fw_cfg",
        f"name=opt/astrid.pio.floor,file={run_dir / 'floor.txt'}",
        "-fw_cfg",
        f"name=opt/astrid.pio.mode,file={run_dir / 'mode.txt'}",
        "-fw_cfg",
        f"name=opt/astrid.pio.crash,file={run_dir / 'crash.txt'}",
    ]
    if not args.no_journal_device:
        qemu_cmd.extend(
            [
                "-drive",
                f"if=none,id=journal,format=raw,file={journal},readonly=off,cache=none",
                "-device",
                "isa-ide,id=astrid-pio",
                "-device",
                "ide-hd,bus=astrid-pio.0,drive=journal,unit=0,write-cache=on,"
                f"serial={args.journal_serial}",
            ]
        )
    (run_dir / "qemu.cmd").write_text(" ".join(qemu_cmd) + "\n")

    if qmp.exists():
        qmp.unlink()
    proc = subprocess.Popen(
        qemu_cmd,
        stdout=(run_dir / "qemu.stdout").open("w"),
        stderr=(run_dir / "qemu.stderr").open("w"),
    )
    deadline = time.time() + TIMEOUT_S
    sent_key = False
    rc = None
    try:
        while time.time() < deadline:
            rc = proc.poll()
            if rc is not None:
                break
            if serial.exists():
                serial_bytes = serial.read_bytes()
                if qmp.exists() and b"PIO1691 BOOT" not in serial_bytes:
                    try:
                        qmp_send_ret(qmp)
                        sent_key = True
                    except OSError:
                        pass
                if args.kill_after_serial and args.kill_after_serial.encode() in serial_bytes:
                    proc.kill()
                    rc = 137
                    break
            time.sleep(0.2)
        else:
            proc.kill()
            proc.wait(timeout=5)
            rc = 124
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        if qmp.exists():
            qmp.unlink()

    after = sha256(journal)
    (run_dir / "journal.after.sha").write_text(f"{after}  {journal}\n")
    serial_text = serial.read_text(errors="replace") if serial.exists() else ""
    marker = "GUEST-ATA IDENTIFY.SERIAL.TEXT="
    observed_serial = (
        serial_text.split(marker, 1)[1].splitlines()[0] if marker in serial_text else ""
    )
    summary = {
        "name": args.name,
        "mode": args.mode,
        "crash": args.crash,
        "rc": rc,
        "sent_key": sent_key,
        "before": before,
        "after": after,
        "changed": before != after,
        "journal_serial": observed_serial,
        "serial_ok": observed_serial == args.journal_serial,
        **(
            {
                "lba11": sector_head(journal, 0x11).hex(),
                "lba11_nonzero": nonzero_count(journal, 0x11),
                "lba21": sector_head(journal, 0x21).hex(),
                "lba21_nonzero": nonzero_count(journal, 0x21),
            }
            if journal.stat().st_size >= 0x22 * 512
            else {}
        ),
        "torn": "RECOVERY=TORN" in serial_text,
        "missing_commit": "RECOVERY=TORN REASON=missing-commit" in serial_text,
        "stale": "RECOVERY=STALE" in serial_text,
        "success_line": "PIO1691 SUCCESS" in serial_text,
        "auth_candidate": "GUEST-AUTH-CANDIDATE" in serial_text,
        "roundtrip": "ROUNDTRIP PASS" in serial_text,
        "panic": "PIO-GUEST-PANIC" in serial_text,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    if (
        rc == DEBUG_SUCCESS
        and summary["success_line"]
        and summary["serial_ok"]
        and summary["auth_candidate"]
    ):
        return 0
    if rc == 124:
        return 124
    return rc if isinstance(rc, int) else 1


if __name__ == "__main__":
    sys.exit(main())
