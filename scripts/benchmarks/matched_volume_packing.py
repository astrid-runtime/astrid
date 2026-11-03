#!/usr/bin/env python3
"""Same-host, unlogged ABBA evidence from two exact storage revisions.

Runs only in a disposable GitHub-hosted macOS workspace. The frozen public-API
probe is injected identically as an untracked example in both clean checkouts;
the report records that injection explicitly. No automatic speed verdict.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time


PROBE_SHA = "bff5f6b391f7ae2ed1b2c43d94def378733de4c89c9287c5c767b7a173ea7faf"
INJECTION = "crates/astrid-storage/examples/volume_packing_probe.rs"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def clean_checkout(path, head, injected=False):
    require(re.fullmatch(r"[0-9a-f]{40}", head), "expected a full commit SHA")
    require(command(["git", "rev-parse", "HEAD"], path) == head, "head mismatch")
    require(not command(["git", "diff", "HEAD", "--"], path), "tracked source changed")
    others = command(["git", "ls-files", "--others", "--exclude-standard"], path)
    require(others == (INJECTION if injected else ""), "unexpected untracked source")


def quiet_snapshot():
    # macOS ps reports percent of one core, as in the local campaign guard.
    # Retain all rows for adjudication; never terminate background processes.
    rows = command(["ps", "-axo", "pcpu=,comm="]).splitlines()
    cpu = sum(float(row.split(maxsplit=1)[0]) for row in rows if row.strip())
    return {"background_cpu_percent": cpu, "rows": rows, "quiet": cpu <= 10.0}


def build(path, head, probe, output, arm):
    clean_checkout(path, head)
    source = path / INJECTION
    require(not source.exists(), "example path already exists")
    source.parent.mkdir(exist_ok=True)
    shutil.copyfile(probe, source)
    clean_checkout(path, head, injected=True)
    require(shutil.disk_usage(path).free >= 2 * 1024**3, "build disk reserve")
    log = output / f"{arm}-build.jsonl"
    with log.open("w") as stream:
        subprocess.run([
            "cargo", "build", "--release", "--locked", "-j", "1", "-p",
            "astrid-storage", "--example", "volume_packing_probe", "--message-format=json",
        ], cwd=path, stdout=stream, stderr=subprocess.STDOUT, check=True)
    artifacts = []
    executable = None
    for line in log.read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("reason") != "compiler-artifact":
            continue
        for filename in event["filenames"]:
            file = Path(filename)
            if file.is_file():
                artifacts.append({"path": filename, "sha256": sha(file)})
        if event["target"]["name"] == "volume_packing_probe":
            executable = event.get("executable")
    require(executable is not None, "Cargo emitted no probe executable")
    binary = output / f"{arm}-probe"
    shutil.copy2(executable, binary)
    clean_checkout(path, head, injected=True)
    return {"head": head, "tree": command(["git", "rev-parse", "HEAD^{tree}"], path),
            "rustc": command(["rustc", "-Vv"], path),
            "lock_sha256": sha(path / "Cargo.lock"), "binary": str(binary),
            "binary_sha256": sha(binary), "artifacts": artifacts,
            "injected_source": INJECTION, "injected_sha256": sha(source),
            "tracked_source_clean": True, "build_log_sha256": sha(log)}


def metrics(stdout):
    return dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline-head", required=True)
    parser.add_argument("--candidate-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "disposable GitHub-hosted runner required")
    require(platform.system() == "Darwin" and platform.machine() == "arm64",
            "native macOS arm64 required")
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    probe = Path(__file__).with_name("volume_packing_probe.rs")
    require(sha(probe) == PROBE_SHA, "frozen probe changed")
    receipt = {"complete": False, "performance_accepted": False, "samples": [],
               "probe_sha256": PROBE_SHA, "runner_sha256": sha(Path(__file__)),
               "platform": platform.platform(), "machine": platform.machine(),
               "workflow_sha": os.environ.get("GITHUB_SHA"),
               "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
               "protocol_checkout_head": command(["git", "rev-parse", "HEAD"], probe.parent),
               "cpu": command(["sysctl", "-n", "machdep.cpu.brand_string"]),
               "ram_bytes": command(["sysctl", "-n", "hw.memsize"]),
               "method": "2 warmups and 16 timed ABBA samples per matched config; 3 capacity controls",
               "instrumentation_removed": [],
               "disk_policy": "Disposable CI only: 2 GiB before builds, 1 GiB before samples; local 40 GiB guard unchanged"}
    result = output / "receipt.json"

    def save():
        temporary = result.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt, indent=2) + "\n")
        temporary.replace(result)

    try:
        for key in list(os.environ):
            if key.startswith(("Malloc", "DYLD_", "ASAN_", "LSAN_", "HEAPTRACK")):
                receipt["instrumentation_removed"].append(key)
                del os.environ[key]
        save()
        builds = {}
        receipt["builds"] = builds
        for arm, path, head in [("main", args.baseline, args.baseline_head),
                                ("candidate", args.candidate, args.candidate_head)]:
            builds[arm] = build(path.resolve(), head, probe, output, arm)
            save()
        schedule = []
        for count, regions in [(32768, 7), (600000, 1)]:
            schedule.extend((arm, count, regions, "warmup") for arm in builds)
            schedule.extend((arm, count, regions, "timed")
                            for arm in ["main", "candidate", "candidate", "main"] * 4)
        schedule.extend([("main", 699051, 1, "negative-control"),
                         ("candidate", 699051, 1, "capacity"),
                         ("candidate", 699051, 7, "capacity")])
        receipt["schedule"] = schedule
        save()
        for index, (arm, count, regions, phase) in enumerate(schedule):
            before = quiet_snapshot()
            receipt["quiet_gate_before_sample"] = {"index": index, **before}
            save()
            require(before["quiet"], "background load before sample: HOLD")
            require(shutil.disk_usage(output).free >= 1024**3, "sample disk reserve")
            fixture = Path(tempfile.mkdtemp(prefix="packing-", dir=output))
            sample = {"arm": arm, "count": count, "regions": regions,
                      "phase": phase, "quiet_before": before, "fixture": str(fixture)}
            receipt["samples"].append(sample)
            save()
            try:
                started = time.monotonic()
                proc = subprocess.run([builds[arm]["binary"], str(fixture / "volume"),
                                       str(count), str(regions)],
                                      capture_output=True, text=True, timeout=180)
                sample.update(exit=proc.returncode, elapsed_s=time.monotonic() - started)
                for name, data in [("stdout", proc.stdout), ("stderr", proc.stderr)]:
                    log = output / f"sample-{index:02d}.{name}"
                    log.write_text(data)
                    sample[f"{name}_sha256"] = sha(log)
                sample["metrics"] = metrics(proc.stdout)
                sample["quiet_after"] = quiet_snapshot()
                if phase == "negative-control":
                    require(proc.returncode != 0 and proc.stderr.strip() ==
                            "probe_error=commit snapshot exceeds format bound",
                            "unexpected baseline capacity failure")
                else:
                    require(proc.returncode == 0 and sample["metrics"].get("complete") == "true",
                            "probe failed exact-readback/functional checks")
                shutil.rmtree(fixture)
                sample["fixture_reaped"] = True
                require(sample["quiet_after"]["quiet"], "background load after sample: HOLD")
            finally:
                save()
        for arm, path in [("main", args.baseline), ("candidate", args.candidate)]:
            clean_checkout(path, builds[arm]["head"], injected=True)
            require(sha(Path(builds[arm]["binary"])) == builds[arm]["binary_sha256"],
                    "probe binary changed")
        receipt["complete"] = True
    except BaseException as error:
        receipt["failure"] = str(error)
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
