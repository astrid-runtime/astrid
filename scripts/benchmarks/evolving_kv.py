"""Storage-io mode of the existing matched runner; no independent entry point."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

BENCH_ROOT = "crates/astrid-storage/benches"
SOURCES = tuple(f"{BENCH_ROOT}/{name}" for name in (
    "storage_io.rs", "storage_io/config.rs", "storage_io/provenance.rs",
    "storage_io/report.rs", "storage_io/workloads.rs",
    "storage_io/workloads/bulk.rs", "storage_io/workloads/evolving_kv.rs"))
FORMAT = "astrid-storage-io-benchmark-v2"
WORKLOAD_DEFINITION = {
    "contract": "evolving-kv-quiescent-sequence-v1",
    "initial_value_bytes": [524288, 8388608],
    "first_insertion_offsets": [250000, 3000000],
    "insertions": 4, "inserted_bytes_per_operation": 4096,
    "subsequent_offset_increment": 4096,
    "original": "xorshift64 seed0x12ab56cd90ef3412; low byte per step; identical source on both heads",
    "inserted_pattern": "4096 bytes0x55 per insertion",
    "closed_sequence_duration": "one sequence: write-phase open through explicit close/store drop and own Tokio runtime drop; runtime drain joins blocking checkpoint jobs; includes client value clones and exact verification; excludes corpus construction",
    "closed_sequence_growth": "one sample: hosted volume length after write close plus runtime/checkpoint drain minus length after initial store open; includes mutation/checkpoint/index-close growth; excludes bootstrap and reopened phase",
    "growth_logical_denominators": [540672, 8404992],
    "api_timers": "individual set/CAS/get/close/open calls with real asynchronous checkpoint work enabled; per-call mutation timings do not include all deferred checkpoint completion",
    "read_warm": "exact post-mutation verification precedes timed get; ordinary production KV hot cache remains enabled",
    "reopen": "fresh runtime after drained write runtime; open/exact readback/close then runtime drop before next sample; same-process reopen, not process restart or crash recovery",
    "unused_legacy_config_fields": ["bytes", "block_bytes", "range_bytes", "small_files", "small_file_bytes", "concurrent_principals", "bulk_workers", "bulk_files"],
    "nonclaims": "volume length growth is not heap ownership, unique physical allocation or reclaimable disk; no automatic speed verdict",
}


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def source_manifest(protocol, hooks):
    discovered = {str(p.relative_to(protocol)) for p in
                  (protocol / BENCH_ROOT / "storage_io").rglob("*.rs")}
    discovered.add(f"{BENCH_ROOT}/storage_io.rs")
    require(discovered == set(SOURCES), "benchmark module set changed; review overlay closure")
    manifest = {}
    for relative in SOURCES:
        path = protocol / relative
        require(path.is_file() and path.resolve() == path,
                f"benchmark source is missing or aliased: {relative}")
        manifest[relative] = hooks["sha"](path)
    return manifest


def verify_overlay(path, head, manifest, hooks):
    git = hooks["command"]
    require(re.fullmatch(r"[0-9a-f]{40}", head), "producer must be a full SHA")
    require(git(["git", "rev-parse", "HEAD"], path) == head, "producer head drift")
    changed = set(git(["git", "diff", "--name-only", "HEAD", "--"], path).splitlines())
    others = set(git(["git", "ls-files", "--others", "--exclude-standard"], path).splitlines())
    require((changed | others) <= set(manifest), "nonallowlisted producer source changed")
    require(not git(["git", "diff", "--cached", "--name-only"], path),
            "producer index changed")
    for relative, expected in manifest.items():
        source = path / relative
        require(source.is_file() and source.resolve() == source,
                f"missing or aliased overlay source: {relative}")
        require(hooks["sha"](source) == expected, f"overlay source drift: {relative}")
    status = git(["git", "status", "--porcelain=v1", "--untracked-files=all"], path)
    return [line for line in status.splitlines() if line]


def prepare_overlay(path, head, protocol, manifest, hooks):
    hooks["clean_checkout"](path, head)
    for relative in SOURCES:
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.is_symlink() and target.parent.resolve() == target.parent,
                "producer overlay path redirected")
        shutil.copyfile(protocol / relative, target)
    return verify_overlay(path, head, manifest, hooks)


def wait_build(process, budget):
    try:
        return process.wait(timeout=budget)
    except subprocess.TimeoutExpired:
        # This unreaped child owns a newly created process group in disposable CI.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


def build(path, head, protocol, manifest, output, arm, deadline, hooks):
    dirty = prepare_overlay(path, head, protocol, manifest, hooks)
    require(shutil.disk_usage(path).free >= 2 * 1024**3, "build disk reserve")
    env = os.environ.copy()
    # Existing disposable-CI exception: one target shared across both producers,
    # outside their source trees and never included in published evidence.
    env["CARGO_TARGET_DIR"] = str(output / "cargo-target")
    command = ["cargo", "bench", "--no-run", "--locked", "-j", "1", "-p",
               "astrid-storage", "--bench", "storage_io", "--message-format=json-render-diagnostics"]
    log = output / f"{arm}-build.jsonl"
    budget = min(900, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before build")
    with log.open("w") as stream:
        process = subprocess.Popen(command, cwd=path, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        code = wait_build(process, budget)
    require(code == 0, f"{arm} evolving-KV build failed: {code}")
    require(verify_overlay(path, head, manifest, hooks) == dirty,
            "producer overlay status changed during build")
    artifacts, executables = [], []
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
                artifacts.append({"path": filename, "sha256": hooks["sha"](file),
                                  "package_id": event["package_id"],
                                  "features": event["features"], "profile": event["profile"]})
        if event["target"]["name"] == "storage_io" and event.get("executable"):
            require(Path(event["target"]["src_path"]).resolve() == path / BENCH_ROOT / "storage_io.rs",
                    "Cargo benchmark source is not the selected producer overlay")
            require("bench" in event["target"]["kind"], "Cargo executable is not a benchmark target")
            executables.append(event["executable"])
    require(len(executables) == 1, "Cargo emitted ambiguous/missing storage_io executable")
    binary = output / f"{arm}-storage-io"
    shutil.copy2(executables[0], binary)
    return {"head": head, "tree": hooks["command"](["git", "rev-parse", "HEAD^{tree}"], path),
            "rustc": hooks["command"](["rustc", "-Vv"], path),
            "lock_sha256": hooks["sha"](path / "Cargo.lock"),
            "binary": str(binary), "binary_sha256": hooks["sha"](binary),
            "binary_bytes": binary.stat().st_size, "artifacts": artifacts,
            "source_overlay": manifest, "overlay_porcelain": dirty,
            "cargo_command": command, "cargo_target": env["CARGO_TARGET_DIR"],
            "build_log_sha256": hooks["sha"](log)}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(raw):
    def invalid(value):
        raise RuntimeError(f"nonfinite JSON value: {value}")
    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid,
                      parse_float=finite_float)


def integers(values, count):
    return (isinstance(values, list) and len(values) == count and
            all(type(v) is int and v >= 0 for v in values))


def same_float(actual, expected):
    if expected is None:
        return actual is None
    # Rust Duration conversion and Python division can round differently.
    # Permit four binary64 ULPs, never a percentage-based benchmark tolerance.
    return (type(actual) in (int, float) and math.isfinite(actual) and actual >= 0 and
            abs(actual - expected) <= 4 * max(math.ulp(actual), math.ulp(expected)))


def validate_duration_summary(row):
    require(set(row) == {"name", "bytes_per_sample", "operations_per_sample", "samples_nanoseconds",
                         "minimum_milliseconds", "median_milliseconds", "maximum_milliseconds",
                         "median_mib_per_second", "median_operations_per_second"}, "metric schema changed")
    values = row["samples_nanoseconds"]
    require(values == sorted(values) and values[-1] < 2**64 * 1_000_000_000,
            "duration samples are not canonical Rust Durations")
    middle = len(values) // 2
    median = values[middle] if len(values) % 2 else values[middle - 1] + (values[middle] - values[middle - 1]) // 2
    seconds = lambda ns: float(ns // 1_000_000_000) + float(ns % 1_000_000_000) / 1_000_000_000
    for key, ns in [("minimum_milliseconds", values[0]), ("median_milliseconds", median),
                    ("maximum_milliseconds", values[-1])]:
        require(same_float(row[key], seconds(ns) * 1000), "duration summary disagrees with raw samples")
    elapsed = seconds(median)
    byte_count, operations = row["bytes_per_sample"], row["operations_per_sample"]
    throughput = byte_count / 1048576 / elapsed if byte_count is not None and elapsed > 0 else None
    rate = operations / elapsed if operations is not None and elapsed > 0 else None
    require(same_float(row["median_mib_per_second"], throughput) and
            same_float(row["median_operations_per_second"], rate), "throughput summary disagrees with raw samples")


def validate_report(raw, build_receipt, argv, dirty):
    envelope = decode(raw)
    require(isinstance(envelope, dict), "storage_io envelope must be an object")
    require(envelope.get("format") == FORMAT, "wrong storage_io evidence format")
    text = envelope.get("payload_json")
    require(isinstance(text, str), "missing payload_json")
    digest = {"algorithm": "sha-256", "scope": f"utf8:payload_json:{FORMAT}",
              "hex": hashlib.sha256(text.encode()).hexdigest()}
    require(envelope.get("payload_digest") == digest, "storage_io payload digest mismatch")
    payload = decode(text)
    require(isinstance(payload, dict), "storage_io payload must be an object")
    require(set(payload) == {"provenance", "package_version", "os", "architecture", "logical_cpus", "config",
                             "metrics", "write_amplifications", "substrate_comparisons", "throughput_scaling",
                             "representation_metadata", "resource_peaks"}, "payload schema changed")
    require(payload == envelope.get("payload"), "storage_io payload representations differ")
    provenance = payload["provenance"]
    require(provenance["git_revision"] == build_receipt["head"], "report producer mismatch")
    require(provenance["repository"] == "astrid-runtime/astrid", "report repository mismatch")
    require(provenance["executable_argv"] == argv, "report argv mismatch")
    require(provenance["executable"] == {"sha256": build_receipt["binary_sha256"],
                                        "bytes": build_receipt["binary_bytes"]},
            "report executable mismatch")
    expected_tree = {"state": "dirty", "porcelain_v1": dirty} if dirty else {"state": "clean"}
    require(provenance["git_tree"] == expected_tree, "report source overlay mismatch")
    config = payload["config"]
    require(config["selection"] == "evolving_kv" and type(config["samples"]) is int and config["samples"] == 1 and
            config["object_cache_bytes"] is None, "wrong evolving-KV run configuration")
    require(config["root"] == argv[argv.index("--root") + 1] and
            config["output"] == argv[argv.index("--output") + 1], "report roots mismatch")
    validate_metrics(payload)
    return envelope


def validate_metrics(payload):
    metrics = payload["metrics"]
    amplifications = payload["write_amplifications"]
    expected, expected_amps = {}, {}
    for prefix, size in [("kv_512k", 524288), ("kv_8m", 8388608)]:
        for suffix in ["initial", "insert_cas", "read_warm", "close", "reopen", "reopen_read", "closed_sequence"]:
            name = f"{prefix}_{suffix}"
            count = 4 if suffix == "insert_cas" else 1
            bytes_per = size if suffix == "initial" else size + 16384 if "read" in suffix else None
            operations = None if bytes_per is not None else 1
            expected[name] = (count, bytes_per, operations)
        expected_amps[f"{prefix}_closed_sequence"] = (1, size + 16384)
    require(isinstance(metrics, list) and len(metrics) == 14, "missing/extra metric rows")
    require({m["name"] for m in metrics} == set(expected), "wrong metric names")
    for row in metrics:
        count, byte_count, operations = expected[row["name"]]
        require(integers(row["samples_nanoseconds"], count), "wrong duration cardinality/type")
        require(row["bytes_per_sample"] == byte_count and row["operations_per_sample"] == operations,
                "wrong operation/byte denominator")
        require((row["bytes_per_sample"] is None or type(row["bytes_per_sample"]) is int) and
                (row["operations_per_sample"] is None or type(row["operations_per_sample"]) is int),
                "noninteger operation/byte denominator")
        validate_duration_summary(row)
    require(isinstance(amplifications, list) and len(amplifications) == 2,
            "missing/extra amplification rows")
    require({a["name"] for a in amplifications} == set(expected_amps), "wrong amplification names")
    for row in amplifications:
        require(set(row) == {"name", "authoritative_bytes_appended", "logical_bytes_per_sample",
                             "minimum_authoritative_bytes_appended", "median_authoritative_bytes_appended",
                             "maximum_authoritative_bytes_appended", "median_physical_to_logical_ratio"},
                "growth schema changed")
        count, byte_count = expected_amps[row["name"]]
        require(integers(row["authoritative_bytes_appended"], count) and
                type(row["logical_bytes_per_sample"]) is int and
                row["logical_bytes_per_sample"] == byte_count, "wrong growth cardinality/denominator")
        observed = row["authoritative_bytes_appended"][0]
        require(observed < 2**64, "growth sample exceeds Rust u64")
        for key in ("minimum_authoritative_bytes_appended", "median_authoritative_bytes_appended",
                    "maximum_authoritative_bytes_appended"):
            require(type(row[key]) is int and row[key] == observed, "growth summary disagrees with raw samples")
        require(same_float(row["median_physical_to_logical_ratio"], observed / byte_count),
                "growth ratio disagrees with raw sample")
    for field in ("substrate_comparisons", "throughput_scaling", "representation_metadata", "resource_peaks"):
        require(payload[field] == [], "unexpected unrelated workload metrics")


def run_sample(build_receipt, path, fixture, output, index, sample, manifest, hooks):
    report = output / f"sample-{index:02d}.report.json"
    argv = [build_receipt["binary"], "--only", "evolving-kv", "--samples", "1",
            "--root", str(fixture), "--output", str(report)]
    sample["argv"] = argv
    try:
        dirty = verify_overlay(path, build_receipt["head"], manifest, hooks)
        require(dirty == build_receipt["overlay_porcelain"], "overlay status drift before sample")
        require(hooks["sha"](Path(argv[0])) == build_receipt["binary_sha256"], "binary drift")
        started = time.monotonic()
        try:
            proc = subprocess.run(argv, cwd=path, capture_output=True, timeout=180)
            stdout, stderr = proc.stdout, proc.stderr
            sample.update(exit=proc.returncode, timed_out=False, child_reaped=True)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
            sample.update(exit=None, timed_out=True, child_reaped=True)
        sample["elapsed_s"] = time.monotonic() - started
        for name, data in [("stdout", stdout), ("stderr", stderr)]:
            log = output / f"sample-{index:02d}.{name}"
            log.write_bytes(data)
            sample[f"{name}_sha256"] = hooks["sha"](log)
        sample["quiet_after"] = hooks["quiet_snapshot"]()
        require(not sample["timed_out"], "storage_io exceeded unchanged 180-second ceiling")
        require(sample["exit"] == 0, "storage_io exact-readback/close/reopen failed")
        require(report.is_file() and not report.is_symlink(), "storage_io report missing/aliased")
        sample["report_sha256"] = hooks["sha"](report)
        sample["storage_io_evidence"] = validate_report(report.read_bytes(), build_receipt, argv, dirty)
        require(verify_overlay(path, build_receipt["head"], manifest, hooks) == dirty,
                "source drift during sample")
        require(hooks["sha"](Path(argv[0])) == build_receipt["binary_sha256"], "binary drift during sample")
        require(sample["quiet_after"]["quiet"], "background load after sample: HOLD")
        sample["complete"] = True
        shutil.rmtree(fixture)
        sample["fixture_reaped"] = True
    except BaseException as error:
        sample["complete"] = False
        sample["failure"] = str(error)
        raise
    finally:
        sample["fixture_preserved"] = fixture.exists()


def public_source_paths(output):
    return [output / "protocol-source" / relative for relative in SOURCES]


def run(args, protocol, output, receipt, save, deadline, hooks):
    manifest = source_manifest(protocol, hooks)
    receipt.update(mode="evolving-kv", source_overlay=manifest,
                   workload_definition=WORKLOAD_DEFINITION,
                   method="2 warmups plus 16 timed ABBA invocations; storage_io --only evolving-kv --samples 1",
                   metric_scope="hosted KV wall time and volume length growth; not allocated memory or reclaimable disk")
    for relative in SOURCES:
        target = output / "protocol-source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(protocol / relative, target)
        require(hooks["sha"](target) == manifest[relative], "archived protocol source drift")
    builds = receipt["builds"] = {}
    for arm, path, head in [("main", args.baseline.resolve(), args.baseline_head),
                            ("candidate", args.candidate.resolve(), args.candidate_head)]:
        receipt["build_attempt"] = {"arm": arm, "head": head, "complete": False}
        save()
        builds[arm] = build(path, head, protocol, manifest, output, arm, deadline, hooks)
        receipt["build_attempt"]["complete"] = True
        save()
    require(builds["main"]["rustc"] == builds["candidate"]["rustc"], "producer toolchain mismatch")
    hooks["settle_after_builds"](receipt, save, deadline)
    schedule = hooks["abba_schedule"]([()], builds)
    receipt["schedule"] = schedule
    save()
    for index, (arm, phase) in enumerate(schedule):
        require(deadline - time.monotonic() >= 180, "run budget cannot contain full sample: HOLD")
        before = hooks["quiet_snapshot"]()
        receipt["quiet_gate_before_sample"] = {"index": index, **before}
        save()
        require(before["quiet"], "background load before sample: HOLD")
        require(shutil.disk_usage(output).free >= 1024**3, "sample disk reserve")
        fixture = Path(tempfile.mkdtemp(prefix="evolving-kv-", dir=output))
        sample = {"arm": arm, "phase": phase, "quiet_before": before,
                  "fixture": str(fixture), "complete": False}
        receipt["samples"].append(sample)
        save()
        path = args.baseline.resolve() if arm == "main" else args.candidate.resolve()
        try:
            run_sample(builds[arm], path, fixture, output, index, sample, manifest, hooks)
        finally:
            save()
    require(source_manifest(protocol, hooks) == manifest, "protocol source drift")
    for arm, path in [("main", args.baseline.resolve()), ("candidate", args.candidate.resolve())]:
        require(verify_overlay(path, builds[arm]["head"], manifest, hooks) == builds[arm]["overlay_porcelain"],
                "producer source drift after schedule")
        require(hooks["sha"](Path(builds[arm]["binary"])) == builds[arm]["binary_sha256"],
                "frozen binary drift after schedule")
