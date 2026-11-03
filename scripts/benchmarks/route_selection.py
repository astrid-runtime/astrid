"""EventBus workload adapter for the existing matched runner; no entry point."""
from pathlib import Path
import re
import shutil
import subprocess
import time

SOURCE = "crates/astrid-events/examples/route_selection_bench.rs"
# Reviewed source is frozen independently from either producer implementation.
HARNESS_SHA = "233b52de9b68f1e7cb914ee8bffd5adb3d16f194e9e3cd92d07273a5bc37d9d4"
TARGET = {"name": "route_selection_bench", "source": SOURCE, "kind": "example",
          "cargo": ["build", "--release", "--example", "route_selection_bench", "-p", "astrid-events", "--locked", "-j", "1"],
          "frozen": "route-selection"}
CONFIGURATIONS = [(0,), (10000,)]
SAMPLE_FIELDS = ("foreign",)
TIMED_ABBA_CYCLES = 8
DEFINITION = {
    "mode": "route-selection",
    "method": "per foreign count (0, 10000): 2 total warmup invocations (1 per arm), then 8 ABBA cycles = 32 total timed invocations (16 per arm)",
    "metric_scope": "unlogged validated iteration: owned-event publish, own-route try_drain, event identity-field assertions, loop overhead and natural per-iteration drops; caller cloning and iterator preparation excluded; no overhead subtraction; not daemon startup or end-to-end IPC",
    "workload_definition": {"foreign_subscriptions": [0, 10000], "own_subscriptions": 1,
                            "iterations_per_invocation": 2000, "in_process_warmup_publishes_per_invocation": 2,
                            "warmup_invocations_per_arm_per_case": 1,
                            "timed_invocations_per_arm_per_case": 16,
                            "n1_means": "foreign0 plus one own scoped subscriber",
                            "delivery": "exact own event id/topic/principal checked on each publish; foreign queues held",
                            "harness_source": "this exact protocol checkout head/tree in outer receipt; frozen SHA below",
                            "harness_source_sha256": HARNESS_SHA,
                            "provenance": "external frozen-artifact receipt; stdout exe path must equal selected binary",
                            "nonclaims": "microbenchmark only; no automatic speed verdict"},
}


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def source_manifest(protocol, hooks):
    source = protocol / SOURCE
    require(source.is_file() and source.resolve() == source and hooks["sha"](source) == HARNESS_SHA,
            "frozen route-selection harness changed or aliased")
    # Existing overlay/archive machinery takes protocol-relative paths. The
    # archived source is also the producer overlay, keeping one exact identity.
    return {SOURCE: HARNESS_SHA}


def validate_report(raw, build, sample):
    text = raw.decode("utf-8", errors="strict")
    pattern = (r"route_selection_bench label=(main|candidate) foreign=(0|10000) "
               r"iters=2000 warmups=2 scope=validated_publish_drain_iteration_v2 "
               r"total_ns=([0-9]+) per_iteration_ns=([0-9]+) exe=(.+)\n?")
    match = re.fullmatch(pattern, text)
    require(match is not None, "missing/malformed route-selection report")
    arm, foreign, total, per, executable = match.groups()
    total, per = int(total), int(per)
    require(arm == sample["arm"] and int(foreign) == sample["foreign"], "route workload identity mismatch")
    require(executable == build["binary"], "route executable/producer mismatch")
    require(0 < total < 2**64 * 1_000_000_000 and per == total // 2000,
            "route duration arithmetic mismatch")
    return {"foreign": int(foreign), "iterations": 2000, "warmups": 2,
            "total_ns": total, "per_iteration_ns": per, "scope": "validated_publish_drain_iteration_v2",
            "producer_head": build["head"], "binary_sha256": build["binary_sha256"]}


def run_sample(build, path, fixture, output, index, sample, manifest, hooks):
    # One authoritative overlay verifier and process-group containment helper.
    shared = hooks["overlay"]
    argv = [build["binary"], "--label", sample["arm"], "--foreign", str(sample["foreign"]),
            "--iters", "2000", "--warmups", "2"]
    sample["argv"] = argv
    try:
        dirty = shared.verify_overlay(path, build["head"], manifest, hooks)
        require(dirty == build["overlay_porcelain"], "route overlay status drift before sample")
        require(hooks["sha"](Path(argv[0])) == build["binary_sha256"], "route binary drift")
        started = time.monotonic()
        process = subprocess.Popen(argv, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            stdout, stderr = hooks["source_build"].communicate_owned(process, 180)
            sample.update(exit=process.returncode, timed_out=False, child_reaped=True)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.output or b"", error.stderr or b""
            sample.update(exit=None, timed_out=True, child_reaped=True)
        sample["elapsed_s"] = time.monotonic() - started
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            log = output / f"sample-{index:02d}.{name}"
            log.write_bytes(data)
            sample[f"{name}_sha256"] = hooks["sha"](log)
        sample["quiet_after"] = hooks["quiet_snapshot"]()
        require(not sample["timed_out"], "route selection exceeded unchanged 180-second ceiling")
        require(sample["exit"] == 0, "route exact-delivery assertions failed")
        sample["route_selection"] = validate_report(stdout, build, sample)
        require(shared.verify_overlay(path, build["head"], manifest, hooks) == dirty,
                "route source drift during sample")
        require(hooks["sha"](Path(argv[0])) == build["binary_sha256"], "route binary drift during sample")
        require(sample["quiet_after"]["quiet"], "background load after sample: HOLD")
        sample["complete"] = True
        shutil.rmtree(fixture)
        sample["fixture_reaped"] = True
    except BaseException as error:
        sample.update(complete=False, failure=str(error))
        raise
    finally:
        sample["fixture_preserved"] = fixture.exists()
