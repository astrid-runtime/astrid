#!/usr/bin/env python3
"""Static security contract tests for the Linux amd64 image."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "container/amd64/Dockerfile").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "container/amd64/entrypoint.sh").read_text(encoding="utf-8")
TEST_HARNESS = (ROOT / "container/amd64/test.sh").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/oci-amd64.yml").read_text(encoding="utf-8")


def shell_function(name: str) -> str:
    match = re.search(rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}$", TEST_HARNESS)
    if match is None:
        raise AssertionError(f"shell function is not extractable: {name}")
    return match.group(0)


def run_extracted_shell(
    functions: list[str],
    invocation: str,
    bin_dir: pathlib.Path,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    inherited_environment = os.environ.copy()
    inherited_environment["PATH"] = f"{bin_dir}{os.pathsep}{inherited_environment['PATH']}"
    inherited_environment["IMAGE"] = "contract-fixture-image"
    inherited_environment["OCI_PLATFORM"] = "linux/amd64"
    inherited_environment.update(environment or {})
    script = "\n".join(("set -euo pipefail", *functions, invocation, ""))
    return subprocess.run(
        ["bash", "-c", script],
        cwd=bin_dir,
        env=inherited_environment,
        text=True,
        capture_output=True,
        check=False,
    )


def docker_call_log(log_path: pathlib.Path) -> list[list[str]]:
    records = log_path.read_bytes().removesuffix(b"\0\0").split(b"\0\0")
    return [
        argument.decode("utf-8").split("\0")
        for argument in records
        if argument
    ]


def dockerfile_run_shell() -> str:
    lines = DOCKERFILE.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith("RUN ")
    )
    command = []
    for line in lines[start:]:
        stripped = line.strip()
        command.append(stripped)
        if not stripped.endswith("\\"):
            break
    else:
        raise AssertionError("RUN command is missing its terminator")
    return " ".join(part.removesuffix("\\") for part in command)


def receipt_field_matcher() -> str:
    shell = dockerfile_run_shell()
    start = shell.index("bind_receipt_field() {")
    open_brace = shell.index("{", start)
    depth = 1
    for end in range(open_brace + 1, len(shell)):
        if shell[end] == "{":
            depth += 1
        elif shell[end] == "}":
            depth -= 1
            if depth == 0:
                return shell[start : end + 1]
    raise AssertionError("receipt field matcher is not extractable")


def run_receipt_matcher(
    matcher: str,
    receipt_path: pathlib.Path,
    key: str,
    expected: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "sh",
            "-c",
            f'{matcher}\nbind_receipt_field "$1" "$2" "$3"',
            "sh",
            str(receipt_path),
            key,
            expected,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


class DockerfileContractTests(unittest.TestCase):
    def test_packages_release_bytes_without_building_source(self) -> None:
        self.assertIn("COPY dist/oci-amd64/astrid-release.tar.gz", DOCKERFILE)
        self.assertIn("ARG ASTRID_ARCHIVE_SHA256", DOCKERFILE)
        self.assertIn("ARG ASTRID_ARCHIVE_BLAKE3", DOCKERFILE)
        self.assertIn("ARG ASTRID_RELEASE_RECEIPT_SHA256", DOCKERFILE)
        self.assertIn("ARG ASTRID_RELEASE_MANIFEST_SHA256", DOCKERFILE)
        self.assertIn("sha256sum --check --strict", DOCKERFILE)
        self.assertIn("/opt/astrid/release-receipt.json", DOCKERFILE)
        self.assertNotIn("cargo build", DOCKERFILE)
        self.assertNotIn("git clone", DOCKERFILE)
        self.assertNotIn("curl ", DOCKERFILE)
        self.assertNotIn("wget ", DOCKERFILE)

    def test_is_amd64_only_non_root_and_distro_neutral(self) -> None:
        self.assertIn("io.astrid.release.target=\"x86_64-unknown-linux-gnu\"", DOCKERFILE)
        self.assertIn("USER 65532:65532", DOCKERFILE)
        self.assertNotIn("EXPOSE", DOCKERFILE)
        self.assertNotIn("aos", DOCKERFILE.lower())
        self.assertNotIn("latest", DOCKERFILE.lower())

    def test_base_image_is_digest_pinned(self) -> None:
        first_line = DOCKERFILE.splitlines()[0]
        self.assertRegex(first_line, r"^FROM .+@sha256:[0-9a-f]{64}$")

    def test_release_receipt_binds_image_to_exact_source_and_archive(self) -> None:
        for field in (
            "repository",
            "version",
            "tag",
            "source-commit",
            "target",
            "archive",
            "archive-sha256",
            "archive-blake3",
            "release-manifest",
            "release-manifest-sha256",
            "release-workflow-identity",
        ):
            with self.subTest(field=field):
                self.assertIn(field, DOCKERFILE)
        for label in (
            "io.astrid.release.archive-sha256",
            "io.astrid.release.archive-blake3",
            "io.astrid.release.receipt-sha256",
            "io.astrid.release.manifest-sha256",
        ):
            with self.subTest(label=label):
                self.assertIn(label, DOCKERFILE)

    def test_receipt_matcher_accepts_object_fields_regardless_of_order(self) -> None:
        matcher = receipt_field_matcher()
        for forbidden_parser in ("grep ", "python", "jq"):
            with self.subTest(forbidden_parser=forbidden_parser):
                self.assertNotIn(forbidden_parser, matcher)

        receipt = {
            "schema-version": 1,
            "repository": "astrid-runtime/astrid",
            "version": "0.10.4",
            "tag": "v0.10.4",
            "source-commit": "b6bf5d1d579915eb5d3c944857d84e62a4fcc878",
            "target": "x86_64-unknown-linux-gnu",
            "archive": "astrid-0.10.4-x86_64-unknown-linux-gnu.tar.gz",
            "archive-size": 1024,
            "archive-sha256": "a" * 64,
            "archive-blake3": "b" * 64,
            "release-manifest": "astrid-0.10.4-release.toml",
            "release-manifest-sha256": "c" * 64,
            "release-workflow-identity": (
                "https://github.com/astrid-runtime/astrid/"
                ".github/workflows/release.yml@refs/tags/v0.10.4"
            ),
        }
        fields = {
            field: value
            for field, value in receipt.items()
            if isinstance(value, str)
        }

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "release-receipt.json"
            path.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.assertTrue(
                path.read_text(encoding="utf-8")
                .splitlines()[-2]
                .lstrip()
                .startswith('"version"')
            )
            for field, expected in fields.items():
                with self.subTest(field=field):
                    completed = run_receipt_matcher(matcher, path, field, expected)
                    self.assertEqual(completed.returncode, 0, completed.stderr)

            reordered = {"version": receipt["version"], **receipt}
            path.write_text(json.dumps(reordered, indent=2) + "\n", encoding="utf-8")
            completed = run_receipt_matcher(
                matcher,
                path,
                "version",
                receipt["version"],
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_receipt_matcher_rejects_swapped_object_fields(self) -> None:
        matcher = receipt_field_matcher()
        fields = {
            "repository": "astrid-runtime/astrid",
            "version": "0.10.4",
            "tag": "v0.10.4",
            "source-commit": "b6bf5d1d579915eb5d3c944857d84e62a4fcc878",
            "target": "x86_64-unknown-linux-gnu",
            "archive": "astrid-0.10.4-x86_64-unknown-linux-gnu.tar.gz",
            "archive-sha256": "a" * 64,
            "archive-blake3": "b" * 64,
            "release-manifest": "astrid-0.10.4-release.toml",
            "release-manifest-sha256": "c" * 64,
            "release-workflow-identity": (
                "https://github.com/astrid-runtime/astrid/"
                ".github/workflows/release.yml@refs/tags/v0.10.4"
            ),
        }

        for field, expected in fields.items():
            receipt = dict.fromkeys(fields, "bounded-contract-value")
            receipt[field] = expected
            with tempfile.TemporaryDirectory() as temporary:
                path = pathlib.Path(temporary) / "release-receipt.json"
                path.write_text(
                    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                completed = run_receipt_matcher(matcher, path, field, expected)
                self.assertEqual(completed.returncode, 0, completed.stderr)

                swapped = dict(receipt)
                swapped[field] = f"{expected}-swapped"
                path.write_text(
                    json.dumps(swapped, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                completed = run_receipt_matcher(matcher, path, field, expected)
                self.assertNotEqual(completed.returncode, 0)

    def test_old_line_binds_reject_last_key_and_escaped_target(self) -> None:
        receipt = {
            "target": "x86_64-unknown-linux-gnu",
            "version": "0.10.4",
        }
        old_version_needle = '  "version": "0.10.4",'
        old_target_needle = r'  \"target\": \"x86_64-unknown-linux-gnu\",'

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "release-receipt.json"
            path.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[-2], '  "version": "0.10.4"')
            self.assertIn('  "target": "x86_64-unknown-linux-gnu",', lines)

            completed = subprocess.run(
                ["sh", "-c", 'grep -Fqx "$2" "$1"', "sh", str(path), old_version_needle],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)

            completed = subprocess.run(
                ["sh", "-c", 'grep -Fqx "$2" "$1"', "sh", str(path), old_target_needle],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)


class EntrypointContractTests(unittest.TestCase):
    def test_rejects_inherited_security_policy_bypasses_before_runtime(self) -> None:
        self.assertIn(
            "inherited ASTRID_SANDBOX_POLICY override is not permitted",
            ENTRYPOINT,
        )
        self.assertIn(
            "inherited ASTRID_ALLOW_LOCAL_IPS override is not permitted",
            ENTRYPOINT,
        )
        self.assertLess(
            ENTRYPOINT.index("ASTRID_SANDBOX_POLICY+set"),
            ENTRYPOINT.index("for daemon_argument do"),
        )
        self.assertLess(
            ENTRYPOINT.index("ASTRID_ALLOW_LOCAL_IPS+set"),
            ENTRYPOINT.index("/usr/local/bin/astrid init"),
        )

    def test_requires_external_pin_and_internal_signature_gate(self) -> None:
        self.assertIn("ASTRID_DISTRO_SHA256 is required", ENTRYPOINT)
        self.assertIn("sha256sum", ENTRYPOINT)
        self.assertIn("--offline", ENTRYPOINT)
        self.assertIn("--yes", ENTRYPOINT)
        self.assertNotIn("--allow-unsigned", ENTRYPOINT)
        self.assertNotIn("--accept-new-key", ENTRYPOINT)
        self.assertIn('export ASTRID_ENFORCED_DISTRO="$staged_distro"', ENTRYPOINT)
        init_tail = ENTRYPOINT.split("/usr/local/bin/astrid init", 1)[1]
        self.assertNotIn('ASTRID_ENFORCED_DISTRO="$distro_path"', init_tail)

    def test_stages_distro_and_rechecks_staged_bytes(self) -> None:
        self.assertIn("mktemp -d /tmp/astrid-distro.XXXXXX", ENTRYPOINT)
        self.assertIn("staged_distro=$staged_dir/distro.shuttle", ENTRYPOINT)
        self.assertIn('cat -- "$distro_path" > "$staged_distro"', ENTRYPOINT)
        self.assertIn('sha256sum "$staged_distro"', ENTRYPOINT)
        self.assertLess(
            ENTRYPOINT.index('sha256sum "$staged_distro"'),
            ENTRYPOINT.index("/usr/local/bin/astrid init"),
        )

    def test_write_probe_uses_exclusive_collision_safe_creation(self) -> None:
        self.assertIn("mktemp", ENTRYPOINT)
        self.assertIn(".astrid-oci-write-probe.XXXXXX", ENTRYPOINT)
        self.assertNotIn(".astrid-oci-write-probe.$$", ENTRYPOINT)

    def test_hosted_profile_fixes_state_workspace_and_home_identity(self) -> None:
        self.assertIn("ASTRID_HOME is fixed to /var/lib/astrid", ENTRYPOINT)
        self.assertIn("ASTRID_WORKSPACE is fixed to /workspace", ENTRYPOINT)
        self.assertIn("ASTRID_WORKSPACE_STATE_DIR is fixed to .astrid", ENTRYPOINT)
        self.assertIn("HOME is fixed to /var/lib/astrid", ENTRYPOINT)
        self.assertIn("ASTRID_HOME=/var/lib/astrid", ENTRYPOINT)
        self.assertIn("ASTRID_WORKSPACE=/workspace", ENTRYPOINT)

    def test_foreground_daemon_allowlist_rejects_ephemeral_and_unknown_flags(self) -> None:
        self.assertIn("exec /usr/local/bin/astrid-daemon", ENTRYPOINT)
        command = ENTRYPOINT.rsplit("exec /usr/local/bin/astrid-daemon", 1)[1]
        self.assertNotIn("--ephemeral", command)
        self.assertIn("--ephemeral is not permitted", ENTRYPOINT)
        self.assertIn("daemon argument is not permitted", ENTRYPOINT)
        self.assertIn("--host-io-concurrency", ENTRYPOINT)
        self.assertIn("--host-blocking-concurrency", ENTRYPOINT)
        self.assertIn("--instance-pool-size", ENTRYPOINT)
        self.assertIn("ASTRID_DAEMON_LOG_TARGET=stderr", ENTRYPOINT)


class RuntimeHarnessContractTests(unittest.TestCase):
    def test_derived_negative_images_alias_the_bound_local_digest(self) -> None:
        self.assertIn('docker image tag "$IMAGE" "$TEST_BASE_IMAGE"', TEST_HARNESS)
        self.assertEqual(TEST_HARNESS.count("FROM $TEST_BASE_IMAGE"), 2)
        self.assertNotIn("FROM $IMAGE", TEST_HARNESS)
        self.assertIn('docker image rm --force "$TEST_BASE_IMAGE"', TEST_HARNESS)

    def test_harness_has_fresh_reopen_owner_and_principal_isolation_probes(self) -> None:
        for marker in (
            "fresh-container reopen",
            "principal",
            "owner state",
            "same mounted workspace",
            "pid1 astrid-daemon",
            "hosted-restricted agent list",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, TEST_HARNESS.lower())
        self.assertNotIn("docker restart", TEST_HARNESS.lower())
        self.assertIn("agent create", TEST_HARNESS)

    def test_daemon_pid1_identity_parses_tab_delimited_proc_status(self) -> None:
        assert_function = shell_function("assert_daemon_is_pid_one")
        parse_function = shell_function("parse_proc_status_field")
        new_parser = (
            "  awk -v field=\"$field\" "
            "'$1 == field \":\" { print $2; exit }' \"$status_file\""
        )
        old_parser = (
            '  sed -n "s/^${field}:[[:space:]]*//p" "$status_file" '
            '| cut -d" " -f1'
        )
        fail_function = (
            "fail() {\n"
            "  printf 'pid1 contract: %s\\n' \"$*\" >&2\n"
            "  exit 1\n"
            "}\n"
        )
        self.assertIn(new_parser, parse_function)
        self.assertNotIn("cut -d", assert_function)

        valid_status = (
            "Name:\tastrid-daemon\n"
            "Uid:\t65532\t65532\t65532\t65532\n"
            "Gid:\t65532\t65532\t65532\t65532\n"
        )
        invalid_status = valid_status.replace(
            "Uid:\t65532",
            "Uid:\t65533",
            1,
        )
        mutant_parser = parse_function.replace(new_parser, old_parser)
        cases = [
            ("tab-delimited-fields", parse_function, valid_status, 0),
            ("old-space-delimited-cut", mutant_parser, valid_status, 1),
            ("wrong-uid", parse_function, invalid_status, 1),
        ]

        for label, parser, status, expected_status in cases:
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as temporary:
                    root = pathlib.Path(temporary)
                    bin_dir = root / "bin"
                    bin_dir.mkdir()
                    fake_docker = bin_dir / "docker"
                    fake_docker.write_text(
                        "#!/bin/sh\n"
                        "case \"$*\" in\n"
                        "*\"cat /proc/1/status\"*)\n"
                        "  printf '%s\\n' \"$FAKE_STATUS\"\n"
                        "  ;;\n"
                        "*\"cat /proc/1/comm\"*)\n"
                        "  printf '%s\\n' astrid-daemon\n"
                        "  ;;\n"
                        "*\"readlink /proc/1/exe\"*)\n"
                        "  printf '%s\\n' /opt/astrid/release/astrid-daemon\n"
                        "  ;;\n"
                        "*\"readlink /proc/1/cwd\"*)\n"
                        "  printf '%s\\n' /workspace\n"
                        "  ;;\n"
                        "*)\n"
                        "  printf 'unexpected docker call: %s\\n' \"$*\" >&2\n"
                        "  exit 64\n"
                        "esac\n",
                        encoding="utf-8",
                    )
                    fake_docker.chmod(0o755)
                    completed = run_extracted_shell(
                        [fail_function, parser, assert_function],
                        "assert_daemon_is_pid_one",
                        bin_dir,
                        {
                            "REAL_CONTAINER": "contract-runtime",
                            "FAKE_STATUS": status,
                        },
                    )

                    self.assertEqual(
                        completed.returncode,
                        expected_status,
                        completed.stderr,
                    )
                    if expected_status == 0:
                        self.assertEqual(
                            completed.stdout,
                            "PID1 astrid-daemon 65532:65532 /workspace\n",
                        )

    def test_runtime_state_readers_resolve_through_runtime_mount(self) -> None:
        for function_name in (
            "read_runtime_state_file",
            "assert_runtime_state_file_mode",
        ):
            function = shell_function(function_name)
            with self.subTest(function=function_name):
                self.assertEqual(
                    function.count('local runtime_file="/runtime/$relative"'),
                    1,
                )
                self.assertEqual(function.count("docker run"), 1)
                self.assertIn("--mount", function)
                self.assertIn('dst=/runtime,readonly"', function)

    def test_workspace_marker_helper_uses_runtime_uid_container_not_host_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            bin_dir = root / "bin"
            workspace = root / "workspace"
            bin_dir.mkdir()
            workspace.mkdir()
            call_log = root / "docker-calls"
            fake_docker = bin_dir / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "for argument do\n"
                "  printf '%s\\0' \"$argument\" >> \"$DOCKER_CALL_LOG\"\n"
                "done\n"
                "printf '\\0' >> \"$DOCKER_CALL_LOG\"\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)

            completed = run_extracted_shell(
                [shell_function("write_runtime_workspace_marker")],
                f"write_runtime_workspace_marker {shlex.quote(str(workspace))}",
                bin_dir,
                {"DOCKER_CALL_LOG": str(call_log)},
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout,
                "",
                "the marker helper must execute inside the container",
            )
            self.assertFalse(
                (workspace / ".astrid-oci-mounted-state").exists(),
                "the marker helper must not write to the host-side directory",
            )
            calls = docker_call_log(call_log)
            self.assertEqual(len(calls), 1)
            arguments = calls[0]
            self.assertEqual(arguments[:2], ["run", "--rm"])
            self.assertEqual(arguments[arguments.index("--platform") + 1], "linux/amd64")
            self.assertEqual(arguments[arguments.index("--user") + 1], "65532:65532")
            self.assertEqual(
                arguments[arguments.index("--entrypoint") + 1],
                "/bin/sh",
            )
            self.assertEqual(
                arguments[arguments.index("--mount") + 1],
                f"type=bind,src={workspace},dst=/workspace",
            )
            self.assertEqual(
                arguments[arguments.index("-ec") + 1],
                'printf "%s\\n" "$1" > "$2"',
            )
            self.assertEqual(
                arguments[arguments.index("-ec") + 2 :],
                [
                    "sh",
                    "same-mounted-workspace",
                    "/workspace/.astrid-oci-mounted-state",
                ],
            )

    def test_harness_never_uses_unsupported_v0104_audit_query(self) -> None:
        self.assertNotIn("audit stats", TEST_HARNESS.lower())
        self.assertIn("audit status", TEST_HARNESS)
        self.assertIn("v0.10.4 baseline blocker", TEST_HARNESS)
        self.assertIn("BLOCKED AUDIT (non-gating)", TEST_HARNESS)
        self.assertIn(
            "this result does not claim hosted-profile qualification",
            TEST_HARNESS,
        )
        self.assertNotIn('fail "v0.10.4 baseline blocker', TEST_HARNESS)
        self.assertIn(
            "no supported chain/head or principal-scoped query",
            TEST_HARNESS.lower(),
        )

    def test_audit_probe_requires_failed_status_and_exact_stub_stderr(self) -> None:
        audit_functions = [
            "fail() {\n"
            '  printf "audit probe: %s\\n" "$*" >&2\n'
            "  exit 1\n"
            "}\n",
            "REAL_CONTAINER=contract-runtime\n",
            shell_function("run_real_cli"),
            shell_function("register_v0104_audit_stderr"),
            shell_function("assert_v0104_audit_is_non_gating"),
        ]
        fake_docker_source = (
            "#!/bin/sh\n"
            "for argument do\n"
            "  printf '%s\\0' \"$argument\" >> \"$DOCKER_CALL_LOG\"\n"
            "done\n"
            "printf '\\0' >> \"$DOCKER_CALL_LOG\"\n"
            'printf "%s" "$FAKE_AUDIT_STDERR" >&2\n'
            'exit "$FAKE_AUDIT_STATUS"\n'
        )

        expected_blocker = (
            "BLOCKED AUDIT (non-gating): v0.10.4 baseline blocker; "
            "audit is deferred and exposes no supported chain/head or "
            "principal-scoped query.\n"
        )
        registered_first = (
            "astrid: audit trail inspection is not available in this release.\n"
        )
        registered_second = (
            "  Tracking issue #675 (Layer 7 audit log routing) — see "
            "https://github.com/astrid-runtime/astrid/issues/675\n"
        )
        registered_stderr = registered_first + registered_second
        cases = [
            ("registered-status-two", "2", registered_stderr, 0),
            ("status-zero", "0", registered_stderr, 1),
            ("status-one", "1", registered_stderr, 1),
            ("status-three", "3", registered_stderr, 1),
            ("old-one-line", "2", "audit trail inspection is not available\n", 1),
            ("first-line-only", "2", registered_first, 1),
            (
                "missing-issue-number",
                "2",
                registered_first
                + registered_second.replace("#675 ", "", 1),
                1,
            ),
            (
                "prefix",
                "2",
                "prefix " + registered_stderr,
                1,
            ),
            (
                "suffix",
                "2",
                registered_stderr.removesuffix("\n") + " suffix\n",
                1,
            ),
            (
                "extra-line",
                "2",
                registered_stderr + "extra detail\n",
                1,
            ),
            (
                "extra-whitespace",
                "2",
                registered_first.replace("\n", " \n", 1) + registered_second,
                1,
            ),
            (
                "ascii-hyphen",
                "2",
                registered_first + registered_second.replace("—", "-", 1),
                1,
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for label, status, stderr, expected_status in cases:
                bin_dir = root / label
                bin_dir.mkdir()
                call_log = root / f"{label}-calls"
                fake_docker = bin_dir / "docker"
                fake_docker.write_text(fake_docker_source, encoding="utf-8")
                fake_docker.chmod(0o755)
                completed = run_extracted_shell(
                    audit_functions,
                    "assert_v0104_audit_is_non_gating probe.out probe.err",
                    bin_dir,
                    {
                        "DOCKER_CALL_LOG": str(call_log),
                        "FAKE_AUDIT_STATUS": status,
                        "FAKE_AUDIT_STDERR": stderr,
                        "TEST_ROOT": str(bin_dir),
                    },
                )

                with self.subTest(case=label):
                    self.assertEqual(
                        completed.returncode,
                        expected_status,
                        completed.stderr,
                    )
                    calls = docker_call_log(call_log)
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0][0], "exec")
                    self.assertEqual(
                        calls[0][-3:],
                        ["/usr/local/bin/astrid", "audit", "status"],
                    )
                    if expected_status == 0:
                        self.assertEqual(completed.stdout, expected_blocker)
                    else:
                        self.assertEqual(completed.stdout, "")
                        if status == "0":
                            self.assertIn(
                                "v0.10.4 unexpectedly exposed an audit query",
                                completed.stderr,
                            )
                        else:
                            self.assertIn("captured stderr", completed.stderr)
                            self.assertIn(
                                "re-evaluate the exact-release proof",
                                completed.stderr,
                            )

    def test_audit_probe_rejects_status_and_matcher_mutations(self) -> None:
        registered_function = shell_function("register_v0104_audit_stderr")
        assert_function = shell_function("assert_v0104_audit_is_non_gating")

        self.assertIn("v0.10.4 / TEST_SOURCE_COMMIT=b6bf5d1", registered_function)
        self.assertIn(
            "SHA-256 8af9a0342aa14e2f65a9f563a0685f8dc8f806f7eda3d2ae5fa088fe667ae8a4",
            registered_function,
        )
        self.assertIn("run_real_cli audit status", assert_function)
        self.assertIn('|| status=$?', assert_function)
        self.assertNotIn("|| true", assert_function)
        self.assertIn('[ "$status" -ne 2 ]', assert_function)
        self.assertNotIn("grep -Fq", assert_function)
        self.assertIn('cmp -s "$error" "$expected"', assert_function)

    def test_harness_rejects_inherited_security_policy_bypasses(self) -> None:
        self.assertIn("ASTRID_SANDBOX_POLICY=off", TEST_HARNESS)
        self.assertIn("ASTRID_ALLOW_LOCAL_IPS=1", TEST_HARNESS)
        self.assertIn("inherited policy override", TEST_HARNESS.lower())

    def test_harness_rejects_host_socket_and_privileged_runtime(self) -> None:
        lowered = TEST_HARNESS.lower()
        self.assertNotIn("docker.sock", lowered)
        self.assertNotIn("--privileged", lowered)
        self.assertIn("--read-only", lowered)
        self.assertIn("--cap-drop=all", lowered)
        self.assertIn("--security-opt=no-new-privileges", lowered)


class WorkflowContractTests(unittest.TestCase):
    def test_oidc_signing_requires_protected_main_and_environment(self) -> None:
        sign_job = WORKFLOW.split("\n  sign:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", sign_job)
        self.assertIn("github.ref == 'refs/heads/main'", sign_job)
        self.assertIn("github.ref_protected == true", sign_job)
        self.assertIn("vars.ASTRID_OCI_SIGNING_ENABLED == 'true'", sign_job)
        self.assertIn("environment:\n      name: oci-signing", sign_job)
        self.assertIn("id-token: write", sign_job)
        build_job = WORKFLOW.split("\n  sign:\n", 1)[0]
        self.assertNotIn("id-token: write", build_job)

    def test_compatible_uplink_fixture_is_source_pinned(self) -> None:
        self.assertIn("repository: unicity-aos/aos-ce", WORKFLOW)
        self.assertRegex(WORKFLOW, r"ref: [0-9a-f]{40}")
        self.assertIn("dist/oci-test/aos-cli.capsule", WORKFLOW)

    def test_exact_export_is_built_once_and_bound_to_tested_image(self) -> None:
        build_job = WORKFLOW.split("\n  sign:\n", 1)[0]
        snapshotter = build_job.index('"containerd-snapshotter": true')
        build = build_job.index("docker buildx build")
        load = build_job.index("docker load --input")
        self.assertLess(snapshotter, build)
        self.assertLess(build, load)
        self.assertIn("io.containerd.snapshotter.v1", build_job)
        self.assertEqual(build_job.count("docker buildx build"), 1)
        self.assertEqual(build_job.count("--platform linux/amd64"), 1)
        self.assertIn("type=oci,dest=", build_job)
        self.assertNotIn("type=docker,dest=", build_job)
        self.assertNotIn("--load", build_job)
        self.assertIn('echo "BOUND_IMAGE=$IMAGE_REPO_DIGEST"', build_job)
        for build_arg in (
            '"ASTRID_ARCHIVE_BLAKE3=$ARCHIVE_BLAKE3"',
            '"ASTRID_RELEASE_MANIFEST_SHA256=$RELEASE_MANIFEST_SHA256"',
            '"ASTRID_RELEASE_RECEIPT_SHA256=$RELEASE_RECEIPT_SHA256"',
        ):
            with self.subTest(build_arg=build_arg):
                self.assertIn(build_arg, build_job)
        first_binding = build_job.index("python3 scripts/oci_export_binding.py")
        runtime_test = build_job.index('container/amd64/test.sh "$BOUND_IMAGE"')
        scan = build_job.index("aquasecurity/trivy-action")
        sbom = build_job.index("anchore/sbom-action")
        recheck = build_job.rindex("python3 scripts/oci_export_binding.py")
        upload = build_job.index("actions/upload-artifact")
        self.assertLess(first_binding, runtime_test)
        self.assertLess(runtime_test, scan)
        self.assertLess(scan, sbom)
        self.assertLess(sbom, recheck)
        self.assertLess(recheck, upload)
        self.assertIn("cmp \\", build_job)
        self.assertIn("sha256sum --check", build_job)
        self.assertIn("amd64.oci-binding.json", build_job)
        self.assertIn("image-ref: ${{ env.BOUND_IMAGE }}", build_job)
        self.assertIn("image: ${{ env.BOUND_IMAGE }}", build_job)
        self.assertIn('test "$IMAGE_REPO_DIGEST" = "$BOUND_IMAGE"', build_job)

    def test_signed_manifest_covers_metadata_and_sbom(self) -> None:
        sign_job = WORKFLOW.split("\n  sign:\n", 1)[1]
        self.assertIn("amd64.evidence.sha256", sign_job)
        self.assertIn("amd64.evidence.sha256.sigstore.json", sign_job)
        self.assertIn('sha256sum --check "astrid-${VERSION}-amd64.evidence.sha256"', sign_job)
        self.assertIn(
            '"dist/astrid-${VERSION}-amd64.evidence.sha256"',
            sign_job,
        )
        build_job = WORKFLOW.split("\n  sign:\n", 1)[0]
        for evidence in (
            "amd64.oci.tar",
            "amd64.oci-binding.json",
            "amd64.spdx.json",
            "oci-amd64/release-receipt.json",
        ):
            with self.subTest(evidence=evidence):
                self.assertIn(evidence, build_job)

    def test_workflow_never_invokes_registry_publication_tools(self) -> None:
        lowered = WORKFLOW.lower()
        self.assertNotIn("docker/login-action", lowered)
        self.assertNotIn("docker/build-push-action", lowered)
        self.assertNotRegex(lowered, r"\bdocker\s+(?:image\s+)?push\b")
        self.assertNotIn("docker login", lowered)
        self.assertNotIn("--push", lowered)
        self.assertNotIn("push: true", lowered)
        self.assertNotIn("type=registry", lowered)
        self.assertNotIn("docker manifest", lowered)
        self.assertNotIn("docker buildx imagetools create", lowered)
        self.assertNotRegex(
            lowered,
            r"\b(?:oras|skopeo|crane|regctl)(?:\s|$)",
        )
        self.assertNotIn("packages: write", lowered)

    def test_workflow_never_uses_mutable_or_canonical_image_tags(self) -> None:
        self.assertIsNone(
            re.search(
                r"(?i)(?:--tag|tags?:|image[:=])[^\n]*"
                r"(?:latest|stable|dev|nightly)(?:[^a-z0-9]|$)",
                WORKFLOW,
            ),
        )
        lowered = WORKFLOW.lower()
        self.assertNotIn("multiarch", lowered)
        self.assertNotIn("multi-arch", lowered)
        self.assertNotIn("canonical tag", lowered)

    def test_workflow_cannot_enable_emulation_or_multi_platform_builds(self) -> None:
        lowered = WORKFLOW.lower()
        self.assertNotIn("qemu", lowered)
        self.assertNotIn("binfmt", lowered)
        self.assertNotIn("tonistiigi", lowered)
        self.assertNotIn("multiarch/qemu-user-static", lowered)
        self.assertNotIn("--privileged", lowered)
        self.assertEqual(
            re.findall(r"--platform(?:=|\s+)([^\s\\]+)", lowered),
            ["linux/amd64"],
        )


if __name__ == "__main__":
    unittest.main()
