#!/usr/bin/env python3
"""Static security contract tests for the Linux amd64 image."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "container/amd64/Dockerfile").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "container/amd64/entrypoint.sh").read_text(encoding="utf-8")
TEST_HARNESS = (ROOT / "container/amd64/test.sh").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/oci-amd64.yml").read_text(encoding="utf-8")


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

    def test_runtime_state_helpers_use_mount_and_uid_for_evidence(self) -> None:
        self.assertEqual(TEST_HARNESS.count('local runtime_file="/runtime/$relative"'), 2)
        self.assertIn("direct filesystem secret writes", TEST_HARNESS)
        self.assertIn("shared state mount", TEST_HARNESS)
        self.assertIn(
            "not authenticated admin IPC or secret-read isolation",
            TEST_HARNESS,
        )
        self.assertIn(
            'write_runtime_workspace_marker "$run_dir/real-workspace"',
            TEST_HARNESS,
        )
        self.assertIn('"/workspace/.astrid-oci-mounted-state"', TEST_HARNESS)
        self.assertIn("--user 65532:65532", TEST_HARNESS)
        self.assertLess(
            TEST_HARNESS.index('prepare_runtime_dir "$run_dir/real-workspace" 0755'),
            TEST_HARNESS.index(
                'write_runtime_workspace_marker "$run_dir/real-workspace"'
            ),
        )
        self.assertNotIn(
            '>"$run_dir/real-workspace/.astrid-oci-mounted-state"',
            TEST_HARNESS,
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
