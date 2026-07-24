#!/usr/bin/env python3
"""Static security contract tests for the native Linux arm64 image."""

from __future__ import annotations

import pathlib
import re
import tempfile
import unittest

import oci_export_binding
from test_oci_export_binding import write_archive


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "container/arm64/Dockerfile").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "container/amd64/entrypoint.sh").read_text(encoding="utf-8")
TEST_WRAPPER = (ROOT / "container/arm64/test.sh").read_text(encoding="utf-8")
RUNTIME_TEST = (ROOT / "container/amd64/test.sh").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/oci-arm64.yml").read_text(encoding="utf-8")


class DockerfileContractTests(unittest.TestCase):
    def test_packages_exact_arm64_release_bytes_without_building_source(self) -> None:
        self.assertIn("COPY dist/oci-arm64/astrid-release.tar.gz", DOCKERFILE)
        self.assertIn("ARG ASTRID_ARCHIVE_SHA256", DOCKERFILE)
        self.assertIn("sha256sum --check --strict", DOCKERFILE)
        self.assertIn(
            'io.astrid.release.target="aarch64-unknown-linux-gnu"',
            DOCKERFILE,
        )
        self.assertNotIn("cargo build", DOCKERFILE)
        self.assertNotIn("git clone", DOCKERFILE)
        self.assertNotIn("curl ", DOCKERFILE)
        self.assertNotIn("wget ", DOCKERFILE)

    def test_uses_arch_specific_digest_pinned_ubuntu_base(self) -> None:
        first_line = DOCKERFILE.splitlines()[0]
        self.assertEqual(
            first_line,
            "FROM docker.io/library/ubuntu@sha256:"
            "7f622ca8766bccb22f04242ecb6f19f770b2f08827dc4b8c707de5e78a6da7ab",
        )

    def test_is_non_root_distro_neutral_and_exposes_no_ports(self) -> None:
        self.assertIn("USER 65532:65532", DOCKERFILE)
        self.assertNotIn("EXPOSE", DOCKERFILE)
        self.assertNotIn("aos", DOCKERFILE.lower())
        self.assertNotIn("latest", DOCKERFILE.lower())

    def test_reuses_the_reviewed_entrypoint_contract(self) -> None:
        self.assertIn(
            "COPY container/amd64/entrypoint.sh "
            "/usr/local/bin/astrid-container-entrypoint",
            DOCKERFILE,
        )


class RuntimeContractTests(unittest.TestCase):
    def test_arm64_wrapper_selects_native_platform_and_architecture(self) -> None:
        self.assertIn("ASTRID_OCI_TEST_PLATFORM=linux/arm64", TEST_WRAPPER)
        self.assertIn("ASTRID_OCI_TEST_ARCHITECTURE=arm64", TEST_WRAPPER)
        self.assertIn('SCRIPT_DIR=$(CDPATH=\'\' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)', TEST_WRAPPER)
        self.assertIn('REPO_ROOT=$(CDPATH=\'\' cd -- "$SCRIPT_DIR/../.." && pwd)', TEST_WRAPPER)
        self.assertIn('exec "$REPO_ROOT/container/amd64/test.sh" "$@"', TEST_WRAPPER)

    def test_shared_runtime_harness_keeps_amd64_defaults(self) -> None:
        self.assertIn(
            "OCI_PLATFORM=${ASTRID_OCI_TEST_PLATFORM:-linux/amd64}",
            RUNTIME_TEST,
        )
        self.assertIn(
            "OCI_ARCHITECTURE=${ASTRID_OCI_TEST_ARCHITECTURE:-amd64}",
            RUNTIME_TEST,
        )
        self.assertIn(
            "OCI_TEST_LABEL=${ASTRID_OCI_TEST_LABEL:-amd64}",
            RUNTIME_TEST,
        )

    def test_derived_images_alias_and_cleanup_the_bound_local_base(self) -> None:
        self.assertIn(
            'docker image tag "$IMAGE" "$TEST_BASE_IMAGE"',
            RUNTIME_TEST,
        )
        self.assertEqual(RUNTIME_TEST.count("FROM $TEST_BASE_IMAGE"), 2)
        self.assertNotIn("FROM $IMAGE", RUNTIME_TEST)
        self.assertIn(
            'docker image rm --force "$TEST_BASE_IMAGE"',
            RUNTIME_TEST,
        )

    def test_restricted_runtime_is_rootless_read_only_and_unprivileged(self) -> None:
        self.assertIn("--read-only", RUNTIME_TEST)
        self.assertIn("--cap-drop=ALL", RUNTIME_TEST)
        self.assertIn("--security-opt=no-new-privileges", RUNTIME_TEST)
        self.assertNotIn("--privileged", RUNTIME_TEST)
        self.assertNotIn("/var/run/docker.sock", RUNTIME_TEST)
        self.assertNotIn("/run/docker.sock", RUNTIME_TEST)

    def test_real_daemon_readiness_and_authenticated_status_are_required(self) -> None:
        self.assertIn("/var/lib/astrid/run/system.ready", RUNTIME_TEST)
        self.assertIn("/usr/local/bin/astrid status", RUNTIME_TEST)
        self.assertIn("Astrid daemon", RUNTIME_TEST)

    def test_entrypoint_stages_and_reauthenticates_signed_distro(self) -> None:
        self.assertIn("mktemp -d /tmp/astrid-distro.XXXXXX", ENTRYPOINT)
        self.assertIn('cat -- "$distro_path" > "$staged_distro"', ENTRYPOINT)
        self.assertIn('sha256sum "$staged_distro"', ENTRYPOINT)
        self.assertIn('export ASTRID_ENFORCED_DISTRO="$staged_distro"', ENTRYPOINT)
        self.assertIn("/usr/local/bin/astrid init", ENTRYPOINT)
        self.assertIn("--offline", ENTRYPOINT)
        self.assertNotIn("--allow-unsigned", ENTRYPOINT)
        self.assertNotIn("--accept-new-key", ENTRYPOINT)

    def test_foreground_daemon_allowlist_cannot_enable_ephemeral_mode(self) -> None:
        self.assertIn("exec /usr/local/bin/astrid-daemon", ENTRYPOINT)
        self.assertIn("ASTRID_DAEMON_LOG_TARGET=stderr", ENTRYPOINT)
        self.assertIn("--ephemeral is not permitted", ENTRYPOINT)
        self.assertIn("daemon argument is not permitted", ENTRYPOINT)
        daemon_command = ENTRYPOINT.rsplit(
            "exec /usr/local/bin/astrid-daemon",
            1,
        )[1]
        self.assertNotIn("--ephemeral", daemon_command)


class Arm64BindingContractTests(unittest.TestCase):
    def test_accepts_exact_variant_free_linux_arm64_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(
                archive,
                architecture="arm64",
            )
            receipt = oci_export_binding.verify_binding(
                archive,
                image_manifest_digest=manifest_digest,
                os_name="linux",
                architecture="arm64",
            )
            self.assertEqual(receipt["platform"], "linux/arm64")
            self.assertEqual(
                receipt["loaded-image-manifest-digest"],
                manifest_digest,
            )

    def test_rejects_arm64_v8_variant_instead_of_silently_widening(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "image.oci.tar"
            _, manifest_digest = write_archive(
                archive,
                architecture="arm64",
                platform_extra={"variant": "v8"},
            )
            with self.assertRaisesRegex(ValueError, "platform is not exact"):
                oci_export_binding.verify_binding(
                    archive,
                    image_manifest_digest=manifest_digest,
                    os_name="linux",
                    architecture="arm64",
                )


class WorkflowContractTests(unittest.TestCase):
    def test_build_and_sign_jobs_use_native_arm64_runners(self) -> None:
        self.assertEqual(WORKFLOW.count("runs-on: ubuntu-24.04-arm"), 2)
        self.assertIn('test "$(uname -m)" = aarch64', WORKFLOW)
        self.assertIn(
            'test "$(docker info --format \'{{.Architecture}}\')" = aarch64',
            WORKFLOW,
        )
        self.assertNotIn("setup-qemu", WORKFLOW.lower())
        self.assertNotIn("tonistiigi/binfmt", WORKFLOW.lower())

    def test_authenticates_exact_arm64_release_target(self) -> None:
        self.assertIn("RELEASE_TARGET: aarch64-unknown-linux-gnu", WORKFLOW)
        self.assertIn('--target "$RELEASE_TARGET"', WORKFLOW)
        self.assertIn("--platform linux/arm64", WORKFLOW)
        self.assertIn("grep -q 'ARM aarch64'", WORKFLOW)

    def test_scan_sbom_and_per_export_blob_evidence_are_required(self) -> None:
        self.assertIn("aquasecurity/trivy-action@", WORKFLOW)
        self.assertIn("anchore/sbom-action@", WORKFLOW)
        self.assertIn("type=oci,dest=dist/astrid-${VERSION}-arm64.oci.tar", WORKFLOW)
        self.assertIn("astrid-${VERSION}-arm64.oci.tar.sha256", WORKFLOW)
        self.assertIn("sha256sum --check", WORKFLOW)
        self.assertIn("cosign sign-blob", WORKFLOW)
        self.assertIn("actions/attest-build-provenance@", WORKFLOW)
        self.assertIn(
            "subject-path: dist/astrid-${{ env.VERSION }}-arm64.oci.tar",
            WORKFLOW,
        )

    def test_exact_export_is_built_once_and_bound_to_consumed_arm64_image(self) -> None:
        build_job = WORKFLOW.split("\n  sign:\n", 1)[0]
        snapshotter = build_job.index('"containerd-snapshotter": true')
        build = build_job.index("docker buildx build")
        load = build_job.index("docker load --input")
        self.assertLess(snapshotter, build)
        self.assertLess(build, load)
        self.assertIn("io.containerd.snapshotter.v1", build_job)
        self.assertEqual(build_job.count("docker buildx build"), 1)
        self.assertEqual(build_job.count("--platform linux/arm64"), 1)
        self.assertIn("type=oci,dest=", build_job)
        self.assertNotIn("type=docker,dest=", build_job)
        self.assertNotIn("--load", build_job)
        self.assertIn('echo "BOUND_IMAGE=$IMAGE_REPO_DIGEST"', build_job)
        self.assertEqual(
            build_job.count("python3 scripts/oci_export_binding.py"),
            2,
        )
        self.assertEqual(build_job.count("--architecture arm64"), 2)
        self.assertNotIn("--variant", build_job)
        first_binding = build_job.index("python3 scripts/oci_export_binding.py")
        runtime_test = build_job.index('container/arm64/test.sh "$BOUND_IMAGE"')
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
        self.assertIn("arm64.oci-binding.json", build_job)
        self.assertIn("image-ref: ${{ env.BOUND_IMAGE }}", build_job)
        self.assertIn("image: ${{ env.BOUND_IMAGE }}", build_job)
        self.assertIn('test "$IMAGE_REPO_DIGEST" = "$BOUND_IMAGE"', build_job)

    def test_signed_manifest_covers_arm64_metadata_and_sbom(self) -> None:
        sign_job = WORKFLOW.split("\n  sign:\n", 1)[1]
        self.assertIn("arm64.evidence.sha256", sign_job)
        self.assertIn("arm64.evidence.sha256.sigstore.json", sign_job)
        self.assertIn(
            'sha256sum --check "astrid-${VERSION}-arm64.evidence.sha256"',
            sign_job,
        )
        self.assertIn(
            '"dist/astrid-${VERSION}-arm64.evidence.sha256"',
            sign_job,
        )
        build_job = WORKFLOW.split("\n  sign:\n", 1)[0]
        for evidence in (
            "arm64.oci.tar",
            "arm64.oci-binding.json",
            "arm64.spdx.json",
            "oci-arm64/release-receipt.json",
        ):
            with self.subTest(evidence=evidence):
                self.assertIn(evidence, build_job)

    def test_path_filters_and_test_lane_include_shared_binding_contract(self) -> None:
        self.assertIn("'scripts/oci_export_binding.py'", WORKFLOW)
        self.assertIn("'scripts/test_oci_export_binding.py'", WORKFLOW)
        self.assertIn("python3 scripts/test_oci_export_binding.py", WORKFLOW)

    def test_oidc_signing_requires_manual_protected_main_and_environment(self) -> None:
        sign_job = WORKFLOW.split("\n  sign:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", sign_job)
        self.assertIn("github.ref == 'refs/heads/main'", sign_job)
        self.assertIn("github.ref_protected == true", sign_job)
        self.assertIn("vars.ASTRID_OCI_SIGNING_ENABLED == 'true'", sign_job)
        self.assertIn("environment:\n      name: oci-signing", sign_job)
        self.assertIn("id-token: write", sign_job)
        build_job = WORKFLOW.split("\n  sign:\n", 1)[0]
        self.assertNotIn("id-token: write", build_job)

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
            re.findall(r"--platform(?:=|\s+)([^\s\\\\]+)", lowered),
            ["linux/arm64"],
        )


if __name__ == "__main__":
    unittest.main()
