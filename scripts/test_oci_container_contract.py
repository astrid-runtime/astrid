#!/usr/bin/env python3
"""Static security contract tests for the Linux amd64 image."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "container/amd64/Dockerfile").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "container/amd64/entrypoint.sh").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/oci-amd64.yml").read_text(encoding="utf-8")


class DockerfileContractTests(unittest.TestCase):
    def test_packages_release_bytes_without_building_source(self) -> None:
        self.assertIn("COPY dist/oci-amd64/astrid-release.tar.gz", DOCKERFILE)
        self.assertIn("ARG ASTRID_ARCHIVE_SHA256", DOCKERFILE)
        self.assertIn("sha256sum --check --strict", DOCKERFILE)
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


class EntrypointContractTests(unittest.TestCase):
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
        self.assertEqual(build_job.count("docker buildx build"), 1)
        self.assertEqual(build_job.count("--platform linux/amd64"), 1)
        self.assertIn("type=oci,dest=", build_job)
        self.assertNotIn("type=docker,dest=", build_job)
        self.assertNotIn("--load", build_job)
        self.assertIn("docker load --input", build_job)
        self.assertIn('echo "BOUND_IMAGE=$IMAGE_REPO_DIGEST"', build_job)
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
