#!/usr/bin/env python3
"""Static security contract tests for the Linux amd64 image."""

from __future__ import annotations

import pathlib
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


if __name__ == "__main__":
    unittest.main()
