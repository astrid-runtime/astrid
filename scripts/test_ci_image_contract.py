#!/usr/bin/env python3
"""Static contract tests for the CI-only Astrid toolchain image."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "container/ci/Dockerfile").read_text(encoding="utf-8")
README = (ROOT / "container/ci/README.md").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/ci-image.yml").read_text(encoding="utf-8")


class DockerfileContractTests(unittest.TestCase):
    def test_base_and_source_are_immutable(self) -> None:
        first_line = DOCKERFILE.splitlines()[0]
        self.assertRegex(first_line, r"^FROM .+@sha256:[0-9a-f]{64}$")
        self.assertIn('org.opencontainers.image.revision="${ASTRID_SOURCE_COMMIT}"', DOCKERFILE)
        self.assertNotIn("latest", DOCKERFILE.lower())

    def test_packages_prebuilt_repository_binaries(self) -> None:
        for binary in ("astrid", "astrid-build", "astrid-daemon", "astrid-emit"):
            self.assertIn(f"COPY --chmod=0755 dist/ci/{binary}", DOCKERFILE)
        self.assertNotIn("cargo build", DOCKERFILE)
        self.assertNotIn("git clone", DOCKERFILE)

    def test_has_the_capsule_ci_toolchain_without_an_entrypoint(self) -> None:
        self.assertIn("rust:1.95.0-bookworm@sha256:", DOCKERFILE)
        self.assertIn("rustup target add wasm32-unknown-unknown", DOCKERFILE)
        self.assertNotIn("ENTRYPOINT", DOCKERFILE)


class WorkflowContractTests(unittest.TestCase):
    def test_pull_requests_cannot_publish(self) -> None:
        publish = WORKFLOW.split("\n  publish:\n", 1)[1]
        self.assertIn("github.event_name == 'push'", publish)
        self.assertIn("github.ref == 'refs/heads/main'", publish)
        build = WORKFLOW.split("\n  publish:\n", 1)[0]
        self.assertNotIn("packages: write", build)
        self.assertNotIn("id-token: write", build)

    def test_publishes_only_the_full_source_commit_tag(self) -> None:
        self.assertIn('IMAGE_TAG="${IMAGE_NAME}:${GITHUB_SHA}"', WORKFLOW)
        for moving_tag in ("latest", "stable", "nightly", "dev"):
            self.assertNotIn(f'${{IMAGE_NAME}}:{moving_tag}', WORKFLOW)
        self.assertNotIn("docker manifest", WORKFLOW.lower())

    def test_publishes_the_exact_tested_archive_with_provenance(self) -> None:
        build = WORKFLOW.split("\n  publish:\n", 1)[0]
        publish = WORKFLOW.split("\n  publish:\n", 1)[1]
        self.assertLess(build.index("container/ci/test.sh"), build.index("docker image save"))
        self.assertIn("sha256sum --check", publish)
        self.assertIn("docker image load", publish)
        self.assertIn("actions/attest-build-provenance@", publish)
        self.assertIn("push-to-registry: true", publish)


class DocumentationContractTests(unittest.TestCase):
    def test_consumers_are_told_to_pin_a_digest(self) -> None:
        self.assertIn("CI-only", README)
        self.assertIn("@sha256:<manifest-digest>", README)
        self.assertIn("Do not consume a moving tag", README)


if __name__ == "__main__":
    unittest.main()
