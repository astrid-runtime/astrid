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
    def test_base_source_and_version_are_bound(self) -> None:
        first_line = DOCKERFILE.splitlines()[0]
        self.assertRegex(first_line, r"^FROM .+@sha256:[0-9a-f]{64}$")
        self.assertIn('org.opencontainers.image.revision="${ASTRID_SOURCE_COMMIT}"', DOCKERFILE)
        self.assertIn('org.opencontainers.image.version="${ASTRID_VERSION}"', DOCKERFILE)
        self.assertIn('io.astrid.ci.rust-version="1.95.0"', DOCKERFILE)

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
    def test_release_completion_and_manual_recovery_are_the_only_publish_events(self) -> None:
        self.assertIn("workflow_run:", WORKFLOW)
        self.assertIn("workflows: ['Release']", WORKFLOW)
        self.assertIn("workflow_dispatch:", WORKFLOW)
        self.assertNotIn("\n  push:", WORKFLOW)
        publish = WORKFLOW.split("\n  publish:\n", 1)[1]
        self.assertIn("github.event_name != 'pull_request'", publish)
        self.assertIn("github.ref == 'refs/heads/main'", publish)
        self.assertIn("!contains(github.event.workflow_run.head_branch, '-nightly.')", WORKFLOW)
        build = WORKFLOW.split("\n  publish:\n", 1)[0]
        self.assertNotIn("packages: write", build)
        self.assertNotIn("id-token: write", build)

    def test_authenticates_the_stable_release_and_source(self) -> None:
        self.assertIn(".immutable == true", WORKFLOW)
        self.assertIn(".prerelease == false", WORKFLOW)
        self.assertIn('[[ "$TAG_COMMIT" == "$SOURCE_COMMIT" ]]', WORKFLOW)
        self.assertIn('.name == "Release"', WORKFLOW)
        self.assertIn('.conclusion == "success"', WORKFLOW)

    def test_image_definition_is_separate_from_exact_release_source(self) -> None:
        self.assertIn("Check out the image definition", WORKFLOW)
        self.assertIn("Check out exact Astrid release source", WORKFLOW)
        self.assertIn("path: .ci-source", WORKFLOW)
        self.assertIn("--workdir /workspace/.ci-source", WORKFLOW)

    def test_binaries_are_built_inside_the_exact_runtime_base(self) -> None:
        base = DOCKERFILE.splitlines()[0].removeprefix("FROM ")
        self.assertIn(f"BUILD_IMAGE: docker.io/library/{base}", WORKFLOW)
        self.assertIn('"$BUILD_IMAGE"', WORKFLOW)
        self.assertIn("--workdir /workspace/.ci-source", WORKFLOW)
        self.assertIn("cargo build --target-dir target --release --locked -p astrid", WORKFLOW)
        self.assertIn("shared-key: ci-image-bookworm-amd64", WORKFLOW)

    def test_publishes_exact_version_variant_and_source_tags(self) -> None:
        self.assertIn('CANONICAL_TAG="${IMAGE_NAME}:sha-${SOURCE_COMMIT}"', WORKFLOW)
        self.assertIn('VERSION_TAG="${IMAGE_NAME}:${VERSION}"', WORKFLOW)
        self.assertIn(
            'VARIANT_TAG="${IMAGE_NAME}:${VERSION}-rust${RUST_VERSION}-${IMAGE_VARIANT}"',
            WORKFLOW,
        )
        for moving_tag in ("latest", "stable", "nightly", "dev"):
            self.assertNotIn(f'${{IMAGE_NAME}}:{moving_tag}', WORKFLOW)

    def test_existing_tags_must_resolve_to_the_canonical_digest(self) -> None:
        self.assertIn('test "$ALIAS_DIGEST" = "$DIGEST"', WORKFLOW)
        self.assertIn("docker buildx imagetools create", WORKFLOW)
        self.assertIn("manifest unknown|no such manifest", WORKFLOW)
        self.assertIn("cannot prove whether $alias already exists", WORKFLOW)

    def test_publishes_the_exact_tested_archive_with_provenance(self) -> None:
        build = WORKFLOW.split("\n  publish:\n", 1)[0]
        publish = WORKFLOW.split("\n  publish:\n", 1)[1]
        self.assertLess(build.index("container/ci/test.sh"), build.index("docker image save"))
        self.assertIn("sha256sum --check", publish)
        self.assertIn("docker image load", publish)
        self.assertIn("actions/attest-build-provenance@", publish)
        self.assertIn("push-to-registry: true", publish)


class DocumentationContractTests(unittest.TestCase):
    def test_consumers_are_told_to_pin_a_release_digest(self) -> None:
        self.assertIn("authenticated stable Astrid release", README)
        self.assertIn(":X.Y.Z-rust1.95.0-bookworm", README)
        self.assertIn(":0.10.4@sha256:<manifest-digest>", README)
        self.assertIn("Do not consume a tag without its digest", README)


if __name__ == "__main__":
    unittest.main()
