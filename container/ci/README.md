# Astrid CI toolchain image

This image is a CI-only build environment for Astrid capsule repositories. It
contains the repository's pinned Rust toolchain, the `wasm32-unknown-unknown`
target, common GitHub Actions utilities, and the `astrid`, `astrid-build`,
`astrid-daemon`, and `astrid-emit` binaries built from one exact Astrid commit.

It is not an Astrid runtime release, release channel, product distro, or a
replacement for the authenticated release OCI images under `container/amd64`
and `container/arm64`.

The workflow publishes one amd64 image tag per protected `main` commit:

```text
ghcr.io/astrid-runtime/astrid-ci:<40-character-source-commit>
```

Consumers must resolve that tag once and pin the resulting manifest digest:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/astrid-runtime/astrid-ci@sha256:<manifest-digest>
```

Do not consume a moving tag. The OCI revision label, published provenance, and
the pinned digest together bind the toolchain to the source commit that built
the Astrid binaries.
