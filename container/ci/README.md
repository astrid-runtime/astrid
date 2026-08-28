# Astrid CI toolchain image

This image is a CI-only build environment for Astrid capsule repositories. It
contains Rust 1.95.0, the `wasm32-unknown-unknown` target, common GitHub Actions
utilities, and the `astrid`, `astrid-build`, `astrid-daemon`, and `astrid-emit`
binaries from one authenticated stable Astrid release.

It is not an Astrid runtime release image, release channel, product distro, or
a replacement for the authenticated release OCI images under `container/amd64`
and `container/arm64`.

## Publication and tags

Pull requests build and test the image without registry write permission. A
successful authenticated stable `vX.Y.Z` release causes the image workflow to
publish the tested amd64 image under three exact tags:

```text
ghcr.io/astrid-runtime/astrid-ci:X.Y.Z
ghcr.io/astrid-runtime/astrid-ci:X.Y.Z-rust1.95.0-bookworm
ghcr.io/astrid-runtime/astrid-ci:sha-<40-character-source-commit>
```

The workflow does not publish `latest`, major, minor, or other moving aliases.
It refuses to replace an existing release tag that resolves to different image
content. A manual dispatch exists only to recover or bootstrap an already
published immutable stable release; it reauthenticates both the release and its
source commit before building.

## Consumption

Select the release or toolchain-variant tag, resolve it once, and pin the
resulting manifest digest:

```bash
docker manifest inspect --verbose \
  ghcr.io/astrid-runtime/astrid-ci:0.10.4 \
  | jq -r '.Descriptor.digest'
```

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/astrid-runtime/astrid-ci:0.10.4@sha256:<manifest-digest>
```

Do not consume a tag without its digest. The OCI version and revision labels,
published provenance, and pinned digest bind the toolchain to the release and
source commit that built the Astrid binaries.

GHCR package visibility and downstream repository access are configured by the
repository owners. This workflow deliberately does not change package
visibility. A private package requires `read:packages` credentials or explicit
GitHub Actions access for the consuming repository.
