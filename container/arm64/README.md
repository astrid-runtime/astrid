# Astrid Runtime OCI image (Linux arm64)

This image is the native ARM64 sibling of Astrid's distro-neutral amd64 OCI
target. It packages the authenticated `aarch64-unknown-linux-gnu` archive from
an exact immutable Astrid release; it does not rebuild Astrid and does not
select or bundle an AOS/product distro.

## Build

Choose an immutable Astrid release and the exact source commit bound by its
signed release manifest:

```sh
python3 scripts/oci_release.py fetch \
  --version 0.10.4 \
  --source-commit b6bf5d1d579915eb5d3c944857d84e62a4fcc878 \
  --target aarch64-unknown-linux-gnu \
  --output dist/oci-arm64

archive_sha256=$(python3 -c \
  'import json; print(json.load(open("dist/oci-arm64/release-receipt.json"))["archive-sha256"])')

docker build \
  --platform linux/arm64 \
  --build-arg ASTRID_VERSION=0.10.4 \
  --build-arg ASTRID_SOURCE_COMMIT=b6bf5d1d579915eb5d3c944857d84e62a4fcc878 \
  --build-arg ASTRID_ARCHIVE_SHA256="$archive_sha256" \
  --tag astrid-runtime:0.10.4-arm64 \
  --file container/arm64/Dockerfile .
```

The fetch step authenticates the exact release manifest and ARM64 archive
against Astrid's `release.yml` identity at `refs/tags/v<version>`, validates
the manifest identity and source commit, and verifies the archive's signed
size, SHA-256, BLAKE3, Sigstore bundle, and canonical layout. It refuses
drafts, mutable releases, duplicate or missing assets, unsafe redirects,
symbolic links, and unsafe archive members.

The Dockerfile only unpacks those verified bytes into the platform-specific
Linux ARM64 manifest of Ubuntu 24.04, pinned by digest. The ARM64 workflow runs
on `ubuntu-24.04-arm`, asserts both host and Docker daemon architecture, runs
the authenticated native `astrid-build`, and never installs an emulator or
binary-format translation handler.

## Run

Astrid Runtime intentionally has no default distro. Mount an
operator-selected signed `.shuttle`, pin its exact SHA-256, and provide
writable state and workspace mounts:

```sh
distro_sha256=$(sha256sum ./distro.shuttle | cut -d ' ' -f 1)

docker run --rm \
  --platform linux/arm64 \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,uid=65532,gid=65532 \
  --mount type=bind,src="$PWD/distro.shuttle",dst=/run/astrid/distro.shuttle,readonly \
  --mount type=volume,src=astrid-state,dst=/var/lib/astrid \
  --mount type=bind,src="$PWD/workspace",dst=/workspace \
  --env ASTRID_DISTRO_SHA256="$distro_sha256" \
  astrid-runtime:0.10.4-arm64
```

The entrypoint is shared with the reviewed amd64 target. It copies the mounted
distro into a private, exclusively created staging path, re-verifies the exact
staged bytes against the operator's pin, and passes only that path to
`astrid init --offline --yes`. Astrid then verifies the shuttle's internal
signature, manifest binding, and capsule hashes. Concurrent replacement of the
operator mount cannot change the bytes Astrid reads, and missing, unsigned,
tampered, or unexpectedly pinned distros fail closed. A downstream product
image may preseed its own signed shuttle and set `ASTRID_DISTRO_PATH` plus its
exact `ASTRID_DISTRO_SHA256`; this neutral image never selects that artifact.

The persistent daemon remains PID 1 and routes ANSI-free logs to standard
error. The image runs as UID/GID `65532`, exposes no ports, needs neither
privileged mode nor a Docker socket, and is tested with a read-only root,
all Linux capabilities dropped, and `no-new-privileges`. State and workspace
mounts must be writable by UID/GID `65532`.

Container arguments are restricted to verbosity and three bounded daemon
concurrency controls. Callers cannot enable ephemeral mode, replace the
image-owned workspace/session identity, or pass a newly added daemon flag
without an explicit entrypoint review. The neutral target deliberately
contains neither `bwrap` nor a product shell/tool stack, so native subprocess
hosting fails closed unless a product-owned image adds and audits those
dependencies.

## Build evidence and signatures

The native workflow creates one OCI archive, imports that exact archive into
the local Docker engine, and binds its sole `linux/arm64` manifest to the
loaded image's content-addressed `name@sha256:...` repository digest. The
binding verifier requires an exact platform object with no ARM variant and
authenticates the index, manifest, config, every layer, and the archive's exact
file inventory. The workflow then:

- authenticates the exact ARM64 release bytes and source commit;
- exercises only the digest-bound image's real release daemon as PID 1 under
  the documented runtime restrictions, requiring its readiness sentinel and
  an authenticated `astrid status` round trip;
- scans and inventories that same digest-bound image;
- re-verifies the archive checksum and regenerates the binding after all
  consumers finish; and
- emits a checksum manifest covering the exact tar, binding receipt, ARM64 SPDX
  SBOM, and authenticated Astrid release receipt.

There is no second container build or export between runtime verification and
signing. The tested, scanned, and inventoried image is addressed by the
manifest digest proven to be the sole manifest in the same tar that the signing
job re-hashes, signs, and attests.

OIDC signing runs only for manual dispatch of protected `main`, requires the
protected `oci-signing` environment, and additionally requires the
`ASTRID_OCI_SIGNING_ENABLED=true` repository variable. That variable is absent
by default. Operators must configure required reviewers and a protected-main
deployment policy before enabling it. Pull requests, tags, unprotected refs,
and disabled repositories cannot request the signing token.

The signing job verifies both the downloaded per-export digest and the complete
evidence manifest. It creates Sigstore blob signatures for the exact OCI tar
and the evidence manifest, then attests the tar as the provenance subject.
BuildKit export metadata can vary, so signatures and attestations apply to the
downloaded export rather than a separately re-exported image; this target does
not claim byte-for-byte reproducibility.

This change uploads only short-lived workflow evidence. It logs into no
registry and publishes no mutable channel, canonical, or multi-architecture
tag. Combining independently verified amd64 and ARM64 outputs is separate
work.
