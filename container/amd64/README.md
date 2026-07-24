# Astrid Runtime OCI image (Linux amd64)

This image is a distro-neutral package of Astrid's authenticated
`x86_64-unknown-linux-gnu` release archive. The image build does not compile
Astrid and does not select or bundle an AOS/product distro.

## Build

Choose an immutable Astrid release and its exact tagged source commit:

```sh
python3 scripts/oci_release.py fetch \
  --version 0.10.4 \
  --source-commit b6bf5d1d579915eb5d3c944857d84e62a4fcc878 \
  --output dist/oci-amd64

archive_sha256=$(python3 -c \
  'import json; print(json.load(open("dist/oci-amd64/release-receipt.json"))["archive-sha256"])')

docker build \
  --platform linux/amd64 \
  --build-arg ASTRID_VERSION=0.10.4 \
  --build-arg ASTRID_SOURCE_COMMIT=b6bf5d1d579915eb5d3c944857d84e62a4fcc878 \
  --build-arg ASTRID_ARCHIVE_SHA256="$archive_sha256" \
  --tag astrid-runtime:0.10.4-amd64 \
  --file container/amd64/Dockerfile .
```

The fetch step authenticates the exact release manifest and archive against
Astrid's `release.yml` identity at `refs/tags/v<version>`, verifies the manifest
identity and source commit, and checks the archive's signed size, SHA-256, and
BLAKE3 values. It refuses drafts, duplicate/missing assets, symbolic links, and
archives with unsafe structure. The Dockerfile only unpacks those verified
bytes into a package-free, digest-pinned Ubuntu 24.04 amd64 base. Ubuntu 24.04
is the compatibility floor for the currently published `v0.10.4` archive
(glibc 2.39); releases produced after Astrid's glibc-baseline gate also run
there.

## Run

Astrid Runtime intentionally has no default distro. Mount an operator-selected
signed `.shuttle`, pin its exact SHA-256, and provide writable state and
workspace mounts:

```sh
distro_sha256=$(sha256sum ./distro.shuttle | cut -d ' ' -f 1)

docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,uid=65532,gid=65532 \
  --mount type=bind,src="$PWD/distro.shuttle",dst=/run/astrid/distro.shuttle,readonly \
  --mount type=volume,src=astrid-state,dst=/var/lib/astrid \
  --mount type=bind,src="$PWD/workspace",dst=/workspace \
  --env ASTRID_DISTRO_SHA256="$distro_sha256" \
  astrid-runtime:0.10.4-amd64
```

The entrypoint verifies the external SHA-256 pin, then runs
`astrid init --offline --yes` without either unsigned or key-rotation
overrides. It first copies the mounted distro into an exclusively-created
private file, re-verifies the staged bytes against the operator's pin, and
passes only that private path to Astrid. A concurrent rename or symlink swap
of the mounted pathname therefore cannot change the bytes Astrid installs.
Astrid verifies the shuttle's internal signature, manifest binding, and
capsule hashes before the daemon starts. A missing, unsigned, tampered, or
unexpected distro fails closed.

The daemon remains PID 1 in persistent foreground mode and routes ANSI-free
logs to standard error. The image runs as UID/GID `65532`, declares no ports,
does not need a Docker socket, and is intended to run with all Linux
capabilities dropped. Bind-mounted state and workspace directories must be
writable by UID/GID `65532`. Container arguments are restricted to verbosity
and the three bounded daemon concurrency controls. In particular, callers
cannot enable ephemeral mode or replace the image-owned workspace/session
identity.

The neutral target does not install `bwrap` or a product shell/tool stack.
Distros that request native subprocess hosting therefore fail closed at
Astrid's required sandbox gate. A product-owned image may add those audited
dependencies and platform configuration without weakening this base target.
A downstream image may also `COPY` its own signed shuttle and set
`ASTRID_DISTRO_PATH` plus its exact `ASTRID_DISTRO_SHA256`; Astrid's image
itself never selects that artifact.

This target does not publish `latest`, channel, or canonical multi-architecture
tags. ARM64 is a separate target and must be validated independently before a
multi-architecture index can be assembled.

## Build evidence and signatures

The workflow's OIDC signing job runs only for a manual dispatch of protected
`main`, requires the repository variable `ASTRID_OCI_SIGNING_ENABLED=true`,
and is assigned to the protected `oci-signing` environment. The variable is
absent by default, so merging this target cannot mint signed artifacts before
the repository protection is configured. Repository operators must keep the
environment restricted with required reviewers and a protected-branch
deployment rule, then explicitly enable the variable. Pull requests, tags,
unprotected branches, disabled repositories, and other workflow refs can build
and inspect evidence but cannot request an OIDC signing token.

The exported OCI tar is an exact per-workflow artifact. Its Sigstore blob
signature and provenance attestation bind the bytes of that specific export;
verify them against the downloaded `.oci.tar`, not against a separately
re-exported image. BuildKit export metadata can vary between runs, so this
target does not claim byte-for-byte reproducible OCI tar archives. That
per-export property is also why this first target retains only short-lived
workflow artifacts and does not publish mutable registry tags.

The restricted-runtime CI probe builds the compatible AOS CLI uplink from an
exact `unicity-aos/aos-ce` source commit, seals it into a test-only signed
distro, and requires both the real release daemon readiness sentinel and an
authenticated `astrid status` round trip. The fixture is test input only; it is
never copied into the distro-neutral runtime image.
