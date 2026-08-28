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
archive_blake3=$(python3 -c \
  'import json; print(json.load(open("dist/oci-amd64/release-receipt.json"))["archive-blake3"])')
release_manifest_sha256=$(python3 -c \
  'import json; print(json.load(open("dist/oci-amd64/release-receipt.json"))["release-manifest-sha256"])')
release_receipt_sha256=$(sha256sum dist/oci-amd64/release-receipt.json | cut -d ' ' -f 1)

docker build \
  --platform linux/amd64 \
  --build-arg ASTRID_VERSION=0.10.4 \
  --build-arg ASTRID_SOURCE_COMMIT=b6bf5d1d579915eb5d3c944857d84e62a4fcc878 \
  --build-arg ASTRID_ARCHIVE_SHA256="$archive_sha256" \
  --build-arg ASTRID_ARCHIVE_BLAKE3="$archive_blake3" \
  --build-arg ASTRID_RELEASE_MANIFEST_SHA256="$release_manifest_sha256" \
  --build-arg ASTRID_RELEASE_RECEIPT_SHA256="$release_receipt_sha256" \
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

The image embeds the release receipt derived from the verified signed release
manifest and archive. It checks the receipt SHA-256 and every identity field
(repository, tag, source commit, target, archive name, archive SHA-256, archive
BLAKE3, manifest SHA-256, and release-workflow identity) during the build.
Those values are repeated as immutable OCI labels, so an image digest cannot be
detached from the exact signed release/source provenance that was tested.

## Run

Astrid Runtime intentionally has no default distro. Mount an operator-selected
signed `.shuttle`, pin its exact SHA-256, and provide writable state and
workspace mounts. A new named state volume inherits the image's UID/GID
ownership. A bind-mounted workspace must be prepared for UID/GID `65532`
(or its user-namespace mapping) because Astrid creates and secures workspace
state there:

```sh
distro_sha256=$(sha256sum ./distro.shuttle | cut -d ' ' -f 1)
mkdir -p ./workspace
sudo chown 65532:65532 ./workspace

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
owned by UID/GID `65532`, not only world-writable: Astrid deliberately applies
owner-only permissions to its state root. Container arguments are restricted
to verbosity and the three bounded daemon concurrency controls. In particular,
callers cannot enable ephemeral mode or replace the image-owned
workspace/session identity.
The entrypoint also rejects inherited `ASTRID_SANDBOX_POLICY` and
`ASTRID_ALLOW_LOCAL_IPS` overrides before initialization; the neutral hosted
profile does not inherit an operator's security-policy bypasses.

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

## Hosted profile evidence

The amd64 target is one bounded hosted profile: a signed Astrid release runs as
the non-root PID 1 daemon on a Linux container runtime. The profile owns fixed
`/var/lib/astrid` state and `/workspace` paths; callers cannot replace those
identities with environment variables or daemon arguments. The checks require a
read-only root, all capabilities dropped, `no-new-privileges`, no
host or container-engine socket, and a writable state/workspace mount owned by
UID/GID `65532`.

The OCI harness starts the real daemon, waits for its readiness sentinel, and
directly checks that the daemon executable is PID 1 as UID/GID `65532` in
`/workspace`. It provisions agent and genuinely restricted principals, asserts
exact self-scoped agent-list responses, uses the release CLI to write distinct
direct owner-state artifacts, and removes the first container before opening
the same state/workspace mounts in a fresh container. It then verifies those
state artifacts, the workspace marker, principal identities, and authenticated
control path across that fresh reopen and rejects cross-principal
modification. This is persistence evidence on deliberately shared mounts; it
does not execute or claim cross-principal workspace, mount, or secret-read
isolation. The harness also rejects absent, externally mismatched,
signed-but-tampered, and path-swapped shuttles before the daemon is reached. A
host Linux UID/path alone cannot mint a new Astrid principal or grant, but a
reader of the state mount can wield existing principal keys.

The pinned v0.10.4 baseline has two explicit custody and evidence limits. The
runtime signing key and all principal-owned files live under the same
UID/GID `65532` state mount: the OS does not give each Astrid principal a
separate UID, and a caller with root access, the container runtime's host
access, or read/write access to that state mount can wield or alter existing
principal-owned bytes. Minting a new Astrid principal or grant still requires
an existing credential or authorized control path; this profile does not claim
OS-level per-principal key custody or protection from state-mount custody. In
addition, v0.10.4's `astrid audit` surface is a deferred stub and exposes no
supported chain/head or principal-scoped query. The harness records that
surface as an explicit
non-gating blocked audit probe rather than substituting a global count or
mutating the pinned release. It therefore does not claim audit continuity or
hosted-profile qualification; issue #1708 remains open until a supported
immutable release supplies that evidence.

This is not a Linux application Realm, a graphics or driver Realm, arm64
parity, a hostless OS, or a claim that the Linux kernel is untrusted. It is
only the signed amd64 hosted profile described above.

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

One BuildKit invocation emits the exact OCI tar. CI loads that same archive,
then requires the loaded repository digest to equal its sole OCI manifest
digest. The restricted runtime test, vulnerability scan, and SBOM therefore all
apply to the image represented by the unchanged export. A binding receipt
records the archive, manifest, config, and layer digests, and the workflow
verifies both that receipt and a separately recorded archive SHA-256 again
after the tests and scans. A signed evidence checksum manifest covers the
archive, binding receipt, SBOM, and authenticated release receipt. The separate
Sigstore archive signature and provenance attestation bind the bytes of that
specific `.oci.tar`; verify the evidence-manifest signature before trusting its
metadata, and verify the archive signature against the downloaded tar rather
than a separately re-exported image. BuildKit export metadata can vary between
runs, so this target does not claim byte-for-byte reproducible OCI tar
archives. That per-export property is also why this first target retains only
short-lived workflow artifacts and does not publish mutable registry tags.

The restricted-runtime CI probe builds the compatible AOS CLI uplink from an
exact `unicity-aos/aos-ce` source commit, seals it into a test-only signed
distro, and requires both the real release daemon readiness sentinel and an
authenticated `astrid status` round trip. The fixture is test input only; it is
never copied into the distro-neutral runtime image.
