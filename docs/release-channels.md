# Astrid release channels

Astrid publishes immutable signed runtime releases, then advances one of three
signed pointers to those exact bytes:

- `stable` is the production channel. Promotion is deliberate, passes through
  the protected `astrid-channel-stable` GitHub environment, and rejects draft
  or prerelease releases.
- `dev` is the signed integration channel. Promotion passes through the
  protected `astrid-channel-dev` environment.
- `nightly` is the signed rolling channel. Promotion passes through the
  protected `astrid-channel-nightly` environment.

All three channels point only to an existing release whose manifest and every
platform archive were signed by Astrid's exact tag-bound release workflow. A
promotion does not rebuild, rename, or replace release archives. The build
train and channel promotion remain separate operations: this repository does
not currently cut a release or advance a channel merely because `main` moved.

No channel pointer is published by this change. Before the first promotion,
configure all three channel environments with a required human reviewer and
disable administrator bypass. Keep the existing `release` environment equally
protected. Add `ASTRID_RELEASE_ADMIN_TOKEN` to the `release` environment using
a fine-grained token scoped to this repository with Administration read/write;
it is used only to inspect and enable the immutable-release setting. The
workflow's scoped `GITHUB_TOKEN` retains ordinary Contents write access.

Run **Bootstrap mutable Astrid channels** from `main` exactly once before the
first release. It creates the three empty, published prerelease containers
`channel-stable`, `channel-dev`, and `channel-nightly`, verifies that they remain
mutable, and only then enables immutable releases for the repository. The
workflow is idempotent after later promotions, but it fails closed if a channel
container is missing after immutability has been enabled. Promotion never
creates a channel container.

The release workflow requires repository immutability, uploads all assets while
the release is a draft, disables file overwrite, and publishes only after the
complete signed asset set is present. A retry may resume only a complete,
never-published draft whose exact inventory, manifest, source and WIT commits,
checksums, and tag-bound Sigstore identities reauthenticate. Published,
incomplete, duplicate, empty, or unexpected assets fail closed. The first
eligible immutable release must contain the release manifest and channel-aware
updater; earlier releases cannot be promoted into this contract.

## Signed contract

Every release publishes `astrid-<version>-release.toml` and its Sigstore bundle.
The manifest binds the canonical version and tag, runtime and WIT source
commits, release-workflow identity, and the size, BLAKE3 digest, SHA-256 package
manager compatibility digest, and Sigstore bundle name for all four platform
archives.

Each channel is hosted at the GitHub release tag `channel-<channel>` and exposes
`channel.toml` plus `channel.toml.sigstore.json`. The pointer is signed only by:

```text
https://github.com/astrid-runtime/astrid/.github/workflows/promote-channel.yml@refs/heads/main
```

The pointer records a positive signed 64-bit generation, publication and expiry
timestamps, the immutable release-manifest BLAKE3 digest, the exact tag-bound
release-workflow identity, and all four archive identities and digests. Stable
pointers expire after 30 days, dev after 7 days, and nightly after 2 days.
Renewal is a new promotion with a higher generation, even if it keeps the same
release version.

The promotion workflow retains each generation as one immutable history archive
containing the pointer and bundle. It validates GitHub's paginated asset state,
removes interrupted non-uploaded asset records, rejects duplicate or empty
uploaded assets, and byte-compares a newly uploaded or reused history archive
before replacing the current files. A retry reuses and reauthenticates that
exact archive, so interruption after history or current-bundle upload is
recoverable. It snapshots and rechecks both current files before publication,
then publishes the bundle before replacing the pointer, so a reader racing
publication fails closed rather than accepting unsigned bytes.

## Client behavior

`astrid update` follows `stable`. Self-managed installations can select another
channel explicitly:

```text
astrid update --channel dev
astrid update --channel nightly
astrid update --channel stable --check
```

The updater authenticates, in order:

1. `channel.toml` against the exact promotion-workflow identity on `main`.
2. The immutable release manifest against the exact release workflow at the
   selected version tag.
3. The selected archive against the same tag-bound release identity.
4. The archive's BLAKE3 digest against both the immutable release manifest and
   `BLAKE3SUMS.txt`.

It stores the accepted pointer and bundle under Astrid's runtime state. A lower
generation is rejected. Different bytes at an already accepted generation are
rejected as equivocation. An expired pointer is rejected. A deliberate rollback
therefore advances the generation while pointing to an older immutable release;
self-managed clients follow that signed rollback.

Homebrew and Cargo installations remain controlled by their package managers
and follow stable. They do not silently switch to dev or nightly; use a
self-managed Astrid installation for those channels. Immutable release creation
does not notify the Homebrew tap; only successful stable promotion does. A
signed stable rollback is applied with an exact Cargo reinstall or a Homebrew
formula reinstall because ordinary package-manager upgrade commands do not
downgrade.

`--source`, `ASTRID_UPDATE_REPO`, and `ASTRID_UPDATE_API` can select a mirror or
test endpoint, but they cannot alter either accepted workflow identity, issuer,
repository, release tag, channel name, or signed digest.

Product distributions such as Unicity AOS pin an immutable Astrid release
manifest and exact runtime source commit. They do not resolve Astrid through a
moving runtime channel while composing a product release.
