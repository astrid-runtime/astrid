# Self-update security

`astrid update` applies an in-place update only when the running binary is
self-managed. Homebrew and Cargo installations remain owned by their package
managers and receive the corresponding upgrade command instead.

For a self-managed install, the updater requires all of the following for the
exact platform archive:

1. A non-expired `stable`, `dev`, or `nightly` pointer signed by Astrid's exact
   `promote-channel.yml` workflow on `main`, with a generation that does not
   roll back or equivocate with accepted local state.
2. An immutable release manifest matching the pointer's BLAKE3 digest and
   signed by the exact release workflow at the selected tag.
3. One archive asset with the canonical version and target name.
4. One `<archive>.sigstore.json` bundle whose certificate identity is exactly
   Astrid's `release.yml` workflow at that version tag and whose issuer is
   GitHub Actions.
5. Fresh Sigstore public-good trust material refreshed through TUF from the
   pinned verifier's embedded production root.
6. One strict lowercase BLAKE3 entry for the archive in `BLAKE3SUMS.txt` that
   also equals the digest in the signed channel and release manifest.

Publisher authentication happens before the independent BLAKE3 integrity
check. The archive is not written, extracted, or installed until both stages
have succeeded. Missing or duplicated assets, malformed evidence, identity or
issuer mismatches, trust refresh failures, and checksum mismatches all fail
closed.

Release publishing has a differential gate before the GitHub release is
created. Cosign first verifies every generated asset against its bundle. The
updater's native production verifier then independently authenticates every
generated archive and bundle pair with the same exact identity, issuer, and
live TUF trust path used by `astrid update`; either verifier rejecting an
archive stops the release.

`--source` and `ASTRID_UPDATE_REPO` can redirect channel and release discovery to a mirror
or test server, but cannot change the required Astrid publisher identity,
issuer, workflow, repository, or tag. `ASTRID_UPDATE_API` likewise changes only
the metadata API endpoint.

The release also publishes a signed SHA-256 compatibility manifest for package
managers and other downstream protocols. It is not accepted in place of the
BLAKE3 integrity manifest. GitHub build-provenance attestations are additional
evidence and are not the trust root used by the self-updater.

The channel guarantee starts with the first release that contains this updater
and the signed immutable release manifest. An older binary cannot retroactively
enforce either policy while downloading that first channel-aware release, so
users crossing that boundary must install through a package manager or
independently verify the published release evidence.
