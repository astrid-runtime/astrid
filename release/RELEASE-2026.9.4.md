# Astrid 2026.9.4

Patch release following v2026.9.3. Existing tags and published artifacts remain
immutable. This preparation must include the merged configuration-retention fix
before it is eligible for release.

## Scope

- Preserve configured capsule values when initialization reapplies distribution
  defaults. Explicit operator input still updates configuration.
- Seed missing values through the daemon's typed, authorized conditional write
  operation, preserving existing agent and shared configuration of the same kind.
- Serialize concurrent default writes. If an install environment transaction is
  unresolved, return an explicit retry error rather than treating staged values
  as committed configuration. Reject empty secrets consistently.
- Keep the release matrix unchanged: GNU and musl Linux on x86_64 and ARM64,
  plus Intel and Apple Silicon macOS. Windows release archives remain out.

## Compatibility

Use the matching CLI and daemon from the release. Older daemons do not implement
the new conditional-default operation and reject it; the CLI must not silently
fall back to overwriting configured values.

## Verification and publication boundary

The source-candidate rehearsal exercised AOS retained-home initialization,
explicit overrides, restart, and volume-only shutdown using matching GNU CLI
and daemon binaries. These results do not certify future published artifacts.
The final release candidate must pass its own CI. AOS must be rebound to and
checked against the published patch before its release.

Production signing, notarization, canonical FSKit certification, archive checks,
and dev/stable channel promotions remain separately executed release steps.
No numerical digest is claimed for an artifact that has not yet been built.
Merging release preparation does not itself authorize tagging or publication.
