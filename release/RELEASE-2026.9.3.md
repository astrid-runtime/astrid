# Astrid 2026.9.3

Patch release following v2026.9.2. Existing tags and release artifacts remain
immutable. The changelog records the net user-visible changes since that release.

## Scope

- Make capsule installation a bounded transaction: batch verified Distro
  members, publish installed state before returning, apply environment once, and
  activate each installed capsule exactly once.
- Add user-scoped principal discovery and explicit ownership repair, invitation,
  assignment, transfer, and deletion boundaries without granting acting
  authority from discovery alone.
- Bind approval replies to their authenticated requesting connection, persist
  remembered command consent across restarts, and add opt-in private secret
  elicitation for enrolled native responders.
- Confirm native projection unmount before lease teardown and preserve the
  existing macOS FSKit and Linux FUSE storage contracts.
- Retain authenticated MCP Streamable HTTP and update the locked TLS dependency
  for RUSTSEC-2026-0285.
- Preserve the existing release matrix: GNU Linux and musl Linux on x86_64 and
  ARM64, plus Intel and Apple Silicon macOS. Windows archives remain out.

## Compatibility

Local single-user installations can discover and claim historical unowned
principals through the authenticated local-operator path. Hosted deployments do
not infer human ownership from a shared home; they must use explicit user,
fleet, invitation, and device delegation flows.

The capsule-install lifecycle changes do not add a guest-visible "final start"
signal because ordinary daemon-owned installs now have one stable activation.
Workspace installs retain their existing explicit live-load nudge.

## Verification and publication boundary

The exact release candidate must pass the repository CI matrix and the
downstream AOS clean-install and published-upgrade journeys before a tag is
authorized. The Codewall staging enrolment retest is tracked separately and
must not be represented as complete until one fresh token succeeds against the
landed runtime.

Production signing, notarization, FSKit certification, release artifact checks,
and channel promotion remain release-workflow evidence. No future artifact
digest is claimed before those artifacts are built.

Merging this preparation does not itself authorize a tag, GitHub release,
publication, promotion, or mutation of a live user installation.
