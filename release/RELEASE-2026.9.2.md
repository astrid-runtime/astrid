# Astrid 2026.9.2

Small patch-series release following v2026.9.1. Existing releases and tags remain
immutable. See CHANGELOG.md for the net user-facing change.

## Scope

- Add an opt-in authenticated MCP Streamable HTTP endpoint, alongside stdio.
- Reuse existing broker execution, principal authority, and consent handling.
- Preserve GNU, musl, and Darwin archive scope. No Windows archive expansion.
- Advance workspace packages and their internal pins together; retain the
  dependencies selected by the HTTP feature without additional dependency updates.

## Compatibility

HTTP does not start automatically. It requires an explicitly selected principal,
loopback listener, and private bearer file. Windows credential-file ACL validation
is not supported by this endpoint. Existing stdio launchers remain supported.

Codex desktop did not refresh the same conversation's named-tool catalog after
a live tool change in the September 12 trial. New sessions or a connection toggle
remain necessary in that tested client; this release does not claim to fix it.

## Verification and publication boundary

HTTP feature tests and actual installed-capsule invocation are supporting
evidence, not a completed release-package rehearsal. Before publication, exercise
the selected package through installation and a real plugin tool invocation,
and verify the release-version CI results. Production signing and native macOS
certification must pass the existing release workflow.

No future artifact digest is promised before those artifacts are built. No tag,
publication, channel promotion, or local plugin replacement is authorized by
merging this preparation alone.

Downstream distributions own their runtime pins and versions. An AOS runtime-pin
update can consume the published Astrid patch; an Oracle release is not required
solely because Astrid adds an optional transport.
