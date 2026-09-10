# Astrid 2026.9.1 hotfix

Patch release following published v2026.9.0. See the corresponding
[Keep a Changelog entry](../CHANGELOG.md#202691---2026-09-10).

This release repairs initialization, durable capsule preservation, daemon
retirement, and synchronous subprocess input. The volume format is unchanged.
Existing v2026.9.0 tags and release artifacts remain immutable. Preservation
fixes do not recreate capsule data already lost by an earlier run; reinstall
affected capsules from their original trusted source if necessary.

The source changes were exercised together through signed disposable AOS/Oracle
packages: credential-free Codex, Claude, and Grok setup, real MCP capsule calls,
an authored capsule invoking a native adapter, and stop/restart with repeated
calls. Published v0.10.4 migration and a macOS FSKit read/write/sync/unmount
round-trip also passed. Private rehearsal signatures are not production signatures.

Production release execution must pass GNU/musl builds and archive validation,
Darwin signing/notarization, supervised verification of the exact Darwin archive,
and authenticated publication. Publish and promote Astrid first; downstream AOS
must bind the resulting production metadata and packaged runtime bytes before
its release. Oracle follows the compatible AOS patch.

All 32 workspace package versions advance to 2026.9.1. Third-party dependency
versions and sources are unchanged from v2026.9.0. Windows remains outside this
release's published archive inventory.
