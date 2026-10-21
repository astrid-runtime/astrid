# Astrid 2026.9.0 release

This release advances published `v0.10.4` to intended tag `v2026.9.0`.
The workspace/package bump already landed in PR #1845; this release PR
consolidates its documentation with all subsequent landed release work.
Do not bump it again merely to create a version-file diff.

## Contents

- [Curated Keep a Changelog entry](../CHANGELOG.md#202690---2026-09-08).
- [Complete Cargo.lock version changes](DEPENDENCIES-2026.9.0.md), including
  direct, transitive, test, workspace and platform-specific packages.
- [Versioning convention](VERSIONING.md).
- [Upgrade guidance and platform limitations](UPGRADING-2026.9.0.md).

The inventory compares `v0.10.4` with landed runtime commit
`7e7d3b1548ce01799302742527f07314f61e4635`. This PR changes documentation and
the inventory generator, not runtime dependency resolution. Regenerate with
`python3 scripts/release_dependency_changes.py --base v0.10.4 --head HEAD`
if Cargo.lock changes before the release.

## Release execution boundary

The intended release order is Astrid, AOS, then Oracle, all 2026.9.0. AOS's
production runtime metadata and published-crate pins must be completed using
the actual Astrid release; QA identity/digests cannot substitute for them.
Production signing, notarization and actual artifact verification happen in
the separately authorized release workflow. Failure blocks affected publication
or downstream consumption. This PR does not authorize tags or publication.

Final checks: required CI, no unrolled fragments, coherent 2026.9.0 workspace
versions, preserved published changelog entries, and reviewed upgrade notes.
