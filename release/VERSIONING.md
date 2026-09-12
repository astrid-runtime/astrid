# Release versioning

Starting with the September 2026 release, Astrid uses
`YEAR.MONTH.PATCH` (calendar year, calendar month, patch number), called
CalSemVer here. The month is not zero-padded.

- The first release in a calendar-month series is `2026.9.0`.
- Follow-up fixes to that series are `2026.9.1`, `2026.9.2`, and so on.
- A new monthly series starts at patch zero, for example `2026.10.0`.
- A later maintenance release for an older series keeps that series' year/month
  and increments its patch; it does not rename an existing release.
- Version alignment does not replace explicit runtime compatibility requirements.
  Document breaking changes and migrations in release notes; the year component
  is not a traditional SemVer compatibility-major guarantee.

Astrid targets `2026.9.2` for this release, with Git tag `v2026.9.2`.
Downstream distributions and integrations own their version and tag policies.

Previously published versions are immutable. Astrid `0.10.x` retains its
historical identity; do not reinterpret it as a calendar-month series.

Changelogs describe the net user-facing change from the preceding published
release. Fold repairs to unreleased implementations into the final behavior;
keep historical published sections and consequential migration limitations.
