# Release versioning

Starting with the September 2026 release, Astrid, AOS, and Oracle use
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

All three products target `2026.9.0` for this release. Git tags retain their
existing repository conventions: Astrid and Oracle use `v2026.9.0`; AOS uses
`2026.9.0`.

Previously published versions are immutable. AOS `2026.1.x` was not a
calendar-month series; do not reinterpret it as January. Astrid `0.10.x` and
Oracle `0.2.x` likewise retain their historical identities. The unreleased
Oracle `0.3.0` preparation is superseded by `2026.9.0`, not an additional
published release.

Changelogs describe the net user-facing change from the preceding published
release. Fold repairs to unreleased implementations into the final behavior;
keep historical published sections and consequential migration limitations.

