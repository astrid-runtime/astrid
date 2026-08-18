# Generated TUF metadata

The repository source does not contain trust-role metadata.  `generate` emits
an unsigned `_tuf-input/` tree; the approved `sign-pages` step emits the
deployable roles under `v1/` as `<version>.root.json`,
`<version>.snapshot.json`, `<version>.targets.json`, and `timestamp.json`.
Those files must contain real threshold signatures.  Do not hand-edit or
publish an unsigned trust role.  `sign-pages` runs the bundled
`astrid-capsule-index-tuf` verifier and refuses to report deployment readiness
unless expiry, rollback/reference consistency, targets, and signatures pass.
