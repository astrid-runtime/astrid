# Legacy audit compatibility fixture

`surrealkv-0.21.3-audit.json` was generated with SurrealKV 0.21.3 through
`TreeBuilder::new().with_path(path).build()`, a public transaction writing
`audit:entries\0fixture-entry` to `opaque-legacy-audit-entry`, commit, and tree close.
Its files include an old-format SST and manifest; they are not release artifacts.

The payload is deliberately opaque. The regression proves blind-MOVE byte
preservation and capacity refusal, not audit-signature or chain recertification.
