# Historical format fixture

`principal-store-pre-fleet-v1.txt` is byte-identical to
`crates/astrid-storage/formats/principal-store-v1.txt` at the parent of
`d6126c65e1a1bdbf8432daa375da339e0aa148e5`.

SHA-256: `8b4645985d45b15358f82b6a4ba155b496531b2c74edf668c4e6ff99b3950f9f`.

The full-open regression independently checks its canonical object identity
against `PRE_FLEET_OWNER_FORMAT_SPEC_ID`. It creates a real active catalogue
and system-owned KV root with the current engine, then exercises migration and
reopening. This is a format-transition regression, not an installation performed
by a historical executable or a public-package upgrade certification.
