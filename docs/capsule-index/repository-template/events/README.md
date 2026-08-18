# Signed event envelopes

Add `event-envelope-v1` JSON objects in chain order at the canonical path
`events/{sequence:020}-{event_digest_without_tag}.json`.  Sequence one has no
prior digest; each later envelope names the previous `event_digest`.  Revoke,
tombstone, and mirror operations are append-only bodies.  The pinned tool
rejects a filename that does not match the envelope's sequence and digest.
Never rewrite a historical event or use an unsigned label as lifecycle state.
