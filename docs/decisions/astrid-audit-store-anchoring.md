# Audit Chain Anchoring into Principal Storage

Status: security design contract. The audit chain remains an independent
append-only security record.

## Non-circular boundary

The audit chain must never live only inside the principal store. A store
corruption investigation needs an independently readable record of operations
that affected that store. Conversely, the audit log should benefit from the
store's export, attestation, and archival machinery without becoming dependent
on the engine it audits.

Astrid therefore anchors rather than absorbs:

```text
independent signed audit log
    -> signed chain-head statement
    -> immutable Evidence object
    -> explicit system/principal custody root
```

## Anchor statement

Each anchor Evidence object binds at least:

- audit-chain identity and format;
- principal or system audit domain;
- signed head sequence and hash;
- signing algorithm and key identity;
- previous anchor ObjectId when present;
- current principal-root or corpus-root set selected by policy;
- store-format specification ObjectId;
- authority-policy epoch; and
- the anchor cadence/policy identity.

The statement is canonical and signed before admission. The principal store
recomputes its ObjectId and publishes it through the ordinary root-CAS path.
An anchor identity grants no audit or state authority.

## Ordering and failure

The independent audit append is authoritative first. Anchoring follows.

- A crash after audit append but before store publication creates an
  observable anchor lag, not a missing audit event.
- A store failure leaves the append-only audit log readable.
- An audit-log failure prevents claiming a new anchor; the store cannot
  fabricate continuity.
- A root conflict retries from the new root while retaining the same signed
  chain-head statement.

The operator configures cadence by event count, elapsed policy interval,
security boundary, or explicit ceremony. Release promotion, key rotation,
re-attestation, GC commit, and recovery are mandatory anchor candidates.

## Verification and export

Verification reads the independent log to the anchored sequence, recomputes
its head, checks the signature and prior-anchor chain, then verifies the
Evidence object and custody root. Archival export includes selected anchors and
their owning closure, but importing them does not import signing authority.

This gives the audit record store-backed archaeology while preserving the
independent witness required to diagnose store corruption.
