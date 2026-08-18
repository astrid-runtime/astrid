# Namespace claims

Namespace claims bind a canonical lower-case namespace to an owner, source
repository IDs, and an authority marker where required.  Ownership transfers
must use the typed, hash-chained event envelope and the three-authority review
described in `OPERATIONS.md`; a normal publication PR cannot silently transfer
ownership.
