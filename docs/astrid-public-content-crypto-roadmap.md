# Future Public Content Crypto Stack

Status: research roadmap only. None of this construction is permitted in the
private principal store.

## Boundary

The private store follows the Tahoe rule: content identity is never read
authority. Its equality, erasure, and principal-isolation guarantees must not
be weakened to obtain encrypted deduplication.

A future deliberately public/shared content domain may choose a different
trade:

- content hash may act as a read capability inside that domain only;
- content equality is intentionally visible to participants;
- confirmation attacks on guessable content are an explicit concession; and
- logical billing and guest admission remain independent of cross-domain
  physical equality.

## Assembled construction shelf

The candidate stack is:

1. a reserved chunk-profile algorithm tag;
2. the keyed content-defined chunking construction in Truong et al.,
   [*Breaking and Fixing Content-Defined Chunking*](https://eprint.iacr.org/2025/558);
3. a reviewed message-locked/convergent-encryption construction from the
   established literature;
4. power-of-two or otherwise frozen padded size buckets to reduce length
   leakage;
5. server-side recomputation of every admitted identity and encoding; and
6. extraction/expansion appropriate for full-entropy content-derived key
   material.

Password stretching such as PBKDF2 is not a substitute for key derivation from
full-entropy hash material. It adds per-object cost without making predictable
content harder to guess. The exact KDF, authenticated-encryption scheme,
padding grammar, chunker parameters, and key-separation labels remain a future
cryptographic design review.

## Non-negotiable rules

- A client-supplied content name is never trusted; the service recomputes it
  from admitted bytes.
- Deduplication cannot change guest-visible admission, logical price, or result
  metadata based on another trust domain's content.
- Padding mitigates length leakage but does not hide content equality.
- Erasure for shared ciphertext removes roots and uniquely owned
  representations; hard per-principal erasure requires a separate encryption
  domain and gives up cross-domain deduplication.
- No mechanism from this page enters private principal storage by convenience
  or “temporary” feature flag.

## Activation gate

Implementation waits for a complete threat model, cryptographic review,
patent/license review at the time of selection, canonical test vectors,
cross-implementation decoding, confirmation-attack analysis, migration and
key-rotation design, and measured benefit on the intended public corpus.
