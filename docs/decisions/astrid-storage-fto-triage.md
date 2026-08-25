# Storage Patent and Freedom-to-Operate Triage

Status: engineering triage, not legal advice. This document maps storage
mechanisms to prior art, records selected design-arounds, and narrows the
questions that require counsel.

Patent status and expiry estimates must be independently verified before a
commercial shipping decision.

## Green: ancient or expired foundations

| Mechanism | Prior art | Engineering position |
| --- | --- | --- |
| Content-defined chunking | Rocksoft/Williams US 5,990,810; LBFS; rsync | Foundational prior art; core family expired or ancient |
| Content-addressed storage | Venti; Centera-era systems | Established foundation |
| Merkle trees | Merkle's original work and expired patent | Established foundation |
| Summary filters and locality-preserved dedup indexes | Data Domain literature, including FAST 2008/2009 | Cite the papers and implement the generic techniques |
| Convergent encryption core | Stac/Farsite-era work | Core patents reported expired; public-layer details still need review |
| B-trees, WAL, group commit, copy-on-write trees | Long-established database/filesystem practice | Established foundation |
| FastCDC and MinCDC algorithm families | Published literature and open-source implementations | Verify the exact implementation license before adoption |

## Yellow: live families avoided by architecture

### Client-side proof-of-ownership systems

Cloud deduplication proof-of-ownership systems address a client claiming a hash
without sending trustworthy bytes.

Astrid's kernel reads the bytes, recomputes identity, and byte-compares
candidate matches. There is no trusted client-supplied identity and no
proof-of-ownership exchange. This is both the stronger security architecture
and a materially different protocol shape.

This server-side recomputation rule is permanent. Performance work may cache a
verified record; it may never accept a guest's identity claim.

### Stream-multiplexed appliance layout

Later SISL patents describe scheduling multiple backup streams into appliance
segments. Astrid's locality begins with one engine's append order and
content/lineage relations. The persistent index may preserve locality but does
not adopt a multiplexed backup-stream protocol.

Design citations should use the earlier published dedup-index literature and
describe Astrid's actual mechanism.

## Amber: adjacent live families with selected design-arounds

### IBM similarity in the chunking scan

The US 9,891,857 / 9,892,048 / 9,892,127 family covers deriving similarity
digests and chunk boundaries through one rolling-hash scan.

Astrid's selected design is DF-1 below: ingest computes only chunking and
identity. Similarity is a later pinned transform over verified bytes during
scrub or compaction.

Counsel should compare the final DF-1 specification to the claims before that
feature ships.

### EMC stream-locality delta pairing

US 8,447,740 concerns selecting delta partners through stream locality.

Astrid uses explicit lineage first. A replacement object names its predecessor,
so the dominant near-version case requires no inferred stream partner.
Cross-name sketch similarity is a later supplement.

### Bitcasa convergent-encryption combination

US 9,253,166 combines convergent encryption, deduplication, caching, and a cloud
service. It is irrelevant to the private principal store.

It returns to the counsel list only if the future public/sync content layer
ships with message-locked encryption.

## Design-forward positions

### DF-1. Sketch at scrub

The write path computes no similarity metadata.

The Refinery's verified cold-path traversal runs a pinned bottom-k sketch
transform and emits Derived evidence:

- zero ingest-latency cost;
- no guest-visible similarity timing surface;
- deterministic, reproducible output;
- independent GC and eviction;
- reuse through Muninn; and
- no similarity computation in the chunking scan.

This is the chosen architecture even if patent review later finds a broader
safe boundary, because it keeps optional analysis off the write path.

### DF-2. Lineage-first delta representations

Explicit version and replacement relations provide delta candidates without
similarity search. DF-1 sketches serve only the residual cross-name or
cross-lineage cases.

The representation layer verifies reconstruction against the logical ObjectId,
keeps the base closure live, and never permits a smaller recipe to remove the
last recoverable representation.

### DF-3. Server-side identity recomputation

Astrid's engine computes identity from admitted bytes and re-verifies it during
recovery. This is the security boundary that avoids both name-squatting and the
proof-of-ownership protocol family.

Skipping verification for performance is rejected. Immutable object caching
moves verification to trusted cache fill and scrub; it does not delegate the
claim to a guest.

### DF-4. Keyed chunking doctrine

The future public/sync layer must use a reviewed keyed-CDC construction. Astrid
does not invent key mixing.

The private store may use public profile constants only while chunk
boundaries, lengths, counts, dedup outcomes, and admission differences remain
below the guest API line.

Reserve an algorithm tag before format freeze. Do not implement the keyed
variant until the public layer has an accepted threat model and conformance
fixtures.

### DF-5. Chunker evidence candidates

The format gate compares the measured FastCDC profile, a robust hashed MinCDC
candidate, and Chonkers or another construction with useful formal size and
locality bounds.

Evidence decides the first durable profile. Algorithm novelty does not.

## Public-layer crypto research shelf

The frozen roadmap and activation boundary are in
[Future Public Content Crypto Stack](../concepts/astrid-public-content-crypto-roadmap.md).

The future public or sync content layer may combine:

- a reviewed keyed-CDC construction, currently led by Truong et al.,
  *Breaking and Fixing Content-Defined Chunking*;
- message-locked or convergent encryption from the established literature;
- padded size buckets to reduce length leakage;
- an explicit privacy and confirmation-attack model;
- the reserved chunk-profile algorithm tag; and
- content hash as read capability only inside that deliberately public trust
  model.

This stack is not permitted in the private principal store. There,
content identity is never authorization.

Message-locked encryption reveals content equality and permits confirmation
attacks on guessable content. Padding mitigates length leakage; it does not
remove equality leakage. The public layer must state that concession rather
than describe deduplicated encryption as private in the ordinary sense.

Content-derived key material uses an extraction construction appropriate for
full-entropy hash input. Password-stretching functions do not add security to
content-derived entropy and create avoidable per-object cost.

## Counsel list

Keep the legal review narrow:

1. IBM's similarity-in-scan family compared with the final DF-1
   scrub-transform specification.
2. The Bitcasa family when a public encrypted-dedup service is actually
   proposed.
3. The exact MinCDC or other chunker implementation license selected by the
   evidence gate.
4. The final public-layer message-locked-encryption composition and any
   jurisdiction-specific patent status.

No other current private-store mechanism has been identified as requiring
specialized counsel beyond ordinary dependency and license review.

## Defensive publication and maintenance

- Keep the storage lineage table current and cite the actual mechanisms used.
- Publish design documents once reviewed so Astrid's own combinations have a
  dated public record.
- Prefer Apache-2.0 or dual MIT/Apache-2.0 for storage crates so contributors
  provide an explicit patent grant and retaliation clause.
- Re-run patent and literature review when the public layer, delta
  representations, or filesystem provider moves from roadmap to code.
- Treat this document as engineering input. Counsel, not the implementation
  team, makes legal conclusions.
