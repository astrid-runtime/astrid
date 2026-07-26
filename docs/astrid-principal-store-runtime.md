# Astrid Principal Store Runtime Realization

This companion to [Astrid Principal Store](astrid-principal-store.md) carries
the runtime boundary, delivery order, remaining evidence questions, and prior
art. Operational economics, accounting, privacy, and retention are specified
in [Astrid Principal Store Operations](astrid-principal-store-operations.md).

## 18. Host filesystem projection

The object graph is authoritative. A normal filesystem is a projection and
ingestion boundary.

For an Astrid-managed workspace:

- a successful write transaction creates a new root;
- external host changes are ingested through a watcher plus periodic
  reconciliation;
- watcher events are hints, never proof of a complete history;
- deletion becomes a directory entry removal in a new root, while prior roots
  remain only under explicit retention;
- materialization occurs in a new directory or file and becomes visible through
  atomic rename;
- path resolution uses beneath/no-follow semantics and rejects device nodes,
  sockets, escaping links, and platform-specific special names; and
- symlink targets remain uninterpreted bytes during import/export.

On platforms where exact mutation capture is required, Astrid should mount a
filesystem service or route writes through a mediated interface rather than
claim provenance from after-the-fact watching.

## 19. Native Astrid integration

The native kernel supplies:

- a block-device capability to the storage domain;
- bounded DMA and memory resources;
- IPC;
- monotonic boot/authority epoch inputs;
- optional compact root or sequence anchoring;
- a bounded verifier path for state views and structural transition witnesses.

The user-space storage service owns:

- object formats and parsers;
- files and KV;
- transactions;
- encryption and compression;
- import/export;
- replication and rebalancing;
- garbage collection and repair.

No filesystem, chunker, database query engine, or placement policy belongs in
ring 0.

## 20. Tensor-ready without a tensor dependency

The principal store should preserve enough type information to support Astrid's
later Tensor Logic work without making tensor evaluation part of durability.

- every object and reference carries a stable schema and relation kind;
- every committed transition can feed a derived relation/index stream;
- exports carry the schema set needed to rebuild derived indexes;
- derived tensor indexes name the source commit from which they were built;
- verified state views expose typed relations without disclosing the rest of a
  principal state;
- an index can be discarded and reconstructed from committed state and
  transition records.

The authoritative state remains the typed object graph and signed transition
chain. A future tensor engine may compile interface compatibility, inputs,
outputs, ownership, or historical transitions into sparse relations and
einsum-like evaluation plans. It is a derived reasoning surface, not a knowledge
graph and not a prerequisite for reading a file or recovering a principal.

## 21. Implementation order and current boundary

The current implementation stack completes the first seven items below.
`SurrealKvStore` remains a migration oracle and read-only import source, not a
configurable runtime backend.

Delivered:

1. `astrid-storage-model` defines canonical identifiers, ownership classes,
   object grammar, closure validation, accounting definitions, and a small
   executable state machine.
2. Typed state views and structural transition witnesses bind
   selectors, patches, and both roots without importing authority.
3. Model and property tests cover commit, crash, view, witness, import, GC,
   and rebalance.
4. The engine prototype operates over in-memory immutable objects and atomic
   roots.
5. The principal-store-backed `KvStore` adapter has differential tests
   against `MemoryKvStore` and `SurrealKvStore`.
6. Durable segments, a disposable index, a checksummed root journal, fault
   injection, recovery, a persistent tree projection, and quota enforcement
   support the native KV cutover. Compaction remains future work.
7. A canonical FastCDC content DAG and named principal content catalog share
   the same object arena, root CAS, and aggregate quota as KV. Full/range reads,
   alias accounting, cross-principal physical reuse, and concurrent mutations
   have executable regression coverage.

Remaining:

8. Add typed filesystem roots and a safe materializer; integrate Linux-realm
   principal-home checkpoints and explicit external-workspace observations.
9. Make local clone/fork root-based while preserving explicit secret behavior.
10. Implement full/view export and staged import, then thin transfer.
11. Add placement epochs, repair, operator dry-run, and online rebalance.
12. Add native block transport only after the same engine passes host
    conformance and power-loss tests.

## 22. Decisions still requiring measured evidence

- canonical encoding: a constrained custom binary form, deterministic CBOR, or
  another format with a small `no_std` verifier;
- additional chunking profiles and corpus-specific selection;
- segment and pack sizing;
- successor identity-algorithm selection and migration timing;
- local-only versus cluster placement algorithm;
- replication versus erasure coding thresholds;
- trusted-local encryption and key-wrap design;
- default deduplication/privacy domain;
- default retention and rollback policy;
- which principal components are included in standard export;
- the exact audit checkpoint carried in a portable bundle;
- canonical selector and proof formats for verified state views;
- canonical typed patches and witness format for structural root transitions;
- proof-retention policy and whether a deployment requires a witness before
  acknowledging selected commit classes;
- how a running Linux realm exposes application-consistent checkpoint hooks.

These are not invitations to improvise in production code. Each becomes a
versioned format or policy decision only with a corpus, failure tests, and a
migration story.

### Explicitly deferred extensions

- Background `doctor` scrubbing may walk arena checksums on a schedule so
  latent corruption is discovered while independent backups still exist.
- Critical owning closures may request additional local copies through the
  existing `ReplicaCount` placement model.
- Multi-device synchronization will exchange verified closures and publish
  roots through ordinary compare-and-swap; its product and conflict semantics
  must be designed when that work is called.
- Delta compression between near-identical chunks is considered only if the
  temporal version-chain sweep demonstrates savings beyond content-defined
  chunk reuse.

None of these extend the current merge scope.

## 23. Prior art used as evidence, not dependencies

- Quinlan and Dorward,
  [Venti: a New Approach to Archival Storage](https://www.cs.princeton.edu/courses/archive/spring13/cos598C/venti.pdf):
  immutable content-addressed blocks and archival roots.
- Quinlan, McKie, and Cox,
  [Fossil, an Archival File Server](https://9p.io/sources/plan9/sys/doc/fossil.ms):
  mutable filesystem snapshots layered over Venti.
- Xia et al.,
  [FastCDC](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia):
  efficient content-defined chunking; parameters still require Astrid data.
- Bellare, Keelveedhi, and Ristenpart,
  [DupLESS](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/bellare):
  the security limits of message-locked encryption and server-aided mitigation.
- Tahoe-LAFS,
  [architecture](https://tahoe-lafs.readthedocs.io/en/latest/architecture.html):
  separation of immutable data, mutable names, verification, and authority
  capabilities.
- Weil et al.,
  [CRUSH](https://main.ceph.io/assets/pdfs/weil-crush-sc06.pdf), and Wang et al.,
  [MAPX](https://www.usenix.org/conference/fast20/presentation/wang-li):
  deterministic placement and controlled migration.
- IPFS,
  [content addressing and Merkle DAGs](https://docs.ipfs.tech/concepts/how-ipfs-works/):
  interoperable graph-transfer lessons; Astrid does not inherit IPFS authority
  or networking semantics.
- Perkeep,
  [permanodes and signed claims](https://perkeep.org/doc/schema/permanode.md):
  prior art for mutable named objects over immutable content. Astrid uses atomic
  principal roots instead of replaying signed claims as its authoritative
  current-state mechanism.
- Unison,
  [content-addressed code](https://www.unison-lang.org/docs/the-big-idea/):
  evidence that semantic, typed content identity can eliminate name- and
  text-level churn. Astrid does not require one language or store executable
  semantics in the storage engine.
- Irmin,
  [Merkle tree proofs](https://mirage.github.io/irmin/irmin/Irmin/module-type-S/Tree/Proof/index.html):
  direct prior art for carrying the minimal partial tree needed to verify a
  computation from one state root to another.
- Nix,
  [store derivations](https://releases.nixos.org/nix/nix-2.31.1/manual/store/derivation/index.html):
  prior art for naming how immutable outputs are produced. Astrid keeps that
  causal execution evidence separate from the content identity and authority
  of principal-owned state.
- Borg,
  [repository internals](https://borgbackup.readthedocs.io/en/stable/internals.html):
  chunk deduplication, authenticated repositories, and append-oriented segment
  and compaction lessons. Astrid's authoritative root remains live principal
  state rather than a backup archive.
- NIST,
  [SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final):
  current media sanitization and cryptographic-erasure guidance.
- Newcombe et al.,
  [How Amazon Web Services Uses Formal Methods](https://cdn.amazon.science/67/f9/92733d574c11ba1a11bd08bfb8ae/how-amazon-web-services-uses-formal-methods.pdf):
  bounded formal models as design and counterexample tools.

## 24. Astrid-specific synthesis

The ingredients are established; their boundary is the opportunity.

- Venti, Git, Borg, and similar stores show immutable content and efficient
  packing.
- Fossil, Perkeep, and Irmin show mutable names or branches above immutable
  history.
- Unison shows the benefit of content-addressing typed semantic units.
- Tahoe-LAFS shows that identity, verification, confidentiality, and read/write
  authority must not be collapsed into one hash.
- Irmin shows that a state transition can carry only the partial authenticated
  tree needed to verify it.

Astrid combines these into an agent operating-system contract:

```text
principal-owned world root
    + external attachments named but not silently owned
    + capability-scoped verified view
    + atomic typed patch and structural witness
    + signed authority/audit transition
    + causal execution/observation receipt
    + ordinary filesystem, KV, and tool projections
```

The important unit is therefore not a file, disk image, backup archive, event
log, or database row. It is a governed world transition whose data, authority,
causal inputs, and resulting state can be independently separated and checked.
That is the design Astrid should prove before optimizing the chunker.
