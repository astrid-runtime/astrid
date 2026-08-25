# Resident-memory authority

Issue: [#1401](https://github.com/astrid-runtime/astrid/issues/1401)

## Purpose

Guest Wasm ceilings govern linear memory, not host memory retained because a
principal caused work. Storage caches, Linux Realm RAM, compilers, filesystem
providers, and GPU staging can each fit their local limit while their sum
exhausts the machine. The kernel therefore owns one authority over all
principal-attributable resident memory.

The authority is policy and accounting, not an allocator. Subsystems reserve
coarse leases and suballocate locally. A cache hit, Wasm page growth, filesystem
read, or GPU command must not take one process-global lock.

## Two ledgers

Physical reservations enforce the operator-wide pool. Logical leases charge
every principal the complete weight it is allowed to use. If Alice and Bob
share one 40-MiB immutable record pool, physical usage is 40 MiB while both
logical accounts are charged 40 MiB. Guest-visible limits and future billing
therefore cannot reveal whether another trust domain has equal content.

Physical and logical leases are intentionally independent:

- an ordinary private allocation acquires both;
- a shared cache reserves its physical slab once and takes independent logical
  leases for participating principals; and
- operator diagnostics reconcile both without exposing physical sharing to
  guests.

## Principal hierarchy

Every principal has a logical subtree limit and an optional parent. A child
reservation consumes its own limit and every ancestor's remaining authority.
Children attenuate an existing allowance; creating more children cannot mint
memory capacity. Live limit reduction can put an account over policy, in which
case evictable logical leases receive shrink targets. Existing non-evictable
state remains accounted, its unreclaimable excess is reported, and new growth
is denied.

Parent changes and principal removal are allowed only with no live subtree use.
Lease destruction releases its accounting automatically.

## Pressure protocol

Lowering the physical pool computes the exact excess and writes target sizes to
evictable physical leases. It does not claim those bytes were freed. A consumer
observes its target, reclaims outside the authority lock, and acknowledges its
actual resident size. Until acknowledgement:

- physical accounting remains unchanged;
- unrelated new reservations cannot consume imaginary space; and
- diagnostics expose requested versus actual bytes.

If evictable leases cannot cover the excess, the remainder is reported as
unreclaimable. Existing execution state is not killed implicitly. New
non-evictable allocations fail before overcommit.

Logical pressure follows the same protocol. Targets are recomputed across the
whole principal tree from deepest child to root, so reclaiming a child charge
also satisfies its ancestors without double-counting the same bytes. Raising a
limit or releasing another lease clears obsolete targets. A zero-sized lease
remains a live reusable handle and therefore still prevents principal removal
or reparenting until it is dropped.

Operator snapshots list every physical and logical lease, current and requested
bytes, owning principal, subsystem, reclaim class, and time held. This is the
reconciliation surface for detecting leaked lifecycle ownership. CPU time and
cross-resource charging policy remain in the general cost-accounting program;
the memory authority supplies exact current reservations rather than treating
peak telemetry as enforcement.

## Runtime policy

The primitive embeds no machine-size heuristic. Managed mode injects its
operator pool. Local mode must derive an adaptive pool from the effective host
or container limit and lower it under native memory pressure. That policy lives
at daemon/kernel composition, not in storage.

Storage's decoded-object controller is the first adapter. It leases a coarse
evictable slab, sets cache capacity from that lease, performs an explicit trim
when the requested target falls, and acknowledges actual resident bytes.
Per-principal cache charge comes from the existing logical cache ledger and
profile-derived shares. Cache exhaustion always falls back to verified arena
reads.

Wasm linear memory, Realm RAM, compiler workers, provider buffers, and GPU
staging then consume the same authority. A mixed-load test must keep physical
reservations within the operator pool, preserve parent attenuation, and release
every lease on teardown.
