# Astrid durable-engine group commit

## Scope

Every strict durable principal-root update currently performs one object-arena
flush followed by one root-journal flush. The ordering is correct, but
concurrent principals serialize `2N` media flushes through the shared engine.
Measured aggregate KV throughput remains about 117 operations per second for
one writer and 135 operations per second for eight writers.

Group commit changes only how independently prepared strict commits share
physical durability. It does not change object identity, graph validation,
principal authorization, quota, root compare-and-swap, or recovery grammar.
Bulk ingest and writable-provider intent batching are separate transactions
with separate acknowledgement contracts.

## Coordinator

`DurableEngine::commit` uses a caller-coordinated queue:

1. A caller appends its transaction and private completion receipt.
2. If no leader exists, that caller becomes the temporary leader.
3. A newly elected leader waits the initial coalescing delay. If multiple
   callers are queued after that interval, it waits one busy extension so
   scheduler skew does not split an otherwise concurrent group. Setting both
   delays to zero disables intentional waiting without disabling batching
   behind an in-flight flush.
4. The leader drains the current queue as one finite group.
5. Transactions are prepared in queue order under the engine mutex.
6. Preparation or root-conflict failure completes only that transaction. It
   appends no bytes and does not prevent unrelated principals from committing.
7. Accepted object frames are deduplicated within the group, then all accepted
   commit frames are appended. One arena flush makes that complete prefix
   durable.
8. Accepted root-journal frames are appended in the same order. One journal
   flush publishes the group durably.
9. In-memory indexes, validation evidence, and current roots advance only
   after the journal flush succeeds. Each accepted caller is then completed.
10. If callers arrived while I/O was in flight, leadership is handed to the
    oldest queued caller. The old leader returns after its own finite group
    instead of servicing an unbounded stream.

The default policy is a 250 microsecond initial delay plus one 250 microsecond
busy extension. It spends at most 0.5 milliseconds under concurrency to avoid
another media-flush pair measured at roughly 8–9 milliseconds on APFS, while
an isolated commit normally pays only the initial 0.25 milliseconds.
`GroupCommitPolicy` also exposes immediate and fixed-delay modes. This is a
latency policy, not an on-disk parameter or resource limit; correctness is
identical at zero delay.

## Ordering and conflicts

The queue is the linearization order for transactions accepted into one group.
A tentative root map records roots accepted earlier in that group. Therefore:

- independent principals can all succeed;
- two concurrent updates expecting the same principal root have one winner and
  one ordinary root conflict;
- a known-stale transaction appends no object or journal bytes; and
- root-journal recovery observes the same per-principal compare-and-swap chain
  as non-grouped commits.

No accepted caller is acknowledged until both the arena and root-journal
flushes have completed successfully. Grouping changes the number of flushes,
not the durability acknowledgement boundary.

Immutable frames with the same `ObjectId` and identical bytes are appended
once per group. A same-identity/different-bytes collision rejects the later
transaction before any group I/O. The privileged `objects_inserted` diagnostic
reflects physical admission by queue order and remains below the guest API
line.

## Durability and failure matrix

| Failure point | Returned result | Recovery truth |
| --- | --- | --- |
| Before group I/O | Failing transaction only; others may proceed | No bytes from that transaction |
| During object append or before arena flush | Accepted group requires recovery | Old roots; orphan/torn arena tail is ignored or truncated |
| After arena flush, before root append | Accepted group requires recovery | Old roots; complete unreachable objects are reclaimable |
| During root append or before journal flush | Accepted group requires recovery | Verified durable root-journal prefix only |
| After journal flush | Accepted group is durable | Every complete root frame in queue order |

Any I/O or injected fault after group I/O starts poisons the engine instance.
All accepted callers are told to reopen; one receives the precise initiating
error and the others receive `RequiresRecovery`. Recovery, not an in-memory
guess, determines whether a journal prefix reached durable media.

## Acceptance

- Concurrent independent principals share one object flush and one journal
  flush per observed group.
- Same-principal compare-and-swap still admits one winner.
- A malformed or stale transaction does not fail an unrelated transaction in
  the same group.
- Every injected group crash recovers an old or new complete root per
  principal, never a dangling closure.
- The before/after benchmark reports aggregate writes per second and
  per-writer tail latency for 1, 2, 4, and 8 principals.
- Strict single-writer latency reports the configured coalescing delay
  separately from media-flush time.

## Measured result

The explicit release-mode probe uses the complete async `TreeKvStore` path,
separate principals, 128-byte values, 64 strict commits per writer, and a warm
APFS store. It is a durability-throughput probe rather than a device benchmark.
The before values are the pre-grouping measurements recorded on issue #1388.

| Writers | Before ops/s | Grouped ops/s | Aggregate p95 | Worst writer p95 | Maximum |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 117 | 117.3 | 9.11 ms | 9.11 ms | 10.98 ms |
| 2 | 111 | 220.7 | 9.91 ms | 9.92 ms | 10.01 ms |
| 4 | not recorded | 438.4 | 10.02 ms | 10.02 ms | 10.13 ms |
| 8 | 135 | 802.5 | 10.92 ms | 16.06 ms | 19.94 ms |

Eight writers therefore improve aggregate strict-durable KV throughput by
5.94 times while keeping the ordinary latency in one media-flush round. The
eight-writer tail includes callers that land after a batch cutoff and wait for
the next finite group; leadership passes to the oldest queued caller, so this
does not become starvation. The underlying flush latency can also produce a
similar maximum for every writer at once. Both p95 and maximum remain part of
the probe output so those cases are not hidden by aggregate throughput.
