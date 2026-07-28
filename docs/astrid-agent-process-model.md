# Agent Process Model

Status: capsule-layer design contract. Astrid Runtime does not ship an
implementation of this model.

Related documents:

- [Principal Store](astrid-principal-store.md) supplies immutable objects,
  copy-on-write roots, lineage, and compare-and-swap publication.
- [Conservation of Computation](astrid-conservation-of-computation.md)
  classifies pure, snapshot-bound, effectful, and nondeterministic execution.
- [Huginn](astrid-huginn.md) defines the context-sequence primitive consumed by
  a downstream context assembler.
- [Muninn](astrid-muninn.md) remembers verified deterministic work.
- [Tensor Logic Composition](astrid-tensor-logic-composition.md) proposes and
  explains typed compositions without granting authority.

## Boundary

Astrid is an operating system that can run agents. It is not defined by agents,
and this document adds no agent-shaped kernel object, syscall, host function, or
storage-model kind.

An agent process is a user-space convention implemented by a distro-provided
harness capsule. The harness composes existing neutral mechanisms:

- a principal-scoped durable root;
- immutable content and lineage;
- capability-scoped workspace attachments;
- resumable jobs and execution receipts;
- staged state changes and root-CAS publication;
- WO-0 execution classes;
- Huginn context sequences; and
- provider and tool capsules selected by the distro.

Tool, driver, storage, provider, and application capsules do not acquire agent
memory merely by running in the same system. They remain ordinary services. The
harness is the consumer that gives one long-lived task an agent-process
interpretation.

## Memory and context

Memory is the durable authorized corpus. Context is the bounded working set
materialized from it for one model invocation.

```text
durable corpus
    -> policy and relevance selection
    -> canonical ordered Huginn sequence
    -> bounded model context
    -> model output and tool observations
    -> validated process transition
    -> durable corpus
```

The model can reason directly only over its current context. The corpus may be
much larger. Retrieval, traversal, summarization, and repeated invocations let a
process work across more material than one context window, but do not create
infinite simultaneous attention.

Summaries, indexes, embeddings, extracted plans, and model-specific prefix
states are disposable `Derived` views. They may accelerate context construction
but never replace or silently rewrite the authoritative source objects.
Discarding every such view loses speed and convenience, not process memory.

## User-space process root

The exact downstream schema belongs to the implementing harness and its
contract. Conceptually, one published root identifies:

```text
AgentProcessRoot {
    schema_contract
    durable_memory_root
    task_state_root
    current_context_sequence
    workspace_attachments
    completed_observations
    resumable_jobs
    proposed_effects
    authority_epoch
    runtime_policy
}
```

This is not a proposed core `ObjectKind`. A harness may represent the fields
with ordinary directories, KV state, evidence, and typed application objects.
The invariant is behavioral: a committed root contains everything needed to
resume the process except authority that must be reacquired from the operating
environment.

Capabilities, secrets, live kernel handles, and provider credentials are not
ordinary process-memory objects:

- capability grants remain external authority and are bound by epoch or
  receipt;
- secret values remain in the secret service;
- a live handle is replaced across restart by a typed resumable job or rebinding
  receipt when its service supports one; and
- an external workspace remains an explicitly granted attachment, not content
  silently absorbed into the process root.

Known object identities grant no authority to recover those objects.

## Transitions and lineage

Every accepted process step publishes a normal principal-state transition. A
downstream process-transition record binds:

```text
ProcessTransition {
    process_before
    process_after
    fork_parent?
    invocation_or_job_receipts
    proposed_effects
    selected_effects
    authority_epoch
    transition_witness?
}
```

`process_before` is the compare-and-swap parent. When a new speculative process
is forked, `fork_parent` records the source process root as a non-owning
`Lineage` edge. Forks are therefore auditable branches rather than unexplained
siblings. Naming a parent does not import its authority, secrets, retention, or
quota.

The state change may carry the existing `TransitionWitness` for the affected
owned subtree. The witness proves the structural root rewrite; execution
evidence and authority receipts prove their separate claims.

Concurrent publication is resolved by ordinary root CAS. A stale branch may be
discarded, rebased through a typed application operation, or explicitly merged.
There is no generic automatic merge of opaque agent state.

## Fork

Forking shares immutable owned roots and creates a new branch root. New storage
is proportional to changed paths and newly produced content.

Authority does not copy by data reference. The child receives an explicitly
attenuated capability view selected by the harness and operator policy.
Non-forkable live handles are absent. Pending effects remain inert proposals,
and in-flight jobs are either:

- referenced as shared read-only observations after completion;
- rebound through a service-defined resumable job contract; or
- cancelled and restarted under a fresh invocation.

This prevents a fork from accidentally duplicating a network request, payment,
deployment, device action, or other external effect.

Fork is useful for alternative plans, model comparison, adversarial review,
bounded search, and recovery experiments. It is not required for ordinary
single-path operation.

## Execution and effects

The process model applies the four WO-0 classes without changing them.

- **Pure:** eligible for Muninn when the complete invocation is identified.
- **Snapshot-bound:** external acquisition occurs once as an effect or
  observation; deterministic processing names the acquired snapshot.
- **Effectful:** the branch stages an inert intent. Selection and publication
  authorize an executor to attempt the effect.
- **Nondeterministic:** recorded as a fresh invocation and observation; never
  silently reused.

Conservation of computation must not become conservation of side effects.
Speculative branches cannot execute staged effects. Only the selected committed
transition may make an effect intent runnable.

Universal exactly-once external effects are not claimed. When the destination
supports an idempotency key, the effect executor binds it to the committed
intent identity. When it does not, a crash after the external effect but before
its receipt produces an explicit `indeterminate` state. Recovery asks the
operator or service-specific reconciler; it never retries blindly and calls the
duplicate impossible.

Completed receipts are observations that an earlier effect occurred. They are
not authority to perform it again.

## Provider portability

The process root is provider-independent. Claude, Codex, Gemma, or another
provider receives a bounded context assembled from the same authorized corpus.
Provider-private conversation state and KV caches are never correctness
dependencies.

A hosted provider may cache an exact prefix. That can reduce cost or latency,
but Astrid must be able to reconstruct the required model input after cache
eviction, provider migration, or process restart.

An Astrid-native local model permits stronger optimization because the
downstream implementation controls the tokenizer, template, runtime, and
physical KV-cache representations. Those representations remain Derived and
backend-profile scoped.

Provider output is an observation, not an authorized state transition by
itself. The harness validates requested tool invocations and state changes
through the same capability and publication boundaries regardless of provider.

## Context operation

The downstream harness uses Huginn as context virtual memory:

1. start from the published process root;
2. select authorized source blocks under an explicit budget;
3. assemble their canonical ordered sequence;
4. reuse identified token or prefix work where the provider/runtime permits;
5. invoke the model;
6. retain model output, tool calls, results, and provenance as observations;
7. update task and memory state; and
8. publish one new process root.

For hosted APIs, paging occurs between model invocations and tool-loop steps.
Astrid cannot interrupt an opaque provider inference to inject a missing page.
A local runtime may additionally page model-owned prefix state at supported
boundaries.

Retrieval quality is downstream intelligence, not a kernel rule. Mimir or
another reasoner may propose relevant blocks and explain the selection. It
cannot bypass the capability-scoped view or publish the transition.

## Jobs and lifecycle

A turn is not the process lifetime. The harness distinguishes:

```text
create -> runnable -> waiting -> runnable -> committed
             |          |
             v          v
           forked     resumable
             |
             v
          selected or retired
```

Foreground execution waits for a bounded result. A background job receives a
durable job identity, resource lease, cancellation contract, output sink, and
supervision policy. The next model invocation observes job state through a
receipt rather than assuming a shell process remained alive.

Process suspension freezes no external system by implication. A service that
offers resumability must state what survives, what is checkpointed, and what is
restarted.

## Privacy and accounting

The process is charged through the ordinary principal or trust-domain ledgers:

- logical owned bytes and retention byte-time;
- CPU and device time;
- resident byte-time;
- physical reads and writes;
- provider tokens or requests; and
- background maintenance.

Cross-domain deduplication, Muninn hits, provider-cache warmth, and shared
physical pages stay below the guest-visible accounting line. Another process's
matching memory or computation cannot change an admission result or bill.

Context assembly must not reveal inaccessible source identities through
missing-block errors, timing, token counts, or cache-hit metadata. The harness
first constructs the caller's authorized view, then operates only within it.

## Distribution boundary

Astrid Runtime ships no capsules. It supplies the neutral mechanisms, not an
agent harness, tokenizer, provider template, retrieval policy, or
raven-branded implementation. Distros compose those programs.

In the operating-system analogy, Astrid is upstream in the role Linux occupies;
the selected distro supplies the user-space experience. An agent-process
implementation may become a defining workload and a default distro component
without becoming part of the kernel or the neutral runtime definition.

## Acceptance

The design is ready for activation only when a downstream implementation
demonstrates:

- **resume without summary:** deleting every disposable summary and cache still
  reconstructs a runnable task from the durable process root;
- **model portability:** two providers can continue the same process without
  provider-private state becoming authoritative;
- **delta-cost fork:** N forks initially share all immutable state and consume
  physical storage proportional to their changes;
- **auditable lineage:** every fork transition names its parent root;
- **no speculative effects:** unselected branches cannot execute an external
  effect;
- **crash-honest effects:** effect destinations without idempotency expose
  indeterminate recovery instead of blind replay;
- **authority attenuation:** a fork, resume, provider switch, or context lookup
  cannot widen capabilities;
- **bounded attention:** every context assembly has explicit token, byte,
  compute, and time ceilings;
- **derived-view independence:** deleting summaries, indexes, embeddings,
  tokenizations, and KV caches changes performance only; and
- **measured reuse:** an unchanged authorized context prefix is not tokenized or
  physically prepared twice when the selected runtime exposes reusable prefix
  state.
