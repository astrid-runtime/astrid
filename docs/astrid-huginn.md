# Huginn: Context Virtual Memory

Status: identity-bearing core design note. The canonical sequence primitive
joins the storage freeze-audit queue before a format tag. Astrid Runtime does
not ship a context-assembler capsule.

Related documents:

- [Agent Process Model](astrid-agent-process-model.md) defines the downstream
  capsule-layer consumer.
- [Conservation of Computation](astrid-conservation-of-computation.md) defines
  complete invocation identity and execution classes.
- [Muninn](astrid-muninn.md) remembers verified token and prefix work.
- [Semantic Representations](astrid-semantic-representations.md) defines pinned
  reference transforms and representation contracts.

## Perch and flight

Huginn has one neutral core perch and downstream flights.

The **perch** is a canonical persistent sequence of identified typed blocks: a
Merkle-rope primitive with stable identities for every ordered prefix. It
belongs in the format because arbitrary user-space encodings would fragment
identity and destroy portable prefix reuse.

The **flight** is a distro-provided context-assembler capsule or harness. It
contains model tokenizers, conversation templates, retrieval and truncation
policy, provider adapters, and product behavior. Astrid ships no such capsule.

The core document defines only the sequence identity, authority rules, and
correctness constraints that every downstream implementation must preserve.

## Memory and context

Memory is the durable authorized corpus. Context is a bounded ordered working
set selected from it for one invocation.

```text
durable source objects
    -> downstream authorized selection
    -> canonical Huginn sequence
    -> tokenizer/template derivation
    -> bounded provider input or local prefix state
```

The context sequence does not claim that its blocks are relevant or true. It
records exactly which authorized blocks, roles, and rendering contracts were
selected and in what order.

Summaries, retrieval indexes, embeddings, token streams, and physical KV caches
are `Derived` representations. They may be rebuilt, replaced, or evicted. They
never become the only memory of the source corpus.

## Canonical sequence primitive

Order changes meaning. A sequence identity therefore commits to:

- the format and sequence-contract versions;
- ordered block identities;
- each block's role and typed content contract;
- exact representation requirements;
- structural delimiter and rendering contracts; and
- committed block and logical-byte totals.

Conceptually:

```text
ContextBlock {
    role
    content_contract
    source
    representation_contract
    rendering_parameters
}

ContextSequence {
    sequence_contract
    ordered_blocks
}
```

`source` names an ObjectId or a contract-governed SemanticId. It is never a
capability. The sequence owns or evidences its exact source records according to
the registered schema; downstream selection cannot smuggle authority through a
known identity.

Ambient JSON, map iteration order, locale, provider SDK serialization, or a
model's display-name template is not identity.

## Merkle-rope shape

A large ordered sequence is not one mutable flat object. It is a canonical
persistent structure over identified blocks.

Appending reuses every source block and every unaffected completed subtree. It
must require bounded metadata proportional to tree depth, not re-encode the
whole prefix. The ObjectId of every already-defined prefix remains unchanged
even when the new sequence does not own the old root directly. A prefix
identity is a real identified sequence boundary, not an integer offset into a
mutable prompt.

Replacing or inserting a block invalidates model-prefix states from the first
changed position onward. It need not rename source block objects. The exact
metadata rewrite cost depends on the canonical structure selected by the freeze
audit and must be measured rather than assumed.

Before the format tag, the freeze audit must settle:

- leaf and internal-node object kinds and domain separators;
- the canonical structure choice, with radix-tree, Merkle-mountain-range, and
  other candidates evaluated against the same requirements;
- canonical fanout, packing, split, and empty-sequence rules;
- whether partial right edges have one unique accepted form;
- committed block-count and logical-byte totals;
- maximum depth, block size, child count, and decode work;
- canonical prefix-boundary representation;
- `Owns`, `Evidence`, and `Derived` edge use;
- decoder re-encode equality and alternative-shape rejection; and
- append complexity, middle-edit amplification, export, GC, and proof fixtures.

There must be exactly one accepted tree for one logical ordered sequence under a
contract. A flexible rope whose balancing depends on edit history is not an
identity format.

## Canonical assembly

The downstream assembler produces an explicit ordered sequence of authorized
typed blocks. Its model-specific derivation binds:

```text
ContextAssembly {
    sequence
    model_contract
    tokenizer_contract
    conversation_template
    separator_grammar
    truncation_and_budget_policy
    tool_and_media_encoding_contracts
}
```

The assembly contract pins one reference transform by ObjectId through the
semantic-contract machinery. Alternate implementations may accelerate the
transform only after output verification; they cannot mint identity by claiming
the same contract name.

Untrusted text cannot create a role boundary or separator because those belong
to the pinned grammar, not the content bytes.

## Context virtual memory

The sequence is the logical address space. A downstream assembler chooses a
bounded resident working set for each invocation.

For hosted providers, paging happens between invocations and tool-loop steps:
the provider receives a reconstructed bounded prefix plus current material.
Astrid cannot page into the middle of an opaque provider call.

For a local runtime, token blocks and KV-cache segments may be physical Derived
representations of exact sequence prefixes:

```text
PrefixState[i + 1] =
    apply(model, tokenizer, runtime_profile, PrefixState[i], block[i])
```

The representation identity binds model bytes, tokenizer, template, numerical
profile, attention implementation, backend semantics, and the exact prefix.
Backend-incompatible states never alias.

The target is strict: an unchanged authorized prefix should never be tokenized
or physically prepared twice when the runtime exposes a reusable
representation. Eviction may force recomputation; it never changes logical
input or correctness.

## Provider-cache doctrine

Provider-side caching is performance, never correctness.

Astrid does not control a hosted provider's cache key, eviction, price, hit
signal, numerical representation, or retention. A downstream assembler may
produce exact stable prefixes likely to benefit from provider caching, but it
must reconstruct the complete required input after:

- provider cache eviction;
- process or host restart;
- migration to another provider;
- provider-policy change; or
- loss of every local Derived view.

Provider-private conversation state is not durable process memory. A provider
switch loses optimization state, not the authorized corpus or process history.

## Gemma testbed

The first downstream evidence target is a local Gemma harness because the
implementing distro can control:

- model and tokenizer bytes;
- conversation template and context grammar;
- inference runtime and backend;
- KV-cache layout and lifetime;
- cold, warm, eviction, and restart conditions; and
- token, latency, resident-memory, and device measurements.

The testbed records two derivation families:

```text
assemble(assembly-contract, sequence) -> model input
advance(model, tokenizer, runtime-profile, prefix, next block) -> prefix state
```

Gemma is an evaluation workload, not part of Astrid's definition and not a
capsule bundled by the runtime.

## Determinism boundary

Context sequence and assembly identity can be exact even when model generation
is stochastic.

Reusable prefix state requires a runtime semantic profile that pins every
observable influence. If two backends cannot promise byte-identical state, their
physical representations use different profiles.

Sampler parameters and an explicit seed may make output reproducible under a
suitable runtime profile. Without that guarantee, generation remains
nondeterministic and outside Muninn even though sequence assembly, tokenization,
and prefix preparation are reusable.

## Authority and privacy

A downstream assembler can select only blocks visible in the caller's
capability-scoped view. A sequence or prefix identity grants no access to its
source blocks.

Private contexts use the caller's computation-sharing domain. Prompt, summary,
tokenization, or prefix presence is never exposed through an API result,
admission outcome, or billing discount. Cache warmth is the documented residual
timing signal shared with Muninn and the host page cache.

Removing source authority prevents future assembly through that principal view.
Retention and erasure policy determine when already-materialized Derived
representations are evicted.

## Host boundary

The core primitive requires no model-specific host function. Internal Rust
interfaces may first express:

- bounded reads over an authorized sequence;
- canonical node construction and prefix traversal;
- bounded token and prefix-state sinks;
- runtime profile selection;
- resource leases; and
- execution evidence.

A capsule-facing streaming, tokenizer, or accelerator contract changes public
WIT and therefore requires the RFC process. The kernel remains prompt-,
tokenizer-, model-, and Huginn-blind.

## Acceptance before activation

- Two independent encoders produce the same bytes and ObjectId for one
  sequence.
- Decode followed by re-encode is byte-exact.
- Alternative tree shapes for the same sequence are rejected.
- Changing order, role, source, contract, or rendering parameters changes
  identity.
- Append preserves every source block, reuses unaffected subtrees, performs
  bounded metadata work, and leaves existing prefix identities unchanged.
- A middle edit invalidates model-prefix states only from the changed position
  onward; its metadata amplification is measured and documented.
- Untrusted content cannot inject structural roles or delimiters.
- Deleting summaries, indexes, token streams, and KV caches preserves the
  logical context.
- Cache eviction produces the same uncached model input.
- A known sequence identity grants no source authority.
- Backend-incompatible prefix states never share an invocation identity.
- A hosted provider-cache miss changes performance only.
- Stochastic generation does not enter Muninn merely because its context did.
