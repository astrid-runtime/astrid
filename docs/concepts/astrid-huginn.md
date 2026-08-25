# Huginn: Content-Addressed Context Assembly

Status: design note. The first testbed is the local Gemma harness. This
document does not activate a capsule or WIT interface.

Huginn turns model context construction into an identified derivation instead
of rebuilding an anonymous prompt on every turn.

It is a consumer of the invocation contract and Muninn:

```text
identified source objects
    -> policy-selected ordered context
    -> canonical context assembly
    -> identified token/prefix state
    -> local model invocation
```

Tensor Logic may propose or explain which objects belong in a context. Huginn
deterministically encodes the selected sequence. Muninn remembers proven
assembly and prefix-state derivations. None of them authorizes access to a
source object.

## Canonical assembly

Canonical ordering does not mean sorting context arbitrarily. Order changes
meaning.

The planner produces an explicit ordered sequence of authorized typed context
blocks. Huginn gives that sequence one canonical encoding:

```text
ContextAssembly {
    format_version
    model_contract
    tokenizer_contract
    conversation_template
    ordered_blocks
    separator_grammar
    truncation_and_budget_policy
    tool_and_media_encoding_contracts
}

ContextId = ObjectId(ContextAssembly)
```

Each block records its role, type, source ObjectId or SemanticId, exact
representation requirement, and identity-bearing rendering parameters.
Untrusted text cannot smuggle a role boundary or separator because delimiters
belong to the grammar, not the content.

The canonical encoding uses the same explicit field and ordering discipline as
`DerivationInvocation`. Ambient JSON serialization is not identity.

The assembly contract pins one reference transform by ObjectId through the
semantic-contract machinery. Alternate implementations may accelerate it only
after their output verifies against the reference; they cannot mint a
`ContextId` by claiming the same display-name contract.

## Persistent sequence structure

A large context should not be one flat mutable blob. Huginn models it as a
persistent sequence or Merkle rope of identified blocks. Appending a turn
retains the prior prefix identity. Replacing one block changes the affected
path without renaming unrelated blocks.

This permits prefix derivations at stable sequence boundaries:

```text
PrefixState[i + 1] =
    apply(model, tokenizer, backend_profile, PrefixState[i], block[i])
```

The materialized KV cache is a physical Derived representation, scoped to the
exact model, tokenizer, template, numerical/backend profile, and prefix.
Another backend may retain a different representation of the same logical
context.

## Gemma testbed

The local Gemma harness is first because Astrid owns:

- model and tokenizer bytes;
- template and context grammar;
- inference runtime and backend;
- KV-cache layout and lifetime;
- timing, token, resident-memory, and device measurements; and
- cold and warm execution conditions.

Provider-side prefix caches remain later beneficiaries. They cannot be the
first evidence because their key construction, eviction, pricing, and hit
signals are outside Astrid's control.

The initial experiment measures:

- context assembly time and bytes processed;
- exact and partial prefix hit rates;
- time to first token;
- tokens processed per turn;
- resident KV bytes and reuse lifetime;
- cold, warm, append-only, and middle-edit behavior; and
- result correctness across cache eviction and process restart.

The experiment records two derivation families:

```text
assemble(context-contract, ordered source closure) -> ContextId
advance(model, tokenizer, backend-profile, prefix, next block) -> PrefixState
```

The local Gemma harness owns both execution and KV-cache measurement, so cold,
warm, partial-prefix, eviction, and restart results are attributable to Huginn
rather than a provider's opaque cache.

## Determinism boundary

Context identity can be exact even when model generation is stochastic.

Reusable prefix state requires a runtime profile that pins every
semantics-visible influence on that state, including model, tokenizer,
template, numeric precision, attention implementation, device/backend class,
and reduction guarantees. If two backends cannot promise byte-identical state,
their KV representations use different runtime profiles.

Sampler parameters and an explicit seed may make output generation
reproducible under a suitable runtime profile. Without that guarantee,
generation remains nondeterministic and outside Muninn even though context
assembly and prefix preparation are reusable.

## Authority and privacy

Huginn can assemble only objects already visible in the caller's
capability-scoped view. A context identity grants no access to its blocks.

Private contexts use the caller's computation-sharing domain. Cross-domain
physical cache sharing follows the same accounting and timing policy as
Muninn. Prompt or prefix presence is never exposed as an API result or billing
discount.

Removing authority to a source prevents future assembly and lookup through
that principal view. Retention and erasure policy determines whether derived
prefix state is evicted immediately or at the next bounded cleanup.

## Host boundary

No model-specific host function is required for the design note. Internal Rust
traits can first express:

- bounded reads from host-selected source objects;
- canonical block assembly;
- bounded token and prefix-state sinks;
- model/runtime profile selection;
- resource leases; and
- execution evidence.

A future capsule-facing streaming or accelerator contract changes WIT and
therefore requires an RFC after the interface freeze. The kernel remains
prompt- and model-blind.

## Acceptance before activation

- Two processes assemble byte-identical context from the same assembly object.
- Changing order, role, separator grammar, tokenizer, or template changes
  `ContextId`.
- Append preserves all prior persistent-sequence nodes and prefix identities.
- A middle edit invalidates only the affected suffix.
- Untrusted block content cannot inject a structural role or delimiter.
- Cache eviction produces the same uncached model input.
- An unauthorized caller cannot use a known `ContextId` to read source blocks.
- Backend-incompatible KV states never share an invocation identity.
- Stochastic generation does not enter Muninn merely because its context did.
