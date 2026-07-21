# Astrid Tensor Logic Composition

Status: architecture design and pre-implementation model

Last reviewed: 2026-07-18

Code baseline: Astrid Runtime 0.10.1

Decision state: preserve current behavior; add an exact composition model first;
reserve Tensor Logic execution for a later, explicitly activated backend

Execution and evidence are tracked in the
[AI-Native OS Workplan](astrid-ai-native-os-workplan.md). Hardware-role terminology
is defined by the [Driver Domain Contract](astrid-driver-domain-contract.md).

## 1. Executive decision

Astrid should treat the installed capsule set as a typed space of possible
compositions.

The system does not need a knowledge graph. It needs an interface relation space
derived from signed artifacts and live runtime authority:

- signed artifacts provide and require interfaces, with component ownership where
  it is actually declared or inspected;
- topics have typed payloads and directions;
- ports belong to content-bound artifacts/components or exact host-service
  implementations;
- principals see different capsule and capability projections;
- adapters explicitly transform one interface into another;
- goals describe required outputs and constraints;
- plans bind concrete providers to consumers;
- the kernel or host materializes only exactly validated plans.

Tensor Logic is the intended AI language for reasoning over that space. In Tensor
Logic, logical rules and Einstein summation share the tensor equation as their
common construct. That makes it possible for exact relations, recursive rules,
learned scores, attention, cost functions, and future neural models to participate
in one program.

References:

- [Tensor Logic: The Language of AI](https://arxiv.org/abs/2510.12269)
- [Tensor Logic project](https://tensor-logic.org/)

The first implementation must not require a tensor runtime. It should implement
the exact relational subset using a deterministic sparse-Boolean reference
evaluator. The internal program representation must nevertheless use named axes,
n-ary relations, contraction, projection, union, fixpoint, and explicit
nonlinearities so that a later tensor backend can lower the same program to einsum
without redesigning manifests, plans, validation, or authority.

This gives the project an incremental route:

~~~text
today
  explicit manifests + semver readiness + topic fan-out
      |
      v
exact composition catalog and reference evaluator
      |
      v
read-only inspection and counterexample testing
      |
      v
principal-scoped candidate planning in shadow mode
      |
      v
exact validated plans using existing runtime operations
      |
      v
transactional plan materialization where new routing is required
      |
      v
optional Tensor Logic backend for learning and neural-symbolic composition
~~~

Current routing, manifests, public WIT, and capsule behavior remain authoritative
until a later gate explicitly promotes composition output into execution.

## 2. The operating-system thesis

Plan 9 made a private namespace of file services the compositional surface of the
machine. Astrid can make a principal-scoped relation of typed interfaces the
compositional surface of an AI-native machine.

The primitive is not a fact about the world. It is an executable affordance:

~~~text
this signed component
  provides this typed operation
  requires these typed operations
  may perform these effects
  under these capabilities
  for this principal
  at this cost and locality
~~~

An AI-native OS should be able to answer:

- What can this machine do for this principal right now?
- Which installed components can be connected to satisfy this goal?
- Which adapter chains are exact and which are merely plausible?
- What authority would the resulting composition possess?
- Why was this provider selected instead of another?
- What becomes possible if a new capsule is Docked?
- Which plans become invalid if a capsule, capability, or route disappears?
- Can the same composition run on the daemon, browser, or native kernel host?

The answer should be an executable, inspectable plan, not natural-language advice.

The division of responsibility is:

~~~text
WIT and manifests       describe executable interfaces
runtime catalog         describes currently available instances
capability projection   describes current authority
Tensor Logic program    relates, learns, ranks, and composes
exact validator         establishes concrete validity
host or kernel          materializes handles and routes
capsules                perform the work
~~~

The AI language never mints authority. A score never changes an invalid edge into a
valid edge. The kernel remains product-neutral and unaware of goals, learned
weights, or Tensor Logic.

## 3. Terminology

**Catalog**

An immutable, epoch-stamped snapshot of installed artifacts, components, exact host
services, WIT types, runtime health, principal visibility, and actual grants. It is
derived state and can be rebuilt.

**Port**

A typed input or output endpoint owned by an artifact boundary, a specific
component, or a trusted host service. A port may represent a Component Model
import/export, an IPC publication/subscription, a tool operation, or a future
driver/system service operation. Current capsule-level declarations must not be
silently attributed to an internal component.

**Relation**

An n-ary tensor-shaped set or weighted function over named domains. For example,
Provides(Owner, Port, Type) or Visible(Principal, Owner).

**Connection**

A potential binding from an output port to an input port. It is derived from exact
compatibility and context; it is not stored as authoritative world knowledge.

**Adapter**

A signed executable component that explicitly converts one type or protocol into
another. Structural similarity alone does not create an adapter.

**Goal**

A typed desired output plus constraints such as principal, locality, maximum cost,
allowed effects, trust class, and latency. Natural language is not the canonical
goal representation.

**Candidate plan**

A proposed subgraph of executable owners, instances, and port bindings produced by an
evaluator. It has no execution authority.

**Validated plan**

A candidate checked against canonical type identities, current artifact hashes,
host-provider identities, actual grants, runtime epochs, routing rules, budgets,
and cycle policy.

**Materialization**

The transactional act of creating or selecting instances, handles, IPC routes, and
supervision relationships for a validated plan.

**Explanation**

A derivation recording which base relations, rules, policy choices, and scores
caused every plan node and edge.

The word **fact** may appear in the Datalog sense of a relation row. It does not
mean Astrid is building an ontology or knowledge graph.

## 4. Explicit non-goals

This design does not:

- introduce a knowledge graph;
- treat Tensor Logic as a cryptographic proof system;
- place an AI model, planner, relation catalog, or type resolver in ring 0;
- grant capabilities based on learned scores;
- replace explicit publish/subscribe ACLs;
- change existing capsule WIT or manifest wire shapes in the first implementation;
- infer conversions from coincidentally similar records;
- make remote and local failure behavior indistinguishable;
- require a GPU, autodiff framework, dense tensor library, or model weights;
- make current boot dependent on the composition engine;
- silently select between ambiguous providers;
- promise that every graph-shaped workflow is safe or terminating;
- require all capsules to be rewritten;
- create a new Astrid repository before a real ownership boundary demands it.

## 5. Existing Astrid foundation

The current runtime already contains the seed of this system.

### 5.1 Interface declarations

Capsule manifests contain namespaced imports and exports:

- imports carry namespace, interface name, semver requirement, and optionality;
- exports carry namespace, interface name, and exact semver;
- the manifest exposes normalized import and export iterators;
- self-satisfaction is excluded for current cross-capsule dependencies.

This is already a binary relation between capsule artifacts and interface
identities. It is not currently a per-component relation: `[components]` declares
component IDs, files, links, and requested capabilities, but does not map each
capsule import/export to a component. The catalog must preserve that distinction.

### 5.2 Typed event directions

The publish and subscribe tables contain:

- a topic or wildcard pattern;
- direction;
- a WIT payload reference or the explicit opaque marker;
- optional source/version pins;
- optional handler and priority on subscriptions.

The keys are also the fail-closed IPC ACL. Composition must consume these
declarations without weakening that role.

### 5.3 Existing graph operations

Current code already:

- tests import/export compatibility by namespace, name, and semver;
- calculates unsatisfied required and optional imports;
- computes agent-loop readiness from the manifest set;
- topologically orders capsules with Kahn's algorithm;
- reports dependency cycles;
- warns when multiple providers export the same interface;
- maintains a runtime schema catalog updated on load and unload;
- maintains per-principal capsule views over content-addressed shared instances;
- filters user-invocable dispatch through a principal-aware access resolver.

These implementations must become inputs to one shared catalog/matching library,
not be copied into a competing planner.

### 5.4 Important current limitations

The existing relations are used for validation and load order, not provider
selection or executable composition:

- any matching provider satisfies an import;
- all matching providers add load-order edges;
- duplicate providers only produce a warning;
- matching topic subscriptions can fan out and double-process;
- import/export identity does not prove the referenced WIT shapes are identical;
- the schema catalog records WIT references but does not yet resolve every shape;
- opaque topics cannot be type-checked;
- tool declarations may carry a WIT input record but do not declare a typed output;
- current routes are topic patterns, not plan-private point-to-point bindings;
- a capsule can disappear or lose authority after a plan snapshot;
- component links in the manifest do not yet express a complete runtime dataflow.

The first design task is to make these limitations explicit in the model.

## 6. Design method

This project should use several established methods, each for the problem it is
good at.

### 6.1 Architecture views

Use the C4 approach for progressively detailed static views:

1. system context: Astrid, operator, capsules, registries, and hosts;
2. container view: catalog, evaluator, validator, materializer, runtime;
3. component view: Rust modules and trust boundaries;
4. dynamic views: plan, commit, revocation, and recovery sequences.

The diagrams in this document are the beginning, not a substitute for the models.

Reference: [C4 model](https://c4model.com/)

### 6.2 Scenario-driven tradeoff analysis

Use a lightweight Architecture Tradeoff Analysis Method review. ATAM evaluates an
architecture against concrete quality scenarios and exposes sensitivity and
tradeoff points across security, performance, availability, and modifiability.

For this design the highest-priority quality attributes are:

1. no authority amplification;
2. principal non-interference;
3. compatibility when disabled;
4. exact type and artifact identity;
5. deterministic explanation;
6. availability during planner failure;
7. bounded evaluation;
8. backend replaceability;
9. performance at large catalog sizes.

Reference: [SEI Architecture Tradeoff Analysis Method](https://www.sei.cmu.edu/library/the-architecture-tradeoff-analysis-method/)

### 6.3 Static relational modeling

Use Alloy for the finite structural model:

- capsules, ports, types, principals, capabilities, adapters, and plans;
- no dangling binding;
- every selected input is satisfied according to cardinality;
- every binding is type-compatible;
- authority only attenuates;
- one principal cannot receive a private provider from another principal's view;
- synchronous plans are acyclic;
- plan explanations cover all selected edges.

Alloy is designed to explore constrained relational structures and generate
counterexamples. Failure to find a counterexample is bounded evidence, not a
universal proof.

Reference: [Alloy](https://alloytools.org/about)

### 6.4 Temporal modeling

Use TLA+ for the live lifecycle:

~~~text
snapshot -> propose -> validate -> reserve -> commit -> run
                  \-> stale / reject / retry
run -> revoke -> quiesce -> release
run -> fault -> contain -> restart or invalidate
~~~

The model should interleave capsule load/unload, capability grant/revoke, catalog
epoch changes, planner retries, partial reservation, commit, and rollback. Its main
purpose is to find time-of-check/time-of-use and partial-commit errors before code.

Reference: [TLA+](https://lamport.org/tla/tla.html)

### 6.5 Executable reference semantics

Before tensor optimization, implement a small deterministic evaluator over sparse
Boolean relations. It is the semantic oracle for:

- hand-worked examples;
- property-based generated catalogs;
- differential tests against future backends;
- regression fixtures from real capsule manifests;
- explanation output;
- bounded recursive evaluation.

The optimized backend must agree with the reference evaluator on exact Boolean
programs.

### 6.6 Decision records

Every decision that changes semantics should have a small ADR:

- type identity and compatibility;
- provider ambiguity;
- recursion and cycle policy;
- plan snapshot/epoch behavior;
- route materialization;
- effect descriptions;
- learned-score interaction with hard validity;
- tensor backend activation.

This design document records the initial decisions; ADRs keep later reversals
visible.

## 7. System architecture

~~~mermaid
flowchart TB
    Artifacts[Signed capsules, manifests, WIT, install metadata]
    Registry[Live capsule registry and principal views]
    Providers[Exact host services and provider epochs]
    Grants[Actual capability and access projections]
    Health[Health, budgets, locality, runtime state]

    Artifacts --> Builder[Catalog builder and canonicalizer]
    Registry --> Builder
    Providers --> Builder
    Grants --> Builder
    Health --> Builder

    Builder --> Snapshot[Immutable principal-scoped catalog snapshot]
    Snapshot --> Compiler[Relation program compiler]
    Goal[Typed goal] --> Compiler

    Compiler --> Ref[Exact sparse reference evaluator]
    Compiler -. reserved .-> Tensor[Future Tensor Logic backend]

    Ref --> Candidate[Candidate plans and explanations]
    Tensor -. later .-> Candidate

    Candidate --> Validator[Exact plan validator]
    Snapshot --> Validator
    Registry --> Validator
    Providers --> Validator
    Grants --> Validator
    Health --> Validator
    Validator -->|valid| Validated[Validated plan]
    Validator -->|invalid or stale| Reject[Reject and explain]

    Validated -. future commit .-> Materializer[Transactional materializer]
    Materializer --> Existing[Existing registry, bus, dispatcher, and domains]
~~~

### 7.1 Trust boundary

The catalog builder, WIT parser, evaluator, and candidate plan are not authority.
They process untrusted artifact metadata under size and complexity limits.

The exact validator is part of the host policy-enforcement path. It:

- resolves every content hash and canonical type identity;
- reads actual runtime grants, never manifest-requested authority;
- verifies the principal view;
- applies effect and route policy;
- checks the current catalog and policy epochs;
- calculates the plan's authority union and budgets;
- rejects ambiguity when policy has not resolved it.

The materializer accepts only a ValidatedPlan value that cannot be constructed
through the public candidate API. A typestate or private constructor should enforce
that boundary in Rust.

## 8. Catalog model

### 8.1 Stable identities

Every identity used by a plan must be stable and content-bound:

~~~text
ArtifactId       = hash of installable capsule artifact
ComponentId      = ArtifactId + component-local id
HostServiceId    = measured implementation digest + contract version + provider class
OwnerId          = ArtifactId | ComponentId | HostServiceId
PortId           = OwnerId + direction + canonical interface path
TypeId           = canonical WIT shape/package identity fingerprint
AdapterId        = ArtifactId + adapter operation
PrincipalScope   = opaque principal/domain identity
CatalogEpoch     = monotonic snapshot generation
PolicyEpoch      = monotonic grant/policy generation
PlanId           = hash of canonical plan contents
~~~

Package name and semver are discovery metadata. They are not sufficient plan
identity.

### 8.2 Base relations

The first catalog should expose relations equivalent to:

~~~text
Artifact(artifact)
Component(artifact, component)
HostService(service, implementation, version)
Owner(port, owner)
OwnedByArtifact(owner, artifact)
Input(owner, port, type)
Output(owner, port, type)
Imports(owner, interface, version_requirement, optional)
Exports(owner, interface, exact_version)
Publishes(owner, topic_pattern, payload_type)
Subscribes(owner, topic_pattern, payload_type)
Visible(principal, artifact)
HostVisible(principal, service)
Running(principal, artifact, instance)
HostRunning(principal, service, instance)
Healthy(instance)
Granted(principal, artifact, capability)
HostGranted(principal, service, capability)
Requires(port, capability)
Effect(port, effect_class)
Located(instance, host_class)
Cost(instance, resource, quantity)
Adapter(adapter, source_type, target_type)
Pinned(policy, requirement, provider)
~~~

Not all relations are populated initially. Missing authority or effect information
must fail closed for automatic materialization.

### 8.3 Derived relations

Schematic Tensor Logic equations:

~~~text
TypeCompatible[out_type, in_type] =
    SameCanonicalType[out_type, in_type]

PortCompatible[out_port, in_port] =
    Output[src_owner, out_port, out_type]
  * Input[dst_owner, in_port, in_type]
  * TypeCompatible[out_type, in_type]

AuthorizedArtifact[principal, artifact] =
    Visible[principal, artifact]
  * RequiredCapabilitySetSatisfied[principal, artifact]

HostAuthorized[principal, service] =
    HostVisible[principal, service]
  * RequiredHostCapabilitySetSatisfied[principal, service]

AuthorizedOwner[principal, owner] =
    OwnedByArtifact[owner, artifact]
  * AuthorizedArtifact[principal, artifact]

AuthorizedOwner[principal, owner] +=
    HostAuthorized[principal, owner]

HealthyOwner[principal, owner] =
    OwnedByArtifact[owner, artifact]
  * Running[principal, artifact, instance]
  * Healthy[instance]

HealthyOwner[principal, owner] +=
    HostRunning[principal, owner, instance]
  * Healthy[instance]

DirectConnection[principal, out_port, in_port] =
    PortCompatible[out_port, in_port]
  * Owner[out_port, src]
  * Owner[in_port, dst]
  * AuthorizedOwner[principal, src]
  * AuthorizedOwner[principal, dst]
  * HealthyOwner[principal, src]
  * HealthyOwner[principal, dst]

AdaptedConnection[principal, out_port, in_port, adapter] =
    Output[src, out_port, type_a]
  * Adapter[adapter, type_a, type_b]
  * Input[dst, in_port, type_b]
  * AuthorizedOwner[principal, src]
  * AuthorizedOwner[principal, adapter]
  * AuthorizedOwner[principal, dst]
  * HealthyOwner[principal, src]
  * HealthyOwner[principal, adapter]
  * HealthyOwner[principal, dst]
~~~

Repeated named variables represent joins/contractions; variables projected out of
the result represent reduction. The reference evaluator implements the exact
Boolean interpretation.

Here `+=` denotes Boolean union of independently derived rows, not numeric
authority accumulation.

At extraction time, capsule-level imports, exports, publish declarations, and
subscribe declarations attach to the `ArtifactId` owner, with an identity
`OwnedByArtifact(artifact, artifact)` row. A declaration attaches to
a `ComponentId` only when a future manifest/WIT mapping or direct component
inspection proves that ownership. Host-provided interfaces attach to a
`HostServiceId` and use an explicit host-authorization relation rather than
pretending they are capsule artifacts.

### 8.4 Type compatibility

Initial automatic compatibility is deliberately strict:

1. the WIT package/interface/type identity is canonical;
2. the content-resolved type shapes match;
3. the import's semver requirement accepts the provider version;
4. direction and operation cardinality match;
5. no opaque payload participates in automatic typed composition;
6. an explicit signed adapter is required for conversion.

Structural record similarity is not enough. Package name and semver without a
resolved WIT fingerprint are not enough. A learned embedding may recommend a likely
adapter or authoring action, but it cannot create TypeCompatible.

This aligns with the Component Model: components are self-describing and compose
through typed imports and exports rather than shared memory.

Reference: [WebAssembly Component Model](https://component-model.bytecodealliance.org/design/components.html)

### 8.5 Effects and authority

Type compatibility says data can flow. It does not say execution is safe.

Each candidate must also account for:

- current principal visibility;
- current capsule-access grants;
- host capabilities used by each operation;
- state namespaces touched;
- network/process/device effects;
- whether an effect is local, remote, persistent, or destructive;
- resource budgets and concurrency limits;
- approval requirements;
- domain co-location and authority union.

Initially these may be conservative, operation-independent projections of the
capsule's granted host surface. Fine-grained per-operation effects require a
separate design and, if exposed to capsules, an RFC. The planner must never infer a
narrower effect than the host can enforce.

Planning and validation never replace enforcement at the host call. Every graphics,
network, storage, process, device, and IPC operation is checked again using the
principal and capability current for that invocation. A validated plan is an
authorized construction recipe, not a bearer token.

## 9. Tensor-ready program representation

### 9.1 Marked reservation

**Reserved, not active:** Tensor Logic execution, dense tensors, learned weights,
autodiff, GPU kernels, embedding-space reasoning, and optimizer integration.

The first crate must compile and test without those dependencies. No release,
security, or performance claim may imply that the reserved backend exists.

### 9.2 Why scaffold now

If the first evaluator is implemented as bespoke graph traversal, later Tensor
Logic integration would require translating an accidental API into tensor
equations. Instead, define the evaluator around the language's natural shape from
the start:

- named domains and indices;
- n-ary relations rather than node-specific structs;
- equation heads and expressions;
- product/join;
- union/addition;
- projection/reduction;
- bounded recursion/fixpoint;
- explicit step or threshold;
- optional weights and scores;
- derivation tracking.

The sparse Boolean evaluator is then one backend for the same program.

### 9.3 Proposed equation IR

~~~text
Program<W>
  domains: DomainId -> finite ordered values
  relations: RelationId -> RelationDecl<W>
  equations: ordered Equation<W>
  limits: EvaluationLimits

RelationDecl<W>
  name
  axes: [Axis { name, domain }]
  kind: input | derived | query
  value: Boolean | Weight(W)

Equation<W>
  head: RelationApplication
  body: Expression<W>

Expression<W>
  Relation(RelationApplication)
  Product([Expression])
  Sum([Expression])
  Project { expression, retain_axes }
  Apply { function, expression }
  Fixpoint { relation, seed, step, max_iterations }
  Constant(W)
~~~

This is illustrative, not a public wire commitment.

### 9.4 Backend boundary

~~~text
trait Evaluator<W> {
    evaluate(program, query, limits) -> Evaluation<W>
}

SparseBooleanEvaluator
  exact
  deterministic
  CPU
  sparse sets/maps
  explanation complete

FutureTensorLogicEvaluator
  named-index lowering
  sparse/dense tensor selection
  einsum contraction
  optional autodiff and learned weights
  must preserve exact Boolean semantics where applicable
~~~

Hard validity and learned preference remain distinct relations. A future tensor
backend may rank only candidates for which Valid is exactly true:

~~~text
EligiblePlan[p] = ExactValidity[p]
RankedScore[p]  = EligiblePlan[p] * LearnedScore[p]
~~~

No thresholded score substitutes for canonical type or capability validation.

### 9.5 Differential contract

For every finite exact program:

~~~text
normalize(reference(program, query))
    ==
normalize(tensor_backend(program, query))
~~~

The test corpus must include empty relations, duplicate rows, recursion, optional
ports, adapters, multiple providers, zero-result queries, and large sparse domains.
Floating scoring may differ within documented tolerance, but the valid candidate
set may not.

## 10. Planning model

### 10.1 Goal IR

A canonical goal should be typed and bounded:

~~~text
Goal {
  required_outputs
  provided_inputs
  principal_scope
  allowed_effect_classes
  denied_capabilities
  required_locality
  maximum_resource_cost
  maximum_adapter_depth
  maximum_plan_nodes
  provider_pins
  ambiguity_policy
}
~~~

Natural-language interpretation may create a Goal, but the Goal is what gets
planned, displayed, approved, hashed, and audited.

### 10.2 Candidate plan IR

~~~text
Plan<Proposed> {
  id
  catalog_epoch
  policy_epoch
  principal_scope
  goal
  nodes: component/artifact/instance selections
  bindings: output port -> input port
  adapters
  routes
  required_grants
  authority_union
  resource_budget
  lifecycle_order
  explanation
  evaluator_identity
}
~~~

Plans pin artifacts and canonical type identities. They do not contain ambient
package-name lookups that may resolve differently at execution.

### 10.3 Cardinality

Every input needs an explicit cardinality:

- exactly one;
- zero or one;
- one or more;
- zero or more;
- fan-out;
- reduce/aggregate.

The existing import optional flag distinguishes required from optional, but not
provider cardinality. Initial composition must assume exactly one provider for
required imports and zero-or-one for optional imports. Existing bus fan-out remains
unchanged outside materialized plans.

Adding a public cardinality declaration would change manifest semantics and needs a
separate RFC.

### 10.4 Ambiguity

When two providers are equally valid:

- return both candidates;
- honor an explicit operator or Distro pin when present;
- otherwise require a selection policy;
- never let hash-map iteration choose;
- record the selected policy and rejected alternatives.

A deterministic content-hash order is useful for stable display, not as an implicit
authority to choose a provider.

### 10.5 Cycles

Distinguish three graphs:

1. install/load dependency graph;
2. synchronous invocation graph;
3. asynchronous event/feedback graph.

Load and synchronous invocation plans must be acyclic initially. Asynchronous
feedback is allowed only across an explicit queue, delay, state, or event boundary
with bounded buffering and supervision. A cycle in names alone is insufficient to
decide safety.

The current topological-sort fallback to discovery order remains current behavior,
but the composition validator must reject an unsafe cycle rather than guess.

## 11. Exact validation

Validation is a fresh, deterministic pass over concrete plan contents.

It must verify:

1. the catalog and policy epochs are current;
2. every artifact hash is installed and visible to the principal;
3. every host service has the exact expected implementation identity and epoch;
4. every selected runtime instance is healthy or launchable;
5. every port belongs to the pinned owner;
6. every WIT identity and type fingerprint is exact;
7. every semver requirement is satisfied;
8. every adapter is explicit, installed, typed, and authorized;
9. every required input has the correct cardinality;
10. optional inputs are represented as absent rather than silently rebound;
11. opaque topics are excluded from automatic typed edges;
12. every host capability is currently granted;
13. the plan's authority union is within policy;
14. budgets and domain-placement constraints are satisfiable;
15. route patterns do not broaden publish or subscribe ACLs;
16. no forbidden synchronous cycle exists;
17. all plan IDs and explanations canonicalize deterministically.

The output is Plan<Validated>. Its constructor is private to the validator. A
ValidatedPlan must carry the epochs and a short validity lifetime or commit token so
it cannot be stored indefinitely and executed after revocation.

## 12. Materialization

### 12.1 Current gap

Astrid's current event bus routes by topic pattern and may fan out to all matching
subscriptions. It does not expose a plan-private point-to-point binding primitive.

Therefore the first composition implementation is read-only. It can:

- inspect;
- explain;
- find missing pieces;
- identify ambiguity;
- compare candidate Distros;
- propose explicit current-topic invocations;
- generate operator-reviewed configuration.

It must not pretend it can atomically rewire the live bus.

### 12.2 Future transaction

A later materializer should use a transaction-like protocol:

~~~text
begin(plan, expected catalog epoch, expected policy epoch)
  revalidate
  reserve instances, budgets, and handles
  construct private route overlay off-path
  quiesce replaced bindings if necessary
  compare epochs again
  append write-ahead audit decision; fail closed if it cannot be recorded
  atomically publish overlay
  append audit commit outcome
commit

on any failure:
  discard overlay
  release reservations and handles
  leave current routes unchanged
~~~

If current bus data structures cannot publish an overlay atomically, the design
must add that primitive before enabling live composition. Partial route mutation is
not acceptable.

### 12.3 Route choices

Candidate implementation approaches:

| Approach | Benefit | Cost/risk | Initial decision |
|---|---|---|---|
| Orchestrator capsule publishes existing topics | Reuses current bus and permissions | Fan-out and correlation may not express selected bindings | Useful for first end-to-end experiments |
| Plan-scoped route overlay in host | Exact provider binding and atomic replacement | New trusted host mechanism | Preferred eventual mechanism |
| Direct Component Model linking | Strong typed composition | Mismatched with dynamic IPC and independently supervised capsules | Use only for static library components |
| New point-to-point WIT host API | Explicit and portable | Public contract and RFC required | Defer until overlay prototype proves need |

### 12.4 Graphical WASM applications as a forcing function

A portable graphical game is a useful test of whether this is actually an operating
system architecture rather than an agent workflow engine. The answer is yes, but
only if the device plumbing is explicit.

A game capsule should not receive raw GPU ownership. It should receive revocable
handles to:

- a graphics device and queue with a fixed feature/limit set;
- a presentation surface with explicit size, format, focus, and visibility;
- an ordered input stream scoped to that surface;
- monotonic and frame clocks;
- an audio output stream or graph;
- optional storage, network, controller, and peer services.

These are separate typed services because their authority and lifecycle differ. A
headless renderer needs a GPU without a surface. A remote-streamed game needs an
offscreen texture and encoder rather than a local window. A UI can lose focus while
its GPU device remains alive. Composition should be able to express each case
without granting the union implicitly.

~~~mermaid
flowchart LR
    Game[WASM game component]
    Clock[clock service]
    Input[input and focus service]
    Audio[audio service]
    Surface[presentation/compositor service]
    Graphics[validated graphics service]
    Native[wgpu platform backend]
    Driver[host OS GPU driver]
    GPU[GPU]

    Clock --> Game
    Input --> Game
    Game --> Audio
    Game --> Graphics
    Surface --> Game
    Game --> Surface
    Graphics --> Native --> Driver --> GPU
    Surface --> Native
~~~

#### 12.4.1 Resource-shaped interface

Graphics is stateful and handle-heavy. It is not a good fit for JSON events per
draw call. WIT resources are the correct shape: the component holds opaque handles
whose actual buffers, textures, queues, encoders, and surfaces remain in a host
resource table. The Component Model explicitly supports resources as handles to
entities living in a host or another component.

A conceptual interface family—not a proposed Astrid WIT contract yet—would contain:

~~~wit
interface graphics {
    resource device { /* create buffers, textures, shaders, pipelines, encoders */ }
    resource queue { /* upload and submit finished command buffers */ }
    resource buffer;
    resource texture;
    resource command-encoder;
    resource command-buffer;
}

interface presentation {
    resource surface {
        configure: func(config: surface-config) -> result<_, surface-error>;
        acquire-frame: func() -> result<frame, surface-error>;
        present: func(frame: frame) -> result<_, surface-error>;
    }
}
~~~

The exact contract should track the WebAssembly `wasi:webgpu` work rather than
casually inventing another graphics API. As of 2026-07-17, that proposal is at WASI
Phase 2 and explicitly leaves displaying to a screen/window out of scope. Astrid
therefore still needs a presentation/compositor contract even if it adopts or
adapts `wasi:webgpu` for device access.

Astrid capsules currently target `wasm32-unknown-unknown`, not a WASI world. Tracking
the proposal means preserving compatible concepts and contributing where useful;
it does not mean granting ambient WASI or bypassing audited `astrid:*` host imports.
Any adopted public surface still follows Astrid's WIT/RFC process.

References:

- [WASI WebGPU proposal](https://github.com/WebAssembly/wasi-webgpu)
- [Component Model resources](https://component-model.bytecodealliance.org/language-support/using-wit-resources/rust.html)

#### 12.4.2 Capability decomposition

Do not use one `gpu = true` grant. At minimum, distinguish:

~~~text
graphics.adapter.inspect
graphics.device.create(feature_set, limits)
graphics.memory.allocate(max_bytes)
graphics.queue.submit(max_work, max_in_flight)
graphics.shader.compile(allowed_languages, max_size)
presentation.surface.create(display, bounds, visibility)
presentation.surface.present(surface)
input.surface.receive(surface, classes)
audio.output.open(device_class, channels, sample_rate)
~~~

The concrete capability system may encode these differently, but it must preserve
the distinctions. Handles are principal-scoped, non-forgeable, revocable, and
cannot be used with a device or surface from another authority domain. Delegating a
surface does not delegate arbitrary input observation; delegating a queue does not
delegate display capture.

The composition catalog represents these as required effects and host-service
ports. It may discover that a game can use the local Metal provider, a remote GPU
provider, or a software provider. Exact policy—not a learned score—decides which
locations, displays, input sources, and data egress paths are eligible.

#### 12.4.3 Command and data path

The event bus remains useful for coarse lifecycle events such as surface resize,
focus, controller attach, device loss, and application shutdown. It should not
carry a high-frequency render command as an individually routed envelope.

The intended fast path is:

1. the game invokes typed graphics imports directly;
2. the host validates descriptors and creates principal-owned resource handles;
3. bulk vertex, texture, and audio data crosses through bounded byte/stream writes;
4. the guest records work into a command-encoder resource;
5. `finish` produces a one-submit command-buffer resource;
6. queue submission validates ownership, limits, and resource states again;
7. presentation consumes only a frame belonging to the granted surface/device;
8. completion, device loss, and quota events return asynchronously.

Astrid already owns a principal-scoped `astrid:io/streams` resource surface. It is
a candidate transport primitive for bounded uploads, but measurement must decide
whether its current copy behavior and call granularity are suitable for frame-time
workloads.

WebGPU is a useful security and execution model here: commands and shaders are
validated before reaching a native driver, resources are initialized so one client
does not read another client's previous contents, and a device exposes an exact
requested feature/limit set. Its command-buffer model also avoids a synchronous
round trip to the physical GPU for each operation.

Reference: [WebGPU specification](https://gpuweb.github.io/gpuweb/)

The ABI still needs measurement. Graphics APIs can make tens of thousands of calls
per frame. If Component Model calls are too expensive, optimize beneath the same
resource contract with bounded command batching, buffer mapping, or an audited
shared-memory transport. Do not expose an untyped native command blob merely to win
a benchmark; that would move validation bugs into the GPU driver boundary.

#### 12.4.4 Where the real driver lives

There are three materially different deployments:

| Deployment | Graphics implementation | Kernel/device consequence |
|---|---|---|
| Astrid on macOS/Linux/Windows | Trusted graphics host service backed by `wgpu` | Existing Metal/Vulkan/D3D12/OpenGL stack owns the physical driver |
| Astrid native kernel in a VM | Trusted service over virtio-gpu or a similarly narrow virtual device | Kernel needs transport, interrupts, memory sharing, and isolation for that virtual device |
| Astrid native kernel on arbitrary hardware | Trusted user-mode GPU driver plus minimal privileged device mechanism | Kernel must safely expose PCI discovery, MMIO, interrupts, DMA/IOMMU mappings, reset, and power; vendor support is substantial work |

The [native-kernel scope](astrid-native-kernel.md) deliberately excludes GPU,
audio, and arbitrary PCI support from its initial machine profile. The graphics
track does not silently expand that scope; it supplies an explicit later bridge.

`wgpu` is attractive for the first path because it already presents one safe Rust
API over Vulkan, Metal, D3D12, and OpenGL, and supports WebGPU/WebGL when compiled
for browser Wasm. It is a provider implementation, not the Astrid contract or the
authority model.

More precisely, `astrid-graphics-wgpu` is an Astrid graphics API
provider/resource broker, not the physical GPU driver. On a conventional host the
vendor user/kernel driver, GPU scheduler, and memory manager remain host-OS
components. On a native host the exclusive device driver, resource virtualizer,
graphics API provider, and compositor are separately identified roles even if an
early prototype co-locates some of them.

The graphics provider is trusted to validate and account for resource use, but it
is not kernel policy or business logic. Run it in a supervised process/domain where
the host permits so a driver or shader-compiler failure does not take down routing,
capability state, or audit. The kernel's irreducible job remains handle isolation,
authority checks, budgets, revocation, and fault containment.

Reference: [wgpu documentation](https://docs.rs/wgpu/latest/wgpu/)

Reference: [Astrid Driver Domain Contract](astrid-driver-domain-contract.md)

A driver can be implemented in WASM only if a smaller trusted substrate gives it
the device primitives it needs. WASM does not make a GPU self-driving: DMA can
overwrite memory, interrupts must be delivered, MMIO ordering matters, and device
reset affects other principals. The useful architecture is a privileged but
isolated **driver domain** with narrowly typed PCI/MMIO/interrupt/DMA imports,
IOMMU-backed mappings where hardware permits, quotas, watchdogs, and revocation.
That domain could contain WASM driver logic while the native kernel retains the
irreducible mechanisms.

For a native Astrid image, virtual hardware is the sensible first graphics target.
Virtio-gpu exposes defined control queues and scanout/resource operations and lets
the hypervisor keep the vendor driver. Direct vendor GPU support should be treated
as a separate hardware program, not hidden inside the game milestone.

Reference: [OASIS virtio 1.4 specification](https://docs.oasis-open.org/virtio/virtio/v1.4/virtio-v1.4.pdf)

#### 12.4.5 Failure and security cases

The graphics design is incomplete unless it handles:

- invalid or adversarial shaders and descriptors;
- GPU memory exhaustion and per-principal residency limits;
- infinite/very long shaders, queue starvation, and hidden compute abuse;
- command buffers referencing destroyed or foreign resources;
- zero-initialization before a resource becomes visible to a new principal;
- surface resize, loss, occlusion, focus transfer, and display removal;
- device loss, driver reset, and re-creation without stale handles;
- input capture only while the correct surface/focus grant is live;
- timing and contention side channels between GPU tenants;
- screenshots, external textures, video decode, and display capture as separate
  authority, not consequences of presentation;
- deterministic simulation time separated from presentation time;
- frame/audio backpressure without blocking the kernel or event dispatcher.

Some risks cannot be perfectly eliminated on commodity shared GPUs. The system
must state that honestly, expose deployment policy such as dedicated-device or
software-rendering modes, and never claim that a WASM sandbox alone isolates GPU
microarchitectural side channels.

#### 12.4.6 First playable slice

The first credible demonstration should run on the existing host-native Astrid,
not wait for a native GPU driver:

1. a trusted `astrid-graphics-wgpu` host provider;
2. one local presentation provider with one operator-granted surface;
3. surface-scoped keyboard/pointer input and monotonic/frame clocks;
4. a WASM component rendering a triangle, then a small deterministic game;
5. fixed graphics limits, memory/queue budgets, shader validation, and device-loss
   tests;
6. catalog relations showing exactly why the game can connect to those providers;
7. an explicit launch plan—the Tensor Logic backend remains inactive;
8. a headless/noop provider for deterministic contract and lifecycle tests.

Audio, controllers, networking, remote presentation, and native-kernel virtio-gpu
then extend the same service graph. The game code remains portable because the
WIT/resource contract stays stable while providers change.

#### 12.4.7 Authoring and scheduling path

“Can run a game” must become a developer workflow, not merely a host ABI. The SDK
needs a small platform facade generated from WIT so game code does not depend on a
browser DOM, JavaScript glue, POSIX, or a native window handle.

A first game world should make these boundaries explicit:

~~~text
imports:
  graphics resources
  one granted presentation surface
  surface-scoped input
  monotonic/frame clocks
  read-only content-addressed assets
  optional audio, state, and network services

exports:
  initialize
  fixed simulation tick or bounded run step
  resize/focus/device-loss handlers
  suspend/resume
  shutdown
~~~

The supervisor, not an unbounded guest loop, owns frame scheduling. It supplies
batched input and time, meters fuel/wall time, applies backpressure, and can suspend
an occluded application. Simulation time is explicit so tests can replay the same
input/tick sequence independently of display refresh and GPU completion.

Assets are packaged or content-addressed and opened through bounded Astrid storage
or stream resources; games do not gain an ambient filesystem. The normal
`astrid capsule build` path must produce the installable artifact, validate its WIT
world and shaders, and declare requested device/service authority for operator
review. Rust can be the first supported authoring toolchain, but the contract must
remain language-neutral so other Component Model toolchains can follow.

## 13. Library sketch

The first implementation should be one crate with strong internal modules, not a
constellation of premature packages:

~~~text
crates/astrid-composition/
  src/
    lib.rs
    ids.rs             content-bound domain newtypes
    catalog.rs         immutable catalog and indices
    extract.rs         manifest, WIT, registry, host-service, grant projections
    canonical.rs       stable ordering, fingerprints, hashes
    relation.rs        domains, axes, relation declarations
    equation.rs        backend-neutral program IR
    rules.rs           Astrid base and derived equations
    goal.rs            canonical goal IR
    backend.rs         evaluator trait and limits
    sparse.rs          exact sparse-Boolean evaluator
    plan.rs            proposed/validated typestates
    validate.rs        exact fresh validation
    explain.rs         derivation tree and diagnostics
    scenario.rs        fixture helpers and golden outputs
~~~

No runtime mutation module belongs in the first crate revision.

### 13.1 Core type sketch

~~~rust
pub struct CompositionCatalog {
    epoch: CatalogEpoch,
    policy_epoch: PolicyEpoch,
    // Canonical ordered domains and base relations.
}

pub struct CatalogSnapshot<P> {
    catalog: CompositionCatalog,
    principal: P,
}

pub struct Program<W> {
    domains: Vec<Domain>,
    relations: Vec<RelationDecl<W>>,
    equations: Vec<Equation<W>>,
    limits: EvaluationLimits,
}

pub trait Evaluator<W> {
    type Error;

    fn evaluate(
        &self,
        program: &Program<W>,
        query: &Query,
    ) -> Result<Evaluation<W>, Self::Error>;
}

pub struct Plan<S> {
    state: S,
    body: PlanBody,
}

pub struct Proposed;
pub struct Validated {
    commit_guard: CommitGuard,
}

pub struct PlanValidator<A> {
    authority: A,
}
~~~

The exact generic bounds are implementation work. The architectural requirements
are:

- principal scope is carried by type or immutable value;
- evaluator backend is generic;
- proposed and validated plans are distinct;
- content IDs are domain-bearing newtypes, not strings;
- public wrappers remain additive and generic where a backend or authority provider
  varies;
- serialization exists for canonical goals, candidates, explanations, and fixtures;
- Validated internals cannot be deserialized from an untrusted candidate.

### 13.2 Catalog builder inputs

Use traits so the pure library can be tested without a daemon:

~~~rust
trait ManifestSource { ... }
trait WitResolver { ... }
trait RegistryView { ... }
trait HostServiceView { ... }
trait AuthorityView { ... }
trait HealthView { ... }
trait ClockOrEpochSource { ... }
~~~

Production adapters live at the core composition root. Test adapters use in-memory
fixtures. The library never reads ambient home directories, environment variables,
or global process state.

### 13.3 Existing code reuse

The initial implementation should extract, not duplicate:

- import_satisfied_by;
- import/export indexing;
- unsatisfied import calculation;
- dependency adjacency;
- deterministic topological ordering;
- topic-pattern matching;
- principal capsule visibility;
- schema-catalog WIT references.

Existing readiness and topological-sort functions should delegate to the extracted
exact catalog helpers, with regression tests proving unchanged results.

## 14. Repository ownership

### 14.1 Does this need another repository?

Not initially.

The Astrid integration belongs in core because it consumes:

- CapsuleManifest;
- the live CapsuleRegistry;
- principal views and CapsuleAccessResolver;
- schema catalog and WIT stores;
- event routing and lifecycle;
- kernel resource/budget views.

Creating a new Astrid repository would make atomic refactors and compatibility
testing harder before the API exists.

### 14.2 Generic Tensor Logic ownership

The general Tensor Logic language, compiler, and tensor backends should remain
independent of Astrid. If an existing tensor-logic repository is the intended home,
Astrid should consume a versioned library from it only after the equation IR and
backend contract are stable.

Do not create a third repository solely for an adapter. Start with:

~~~text
core/crates/astrid-composition
  exact Astrid catalog, IR, sparse evaluator, validator

external tensor-logic library, later
  general language/compiler/tensor backend

core adapter module or crate, later
  converts Astrid Program into the external Tensor Logic representation
~~~

Split an adapter crate only when dependency weight or release cadence proves the
boundary.

### 14.3 Other repositories

- **wit:** unchanged initially. A new public plan/materialization contract requires
  an RFC and canonical WIT update.
- **sdk-rust/sdk-js:** unchanged initially. Add authoring helpers only after a
  public composition annotation is accepted.
- **astrid-rfcs:** use only for new manifest or WIT contract surfaces, not for the
  internal catalog experiment.
- **native kernel:** no dependency. The composition engine lives in the system
  plane and should run above either the daemon or native-kernel host.

## 15. Preserving current behavior

Compatibility is a first-class invariant.

### 15.1 Disabled mode

When composition is disabled:

- manifests deserialize exactly as today;
- load order matches current tests;
- readiness results match current tests;
- topic routing and fan-out are unchanged;
- capability enforcement is unchanged;
- no additional capsule is required;
- no model or tensor dependency is loaded;
- boot succeeds if the composition catalog cannot be built.

### 15.2 Inspect mode

The first user-visible mode is read-only:

~~~text
astrid compose inspect
astrid compose explain <goal fixture>
astrid compose check <distro or installed set>
~~~

Names are illustrative. Inspect mode may report:

- satisfiable and missing imports;
- all compatible providers;
- ambiguity;
- WIT identity drift;
- unsafe/unknown opaque edges;
- candidate adapter chains;
- authority union;
- synchronous cycles;
- catalog epoch and artifact pins.

It cannot mutate routes or grants.

### 15.3 Shadow mode

The runtime may evaluate goals beside current explicit behavior and record:

- which plan it would select;
- whether that matches the actual execution;
- why they differ;
- evaluation latency and candidate count;
- whether a later registry/grant change would stale the plan.

Shadow output is diagnostic only and must be rate- and size-limited.

### 15.4 Opt-in execution

Execution becomes possible only after:

- exact validator tests pass;
- a materialization mechanism exists for the required plan shape;
- operator configuration enables it;
- current explicit behavior remains the fallback;
- rollback is tested;
- audit identifies evaluator and exact plan hash.

No release may silently change current fan-out into provider selection.

## 16. Theory scenarios

The following scenarios are architecture tests. Each should become a fixture,
property test, Alloy command/assertion, TLA+ trace, or end-to-end test as indicated.

### 16.1 Normal composition

| Scenario | Expected result |
|---|---|
| One required import, one exact provider | One candidate; exact explanation |
| Required and optional imports both satisfied | Both bound according to cardinality |
| Optional import absent | Valid reduced plan with explicit absence |
| Multi-step explicit adapter chain | Valid if every adapter is visible and authorized |
| Same capsule set in different input order | Canonical catalog and plan IDs unchanged |
| Same signed capsules on daemon and native host | Same logical candidates; host-specific availability may differ explicitly |

### 16.2 Provider ambiguity

| Scenario | Expected result |
|---|---|
| Two exact providers, no pin | Ambiguous candidate set; no silent execution |
| Operator pins one provider | Pinned candidate selected and explained |
| Pinned provider unhealthy | Reject or fall back only if policy explicitly permits |
| Learned backend prefers provider B | B may rank first only after exact eligibility |
| Equal learned scores | Stable presentation; explicit ambiguity remains |
| Provider added after a plan is validated | Existing plan remains pinned; new planning sees it |

### 16.3 Type and version behavior

| Scenario | Expected result |
|---|---|
| Same namespace/name, incompatible semver | No direct edge |
| Matching semver, different WIT fingerprint | Reject as type drift |
| Structurally similar records, different identity | No implicit edge |
| Explicit signed adapter bridges versions | Adapter candidate appears |
| Adapter requires unavailable capability | Candidate invalid for that principal |
| Opaque publisher and typed subscriber | No automatic typed connection |
| Two wildcard topics claim different WIT types | Catalog conflict and no automatic edge |
| Old capsule uses a still-supported published WIT version | Existing host compatibility remains unchanged |

### 16.4 Principal and authority behavior

| Scenario | Expected result |
|---|---|
| Principal A sees provider; B does not | Only A's snapshot contains it |
| Shared runtime hash visible to A and B | Plans remain separately principal-scoped |
| Manifest requests capability not granted | Relation uses actual grant; candidate fails |
| Grant revoked after proposal | Exact validation fails |
| Grant revoked after validation before commit | Commit guard fails and retries/rejects |
| Learned score favors unauthorized provider | Provider absent from eligible set |
| Adapter broadens authority union | Explanation exposes union; validator applies policy |
| Admin wildcard access | Explicit admin policy path, never inferred from capsule metadata |

### 16.5 Lifecycle and concurrency

| Scenario | Expected result |
|---|---|
| Capsule unloads during evaluation | Snapshot result may complete but validation sees stale epoch |
| Capsule unloads during reservation | Transaction rolls back |
| Capsule crashes after commit | Supervisor invalidates or restarts pinned node according to policy |
| Capsule upgrades to new content hash | Existing plan is stale; no name-based substitution |
| Two planners commit conflicting routes | Only one epoch/route transaction commits |
| Planner crashes | Current routes remain live |
| Validator crashes | No candidate is materialized |
| Audit append fails | Policy decides fail-closed before route publication |
| System restarts | Catalog rebuilds from signed artifacts and live grants; candidates are reproducible |

### 16.6 Cycles and recursion

| Scenario | Expected result |
|---|---|
| A synchronously calls B, B calls A | Reject |
| A publishes event consumed by B, B later publishes to A | Allowed only with explicit async boundary and limits |
| Recursive adapter search reaches fixed point | Terminates within configured bound |
| Recursive rule grows new domain values | Rejected; domains are finite per snapshot |
| Adapter graph contains zero-cost cycle | Deduplicate states and enforce depth/budget |
| Tensor/backend recursion does not converge | Evaluation limit error; no partial plan |

### 16.7 Scale and denial of service

| Scenario | Expected result |
|---|---|
| Empty catalog | Empty candidate set with useful explanation |
| Thousands of capsules and sparse ports | Indexed sparse evaluation; bounded memory |
| Capsule declares enormous WIT or manifest | Existing and new parser size limits reject |
| Capsule creates combinatorial adapter graph | Goal node/depth/candidate budgets stop search |
| Wildcard produces huge topic expansion | Symbolic pattern relation; no unbounded enumeration |
| Repeated identical query | Optional cache keyed by all epochs and goal hash |
| Principal churn | Bounded snapshot/cache lifetime and eviction |
| Malicious backend returns enormous result | Output limits before candidate deserialization |

### 16.8 Backend behavior

| Scenario | Expected result |
|---|---|
| Tensor backend absent | Exact reference engine works |
| Tensor backend fails to initialize | Fall back to reference/shadow policy; never skip validation |
| Tensor and reference disagree on Boolean candidates | Test/production alarm; no auto-materialization |
| Floating score is NaN or infinite | Reject score and retain exact candidates |
| Model weights change | Evaluator identity and weight digest change plan explanation |
| Nondeterministic GPU reduction | Allowed only for ranking; exact candidate set and validation deterministic |
| Adversarial model output | Treated as untrusted candidate data |

### 16.9 Preservation behavior

| Scenario | Expected result |
|---|---|
| Composition crate present but disabled | Byte-for-byte equivalent external behavior |
| Catalog build fails | Warning/diagnostic; normal boot and routing continue |
| Existing dependency cycle | Existing boot behavior retained outside compose inspection |
| Duplicate current exporters | Existing warning/fan-out retained; compose reports ambiguity separately |
| Existing capsule has no imports/exports | It remains loadable; composition sees only declared topic/tool ports |
| Existing opaque proxy | It remains usable explicitly; excluded from automatic typed connection |

### 16.10 Dock and AI-native OS behavior

| Scenario | Expected result |
|---|---|
| Dock adds a website application capsule | New typed ports enter next catalog epoch |
| Dock needs ingress, identity, and KV | Planner finds only providers visible and granted to the principal |
| Local ingress unavailable but remote exists | Locality constraint decides; topology is not hidden |
| App removed | New plans exclude it; committed plan follows quiesce/invalidation policy |
| Natural-language goal is underspecified | Goal construction asks for/derives explicit constraints before planning |
| Goal has no satisfying plan | Explain the minimal missing interfaces/capabilities |
| Several plans satisfy goal | Return alternatives with authority, cost, and locality tradeoffs |

### 16.11 Graphical WASM game behavior

| Scenario | Expected result |
|---|---|
| Local graphics, presentation, clock, and input providers are eligible | Exact launch plan identifies every provider and authority union |
| GPU exists but no surface grant exists | Headless rendering may plan; local presentation cannot |
| Surface is granted but input is not | Rendering works; no keyboard/pointer events are delivered |
| Local and remote presentation providers exist | Locality/egress policy keeps alternatives explicit; no silent remote stream |
| Game requests an unsupported GPU feature | No device is created; explanation names the missing feature/limit |
| Game requests excessive GPU memory | Exact budget check rejects before allocation and host boundary rechecks |
| Shader or command descriptor is invalid | Graphics provider returns a validation error before native driver submission |
| Command buffer contains a foreign handle | Reject; resource ownership is principal/device scoped |
| Surface resizes between acquire and present | Defined stale-frame/surface error; game reconfigures without stale handle reuse |
| Device is lost during a frame | Handles invalidate; bounded recovery or clean termination, never host crash |
| Focus moves to another surface | Input grant/event routing changes atomically; old surface receives no new input |
| Guest submits faster than GPU completes | Per-principal in-flight limit/backpressure, not unbounded queue growth |
| Two games share one GPU | Separate handles/budgets; acknowledge residual timing/contention side channels |
| Headless/noop provider is selected in tests | Resource lifecycle is testable without claiming rendered pixels |
| Host provider changes Metal to Vulkan | Game artifact and WIT contract remain unchanged |
| Native VM uses virtio-gpu | Same upper contract; different explicitly identified provider and limits |
| Physical driver domain crashes | Kernel revokes device handles, resets where possible, and isolates other domains |

## 17. Invariants and model checks

### 17.1 Safety invariants

1. **Type soundness:** every materialized binding has exact canonical type
   compatibility or an explicit validated adapter chain.
2. **Authority attenuation:** a plan cannot obtain a capability absent from the
   principal and selected owner grants.
3. **Principal isolation:** no private view, state namespace, or grant crosses
   principal scope through composition.
4. **Artifact pinning:** execution uses exactly the validated content hashes.
5. **Snapshot consistency:** stale catalog or policy epochs cannot commit.
6. **Atomic visibility:** a route overlay is entirely old or entirely new.
7. **No score authority:** scoring changes order, never eligibility.
8. **Bounded work:** planning and recursion have hard limits.
9. **Explainability:** every selected node, edge, adapter, grant, and rejection has
   a derivation.
10. **Compatibility:** disabled composition does not change current behavior.

### 17.2 Useful algebraic laws

For the exact backend:

- relation union is associative, commutative, and idempotent;
- join is associative where axis/domain typing permits;
- projection distributes over union;
- canonicalization is idempotent;
- catalog construction is independent of input iteration order;
- adding an unrelated invisible capsule does not change a principal's candidates;
- removing a provider removes all plans pinned to it;
- adding a provider can add alternatives but cannot silently change a pinned plan;
- validation is deterministic for the same epochs and inputs;
- explanation normalization is deterministic.

These should be property-based tests.

### 17.3 Alloy assertions

The first Alloy model should check finite scopes for:

- no selected edge without compatible types;
- no selected artifact/component or host service outside the principal projection;
- no required input with zero providers;
- no exactly-one input with two providers;
- no authority in Plan.required absent from Principal.granted;
- no unaccounted adapter;
- no synchronous cycle;
- no valid committed plan with stale epochs;
- no cross-principal artifact view leak.

Generate examples as well as counterexamples. Seeing valid small topologies is part
of validating that the constraints are not accidentally impossible.

### 17.4 TLA+ properties

The lifecycle model should check:

~~~text
Safety:
  committed implies validated
  committed epochs equal current epochs at commit
  visible routes are old overlay or new overlay, never partial
  revoked handles are not reachable from a running invalidated plan
  failed reservation eventually releases every reserved resource

Liveness under stated fairness:
  a non-stale valid plan can eventually commit
  a revoked running plan eventually quiesces or is forcibly stopped
  a failed planner does not prevent current explicit routes from progressing
~~~

### 17.5 Claim boundary

The design cannot literally test every possible real system. Rigor means:

- exhaustive bounded structural exploration;
- exhaustive bounded lifecycle interleavings;
- algebraic property tests over generated catalogs;
- a curated scenario corpus;
- differential backend testing;
- real end-to-end fault injection.

Each method has a stated scope. None should be described as a proof beyond that
scope.

## 18. Security review

### 18.1 Untrusted inputs

Treat all of these as untrusted:

- manifests;
- WIT files and component metadata;
- registry metadata;
- natural-language goals;
- evaluator programs and learned weights;
- candidate plans and explanations;
- adapter claims;
- runtime health reports from capsules.

Parsers need byte, depth, count, recursion, and time limits. Catalog identities come
from host verification and content hashes, not self-asserted IDs.

### 18.2 Information exposure

A principal-scoped snapshot must not reveal:

- capsules installed only for another principal;
- secret values or environment data;
- capability tokens;
- hidden route names whose existence is sensitive;
- other principals' health/activity;
- private model weights without authorization.

The evaluator should receive symbolic capability classes or opaque IDs, never bearer
tokens.

### 18.3 Confused deputy risks

The planner can compose a low-authority caller with a high-authority service. The
validator must check the service's delegation policy, caller stamping, and resulting
authority, not merely whether both nodes are individually visible.

An edge means “type-compatible,” not “permitted delegation.” Those are separate
relations joined only during eligibility.

### 18.4 Explanation safety

Explanations are important but may leak catalog topology or denied capabilities.
Generate them through the same principal projection and redact sensitive policy
details while retaining a stable reason code.

### 18.5 Learned backend

A future learned backend expands the attack surface:

- poisoned weights;
- adversarial goals;
- unstable ranking;
- model extraction through explanations;
- denial of service through expensive queries;
- backend native/GPU vulnerabilities.

It belongs in a restricted system capsule or process where feasible. Its output
remains a bounded candidate plan validated by the host.

## 19. Performance model

The exact engine should optimize for sparse catalogs:

- intern canonical domains and IDs;
- index providers by type and interface;
- index ports by direction and WIT identity;
- push principal/authority filters before joins;
- represent wildcard topics symbolically;
- memoize bounded relation results per catalog/policy epoch;
- avoid materializing the global all-pairs connection relation;
- evaluate goal-directed slices;
- cap candidates, adapter depth, fixpoint iterations, memory, and wall time;
- make explanations optional but reproducible.

Measure:

- catalog build/update time;
- snapshot size per principal;
- candidate count before and after hard filters;
- exact evaluation latency;
- explanation cost;
- memory at 100, 1,000, and 10,000 components;
- invalidation latency after unload/revocation;
- reference versus future tensor backend agreement and performance.

The first benchmark should use generated sparse manifests plus a corpus of real
Astrid capsule manifests.

## 20. Tradeoffs

| Decision | Gains | Costs |
|---|---|---|
| Exact reference backend first | Determinism, semantic oracle, no heavy dependency | Does not yet learn or exploit GPU tensor algebra |
| Strict canonical type identity | Sound automatic composition | More explicit adapters |
| Principal snapshot before planning | Privacy and correct authority | Less cache sharing |
| Read-only introduction | Preserves runtime and exposes model errors safely | Delays visible automation |
| One core crate initially | Easy atomic refactor and testing | Generic language boundary remains provisional |
| Host exact validator | Authority remains below AI language | Trusted code and duplicate semantic checks to minimize |
| Plan-scoped route overlay later | Exact provider selection and rollback | New host mechanism |
| Explicit ambiguity | No accidental provider authority | More operator/policy decisions |
| Bounded recursion | Availability | Some valid large plans need adjusted limits |
| Backend-neutral IR now | Later Tensor Logic activation without redesign | More care than bespoke graph traversal |

Sensitivity points:

- type identity rules;
- provider cardinality;
- route atomicity;
- catalog epoch granularity;
- effect metadata quality;
- evaluator result limits;
- domain placement and authority union;
- whether the external Tensor Logic library's IR matches Astrid's reserved seam.

## 21. Questions and current answers

### Does this need another repository?

No new Astrid repository now. Put the Astrid-specific exact library in core. Keep
the general Tensor Logic implementation independent and integrate later through the
reserved backend.

### How do we preserve what currently works?

Extract existing matching semantics into shared pure helpers; keep current callers;
start read-only; default composition off; do not change routing, WIT, or manifests;
use differential regression tests against readiness/toposort results.

### Should Tensor Logic itself be a capsule?

Eventually, likely yes for learned and heavyweight evaluation. The exact catalog
and validator remain host libraries. A Tensor Logic planner capsule can receive a
bounded principal-projected program and return candidate plans over IPC. This keeps
AI policy outside the kernel and makes the backend replaceable.

The first sparse evaluator should remain an in-process pure library because it is
the semantic oracle and design harness, not an intelligent service.

### Is the graph stored?

No. Base relations are derived from artifacts and runtime state. Connections and
plans are query results. Caches are epoch-bound and disposable.

### Are WIT imports/exports enough?

They are the type foundation, but not the whole safety decision. Composition also
needs direction, version, actual authority, effects, cardinality, runtime health,
locality, budgets, and delegation policy.

### Can Tensor Logic infer new adapters?

It may recommend or synthesize candidate adapter code in a future workflow, but an
adapter becomes usable only after normal build, signature, WIT, install, review,
capability, and exact-validation paths. An embedding similarity is not an adapter.

### Does every capsule become dynamically wired?

No. Static explicit configurations remain valid. Some services may deliberately
forbid automatic composition. Composition is an additional way to derive a plan.

### Who chooses among providers?

Explicit pins and operator/Distro policy first. Later learned ranking may order
eligible alternatives. Ambiguity without policy remains visible.

### How is a natural-language request grounded?

An AI model produces a typed Goal using catalog-visible types and constraints. Goal
validation happens before planning. Unknown or ambiguous terms become questions or
multiple goal candidates, not invented ports.

### What is the kernel primitive?

None specific to Tensor Logic. The native kernel needs capability-bearing domains,
IPC endpoints, budgets, and revocation. Composition remains a system-plane program.

### Can a WASM capsule drive a GPU?

Yes through typed, capability-checked host resources; not by magic and not safely by
receiving raw hardware. On a conventional host, a trusted graphics provider can
translate the resource API through `wgpu` to the platform driver. On a native
Astrid kernel, a WASM driver domain would still require privileged PCI/MMIO,
interrupt, DMA/IOMMU, reset, and memory-sharing mechanisms from the kernel. Start
with the host provider, then virtio-gpu; treat arbitrary vendor hardware as its own
long-running driver program.

### Does graphical support belong to Tensor Logic?

No. Graphics, presentation, input, audio, and clocks are typed services. The exact
composition model can discover and validate a launch graph. Tensor Logic may later
rank viable providers or reason about placement, but it is not on the render path
and is not required to run a game.

### What would force a public RFC?

- new manifest cardinality/effect/adapter declarations;
- public goal/plan WIT;
- a point-to-point or plan-route host interface;
- component-visible composition introspection;
- any change to existing publish/subscribe or import/export semantics.

### When should the tensor backend be activated?

Only when:

- the exact IR and reference evaluator are stable;
- a real workload benefits from learned or tensorized inference;
- differential exact tests pass;
- backend resource limits and isolation exist;
- evaluator/weight identity is auditable;
- failure falls back safely;
- no security decision depends solely on a floating score.

## 22. Implementation gates

### Gate A: design corpus

Deliver:

- this design review;
- ten or more real capsule catalog fixtures;
- canonical expected relations;
- hand-worked plans and explanations;
- initial Alloy structural model;
- initial TLA+ lifecycle model;
- ADRs for type identity, ambiguity, and epochs.

Exit:

- valid examples exist;
- counterexamples expose intentionally invalid cases;
- no unresolved question changes the catalog's fundamental identities.

### Gate B: exact pure library

Deliver:

- astrid-composition crate;
- catalog and named-index equation IR;
- sparse Boolean evaluator;
- exact explanations;
- property-based tests;
- generated scale fixtures;
- no daemon integration and no tensor dependency.

Exit:

- current readiness/toposort compatibility cases agree;
- input-order independence holds;
- all safety scenario fixtures pass;
- evaluation limits fail closed.

### Gate C: read-only Astrid integration

Deliver:

- production catalog adapters;
- canonical WIT resolution/fingerprinting;
- principal-projected inspect commands/API;
- ambiguity, drift, authority-union, and missing-interface reports;
- catalog epoch invalidation on load/unload/grant changes.

Exit:

- normal boot/routing behavior is unchanged;
- catalog failure cannot block boot;
- cross-principal visibility tests pass.

### Gate D: shadow planning

Deliver:

- typed Goal fixtures;
- candidate planning beside current behavior;
- plan/execution comparison;
- evaluator identity and plan audit diagnostics;
- performance telemetry with bounded cardinality.

Exit:

- plans explain current successful workflows;
- disagreement is understood;
- no candidate can bypass exact validation.

### Gate E: first explicit execution

Choose one workflow expressible through existing routes. Require operator opt-in.

Deliver:

- Proposed/Validated typestate;
- fresh authority validation;
- pinned artifacts and epochs;
- fault/rollback tests;
- explicit current-behavior fallback.

Exit:

- stale/revoked plans cannot execute;
- the chosen workflow survives planner failure;
- no global routing semantics change.

### Gate F: transactional materialization

Only if real workflows require private bindings.

Deliver:

- route overlay prototype;
- TLA+ model checked against implementation protocol;
- atomic commit/rollback;
- quiesce and upgrade behavior;
- RFC for any public contract.

Exit:

- partial route state is impossible in the model and fault-injection tests;
- current routes remain available through planner/materializer failure.

### Gate G: optional Tensor Logic backend

This gate is marked **future and inactive**.

Deliver:

- adapter to the general Tensor Logic implementation;
- einsum/named-index lowering;
- exact Boolean differential suite;
- learned ranking workload;
- backend isolation and resource limits;
- deterministic evaluator and weight identities;
- no change to exact validation.

Exit:

- measurable benefit over the reference backend on a real composition workload;
- exact candidates agree;
- failure cleanly returns to reference or explicit behavior.

### Independent graphics track

Graphics validates the general service model but does not wait for Gate G.

**Graphics contract experiment**

- compare `wasi:webgpu`, current WIT resource support, and Astrid's
  `wasm32-unknown-unknown` host binding model;
- specify separate graphics, presentation, input, clock, and audio authorities;
- prototype resource-table lifecycle and command-call overhead outside the public
  WIT repository;
- build a threat model around shader validation, driver exposure, GPU memory,
  queue denial of service, and surface/input capture;
- open an RFC before any public Astrid WIT is adopted.

**Host-native playable slice**

- implement a `wgpu` provider and one desktop presentation/input provider;
- render a deterministic sample game from a capsule artifact;
- enforce fixed device features, memory, in-flight work, focus, and surface grants;
- test malformed shaders/commands, foreign handles, resize, backpressure, device
  loss, and provider crash;
- expose the providers in the exact catalog and inspect the explicit launch plan;
- keep the Tensor Logic backend disabled.

**Native-kernel bridge**

- preserve the upper resource contract;
- implement a virtio-gpu provider and minimal presentation/input path in a VM;
- measure copies, Component Model call overhead, frame pacing, and reset behavior;
- only then decide whether a WASM driver domain and direct hardware primitives are
  justified.

## 23. Recommended next artifact

Do not start with a tensor library or live planner.

Create the finite design harness:

1. extract ten representative Capsule.toml manifests and their WIT references into
   sanitized fixtures;
2. define the canonical domains and base relations;
3. hand-write expected connections and three goal plans, including one graphical
   game goal whose GPU, surface, input, and clock are distinct providers;
4. write the Alloy model for type, authority, cardinality, and principal isolation;
5. write the TLA+ model for snapshot/validate/commit versus unload/revoke;
6. sketch the Rust IR against those fixtures;
7. review whether every relation can be sourced from current trusted state;
8. only then create astrid-composition.

That is the rigorous way to “run it in our heads”: diagrams communicate the
components, scenarios exercise quality attributes, Alloy exhausts small structural
worlds, TLA+ exhausts small temporal interleavings, and the sparse reference
evaluator makes the semantics executable before optimization.

## 24. Success criterion

The design succeeds when Astrid can answer, for a principal and typed goal:

~~~text
Here are all exact executable compositions currently possible.
Here is what each requires and may affect.
Here is why each edge exists.
Here are the missing or ambiguous pieces.
Here is the exact artifact-pinned plan you selected.
Here is the authority the host will enforce.
~~~

Later, Tensor Logic can learn, rank, and reason over the same relation program.
Nothing about that later intelligence should require weakening the exact plan or
kernel boundary designed now.

The resulting OS principle is:

> Astrid does not encode what the world knows. It continuously computes what its
> signed components can validly become together, for this principal, under this
> authority.
