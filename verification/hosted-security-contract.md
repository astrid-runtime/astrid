# Security contract for hosted Astrid

## Claim to be established

For each supported hosted configuration, every privileged effect caused by an untrusted guest or external caller must correspond to an admission permitted by the authority policy. The admission identifies the effective principal, its generation, the operation and its target. A forwarded request must retain authenticated provenance. Redirects, aliases, transferred handles and deferred work must preserve the authorization for the actual effect.

The specification must identify the admission point for each operation. Revocation prevents subsequent admissions under the revoked grant. A previously admitted operation may finish where the interface permits it. Acknowledged durable revocation survives every supported restart. A single-use grant permits at most one successful admission across retries and restarts. Reissuing an alias must never transfer the authority of its previous owner.

## How to discharge the claim

A refinement proof must map each production execution to a permitted sequence of abstract events. Internal steps may leave the abstract state unchanged. Each externally visible effect requires a matching admission. Recovery must reconstruct a state consistent with the acknowledged durable history. The argument must include concurrent calls, canceled futures, errors after a durable write and recovery before admission reopens.

The production Wasmtime linker uses the synthetic world in `crates/astrid-capsule/src/engine/wasm/bindings.rs`. It imports 18 versioned interfaces, including both HTTP and process versions, resource methods on streams and pollables, and the guest lifecycle type interface. The same linker configuration is used during component loading and lifecycle hooks. The proof must account for each effectful method and for resource methods invoked after the initial handle is issued. Import enumeration alone establishes no authority property.

Kernel management IPC, enrollment and redemption, MCP invocation, and native capsule execution also require coverage. Their authority may come from authenticated management policy, durable reservations or trusted runtime ownership. Each path needs a specification for its own authorization decision and a connection between that decision and the eventual effect.

## Native MCP network authority

Native stdio MCP capsules requesting network domains or outbound TCP destinations fail during load. The process sandbox accepts only a Boolean network setting and cannot express the manifest's destination policy. Accepted native capsule configurations request networking disabled, including for uplinks. The scope of this decision is the capsule host engine. Standalone MCP server configurations and operator-selected sandbox policies require separate treatment in the hosted security argument.

## Evidence and trust

The current verifier entry point imports four production modules. Their contracts cover fuel arithmetic, per-principal operation tracking, static pattern matching and containment, and token status transitions. The hosted backend regression exercises abrupt exit and reopening. Complete mediation and concurrent runtime refinement remain open.

The hosted security argument must state its assumptions about the OS, hardware, Wasmtime, cryptography, persistent storage, compiler and verifier. Release evidence must identify the source, build configuration, binary digest and proof result. Evidence about an installed instance must also identify the running binary and security-relevant configuration through a measurement mechanism whose trust assumptions are disclosed.
