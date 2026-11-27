# Security contract for hosted Astrid

## Claim to be established

For each supported hosted configuration, every privileged effect caused by an untrusted guest or external caller must correspond to an admission permitted by the authority policy. The admission identifies the effective principal, its generation, the operation and its target. A forwarded request must retain authenticated provenance. Redirects, aliases, transferred handles and deferred work must preserve the authorization for the actual effect.

The specification must identify the admission point for each operation. Revocation prevents subsequent admissions under the revoked grant. A previously admitted operation may finish where the interface permits it. Acknowledged durable revocation survives every supported restart. A single-use grant permits at most one successful admission across retries and restarts. Reissuing an alias must never transfer the authority of its previous owner.

For token revocation, the capability store takes its live authority write lock and fences the requested token before awaiting the durable marker write. The checked map transition preserves consumption and every other token's status. It returns the revocation namespace and the exact fenced token ID for the write. Both single-use and reusable admissions read that token as revoked. The proof assumes the token key's hash, equality and clone laws. The marker encoder emits the existing lowercase hyphenated UUID format. For all 16-byte identities the production decoder recovers the exact original bytes from that key. Startup consumes the complete grouped marker map and reconstructs exactly its token domain, preserving both marker kinds for each token. An admission theorem covers every requested token, including one absent from both namespaces. The asynchronous enumeration and grouping that supply this input remain outside the theorem. Native code uses the checked path for canonical markers and retains the UUID library parser for legacy spellings. UUID byte access and UTF-8 conversion, lock and future semantics, and recovery of all acknowledged writes across a crash remain open.


## How to discharge the claim

A refinement proof must map each production execution to a permitted sequence of abstract events. Internal steps may leave the abstract state unchanged. Each externally visible effect requires a matching admission. Recovery must reconstruct a state consistent with the acknowledged durable history. The argument must include concurrent calls, canceled futures, errors after a durable write and recovery before admission reopens.

The production Wasmtime linker and the inventory test resolve the same checked-in world in `crates/astrid-capsule/wit-staging/kernel.wit`. Its 18 versioned interfaces declare 202 functions and 15 owned resource types with implicit drop operations. The [host import inventory](../crates/astrid-capsule/tests/fixtures/host-imports.txt) names each function and destructor, including resource methods in both HTTP and process versions. The guest lifecycle interface contributes types only. Run `cargo test --locked -p astrid-capsule --test host_import_inventory` to compare the list against the resolved world. The inventory records the resolved interface definitions without documentation, including parameter and result types, resource ownership, named type definitions and implicit destructors. Call-site mediation and the effects of implementation changes require separate evidence. Component loading and lifecycle hooks use the same linker configuration.

Kernel management IPC, enrollment and redemption, MCP invocation, and native capsule execution also require coverage. Their authority may come from authenticated management policy, durable reservations or trusted runtime ownership. Each path needs a specification for its own authorization decision and a connection between that decision and the eventual effect.

## Guest host implementation inventory

The function and implicit destructor counts below come from the resolved kernel world. Each adapter path is relative to `crates/astrid-capsule/src/engine/wasm/host`. The table identifies where to start tracing each family. A trace must also account for callbacks, shared backends and errors that publish state before returning.

| Interface | Functions | Drops | Adapter | Effect obligation |
| --- | ---: | ---: | --- | --- |
| `astrid:approval/host@1.0.0` | 1 | 0 | `approval.rs` | Bind the action, target, requester and responder through approval, allowance lookup and persistence. |
| `astrid:elicit/host@1.0.0` | 2 | 0 | `elicit.rs` | Bind requested input or secret presence to the principal and responder. Account for release of the reply. |
| `astrid:fs/host@1.0.0` | 23 | 1 | `fs/mod.rs` | Trace implemented path operations through the selected mount or filesystem. The guest file-handle constructor and positional methods return errors. Its destructor returns success without performing I/O. |
| `astrid:guest/lifecycle@1.0.0` | 0 | 0 | `mod.rs` | This imported interface declares types only. Guest lifecycle invocation uses the configured linker. |
| `astrid:http/host@1.0.0` | 8 | 1 | `http/mod.rs` | Bind the V1 request, redirects, credentials and response stream to their admitted destinations. |
| `astrid:http/host@1.1.0` | 15 | 2 | `http/mod.rs` | Also account for request options, streamed uploads, trailers and ownership of the upload and response resources. |
| `astrid:identity/host@1.0.0` | 5 | 0 | `identity.rs` | Bind resolve, link, unlink, user creation and link disclosure to their exact store arguments after capacity and policy waits. |
| `astrid:io/error@1.0.0` | 1 | 1 | `io.rs` | Account for error description disclosure and release of the selected error resource. |
| `astrid:io/poll@1.0.0` | 3 | 1 | `io.rs` | Preserve resource identity, cancellation and accounting through readiness observation and blocking. |
| `astrid:io/streams@1.0.0` | 15 | 2 | `io.rs` | Bind reads, writes, flushes and splices to the actual resource table entries, including both ends of a splice. |
| `astrid:ipc/host@1.0.0` | 7 | 1 | `ipc.rs` | Preserve producer, recipient, topic and subscription authority through publication, receive and destruction. |
| `astrid:kv/host@1.0.0` | 7 | 0 | `kv.rs` | Bind each lookup, scan, write, prefix clear and compare-and-swap to the admitted principal and namespace. |
| `astrid:net/host@1.0.0` | 47 | 4 | `net/mod.rs` | Account for socket creation, accept, peer identity, connected I/O, socket options and close on each transport. |
| `astrid:process/host@1.0.0` | 27 | 1 | `process/compat.rs` | Trace legacy request translation, launch and child-handle operations into the shared process implementation. |
| `astrid:process/host@1.1.0` | 27 | 1 | `process/mod.rs` | Bind executable, environment, roots, descriptors and process generation across launch, signals, wait and cleanup. |
| `astrid:request-context/host@1.0.0` | 2 | 0 | `request_context.rs` | Bind returned caller and owner observations to the borrowed connection and its current registration. |
| `astrid:sys/host@1.0.0` | 10 | 0 | `sys.rs` | Account for config and capability disclosure, log writes, readiness, sleep, clock and randomness. |
| `astrid:uplink/host@1.0.0` | 2 | 0 | `uplink.rs` | Bind registration and queued inbound delivery to the capsule, selected uplink and platform identity. |

All three hosted process launch methods use the same checked constructor in `process/command.rs`. Its output trace starts with the requested program spelling, complete argument slice and prepared directory. It clears the environment, then applies each prepared key and value in order, followed by each host injection in order. The Unix regression runs a fixed environment-printing binary to inspect the resulting child environment, including duplicate keys. The native adapter relies on Rust’s `Command` methods for each operation. Linux and macOS then construct a second command for their sandbox helper. Copying argv, explicit environment changes and cwd into that command, and passing the separate clear-environment flag through both wrappers, are native adapter obligations. Resolution of the actual executable in that sandbox, sandbox policy, descriptor inheritance and child lifetime remain open.

Fourteen HTTP, network, IPC and process adapter call sites currently allocate placeholder resources. Their successful allocation returns an always-ready pollable, a closed input stream or a closed output stream. These methods do not attach the returned resource to the underlying transport or process. The constructors propagate allocation errors through trappable host imports. A failed pollable subscription releases its partially allocated parent. Resource identity, accounting and guest-visible trap refinement remain proof obligations. The file-handle destructor above is distinct from the internal storage-backed file publication described below.

The immediate and blocking I/O splice adapters admit one request containing the output representation, input representation, byte limit and mode. Native admission checks current invocation and device authority, resolves the expected principal UID, and checks both types in the calling Store's table. The checked start function accepts only the admitted mode and supplies the retained admission, both representations, byte limit and table to the transfer callback. The directory helper now checks both the forward alias-to-UID and reverse UID-to-alias bindings before passing the original operand tuple to native WASI. Refusal returns the original input for cleanup. The composed splice theorem checks the fresh directory observations against the alias and UID retained at admission and carries the selected table, destination, source and count through the successful lookup. Immediate splice runs under the directory read lock. Blocking splice rechecks the binding after acquiring I/O capacity and holds the invocation and device admission through the transfer. Each synchronous backend poll runs under a fresh directory binding and liveness check. A pending poll releases the directory lock. The checked byte limit equals the smaller of the request and the first output permit. The handoff requires a nonempty observed chunk within that limit and passes the original payload to the writer. A source read may remain pending over many polls. When it returns bytes, the native adapter measures that buffer, calls the writer synchronously before yielding, and can subsequently wait for flush completion. The verifier checks the measured-buffer handoff and byte count under the measurement and writer contracts. Native byte measurement, WASI permit validity, actual write and flush outcomes remain trusted. A backend write error may follow a successful source read. Device retirement and invocation cancellation can stop that wait. A native regression supplies distinct in-memory streams through the generated host traits to check the selected bytes and destinations in both modes, including refusal for a mismatched invocation UID. A separate queued-transfer test renames the principal before permit release and checks refusal, intact source bytes and an empty destination. In the current hosted world the HTTP and TCP stream constructors expose closed sentinels. The regression pipes exercise the adapter only. The verifier does not model Wasmtime's handle resolution, byte movement, blocking waits or the creation-time principal of an arbitrary stream. Blocking splice rechecks the opening UID, current directory binding and liveness before returning its transferred byte count, using the same checked completion as the single-stream methods. An admitted asynchronous transfer may have consumed input or written part of its output before cancellation. Atomic transfer, native stream provenance and OS delivery remain open.

Six immediate stream operations (read, skip, check-write, write, write-zeroes and flush) retain the principal and device admission and execute under the current directory read lock. The checked dispatch consumes the typed handle, operands and operation returned by that binding. It refuses a sampled cancellation or retired device. Its composed theorem preserves the callback result for the selected table and operands, including the original write payload. The native adapter selects the WASI method, samples liveness and supplies the actual table. Wasmtime handle resolution, the stream implementation, the provenance of the stream at allocation and cancellation after the liveness sample remain outside this theorem.

The native adapter composes the verified directory and dispatch routines. The proof consumer checks their contracts together. Lock acquisition, token sampling and WASI effects remain trusted.

The five blocking single-stream operations (read, skip, write-and-flush, flush and write-zeroes-and-flush) use the same dispatch after acquiring I/O capacity and check the owner under the directory lock on every synchronous poll of their WASI futures. The lock is released between polls. Their completion rechecks the directory, cancellation and device retirement before returning the observed result. The completion theorem composes selection of an expected or freshly observed UID, both directory observations and release of that exact result. Native guard capture, reading the token and device signal, WASI method selection, and execution of the future remain outside the theorem. The checks cannot undo bytes already consumed or written. Input and output subscriptions use the immediate dispatch to publish a child of the selected borrowed stream. Independent ownership of derived pollables across invocations remains open.

The input-stream, output-stream, pollable and I/O error destructors use the owned handle delivered by component lowering. Under an exclusive table borrow they inspect the resource type and whether it has children, then pass that same table and handle to the destructor. The removal callback requires an owned, childless entry with a successful typed lookup. Verus checks each invocation against that precondition. The selector proves the three refusals and the exact handoff on success. Cleanup can run after caller cancellation. The native stream destructors await WASI cancellation; a pollable created with an owned private parent delegates parent removal to WASI. Native regressions check direct refusal of a borrowed handle, that a subscribed stream survives child disposal, that an owned private parent drains with its pollable, and that unrelated resources survive each step. Component ownership lowering, identity across table resets, child edges in Wasmtime, and the effects of native cancellation are trusted at this boundary.

### Guest command approvals

A guest prompt subscribes to its UUID-specific reply topic before publication. Command approval and local-egress consent use the same checked comparison of the responder's stamped principal and authenticated request owner. Both classify the reply bytes using the exact three wire spellings for one-shot, session and persistent consent. Every other byte string yields denial.

The host acquires the caller's principal and device admissions before consulting saved grants, consuming a session allowance or publishing the prompt. It releases these hostcall admissions before waiting for a human. On receipt it reacquires the principal and binds the caller and responder device stamps separately. A missing device stamp on a trusted unstamped path has no registration to acquire. A generation without a fingerprint, an unknown key, or a replaced generation fails admission. The checked reply selector requires both admission results and borrows their guards during persistence. The host retains the guards through a session grant and return. A native host regression completes retirement while a prompt waits, independently replaces the caller or responder generation, and checks the saved profile. This demonstrates rejection at profile selection. A separate regression keeps the matching profile record unchanged and retires the challenge during the production lookup. The subsequent registry bind returns Retired and the approval selector refuses admission. The production profile lookup uses a checked selector. It returns the unique matching fingerprint only if the profile is enabled, keypair authentication is active and the recorded generation equals the captured generation. A downstream theorem for arbitrary registration tables proves both acceptance and rejection, including legacy generation equality and ambiguous fingerprints. A second theorem composes two independently observed signed-envelope lookups with responder identity, wire decision, destination and the writer history. A stale caller or responder produces zero profile-write attempts. When both pass and persistence is selected, the trace records the exact attempted write and its outcome. The registry proof appends a fresh challenge after an arbitrary consistent prefix with distinct channel identity for that challenge. It executes the production retirement and binding transitions and proves that a retirement during lookup fences the bind exactly when its owner and fingerprint match. The signed approval trace uses that result independently on each side and also requires successful principal admission. The model assumes that channel identity and profile field projections are faithful, that the mutex orders the snapshots, and that the cache returns the current profile for the principal. The registry lock, signal delivery and cache invalidation remain integration obligations.

Device removal publishes the profile before it signals and drains the registry. For a durable command grant the writer acquires the same cache write lock as paired-device removal, loads the enabled profile from disk and rechecks the caller and responder against that snapshot before acknowledging an existing grant or saving a new one. A signed stamp requires its issuing principal, unique active fingerprint and captured generation. An unstamped party carries neither fingerprint nor generation. The checked transaction selects its update callback only if both checks succeed, and passes it that same profile. A theorem uses the production registration lookup for both signed parties. A native regression admits both devices, removes either one using the cache transaction while the guards are held, and checks the result and the profile on disk; a control keeps both devices live. This covers ordering against paired-device removal through this cache. For a session reply carrying device evidence, the host takes the read side of that same lock, checks both stamps against the current enabled profile and retains the lock through the in-memory allowance insertion. It reports a stale device before recording a granted audit decision. The wire-to-route consumer requires even a responder generation with no fingerprint to take the checked path. Two unstamped parties retain the existing principal-only route. The native regression also queries the in-memory store for reuse after each removal. Cross-process writers, other profile writers using a different lock, the allowance store’s insertion outcome and crash durability have separate obligations.

The local-egress reply selector takes a principal, capsule, host and port together. Denial and one-shot approval leave grant history unchanged. Session approval calls the in-memory writer once. Persistent approval calls the profile writer once when a profile cache is configured and propagates its failure; the existing cache-free configuration calls the in-memory writer instead. The theorem checks the selected store and all four target fields against an arbitrary previous history. A native regression invalidates the admitted profile immediately before publication and checks refusal, an empty session store and the on-disk entries using a fresh cache. Its positive control checks the selected principal, capsule and port. The in-memory adapter currently logs insertion errors and returns to the caller. These proofs count attempts. The buffered and streaming HTTP backends carry the same parsed URL through scheme checks, per-hop policy, egress consent and request construction. Verus proves that the generic hop passes the admitted method and target to its construction callback and propagates refusal. In native Rust that callback calls reqwest with the supplied method and URL. The native callback and the policy checks preceding admission are outside this theorem. A loopback regression compares the prompted endpoint to the receiving socket and the Host header, and inspects the POST path and query on both backends. The egress host releases its prompt guards after publishing, retains the matched reply event and acquires principal, caller-device and responder-device guards before interpreting the decision. The verified selector requires a borrowed reply authority. Native code checks the pinned profile and both device stamps against disk under the profile-cache lock for one-shot approval, session insertion and durable persistence when a profile cache is configured. Both HTTP backends carry the acquired guards into the request send. While waiting for the semaphore or response headers, the native adapter observes invocation cancellation and retirement of either device. The buffered path carries those same guards through the body read. A successful read may finish integrity checking and audit publication while retirement waits for its guards to drain. Verus checks the buffered publication selector: either cancellation discards the accumulated bytes, transport failure preserves its error, and successful completion releases the exact accumulated bytes. Native code supplies the nested device, invocation and transport outcomes and hashes the bytes received before a failure for audit. A loopback test retires each device before headers, while queued for body I/O, and during an incomplete response body. For streaming responses a native task holds the response and the opening guards while the handle is idle. It wakes on either opening-device retirement, opening invocation or principal cancellation, or resource disposal. A read retains these guards and its reader admission through the pending I/O. Metadata and returned chunks check the opening alias/UID binding under the directory read lock. The verified disclosure selector returns no value on any denied input. Success returns a value satisfying the callback postcondition for the exact supplied resource. Verus checks the production comparison of the reader alias with the opening alias and compares all 32 bytes of a supplied owner UID. The native metadata callbacks read status and headers from the response object supplied by the selector. A chunk callback captures the bytes returned by the pending native transport read. Binding those bytes to the read in the formal semantics remains open. Opening a stream requires a directory binding for the effective principal and agreement with any supplied invocation or runtime-owner UID. A host with an empty directory refuses streaming before sending a request. Directory, task and transport scheduling and the correspondence from these native observations to the formal decisions remain refinement obligations. Transport activity after cancellation remains outside the disclosure proof. The loopback regression denies a read through a renamed alias with the original UID and a valid reader device. Retiring a distinct reader device stops its pending read while the opening device can still obtain status. The regression also replaces the alias binding and checks that the old resource denies access, restores the opening UID and receives an initial chunk, then retires each opening device or the principal while the resource is idle or reading. The operator can complete retirement before the guest closes its handle or the peer sends EOF. In both HTTP interface versions, subscribe-readable allocates an always-ready pollable and body-stream allocates a closed input stream. HTTP 1.1 trailers returns no trailers and its upload constructor returns an error before allocating an upload handle. These adapters still contribute resource-table effects where they allocate a sentinel. Relating a URL to an arbitrary remote peer across DNS, proxy selection, TLS and OS socket execution also remains open.

The two HTTP interfaces share one stream slot lifecycle. The component table reserves the representation until the owned destructor. Borrowed close releases the response and its quota slot while leaving the representation reserved. A verified transition over the live Rust hash map admits a new response only under the configured limit and at an unused key. It returns the allocated representation and stores the supplied response at that key. Release returns exactly the removed value. The destructor theorem passes the representation to a Boolean callback and removes its map entry exactly when that callback reports success. The native callback checks the Wasmtime marker type and deletes the slot. Correctness of that callback and preservation of a reserved slot until owned drop are assumptions at the Wasmtime boundary. The close/reopen consumer assumes distinct representations and checks that repeated close preserves the replacement. It also checks refused publication and destructor refusal. A native loopback test closes an HTTP 1.0 resource twice, drops it, and reads a separate HTTP 1.1 response. These results depend on Wasmtime preserving Store-local owned and borrowed handle identity and on the native marker callbacks. Reclamation authority across invocations, pool reset and native transport teardown remain open.

After a native response read finishes, timeout, transport error, data and EOF pass through the stream identity and liveness check. The checked result selector returns the supplied timeout without a completion record, passes the transport error to its failure callback, and passes the received data or EOF to its success callback. A chunk returns the bytes produced by the digest callback. EOF returns an empty vector with the completion selected under the directory lock. The read carries its source response and its native outcome together through the directory and reader checks. The release helper tests the original source against the selected response and returns the captured outcome only on a match. Native code uses `Arc::ptr_eq` on the response holding the reqwest transport. A regression attempts to exchange observations from two distinct responses with identical bodies. A composed EOF theorem checks forward and reverse directory observations, reader alias and expected UID, opening and reader liveness, source identity and the selected receipt. The comparison of native pointer identity to the model identifier and the native observations supplied to those checks remain trusted. Admission is decided under the directory lock. Retirement can occur before the subsequent audit write completes. A loopback regression holds a chunked response open, renames its principal while the read holds the I/O permit, then supplies EOF. The host returns `Closed` and emits one failed, incomplete completion. Separate coverage checks the native invocation UID mismatch against status, headers and reads. The proof trusts the native mapping of reqwest and timer outcomes, the sink's durability and native mutex handling. A poisoned audit mutex or previously consumed exchange yields no receipt. Dropping the pending commit future can lose the selected completion before it is written. The legacy semaphore-cancellation path separately records failure and returns an empty list.


For interceptor pools the production return decision checks the checkout health flag, the configured resource-reset policy, the live HTTP response map and a native Wasmtime table occupancy observation. An interrupted checkout selects retirement. Free checkout selects warm reuse only when the map is empty and the table reports empty. A healthy persistent-process checkout retains resources on return. The verified cleanup handoff passes the leased value and the selected reset flag to the cleanup callback. The production resource-reset helper installs the exact table returned by its factory and empties the actual HTTP response map on reset. Otherwise it preserves both. A composed theorem follows a leased store identifier, its table and arbitrary prior response map through the policy and these cleanup transitions. Only a warm decision can return its result in the variant enqueued by the native pool. A native regression also checks that a nonempty HTTP map prevents free reuse even when the table is empty. The proof depends on the native code marking guest entry and completion correctly, Wasmtime reporting occupancy, the factory supplying an empty Wasmtime table, the native cleanup callback threading the reset flag into the helper, and the pool enqueuing only warm results. Native destructors, shared quota atomics, cancellation during teardown, and reuse of guest memory across calls remain outside this theorem.


Before publishing a command prompt, the host captures its persistence destination or the error that makes that destination unusable. A persistent reply with a usable destination incurs exactly one profile-write attempt for the prompt's principal, sanitized action and captured destination. It returns persistent approval only on success. The selector preserves the host error returned by the writer. The native writer maps profile persistence failures to StoreUnavailable. The writer's history is unchanged for a nonpersistent reply, a mismatched responder or an unusable destination. An unusable destination affects only persistent approval. The persistence selector sends a hosted grant to the profile writer with the selected pristine workspace path and sends an Astrid-workspace grant to the path-free writer for that principal. A theorem composes the responder check, wire classification and both persistence destinations. The consumer records actual calls in a vector and distinguishes the two workspace kinds, a different path, a different command family or principal, and a storage error. The proof counts a call to the selected primitive writer. In production a usable captured destination requires a profile cache. The adapter holds an immutable host-state reference and calls the selected cache method once on that path. Concrete cache writes, atomic publication and crash recovery require separate refinement.

The native adapter supplies the event fields, workspace selection and actual profile writer. The theorem assumes the request topic and sampled stamps are authentic. The admitted action is a command family. Concrete allowance matching and consumption, session-grant insertion, correspondence between principal tracker state and reply admission, Tokio channel identity and closure, and durable profile publication remain separate obligations.

### Guest uplink registration and enqueue

Each pooled Wasmtime store owns a descriptor vector and takes its uplink capability bit from the manifest. Stores in one pool share the optional channel sender created at load when the manifest declares uplinks. Registration normalizes the platform, checks the configured gate, constructs a descriptor for the capsule and appends it through the verified registry routine. The routine preserves the vector on rejection and appends exactly the supplied descriptor on success. Its comparison uses both name and platform. At capacity it refuses even a fresh pair.

Send supplies the verified selector with the store's registry, the parsed uplink ID, the operation guard and the guest's two message fields. The selector calls the enqueue closure on the first descriptor with that ID. The closure passes the selected descriptor's ID and platform to the message builder, which normalizes the platform, and reports the result of the channel's nonblocking send. The composition in `verification/hosted_uplink_model.rs` checks refusal for a retired or saturated tracker, absence of a matching descriptor, and the exact fields and active count observed at the modeled sink.

The registry belongs to the capsule instance. Returning a pooled store clears invocation state but retains its registered descriptors. A later caller on that store with the uplink capability and matching ID can send using a retained descriptor. The verified selector takes a generic guard and sink. Its tracked-call theorem uses a single principal's transition state and a tuple-valued sink. The concrete guard destructor, message builder and channel operation are exercised by runtime tests and still require implementation refinement. The tracked-call theorem assumes a tracker. The pooled constructor installs one. Constructors with optional or absent trackers require separate reachability analysis. The proof still needs to establish the authority of each store configuration, the binding between a runtime guard and its principal generation, and channel creation and lifetime. The tracked tree exposes the receiver to embedders through `take_inbound_rx`. Successful enqueue alone establishes no claim about processing by a downstream recipient.

## Hosted management IPC inventory

The request bus has two management subscribers. The kernel subscriber decodes
20 variants of `KernelRequest`, and the admin subscriber decodes 48 variants
of `AdminRequestKind`. The table lists the methods to account for at the
effect boundary. A read also has an effect when data leaves its owner's
domain. The authority for a response must cover its recipient.

| Subscriber | Effect family | Request variants | Target or state the proof must bind |
| --- | --- | --- | --- |
| Kernel | Package publication and recovery | `BeginCapsuleInstallBatch`, `InstallCapsule`, `FinishCapsuleInstallBatch`, `GetInstalledCapsuleIdentity`, `GetCapsuleInstallResumeReceipt`, `PutCapsuleInstallResumeReceipt` | Owner UID, archive digest, installed generation, batch member and durable receipt |
| Kernel | Runtime lifecycle | `ReloadCapsules`, `ReloadCapsule`, `UnloadCapsule`, `RemoveCapsule` | Captured runtime generation and owner, including optional state purge |
| Kernel | Workspace changes | `PromoteWorkspace`, `RollbackWorkspace` | Workspace owner, source generation and resulting directory state |
| Kernel | Runtime visibility | `ListCapsules`, `GetCommands`, `GetCapsuleMetadata`, `GetCapsuleMetadataForPrincipal`, `GetAgentReadiness` | Caller-visible runtime set and recipient of the response |
| Kernel | Daemon operations | `Shutdown`, `GetStatus`, `ApproveCapability` | Daemon shutdown, status recipient or exact pending approval |
| Admin | Principal management | `AgentCreate`, `AgentDelete`, `AgentEnable`, `AgentDisable`, `AgentList`, `AgentModify`, `UserPrincipalList`, `UserPrincipalClaim` | Principal alias and UID, source and target of inheritance, ownership and retirement |
| Admin | Quota and usage | `QuotaUserList`, `QuotaAssignUser`, `QuotaSet`, `QuotaGet`, `UsageGet` | Resource ledger owner and assigned user |
| Admin | Environment and secrets | `EnvSet`, `EnvSetIfAbsent`, `EnvList`, `EnvDelete` | Owner, capsule, key, kind and visibility of returned data |
| Admin | Distribution policy | `DistroLockGet`, `DistroLockSet`, `DistroSelfGrant` | Lock owner, desired distribution and policy revision |
| Admin | Groups and capability profiles | `GroupCreate`, `GroupDelete`, `GroupModify`, `GroupList`, `CapsGrant`, `CapsRevoke` | Group definition, affected principal and capability pattern |
| Admin | Capability tokens | `CapsTokenMint`, `CapsTokenRevoke`, `CapsTokenList` | Token owner, audience, scope and durable grant state |
| Admin | Enrollment | `InviteIssue`, `InviteRedeem`, `InviteList`, `InviteRevoke` | Invitation owner, redemption input and durable consumption |
| Admin | Device pairing | `PairDeviceIssue`, `PairDeviceRedeem`, `PairDeviceList`, `PairDeviceRevoke` | Issuing principal and registration, requested child scope, redeemed credential or revoked registration |
| Admin | Audit | `AuditStats`, `AuditPrune`, `AuditHealth`, `AuditHeads`, `AuditExport`, `AuditAnchorMark`, `AuditAnchorStatus` | Selected chains, exported entries, prune boundary and anchor |
| Admin | Storage mounts | `StorageMountIssue`, `StorageMountStatus`, `StorageMountSync`, `StorageMountRevoke` | Mount owner, mount identity, sync target and revocation state |

The `hosted_management_inventory` integration test reads the supported method
names from both production Serde decoders and compares each subscriber with
the table. Each method occurs once and has a target obligation. This checks
wire coverage; the handler and sink refinement obligations are tracked separately.

Two wire paths branch before enum decoding. On the request subscriber,
`projection_names::try_handle` recognizes `ProjectionNameDiagnosticV1`
and reads the authenticated caller's catalog. On the admin subscriber,
`agent_derive::try_dispatch` recognizes `astrid.v1.admin.agent.derive`
and spawns work that can create a principal. Both require independent
provenance and reply-delivery arguments. Within the admin enum,
`handle_redeem_admin_request` dispatches invitation and pairing redemption
using token possession. The ordinary capability preamble cannot establish
authorization for those two paths.

The enumerations are in `crates/astrid-core/src/kernel_api/mod.rs`.
Dispatch and policy selection live in `crates/astrid-kernel/src/kernel_router`,
including `request_policy.rs`, `admin/request_authorization.rs` and
`admin/handlers`. Each handler may have several effects, including audit
writes, profile changes, publication and replies. These rows enumerate entry
points. The contracts below identify the effects already covered.

### Capsule install resume receipts

The two receipt methods acquire the administration write lock before checking
the caller's policy and hold it through lookup of the caller's UID, access
to its control namespace, and publication of the response. An integration
test exercises both request methods while a writer reassigns the alias.
The checked receipt validator requires the decoded capsule ID to equal the
requested key and each of the four digest fields to contain exactly 64
lowercase hexadecimal bytes. The checked transition after compare-and-swap
returns the same store, key and encoded bytes only on reported success.
The read-back acknowledgement requires a present value equal at every byte.
These contracts rely on the store implementing compare-and-swap and reading
the addressed key, and on serialization, principal lifecycle locking and
recovery. Digest syntax alone establishes no relationship with installed
archive contents.

## Guest filesystem mount selection

For each of the workspace, home and temporary mounts, the checked selector
returns the invocation's mount when present, otherwise the runtime's mount.
The checked VFS binding returns the selected bundle and the supplied relative
path together. A missing selected mount fails even if a sibling is present.
The production adapter takes the VFS instance and directory handle from that
one bundle. A WIT host regression reads distinct file contents from six real
mounts using the same relative filename across invocation and runtime scopes.

For a device caller, path resolution holds its registration guard. Each of the
eight guest filesystem operations reacquires the guard after obtaining I/O
capacity and holds it while awaiting the VFS. A real WIT regression replaces
the registration for the same key while a write waits for capacity. All eight
operations reject the old registration, and the original file bytes survive.

This covers the handoff from a resolved target to its VFS operation. Physical
canonicalization, symlink changes, the relationship between the path checked
by the manifest gate and the file opened by the VFS, installation of a mount
under the correct owner, and refinement of backend completion and cancellation remain open.

For scratch mounts the opened runtime store retains its principal scratch root,
including during finalization handoff. The mount builder appends the resolved
UID and `tmp` below that root. A receive-loop regression writes bytes and checks
their location under an explicit runtime home, then switches principals and
checks isolation. The production UID text encoder and decoder are checked:
each of the 32 input bytes supplies its high and low nibble to the corresponding
two lowercase hex digits, and decoding accepts exactly 64 lowercase hex digits.
A uniqueness theorem rules out two different UIDs with the same spelling.
Filesystem directory creation, canonicalization, and identity-to-UID resolution
remain trust or refinement obligations at this boundary.

### Storage-backed file publication

For the owner-backed home and workspace-branch adapters, the checked
`OpenFile` constructor keeps the resolved destination, initial bytes and
open mode. Write admission rejects read-only handles and offset overflow.
A successful write copies exactly the supplied bytes at the cursor, preserves
the other existing bytes, advances the cursor by the input length and marks
the handle dirty. Both error paths preserve the complete state. A read from
an in-bounds cursor returns exactly the unread suffix and advances to EOF.
Construction starts the cursor at zero and successful reads and writes leave
it in bounds. The adapter locks the handle around each transition.
On close, the checked publication decision yields the original path and
the complete current buffer exactly when the handle is writable and dirty.
The production handle table is checked against a map. It starts empty,
rejects duplicate handle text without changing any binding, returns only
the entry bound to the requested text and removes exactly that entry on
retirement. A uniqueness lemma proves that two bindings of the same handle
text in a valid table have equal values. Each storage VFS owns its table.
Its read and write methods borrow the entry under a table read lock. Close
acquires the write lock, removes the entry and owns its buffer. There is no
await between removal and synchronous publication to the bound backend.

Adapter tests cover owner isolation, a foreign handle, independent
open handles and cancellation of a waiting close while a write holds admission.
The synchronization argument relies on Tokio lock semantics and the inspected
production call sites. Machine-checked refinement still needs
to establish ownership at mount installation and durable backend publication.

The directory table belongs to the same VFS instance as its backend. At mount
construction it contains exactly the supplied root handle and prefix. The guest
path adapter snapshots that handle's current directory and joins the validated
relative suffix below it. The host VFS method `open_dir` can bind a supplied
directory handle again. Its verified table update affects only the supplied handle.
Closing a directory removes its binding. A storage regression writes through a
subdirectory handle, rebinds it, closes it, and reads the original bytes by
their full name from the root. Directory close does not revoke earlier file
handles or undo a directory snapshot already taken by a concurrent operation.

For logical storage paths, the production validator checks all UTF-8 bytes. A
nonempty name has no NUL, leading, trailing or doubled separator, or complete
`.` or `..` component. The directory join preserves the complete base and
suffix, inserting one slash when both are nonempty. A checked composition
lemma establishes that joining two canonical nonempty byte names this way
preserves canonicality. The root is the empty spelling. The byte-level lemma
and string-level executable contract rely on Rust UTF-8 string semantics.

### Principal retirement under the engine tracker lock

Admission returns the principal key that the invocation guard stores alongside the owning tracker. A checked update of the production hash map refines each begin, finish, retire and resume to the one-principal transition, preserving every other key. A consumer acquires a guard, retires its owner, finishes using the returned key and samples the same count used by the quiescence waiter. The count returns to its original value, including zero, and the retired entry stays closed. This applies to arbitrary initial counts below saturation. At saturation, begin refuses without changing the count. The proof assumes the standard hash, equality and clone laws for the principal key. Mutex exclusion, guard lifetime, waiter notification and restoration of fences at startup still need a concurrent runtime refinement.

### Native guest log writes during retirement

For a managed log, the checked directory operation looks up the immutable destination UID in the reverse map and confirms that the resulting alias maps forward to the same UID. A missing or inconsistent binding returns the original uncalled callback. The production adapter discards that callback after releasing its directory read guard. On success it preserves the alias callback’s result, including any I/O error. The checked admission operation reuses an existing operation only when its tracker and bound alias both match. Otherwise it requests a fresh operation from the destination tracker for that alias. A matching outstanding guard can finish after retirement closes new admissions. If a new operation is refused, that binding supplies no file. The theorem covers one binding resolution. The outer resolver’s choice among invocation files, invocation bindings and owner destinations remains a separate obligation. The result retains the borrowed or newly owned guard, and the host borrows the file mutex from that result through the write. The caller’s own operation remains live through fallback handling.

The verifier composes the comparison and guard selection with the production tracker-map acquisition. A fresh guard requires the selected alias to be open with an active count below saturation. Reuse still requires a matching operation even when new admissions are closed. Native tracker pointer identity and the association of the mutex-protected map with that tracker remain assumptions. The Rust lifetime binds the reused guard to the resolved file view. The composed proof follows both directory maps into guard selection. It assumes the supplied maps constitute the live locked directory, and the UID and alias keys obey the standard hash and equality laws. Path construction for the UID-bound file, the native open and write, explicit embedder file injection, and the tracing fallback still need separate refinement.

For deferred first-open on Unix, the leaf acquisition used by `PrivateAppendRoot` now has a checked call history. It probes the captured directory descriptor and leaf name. An absent entry permits one exclusive create. An existing entry, or an already-exists result from that create, requires observing a regular file, opening the same parent/name pair, and confirming the opened handle against the observed identity. The returned handle is exactly the one created or confirmed. A different create error stops the acquisition. The lower-level filesystem calls, parent walk, mode repair, sync and final boundary revalidation remain native assumptions. Eager rotation, its directory scan and deletion, and Windows append acquisition follow separate paths.

On Windows, the production post-open check returns the acquired leaf handle only after reading matching volume serial numbers from that handle and the retained root handle, checking the parent and root directory guards in order, and recapturing the original path against the retained root handle. A differing serial number stops the operation after the two reads. Each native error ends the operation at the failing check. This proof assumes the native identity and private-directory checks implement their contracts. Initial root capture, descendant selection, native leaf open and ACL repair, and the eventual write remain outside this post-open theorem.

The guest log host call dispatches a single record containing the capsule, level, timestamp and message. Its resolved destination is either a file paired with a lifecycle operation, an explicitly injected file, or absent. A managed file attempt borrows that exact file and guard. An explicit file attempt carries no owner guard. Absence sends the record directly to daemon tracing. A failed file attempt also sends the same record to daemon tracing. A successful file attempt does so only under the always-emit policy, which the native host selects for error-level records. The Rust caller holds the invocation operation and the resolved destination through both callbacks.

For a single managed candidate, the verifier composes tracker admission with this dispatch. The file callback carries either the matching held operation or a fresh operation for the same tracker and owner. If neither is available, the composed path has no file attempt. Selecting the candidate in the outer resolver, matching it to the physical file across restart, enforcing the file mutex, formatting and writing bytes, and subscriber delivery remain native obligations. The trace counts logical file attempts and guest-record tracing calls. A failed attempt can write a partial line or emit a host diagnostic.

For an already-populated file slot, the production resolver compares the selected file with the cached file of its corresponding binding. A matching identity requires exactly one admission attempt on that binding. Success pairs the selected file with the returned operation. Refusal supplies no file. A missing cached identity or a mismatch preserves the explicitly supplied file and performs no owner admission. The checked composition follows each result through dispatch, including guest-record tracing on refusal. This uses the host's Arc allocation identity for an embedding slot. The native observation of the eager file or initialized deferred cache, and the provenance of explicitly injected files, are trusted here. Selection among the invocation and owner slots and cold-path fallback remain separate obligations.

### Restoring retirement fences before serving

For each pending deletion in the loaded ownership snapshot, kernel startup selects the retained alias and any distinct current alias of the reserved UID. It holds one reverse-directory read guard across all reservations and both store updates. A legacy reservation with no retained alias therefore fences the current name when one exists. Capability and allowance stores use the same checked set insertion and membership functions. A composition proof shows that applying the selected names in both sets preserves all previous fences and closes precisely those additional names. Native tests exercise an older reservation, a changed alias, an unrelated principal, and storage reopened after abrupt exit. The production replay loop starts from the complete immutable reservation map. Verus checks termination and proves a single successful traversal restores both fences and removes the grant bucket for every retained or live name while preserving all three observations for every other name. The proof tracks attempted aliases and store outcomes without adding runtime state. Every attempt belongs to a loaded reservation. On error, the call history ends with exactly the returned error and every earlier call in this traversal succeeded. A checked sink that always refuses a named reservation receives exactly one attempted alias. The failing store can have partially updated private state. The kernel holds the directory read guard throughout and owns both stores until success. Each capability-set update produces an owned receipt consumed by allowance recovery for the same alias. A checked consumer instantiates the sink contract with the production map transitions. The two Rust store accessors, their lock semantics and their wiring to the actual kernel fields remain refinement assumptions. Native tests fail on the retained or live alias of the first reservation, observe the exact attempted prefix, and check that the directory lock is released. Shared handles and the secure MCP client are created only after success. A separate consumer checks that releasing one name preserves every other fence. These results assume the ordering, equality, hash and clone laws for the concrete UID and alias keys. For a retained alias that differs from the live one, startup fences both, while the current deletion completion releases only its requested alias. Automatic reconciliation of those two names is unproved. A legacy reservation with neither name closes no alias; excluding stale alias-based grants in that state also remains open. Snapshot decoding and validation, the native store adapters, and the ordering of all admission paths still require refinement.

## Guest identity policy

All five identity host methods call the security gate before using the
injected identity store. The production manifest gate checks the actual
declared strings. A resolve grant permits resolution only. A link grant
also permits creating or removing links and listing a user's links. An admin
grant permits all five operations, including user creation. The checked
decision requires at least one sufficient grant, independent of its position
in the list. All five host methods acquire the effective principal’s operation guard where its tracker is installed, before waiting for capacity. A WIT user-creation regression holds the backend write, observes principal retirement waiting, then releases the write and checks the stored user and denial at all five imports. A machine-checked connection from the lifecycle guard, caller and device registration to the actual store arguments and reply remains open.

## Guest key-value storage

All seven operations in `astrid:kv/host@1.0.0` enter through `impl kv::Host for HostState` in `crates/astrid-capsule/src/engine/wasm/host/kv.rs`. Get, set, delete and compare-and-swap take a key. List, paginated list and clear take a prefix. Both list operations call the same backend prefix listing. The cursor and limit select a page after that listing returns.

The shared host adapter checks invocation authority and, where installed, acquires the effective principal's tracker guard before handing the selected scoped store to the operation. It holds admission through the semaphore wait and completion of the storage future. The scoped store supplies the namespace to the backend independently of the guest's key or prefix.

The production store selector takes the invocation store when present and
otherwise keeps the runtime's load-time store. The shared WIT adapter hands
that store and the unchanged operation to a synchronous sink which borrows the
owner guard until it returns. The sink waits for the backend future. The
tracked-call model composes this handoff with the production tracker and
durable owner selector. A retired tracker cannot admit a new call. For an
admitted call, an isolated neutral store remains neutral, and a pinned store
can address only its original owner, with both namespace and current UID
matching. A mismatch denies the modeled action. The active count returns to
its prior value on completion. The modeled sink receives a borrow of the same tracker after admission, with its active count one above entry. The model covers a tracked call; deployment paths without a tracker and namespace-only stores require separate treatment. This result assumes store construction matches
the modeled binding. Interleaved retirement, future cancellation, reply
delivery and backend persistence need separate refinement.

The hosted owner codec preserves the existing durable spelling. System is one zero byte. Principal and fleet use distinct tags followed by all 32 UID bytes. The checked decoder accepts exactly these forms. A consumer composes pinned guest selection with encoding and decoding and proves that a matching selection recovers a principal with exactly the admitted UID, even if a fleet uses identical UID bytes. A regression checks the typed runtime adapter against the durable byte format.

The native tree captures the resolved owner in its blocking mutation and takes the expected root from that owner’s header. Live durable preparation and root-journal recovery use the same checked comparison of generation and all 32 commit bytes. A missing root starts at generation zero. A matching existing root advances once unless its generation is exhausted. WAL replay skips an already published replacement, applies a transition at its expected root and rejects other histories. A verifier consumer checks first and repeated replay for every admitted generation, including equal commit bytes across generations. These contracts assume the adapter supplied the correct owner’s root and decoded transaction. Connecting the prepared principal, bytes made durable, acknowledged result, cancellation and complete journal history to the guest admission remains open.

During native transaction preparation, the engine now constructs an immutable record containing the target owner, expected root, replacement root and journal bytes returned by the encoder for that same transition. Both WAL staging and appending borrow this record. After the group durability frontier succeeds, the engine supplies its owner and replacement to root publication and returns that published root in the commit acknowledgement. The checked consumer composes pinned guest selection with encoding, WAL append and publication. A successful modeled result carries the encoder and append postconditions for the same bytes and the publication postcondition for the same owner and acknowledged root. The group loop, its actual commit frontier, store lookup and B-tree updates are still outside the proof. In particular, the consumer assumes it received the right transaction for the guest call.

The root journal and WAL use the same transition payload encoder. It writes the length and owner, tags the optional expected root, and writes each generation, identity scheme and 32-byte commit in order. The production journal and WAL transition readers share the checked tail parser. It checks field boundaries, advances after a complete field, validates scheme bytes, and requires the replacement to consume the remainder. The WAL also uses the checked owner-length reader. Snapshot entries use the same fixed-root parser. A round-trip consumer runs the production owner selector, owner codec, prepared-root constructor, payload encoder and WAL field readers. WAL generation validation also consumes the checked live successor decision. For every valid pinned guest selection, decoding returns that same principal and both roots, with exact generation and commit bytes. A hosted regression issues WIT set and compare-and-swap calls for two principals using the same key. The child exits after both acknowledgements without closing the store. The parent opens the same storage and reads each principal’s value through the WIT host. This establishes the payload relationship in the verifier and exercises one abrupt restart in the runtime. Frame selection, checksums, outer numeric conversion, validation against the live owner codec, snapshot restoration and the physical durability frontier have separate obligations.

The live WAL writer validates the prepared journal bytes against the transaction owner, expected root and replacement. It feeds those same bytes to framing and the transaction digest. The shared logical record codec appends and recovers the kind, flags, reserved bytes, sequence, ordinal and exact body. Before dispatching a record in an active transaction, the production scanner checks its sequence and ordinal against the active position. The round-trip theorem includes the encoded position and the guest's owner and roots. The scanner decodes each 72-byte commit marker and compares the transaction sequence, the three record counts, the logical byte length and all 32 digest bytes to the observed transaction. Only a successful check constructs the marker consumed by replay. The repair probe and canonical replay share a descriptor accumulator. It releases a batch only for the matching begin offset, sequence and object and root counts, and discards a torn tail. For an arbitrary commit body and arbitrary ordered object and root descriptors, the verifier checks that the released batch contains exactly those descriptors. A byte-cut regression runs the production scanner and accumulator at every truncation of a two-owner WAL and checks the visible owners. These results assume the scanner's observations reflect the correct physical stream. The stable-stream argument below handles physical frame bounds and interior candidates. Establishing which bytes the file adapter actually supplies and applying committed descriptors to the durable owner map remain proof obligations.

For Begin, Object and Root records the writer constructs one measured record with an immutable body, kind, flags, sequence and ordinal. Its verified write method seals the physical frame, returns the updated counters and passes the same record to the digest callback. The scanner constructs a measured record from the stored body it selected, including compressed object bytes. The round-trip theorem reads the emitted frame at its boundary between arbitrary neighboring bytes under a supplied physical payload limit with the physical and logical decoders, checks its features and position, and recomputes identical counters and digest input using the reader transition. The prefix theorem composes that result over any supplied list of representable records with supported flags, then checks the emitted Commit frame. The production marker constructs the Commit header sequence, ordinal, and body from the same counters. Given arbitrary neighbor bytes and independent scanner counts and digest, the framed-marker theorem checks the 92-byte payload limit, nonzero sequence, at least one root, count equality, and digest equality. The writer list theorem uses a separate frame for each supplied record.

A separate reader theorem starts at a supplied offset in one immutable byte stream. It follows each decoded extent to the next frame and stops at the first confirmed Commit. A successful result identifies the contiguous Begin, Object and Root intervals and the end of Commit. The verifier binds the kind, stored body, sequence, ordinal, physical checksum, logical counts and transaction digest to those bytes. It passes the marker recovered from this stream into the production replay accumulator and proves that the released batch contains precisely the Object and Root spans in their original order, bound to the Begin offset and sequence. It also proves acceptance whenever the stream contains a complete layout satisfying those framing and measurement rules. The executable loop receives no layout or event list. The production scanner and object rereader use the same logical header classifier. A writer-to-reader theorem constructs a Begin, Root and Commit with the production encoders for any nonzero sequence, representable bodies and shared deterministic hash functions. It supplies the resulting layout to the reader and recovers its exact ordered trace, Root span, counters and digest. These are stored bytes. Semantic validation of the bodies, torn-tail disposition and durable root-journal publication require further composition. The checksum is a shared deterministic function in the proof. Equivalence between incremental BLAKE3 updates and hashing the concatenated transcript is assumed. The runtime adapters still choose the initial input, do actual file I/O, feed BLAKE3 and publish the result. A fixed byte-vector regression exercises the production writer adapter against independently encoded frames and a domain-separated digest.

A typed recovery theorem encodes any supported System, Principal or Fleet owner and both root versions, reads the body from the released batch, and decodes the owner and root fields from those recovered bytes. It rejects invalid successor generations. For valid generations the production replay comparison returns already published, apply or conflict according to that recovered owner's history, including the full commit identity. The production fold queries a Rust BTreeMap and records the replacement and recovered source offset only after journal encoding succeeds. An idempotent replay, conflict, or encoding failure preserves the map. The writer-to-reader theorem uses that fold, recovers the offset following the Begin frame, checks the re-encoded journal bytes, and preserves every other owner's history. A separate consumer runs two writer-to-recovery traces with identical UID bytes under Principal and Fleet tags and checks both entries in the resulting map. Replaying an applied replacement again returns already published and preserves the original offset, even when the encoder would now return an error. It assumes an injective mapping from canonical owners to well-ordered keys and the Verus standard library's BTreeMap contract. The stored offset identifies the WAL root frame for a replayed entry. Entries initially loaded from the canonical root journal carry offsets in that file. Refinement of the hosted StateOwner codec and ordering, graph source, publication and crash durability remain open.

Live commit preparation, transaction restore (through `validate_pending_closure`) and WAL replay call `validate_incremental_closure`. Its production worklist checks the root is a Commit before consulting the validated cache. For a stable source graph and correctly ordered keys, an accepted set is the least set containing the root and every owning child of its uncached members. Every uncached member exists in the graph. Each uncached owning edge descends in a finite completion order, excluding reachable uncached cycles. A cycle error identifies an object on a reachable, nonempty loop of uncached owning edges. A source error comes from a required uncached record or the initial root check. The scheduler preserves the original reference order and visits only Owns targets. Verus checks all four reference-kind wire codes and the production target selector. An independent finite-map consumer establishes acceptance for complete acyclic inputs and exercises a self-reference with and without a trusted cache entry.

The cache certifies previously validated subgraphs. The walk intentionally stops expanding at their roots. On one stable graph the empty cache is certified, and unioning a successful result into a certified cache preserves object presence, closure and acyclicity. Reconstructing this certificate for a cache loaded across recovery, proving that incoming, pending and indexed records implement the same identity-bound graph, and connecting acceptance to on-disk root publication remain open. The concrete `ObjectReference` adapter now supplies its checked edge target. The live `ClosureObjects` adapter still needs to establish source validity, stable edges, root kind and read failures over the lifetime of a walk. The verified finite-map source supplies these definitions for the model. Cache provenance also depends on root-journal recovery in `roots.rs`, standalone object insertion in `engine.rs`, individual and batched staging in `staging.rs`, prepared group publication in `group/mod.rs`, restore in `restore.rs`, and the temporary and final sets in `wal/replay.rs`. Each writer must establish the certificate for the same object graph.

The coalesced arena reader, single-object reader and prepared WAL overlay decode the concrete `ObjectRecord` from its canonical frame. They accept the requested id only when it matches both the typed frame prefix and the identity implementation’s result for that decoded record. The decoder checks kind, nonzero format version, accounting class, logical size, canonical bytes, reference count, every variable-length label and target, and the final cursor. Construction requires strictly increasing labels in lexicographic byte order. Both closure materialization and worklist expansion select strong owning targets through the checked concrete reference type.

For coalesced arena reads, the production slice selector converts the requested absolute offset into a range within the supplied span. The envelope validator checks magic, version, reserved bytes, length, limit and checksum. The visitor receives the same payload slice as the typed decoder. The production positional fill loop advances by each short read’s actual count and reconstructs the requested interval. A theorem follows that loop through a successful decode and identifies the payload in the provider’s media image at the absolute index offset. It relates the decoded record to the supplied identity function. Single-object reads use the checked placement selector before decoding. A one-frame source witness admits a valid leaf exactly at the matching offset, size and checksum. The provider contract assumes each primitive read returns the indicated prefix of one stable media image or reports an I/O error. The concrete checksum and identity algorithms, construction of the index, and preservation of the selected media generation still require refinement. A separate executable witness instantiates the canonical record round trip with a name derived from the decoded logical size.

For any canonically ordered production record and supported identity scheme, the writer-to-reader theorem recovers the original fields and every labelled relation in order, assuming the identity implementation names a semantically equivalent record with the requested digest. Nonempty reference lists can report a failed allocation. A separate theorem starts from arbitrary complete frame bytes and relates the worklist to the encoded owning digest at each reference position. Prepared WAL publication retains the decoded object and the frame it confirmed. Merging a repeated key rejects differing frame bytes, preserves the existing record, and upgrades a missing arena location only with its paired direct metadata. The production overlay map installs the exact candidate at a fresh key and preserves all other keys on both insertion and merge. A consumer decodes a prepared frame, installs it under its recovered name, then stages a second declaration against that map. A collision preserves the prepared entry. Matching bytes retain the first decoded record and install the supplied staged placement and direct metadata. This uses the Verus standard library’s ordered-map contract and assumes consistent ordering and equality for object ids. Physical provenance of staged locations and direct metadata, host media selection, and the concrete hash remain open.

Staging, checkpoint folding, standalone writes, restore and group publication use the same checked update for the live arena index and its checkpoint delta. Batched staging pairs ids and append locations by position and installs each optional direct description at that position under the description’s own object name. Unequal input lengths leave the index, delta and direct catalogue unchanged. The staged-first theorem takes a described row whose name matches its id, with no later occurrence of that id and no pre-existing WAL entry. The publisher’s lookup selects that row’s location, blob and canonical length. A later prepared declaration can succeed exactly for equal bytes and always preserves the staged data. Another consumer follows a tagged frame’s complete canonical suffix through the supplied profile-specific blob function and this installation sequence. These theorems take the append results, ordered input rows and metadata clone as inputs. The next result connects append locations to submitted frame bytes. The concrete hash implementation and the recovery path that reloads the index and catalogue remain open.

The staging batch appender prepares each physical header with its magic, version, payload length and checksum. Starting at the end position supplied by the file, its layout pass assigns each frame the offset following all preceding headers and payloads. It returns the locations only after submitting every chunk. A checked consumer publishes those locations into the live index and checkpoint delta and identifies the exact submitted interval for a selected row. On layout overflow the sink is unchanged. A chunk failure can leave a prefix written without returning any locations. A buffer-backed writer and reader recover a valid named leaf in a later chunk at a nonzero base. The production vector builder supplies each header before its payload, and the short-write loop advances only by the accepted byte count. These results depend on the native adapters binding the resulting vectors to the initial cursor and on the seek, vectored write and slice-advance operations honoring their contracts. Submission does not establish synchronization, survival of a crash or selection of the same media generation after restart.

The snapshot and delta writers encode an arena location as two little-endian 64-bit fields followed by its 32-byte checksum. Recovery uses the same checked location decoder for the tail and for each object row. A consumer follows a selected published delta row through this byte encoding and into a second map. Given the recovered key and arena length, the row is accepted exactly when the complete frame fits and the prior mapping is absent or identical. Rejection preserves the prior map. The checkpoint key decoder checks the store’s identity scheme, the digest width and the actual digest. The production table decoder checks the declared count against available bytes and enforces strict bytewise order before inserting the decoded key and location. For any selected row of an accepted table, looking up its decoded name yields that row’s location. A two-row consumer starts at a nonzero cursor and checks that repeated or reversed names are rejected. The enclosing snapshot and delta records and the ordered sequence selected from persistent media remain open.

Recovery compares the checkpoint’s covered length with the measured arena length before allocating its read list. Sorting that list preserves every object and location in the candidate map. For each entry the reader seeks to the cached offset and checks the frame extent, magic, version, reserved bytes, declared length, header checksum and tagged object name. An undersized payload stops at the end of the header. A byte-backed proof checks that boundary with a following byte available. The tail goes through a separate full-frame read and placement check. Ordinary rows compare the checksum in the header and defer hashing the entire payload until an indexed object read.

A validated checkpoint returns its complete original state. On a cache miss, native and volume-backed recovery share a checked selection function that requires successful publication of the state returned by the arena scan. Scan and replacement failures propagate to the caller. The native adapter performs file replacement and the volume adapter also syncs the volume. The proof assumes a stable arena for the primitive reads and the contracts of the scan and publication callbacks. On a packed arena, the ordered rows partition the measured bytes and every frame visited from byte zero has its exact physical location in the admitted map. A gap can also contain repeated frames. The production reader bounds each duplicate read by the end of the gap and the retained read by the current offset. The driver checks the duplicate's tagged identity, obtains the earlier location from the candidate map, and compares the two complete payloads. The frame walk must finish exactly at the boundary.

For a stable table of checksum-validated frames, the reverse-coverage theorem follows a walk from byte zero. Each visited identity has either the visited location in the map or an earlier indexed frame with the same complete payload. A single retained row followed by a second equal-length frame admits exactly when the two payloads match, under the stated valid header and tail assumptions. The theorem assumes the native CandidateArena gap callback passes the actual arena, range and candidate index to duplicate_range, and that CopyReader returns bounded, checksum-validated frames from that arena. Verus checks the comparison and traversal using that interface. Indexed rows in the normal path still defer payload hashing until use. Crash persistence, a matching media generation, and the concrete sync and rename operations remain open.

The lookup used by `ClosureObjects::load` checks the incoming map first, the optional pending WAL map next, and the arena index last. On a disk lookup the result comes from the reader invoked with the original object id and its mapped location, including when that reader fails. When all layers miss, the error constructor receives the same id. The theorem assumes the ordered-map invariants and specifies the in-memory clone and media-reader callbacks at their interfaces. For transactions without a matching engine seal, the live preparation path checks every declared id against the identity computed over its corresponding record. A mismatch reports the first offending declaration and computed digest. Snapshot restore uses that same per-record check before inserting a record.

Both the durable and in-memory commit paths run the same checked admission decision. An unsealed transaction always takes the per-record check. With an engine seal, the production adapter calls `Arc::ptr_eq` on the retained and current authority. Only a match can skip that check and take a KV checkpoint for publication. A foreign seal takes the full identity check and retains no publication authority. A proof consumer checks all three cases for an exact authority comparison. The engine adapters still supply the identity and the allocation comparison.

During runtime finalization, the native store creates a fresh validation cache and attempts to rebind the system owner’s KV memo against the transferred engine. The ordinary KV projection publisher and the handoff seeder recheck the captured cache epoch and sample the selected owner’s current root under the destination projection lock. Verus checks that a successful sample agrees on presence, commit identity and generation. A failed read rejects publication. After a purge, a ticket issued before that purge cannot authorize publication even if the owner’s root is unchanged. Epoch exhaustion permanently disables this cache publication. The theorem assumes the production lock orders the purge and publication operations and that the engine’s root query observes the selected owner correctly. Projection validity and the preceding handoff certificate checks remain separate obligations.

KV staging and the content DAG builder compute the key from the same record they move into staging. Equal duplicate declarations keep the existing record. Conflicting duplicates leave the staging map unchanged. Durable preparation consumes the supplied vector into a checked map: every successful entry originates in the vector, every declaration is represented, and a collision identifies two distinct records supplied under the same key. A consumer composes this fold with unsealed identity checking and the production layered lookup. If the caller requested an id present in the supplied batch, the returned record equals its authenticated input row. Authenticity on a pending or indexed hit depends on the corresponding producer or reader establishing that relation. It assumes ordered keys and structural record equality. For the same-engine fast path, the remaining chain includes capture of the paired authority and identity implementation, filtering the builder map to reachable records, collecting those records into the sealed transaction, and the clone boundary that discards its seal. The live overlay map must establish provenance for newly staged arena objects and preserve it across checkpoint folding and recovery. Stable cache provenance across restart remains open.

The physical envelope codec checks the eight magic bytes, supported version, reserved bytes, little-endian payload length and complete checksum. A stable-stream theorem seals a logical record between arbitrary neighboring bytes and reads it back at its offset. Its success returns the end offset, the exact logical body and the version/feature decision. The checksum function is an explicit parameter shared by writer and reader. The production scanner and stable-stream theorem use the same buffer-filling loop, physical payload offset calculation, length-and-restore operation, and payload integrity check. Under the stable-source contract the loop accumulates exactly the next bytes through short reads, stops at a full destination or EOF, and propagates read errors. A successful length probe restores the requested payload position before the checksum is checked. The proof instantiates this contract with a byte reader for any positive maximum read size. Platform read and seek implementations, their consistency across handles, and BLAKE3 remain trusted at this layer.

The live scanner adapters in `wal/scan.rs` remain outside Verus. These include `FrameInput`, `stream_len_at`, `read_probe`, the offset and error handling in `next_event`, and the calls into the digest accumulator. The main frame path uses the verified length-and-restore and payload integrity helpers. Interior probes perform their own seek and checksum steps.

On a damaged header or checksum, the production scanner searches subsequent byte offsets in order. The search propagates probe I/O errors and stops at its first finding or observed end. A complete candidate above the allocation limit counts as interior evidence before reading its payload. A bounded candidate requires a valid checksum. In the stable-byte model, truncation is permitted exactly when there is no such later candidate. With an active transaction the resume offset is its Begin. The Rust adapters `probe_candidate` and `bad_physical` are inspected and runtime-tested. Their actual seeks, reads and error observations, stability during recovery, application of the resulting descriptors and publication to the original caller remain obligations.

The accepted commit group owns its pending receipts. Production now keeps the group and the result of persisting it together until the frontier operation returns. The checked transition returns the original ordered group on either error. A successful transition requires the persistence and frontier operations to agree on the same persistence result. The WAL arena cursor rejects shorter lengths, retains the old tail at equal length and adopts the newest available tail when the arena grows. The WAL writer calls a checked transition with its real sync operation. Active or empty publication is refused. Sync failure poisons the writer and retains the pending count. Success returns the entire pending count and resets it to zero. If sync succeeds and a subsequent frontier operation fails, the caller receives an error and recovery can still apply the synced transaction. An error therefore leaves the final transaction outcome indeterminate. The group consumer assumes the filesystem and index operations implement their reported outcomes. It does not establish which WAL transactions survived a crash or that receipt delivery is linearizable.


The retirement regression exercises all seven WIT methods. A second regression starts the actual WIT set method, holds its backend write at a barrier, and observes retirement waiting for it. The hosted tree view keeps the original namespace encoding and pins the principal UID when the view is constructed. The production selector proves that a storage operation selects an owner exactly when both the namespace bytes and the current directory UID match the admitted values. The tree adapter uses the returned UID for storage access. A native storage regression rebinds an alias and checks that the former view loses access while the new view and the ordinary backend agree on the replacement's data.

A device-stamped KV invocation registers a pending profile lookup after acquiring host capacity, checks the captured registration against the caller’s current profile, and holds the bound device session through backend completion. A runtime regression parks the WIT set operation inside its backend, observes that device retirement cannot yet acknowledge, releases the write, then re-pairs the same key. All seven WIT imports deny the retired registration and the replacement can read the committed value. The registration selector and session phase transitions have machine-checked contracts. Their composition with the asynchronous backend and durable recovery remains a proof obligation.

Install and upgrade hooks pass the UID admitted for their secret and environment scopes into construction of the durable guest KV view and home mount. A changed alias denies startup, and an existing durable guest KV view can only select its admitted UID. Independently injected KV backends retain their original scope.

The production point-address encoder in `kv/encoding.rs` proves its output is the complete namespace, a zero byte, and the complete key. For zero-free namespaces the checked injectivity theorem shows that equal physical addresses imply equal namespaces and keys. This applies to point addressing in the tree adapter. The production prefix upper-bound constructor proves that its half-open byte interval contains exactly the addresses starting with the complete lower bound. For validated namespaces, `logical_prefix_range` proves membership is equivalent to namespace equality and a matching logical key prefix, including the empty prefix. Checkpoint leaves apply a checked interval predicate to the stored entry key. The checked branch decision preserves any child whose declared fences contain a matching key. Overlay iteration calls the checked byte comparator at both fences. For an ordered overlay snapshot, the production lookup used to suppress a shadowed checkpoint entry returns the value or explicit tombstone of that exact key iff it occurs anywhere in the overlay. The production overlay update preserves this ordering across recursive insertion and rebalancing. Lookup on its new root returns the supplied value or tombstone for the written key and is unchanged for every other key. Tree summaries, traversal stacks, pagination and durable application of deletion replacements still require refinement.

These results still depend on correct invocation provenance, the directory lookup, and backend confinement of each operation to its selected owner and key or prefix. An operation which already obtained its owner may finish against that owner. Serialization with deletion and reclamation, lifecycle retirement tracking, and the neutral system fallback remain runtime refinement obligations.

## Management request targets

The management wire API defines 20 `KernelRequest` variants and 48
`AdminRequestKind` variants in `astrid-core/src/kernel_api/mod.rs`.
The admin listener also dispatches agent derivation before deserializing the
admin enum. The two variant counts therefore do not exhaust management ingress.

Ordinary requests, typed admin requests subject to capability admission, agent derivation, and the projection-name diagnostic pass the device fingerprint and registration from the IPC envelope into the common management admission check. The scope and public key used for authorization come from the same selected profile record. Production calls the checked registration selector on that record. A generation without a fingerprint denies admission. Token redemption has its own authorization path. Management errors, keepalives and terminal responses retain the request stamp. A bus regression replaces a registration for the same key and checks both the authorization outcome and the response stamp. This establishes the decision at admission. The remaining obligations include ordering individual management effects with acknowledged retirement and binding each final transport delivery to the recipient registration.

Pairing-token issuance preserves restrictions from the policy snapshot admitted by the router, then checks the issuer again while holding the administration write lock through durable token creation. On the device-authenticated route the second lookup uses the registration recorded in the admitted snapshot. Kernel regressions queue issuance behind a writer and exercise both removal and replacement by the same key. Both deny issuance and leave the token store empty. A policy-only change on the same registration retains restrictions from both snapshots. The production deny-list fold proves exact union membership, retention of the original ordered prefix, and that each newly appended pattern was absent from all earlier entries. This binds the inherited pattern strings. Their interpretation depends on the capability matcher. The lock interval and durable store operation are runtime-tested refinement obligations.

The production insertion transition releases the supplied pairing token only
when the durable store reports a successful new insertion. A collision and
a store error have distinct outcomes. The checked audit classifier maps
issuance to success, a policy refusal to denied authorization, and bad input
or storage failure to a failed operation. Failure rows preserve the original
error. A router regression disables a queued issuer and checks for exactly
one denied row and an empty durable token store. Atomicity between the token
store and the audit log across a crash is a separate obligation.

The ordinary kernel router matches every `KernelRequest` variant in
`request_policy::request_principal`. Install, install-batch and targeted
metadata dispatch reuse the explicit principal selected for admission.
The checked `AuthorityScope::for_target` function returns self scope exactly
when the supplied caller and target bytes match and the shared-state flag is
clear. Selected administrative requests use the same decision, including
shared environment writes and deletes. Capability selection for each operation
remains in `request_policy::required_capability` and
`admin::required_capability_for_admin_request`. An explicit metadata read
checks global list authority on the pinned profile, groups and device scope
before constructing a cross-principal view.

The install handler captures a durable target UID. Under the environment write
lock, staging checks the current directory binding against that UID. Rollback
uses the staged UID. Storage-backed installation uses the captured UID for
package conflict checks, generation-cache selection, prior metadata, lifecycle
hooks, durable publication and import validation. The production owner selector
returns an owner exactly when the observed UID matches the supplied pin, or
when the caller supplies no pin for initial resolution. A regression reassigns
the alias before install and checks both package registries for absence.

Durable activation captures the owner UID together with the package snapshot.
The cache path check compares all three normalized components (UID, capsule ID,
and archive digest) against the expected bytes. Repair checks the owner’s
published package against the supplied snapshot under the repair lock before
removing or creating a projection. The repair lock and registry read use the
same UID. Principal runtime construction checks the binding against the
captured UID. A replacement retains the UID from its validated runtime scope.

Install activation uses the validated capsule ID returned by the installer. The
install audit takes that same ID and the hash of the receipt-checked manifest
bytes from the install result.

Install reload rechecks the admitted UID after acquiring the capsule view lock.
For an existing principal runtime it compares that UID to the runtime scope,
passes the observed generation into restart, and reports a superseded generation
as a failed reload. Verus checks the production generation allocator: a successful
reservation returns the previous counter and advances it by one. At exhaustion
the counter remains unchanged and reservation fails. This covers a single
registry lifetime. Initial principal runtime registration and replacement both
hold a directory read lock through the registry mutation. The verified
predicate requires the current UID for the alias and the current alias for the
UID to match. Rejection returns the candidate for cancellation and unloading.
Fresh install reload passes the admitted UID through dependency discovery,
durable package lookup, cache repair selection, fallback loading and the final
registry lookup. A reused principal runtime must match the admitted viewer UID.
For a shared runtime the scope check delegates authority to the explicit system
classification and view attachment. When discovery supplies a viewer UID,
attachment and resumption of an existing singleton hold the viewer binding
through the synchronous registry operation. Initial publication also holds the
owner binding through route opening when a UID is available. Route opening
after replacement, continuity of package generation and the full
singleton replacement path still require end-to-end proof. Ordering with
retirement, authenticated request admission and durable commit still needs a
proof across the full operation.

This proves scope classification for the supplied identities. The authenticated
origin of the caller, alias-to-UID continuity through handlers, capability-table
correctness and sink coverage still require production refinement. Invite and
device redemption have separate admission paths.

## Routed IPC delivery

Hosted capsule construction stages the composite delivery gate. A successful
load and internal activation leave it staged until runtime publication. Each
subsequent load retires the old gate before installing a fresh one.
The production gate uses a sequentially consistent atomic byte. Verus checks
its compare-and-exchange from staged to published, its retirement store and
its load against an invariant at each atomic operation. Retirement issues a proof-only witness bound to this gate’s atomic invariant.
A caller can retain that witness through later publications and repeated retirement.
A load accompanied by that witness must observe the retired byte. Ordinary
runtime reads use the same atomic load with no witness. Once retired, the same gate cannot
reopen, including when publication races retirement. The checked release
function returns the exact pending payload or held commit guard only for the
published byte. Gate identity across registry replacement, association with
the correct route, the native commit mutex and wakeup scheduling remain
integration obligations. Single receive,
blocking receive and batch drain apply it after private queue extraction.
Retirement wakes a waiting receiver and prevents delivery of buffered events
on the next admission check.

Matching and enqueue use a checked principal predicate over the unrestricted,
system-only, exact-principal and principal-or-system cases. A principal match
requires equality of the publisher and owner bytes. The predicate takes the
publisher identity stamped on the same IPC message that is enqueued. The
fan-out bucket is keyed by that stamp. The checked request-owner predicate
requires equality of the full 128-bit ID for an owner-scoped subscription.
An absent stamp fails that comparison. Ordinary guest publication validates
a present caller principal before accounting or delivery. The checked principal
parser accepts exactly 1–64 ASCII letters, digits, hyphens or underscores and
identifies the first invalid byte within that length range. Both the throughput
charge and the outgoing stamp use the resulting typed principal. Interceptor
admission rejects a malformed caller stamp before acquiring its invocation
guard. The receive path installs restricted authority for a malformed stamp on
both private and shared runtimes. The upstream
authentication of these stamps, receipt visibility, mutex and atomic ordering,
delivery after an
already admitted handoff and confinement of subsequent handler effects remain
separate obligations.

At reserved bus commit, the Verus-checked decision returns the exact delivery
reservation and ordered handoff supplied by the publisher. A missing reservation
requires an observation that the corresponding lane is absent. A captured
handoff requires an observation that its own sender is open. The bus makes
these observations under its publication-order lock, then acquires route guards
from the returned delivery reservation. The proof treats the observed slot occupancy and sender closure as inputs.

The ordered receiver and its shutdown drain consume each dequeued item through
the same checked dispatch. An ordinary item returns its exact event for
matching. A reserved item applies the supplied delivery callback to its original
reservation and event and returns its result. The production callback invokes
the reservation’s delivery method. Queue scheduling, callback effects and
source-device grant continuity after commit remain open.

For host-local framed ingress, each Wasmtime Store owns the connection
identities indexed by its own resource table. The framed read clears any
previous stamp before resolving the handle. Its checked selector returns
the supplied identity exactly when the capsule holds the uplink capability
and the read produced data. A byte read, read-stream request, lease reset
or successful drop of the stamped connection also clears the stamp.
For a bound frame the host extracts its topic and JSON payload. An
authenticated publish-as attempt consumes that operation before awaiting
delivery. The checked comparison requires equality of the topic bytes and
normalized payload bytes. The host forwards the captured topic and body.
A second attempt under the same stamp is denied. Object key order and JSON
whitespace do not affect the comparison. An unbound publication retains
the anonymous principal and system origin. The selector theorem assumes its
binding input. Handshake authenticity, Wasmtime handle allocation, the JSON
parser and serializer, and downstream interpretation remain proof obligations.

Both socket handshake implementations select candidate signing keys from the
validated principal profile. The checked selector returns the supplied keys
only if the profile is enabled and permits keypair authentication. Both capsule
dispatch and the kernel's device-scoped capability and native private-input
checks use that same selector on the resolved profile. A supplied device stamp
must match exactly one registered fingerprint byte for byte. Profile validation
rejects duplicate fingerprints.

Both native and Wasmtime socket authentication construct the signed UTF-8
message with the same checked function. For a fixed protocol prefix and
colon-free principal names, equal transcripts imply equal principals and
nonces, even if the nonce contains a colon. The shared registration scan
passes the actual signature, message bytes and each candidate's canonical
public key to the verifier. It returns the complete first accepting record, including its persisted registration ID,
and skips records without a canonical key. Both socket adapters copy the fingerprint
and registration ID from that record into handshake admission. The resulting session
retains the registration ID, including its absence on a legacy key. The scan proof
assumes the production key projection and signature verification callback. Hex decoding, Ed25519 verification, nonce generation,
profile freshness at effect admission and the lifetime of the socket owner's
generation remain outside these theorems.

Gateway pair redemption puts the kernel-returned registration into the signed device
bearer. On refresh the gateway signs the same registration as the verified input.
Legacy bearers keep their existing format and have no registration ID. The v4
transcript proof binds the exact first five encoded fields and the canonical UUID.
Equal transcripts with dot-free registration strings require both inputs to be equal.
Base64, UUID parsing and Ed25519 remain trusted adapters.

Gateway publications, native socket ingress, signed Wasmtime forwards and guest
IPC fan-out carry the original registration in host-derived bus metadata.
Ordinary and reserved dispatcher matching select a unique, enabled fingerprint
and check its generation. The checked comparison returns the same selected record
exactly when the captured and live generations agree. A legacy record matches an
absent generation. Missing profile resolution denies device-stamped matches.
Tests remove a key, re-pair it and compare the old, absent and new generations.

FIFO consumers repeat registration resolution after dequeue. Each ordered-chain
handler repeats it after taking its execution lock. A reserved-publication test
replaces the registration between selection and commit, observes a terminal failure
for the original registration and observes execution for the replacement. Native
and guest failure receipts carry the registration of the request. These checks
establish admission observations. In-flight effects require their own lifetime
fences. Kernel management and reply routing remain separate obligations.

## Native local socket transport

Native queue admission compares the target registration with the registration captured by the receiving socket handshake. A device-addressed message requires the same fingerprint and generation, including the unversioned case. A generation without a target fingerprint is rejected. Principal-only destinations retain their principal, session and connection-owner constraints. The Verus contract on the production recipient selector states these conditions. A registry regression subscribes three sockets with one principal and one fingerprint and confirms that each of two versioned replies and a legacy reply appears only on its corresponding queue. A configured private elicitation resolves its responder in the active profile before publication and stamps that registration on the notification. Enqueue selection is one step in the transport proof. Final socket writes, retirement acknowledgement and durable recovery require their own refinement evidence.

The built-in local server in `astrid-uplink/src/native` accepts a socket,
authenticates it, and subscribes a per-connection queue. Its topic policy uses
a checked byte-slice search for exact topics and prefixes. A blocked ingress
prefix always denies a request, including one in an allowed control family.
The checked lookup assumes the allowlists defined in `routing.rs`.

At outbound publication, `egress::Registry::install` iterates the subscribed
clients. Its checked recipient predicate requires an allowed topic, matching
principal (or an explicitly allowed untargeted broadcast), matching device
when targeted, and a present matching session for chat. Ordinary messages
carrying an owner must match the connection owner or active turn owner.
Approval messages additionally require a kernel source, matching envelope
owner, and matching owner text in the typed approval payload.

The checked chat transition admits a matching host-stamped owner. Only an
owned nonterminal message with a nonzero producer and nonce can establish
the correlation for an unbound turn. A subsequent ownerless terminal frame
must match both captured values. An explicitly foreign owner cannot use that
exception. The registry and turn locks supply the active turn.

Before serving the accepted socket, the handler compares its authenticated
owner, principal, fingerprint and registration with the fields on the egress
queue itself. The checked binding function returns that exact queue handle
only for matching identities. A registration without a fingerprint is
rejected. The normal writer and shutdown drain use this handle. The checked
FIFO appends the actual event, returns the oldest retained event, and counts
the sum of the charges supplied with all retained events. Slot exhaustion,
byte overflow or a reply-record conflict closes and empties the queue.
Closure is permanent. These statements use the verifier library's contracts
for the Rust standard library deque. The byte charge is a runtime estimate.

A pending human reply carries its owner and claim phase in one map entry.
Its checked transition permits one live claim for the registered owner.
Cancellation restores availability, and successful completion spends the
claim before removal. Repeated delivery of an outstanding request keeps its
phase. The map operations, mutex, delivery reservation, and operating system
socket identity remain refinement obligations. The registry and transport
have separate closure conditions.

The established native reader classifies the buffered wire bytes before JSON
decoding. Its checked transition derives the big-endian length from the four
header bytes, rejects an oversized declaration as soon as the header is
available, and returns a borrowed slice of exactly the first complete body.
The consumed count ends at the same boundary. The production reader drains
that count after decoding. A back-to-back transport regression checks both
payloads and source IDs. The async read, dequeuing of bytes, and JSON parser
remain trusted by this transition.

The daemon and client now use the same `frame_writer::write_frame` for handshakes and established IPC. A native socket-pair regression reads the length and the complete tool-call message from the client and compares them with the serialized principal-stamped request.
The checked header constructor rejects lengths above the four-byte wire limit
and encodes every representable body length exactly in big-endian order.
For that header and serialized body, `FrameSegments::next` returns
a prefix of exactly the remaining bytes. It is empty exactly at completion.
An accepted short write drops precisely the count reported for that offered
slice. Zero or excessive counts leave the cursor unchanged. The async driver
passes each offered slice to Tokio, advances after a successful write, and
flushes once all bytes have been accepted. For a complete frame within the receiver limit, the peer parser recovers exactly the serialized body and consumes only that frame even when subsequent bytes are already buffered. These proofs cover selection and
advancement. Serialization, the driver's control flow,
Tokio's reported count, the OS peer binding and what the peer actually receives
are outside these theorems. Cancellation can leave a prefix at the peer.

### Private input and secret answers

For a device-bound private prompt, the Wasmtime host resolves the operator-selected responder, captures its registration in the pending slot and sends the same stamp on the notification. The daemon's native reply adapter supplies the identity of the authenticated socket and checks the current registration. Under the registry mutex, the checked responder predicate requires the captured principal, fingerprint and generation before the slot can consume the answer. A rejected answer leaves the slot available. Host-opened slots without a device binding retain their principal-only contract. The request ID, capsule and secret key remain host-owned.

The host waits for input without holding a device session. After receipt it binds the request caller (if device-authenticated) and the selected responder again. It holds both sessions through conversion to a guest value or return from the selected secret store. A WIT regression replaces the responder registration while a guest is waiting, delivers the old answer to the slot, and observes cancellation at the guest. A separate case rejects a replacement's cancellation and an unstamped reply without losing the rightful request. The predicate is machine-checked. Registry-lock implementation, waiter cancellation, choice of secret-store target, backend durability, and recovery still require refinement.

### Paired-device removal on the native daemon

The daemon passes its kernel's `DeviceSessions` to the native listener. The
listener registers a challenge before sending the nonce and binds the key that
verified the signature before sending success. Device removal saves the profile
and invalidates its cache before retiring sessions. Registration, binding and
selection of channels to drain use the same registry mutex. The checked
binding scan compares the challenge channel with each entry using Tokio's
channel-identity callback. It changes only the first matching entry and
preserves its owner and channel. A missing entry, an excluded key, or an
already-bound entry leaves the registry unchanged and denies admission.
Channel identity and mutex linearization are assumptions of this scan.

For the actual registry slice supplied to `retire_and_capture`, Verus checks
that each pending challenge owned by the removed principal excludes exactly
the keys excluded before plus the removed key. A challenge for another
principal retains its exclusions. Binding a previously excluded key fails.
An established entry retains its owner, bound key and channel. The capture
callback receives the channel of each established entry matching both
principal and key, once per entry. The same verified routine binds the selected handles to the requested
principal and key. After awaiting receiver closure, the adapter submits that
batch for certification. A successful receipt requires an affirmative closure
observation on every handle and carries exactly the batch's principal and key.
Failure to certify requires a negative observation on at least one handle.
The kernel builds the revocation response from the receipt's key.

Profile removal scans the actual registered records using their fingerprint
field. The checked routine removes the unique match and preserves the order
and contents of every survivor. An absent or ambiguous match leaves the
vector unchanged. The adapter disables the keypair method when the set becomes
empty and uses the removed record's fingerprint for session retirement.

The signed native socket's serving future and its session receiver have a
single owner. Its field order and the Tokio select scope release the work
before the receiver on completion, retirement or task cancellation. A runtime
regression observes destructor order on those paths and before the first poll.
The argument relies on Rust destruction semantics, Tokio channel identity and
closure, the profile fingerprint projection, filesystem behavior and the OS
transport. It does not yet prove the complete concurrent transition or the
response serialization. Previously accepted OS bytes may arrive after local
retirement. On Unix, profile replacement syncs the temporary file and renames it.
After cache invalidation and session retirement, the acknowledgement path
syncs the profile directory. A failed directory sync withholds success after
the live policy has changed. Persistence across power loss depends on the
filesystem, the identity of that directory, and the storage device honoring
those barriers. These assumptions and the recovery reader have yet to be
joined to the retirement proof. A Unix regression runs the management removal
in a child process and exits immediately after checking its acknowledgement.
A fresh kernel reopens the same home and denies the removed key while accepting
the surviving key. This exercises process exit with an intact filesystem.
Whole-principal deletion, alias reuse and Wasmtime socket resources have separate obligations.

The Unix daemon claims the native listener before loading boot capsules.
Kernel capsule-context construction withholds this listener once claimed.
An embedded kernel may instead supply its listener to a capsule, so its
authenticated socket path is a separate production obligation.

Live device admission and profile revocation use the same checked search.
For the fingerprint projected from each record, a unique match selects the
entire original record, including its persisted registration ID and scope.
No match or multiple matches yield a denial for admission and leave the
registration vector untouched on removal. The profile file, UUID generator and
its atomic publication remain trusted for this step. Generation-aware binding
at ingress and subsequent consumer effects is still required.

Both Wasmtime socket accept methods read device registrations from the
profile home captured by the kernel cache when supplied. A signed socket test
exercises both methods with an explicit temporary home. Each method registers
a challenge with the kernel's device registry before issuing the nonce and bind the verified key before handshake
success. The signed resource owns the resulting principal, key and request
owner. Each raw or framed I/O operation holds the session while touching the
socket. A captured frame retains forwarding authority across ordinary socket
release. Retirement closes the transport, emits its disconnect, cancels pending
forwards and prevents future operations on the old grant after re-pairing.

The checked publication selector returns the supplied lease only for an exact
principal, device and 128-bit request-owner match. A missing lease with a
device stamp is denied. The unguarded branch requires both the lease and
device stamp to be absent. The production caller dispatches the signed
operation through that lease around bus reservation and publication. Runtime
tests cover retirement on both WIT accept paths, sibling isolation, an active
read, a forward blocked on I/O admission, a frame held over socket release,
and the ordering of disconnect and acknowledgement. The concurrent argument
still relies on the semantics of Rust futures and field destruction, Tokio
watch and mutexes, bus publication, and OS socket close. Downstream consumption
of work already published before retirement needs its own generation fence.

| Native effect | Production path | Outstanding refinement |
| --- | --- | --- |
| Register a connection and emit lifecycle events | `ConnectionRuntime::handle`, `serve_connection`, `publish_lifecycle` | Peer identity, durable owner, subscription lifetime and disconnect accounting |
| Demand-load a capsule runtime and publish a client operation | `input::PendingInput`, `readiness::ensure`, `publish_trusted_ingress` | Caller generation, asynchronous readiness, publication reservation and commit |
| Deliver a private answer | `private_elicit` calls the configured responder directly | Registry owner, cancellation and handling of secret bytes |
| Queue a bus event and write a client frame | `Registry::install`, `forward_outbound`, `write_message` | Authenticated socket identity, mutex ordering, device revocation during buffering, wire serialization and partial writes |
| Return handshake, refusal and completion frames directly | `handshake`, `route_connection_message`, `write_ingress_refusal`, `input` | Binding each response to its accepted socket, including partial writes and canceled requests |

## Remembered local egress consent

A local egress consent reply must carry the expected principal bytes and full
128-bit request owner. The checked matcher rejects missing or different
stamps. The host captures the current profile before asking for consent.
A changed or missing profile cancels the decision. With a profile cache,
durable approval compares the captured profile again under the cache write
lock and loads the enabled profile before saving. Removing a non-default
profile prevents its recreation through consent. A durable approval has no
duplicate process-lifetime allowance. Direct filesystem edits, alias ownership
across profile replacement, and the interval between consent and socket
connection still require separate treatment.

## Outbound TCP destination selection

After host policy and capability checks, the TCP connector resolves the requested host and port once. Its checked selector rejects an empty answer list and rejects the whole list if any address fails the address policy or carries a different port. On success the dial callback receives the original slice in resolver order, including every candidate Tokio may try. The native adapter supplies the IP classifier and the observed socket port. This theorem covers the selection decision. DNS answer authenticity, the configured IP policy, Tokio and the OS connection, and ownership of the resulting stream across calls remain outside it.

### Inbound TCP listener targets and reservations

After the capability check on the requested spelling and port, the native adapter parses a numeric address. It translates the case-insensitive literal `localhost` directly to IPv4 loopback. The checked selector admits exactly IPv4 addresses in 127/8 and IPv6 ::1 and retains the requested port. Both the private bind and the shared worker bind pass a numeric socket address to Tokio. The shared registry uses its canonical IP spelling and port. Before publishing a listener handle, the selector checks the IP reported by the OS and the assigned port. A fixed port must match exactly. A request for port zero may publish any nonzero assigned port. The proof consumer composes admission, the OS operand and the reported-endpoint check. It characterizes the IPv4 range directly and returns the actual observed IP and assigned port on success. A native regression supplies a cached loopback listener at a different port and checks refusal, an empty guest table and restoration of the existing holder count. IP parsing and conversion, the OS bind, registry locking, table insertion and cleanup on publication failure remain native obligations.

The atomic update used by the two TCP listener bind paths, direct stream reservation and listener-readiness reservation calls the same checked increment. For any observed occupancy it proposes exactly one additional unit below capacity and refuses at or above capacity. A consumer checks two successive reservations including the last free slot. Under the pending-slot mutex, blocking and polling accept use the same checked admission function. It consumes the exact reserved connection, including at capacity. With an empty slot it permits fresh accept only below the observed limit. A consumer checks two successive admissions and rules out reuse of the reserved socket. The registration function claims a reserved socket or obtains a fresh quota unit before passing the exact socket to the table adapter. If insertion succeeds, it returns that handle. An insertion error triggers one release and propagates the table error. A quota refusal makes no insertion. A consumer composes the locked admission decision at capacity with registration and checks the exact call sequence. The native table and counter operations implement the proof callbacks. Atomic scheduling, Wasmtime table semantics, and balancing counters during cancellation or restart remain open.

### Runtime scope at initial load and live replacement

Both paths pass the manifest's uplink capability, presence of provided uplinks and MCP server declarations, and the operator's capsule allowlist observation to the same classifier. An unapproved uplink provider is refused. System residency requires operator approval and an uplink capability or provider. The hosted classifier refuses a system-resident manifest with any MCP server declaration. Otherwise the runtime is principal-scoped. On new instance allocation, the owner selector uses the caller and expected UID at the directory lookup. A lookup error refuses allocation and a successful principal lookup carries its exact UID. Only the system branch can return an absent owner. Registry allocation constructs the actual runtime key and ID in verified code. Production specializes those records with CapsuleId, WasmHash and RuntimeScope. The proof consumer reads the result through the same public capsule, artifact, scope and generation accessors used by registry clients. Initial load and replacement both convert the admitted optional UID through the verified RuntimeScope constructor. A composed theorem uses that enum and represents the opaque capsule ID, artifact and UID with model values. It checks those values through the issued key, exact generation advance on success and no advance on classification refusal, lookup error or exhaustion. A second theorem allows arbitrary keys, including identical keys, and proves that two successive successful allocations receive strictly increasing generations. That result assumes callers serialize updates to the same live counter. A fresh registry starts its counter at one. Cross-restart authority requires independent evidence that a handle from a former registry cannot be presented as a current one. The proof assumes the manifest extraction, allowlist snapshot and directory callback. Before reserving a live replacement, the kernel checks the installed owner scope against the running scope. The composed proof shows that a scope mismatch, including a different principal UID, consumes no generation. On success the reserved identity carries the running scope, package and candidate artifact. A further consumer takes the observed view and installed instance maps, captures the handle and identity, and feeds that identity’s scope into reservation. It checks the resulting package, candidate artifact, running scope and generation, as well as an unchanged counter on refusal. This composition assumes faithful scope equality, the supplied directory observation and the native orchestration of these calls across asynchronous preparation. Attachment to an existing instance and subsequent socket access have independent obligations.

The guarded stale-generation check reads the selected principal's package slot through the production nested hash map and compares the complete runtime identity with the captured one. A missing principal or package refuses the check. The registry’s package lookup resolves that same slot before cloning the installed capsule handle, returning no handle if its instance is absent. The consumer uses the production RuntimeId and RuntimeScope representations with modeled package, artifact and UID values, and allows an unsized capsule payload. It assumes the stated equality and hash laws and well-formed indexes. Before restart preparation the kernel captures the installed handle and its full identity in one checked lookup under the registry read lock. A missing view or instance fails before source-directory access. A different expected identity returns Superseded. A successful capture supplies both the capsule queried for its source directory and the generation checked again at publication. The identity clone must preserve its value. This is a point-in-time lookup; continuity through an asynchronous call is a separate obligation.

The instance swap operates on the production hash map under the registry write lock. The swap returns the capsule removed under the expected key. Under the same write guard, the replacement receipt resolves the installed handle using the complete reserved key. The kernel retires and cancels the previous capsule, then resumes and publishes the capsule resolved by the receipt. It obtains neither handle by resolving an alias again. The map proof assumes a well-formed map and a key whose equality and hashing follow the Verus key model. With distinct generations and a fresh reserved key, retrying the removed generation leaves every map entry unchanged. Each visited view slot is changed from the expected identity to the reserved identity exactly when it still equals the expected identity. The resume-list traversal checks every principal in the production nested map and includes each principal exactly once if and only if its view contains the installed runtime identity. Source UUID registration uses the same checked inner membership test. The proof assumes well-formed inner and outer maps, the key laws for their native keys, concrete runtime equality and faithful cloning of principal IDs. The full view and source-index transitions are specified below. Freshness of the reserved key at each caller and the behavior of the dynamically dispatched capsule methods remain obligations. Native principal and shared-system regressions compare handle allocation identity with the affected views.

### Registry publication and withdrawal

The production uplink index looks up a descriptor by its complete uplink ID. Withdrawing a capsule’s registrations removes every entry owned by that package and preserves the full descriptors of every other owner. A consumer withdraws one package, looks up its retired ID and a peer ID, and observes only the peer’s original descriptor. For system-owner departure, the composed check starts before detachment. Package registrations survive precisely when another slot for that package names a different generation. With no such slot, the index loses exactly the retired package’s descriptors. This checks package-level registration within one registry write. Previously captured descriptors, the source of replacement IDs, and in-flight uplink messages have separate obligations.

Fresh publication writes the installed handle and owner alias, principal/package view, scoped UUID route, reverse UUID and public package name in a single checked transition under the registry write lock. Its consumer calls the production package and UUID lookup functions and obtains the same installed handle through both, even in the presence of legacy aliases. A second consumer starts with a new principal row, unused generation and unused scoped source and public name. It publishes a principal runtime, dispatches by source, detaches the package, retires the instance and revokes its source routes. Principal-scoped departure removes the instance and leaves other principals’ package slots untouched. The captured and dispatched handles agree, only the registering principal is reported, and all five maps return to their exact prior contents. The native regression also seeds a legacy artifact alias under the new UUID. That alias lives in a separate map from the initially absent public package name. For two initially absent principals with distinct admitted UIDs and the same package, bytes and UUID, another consumer issues two generations and publishes them in reverse order. If all installed generations precede the counter, both scoped routes resolve to their respective handles. Publication writes the common UUID’s public package name even if that key already existed. Entries outside the specified insertions survive. Exhaustion while issuing the pair advances the counter only through available reservations and leaves every map unchanged. This establishes the specified serialized interleaving within one registry lifetime. The transition specifies insertion at the supplied keys. Reservation freshness, preflight and UUID derivation remain caller obligations.

Fresh runtime registration and attachment of a shared system runtime write the package slot using the selected generation’s own package ID. The checked update preserves all other principals and all other package slots in that row. Starting from views indexed by their generations’ package IDs, either write preserves that property, so the newly published generation cannot occur under another package in the principal’s row. Shared lookup selects an installed generation with exactly the requested package, artifact and system scope. It returns no generation precisely when none qualify. Multiple qualifying generations permit any match. The shared attachment updates the principal view and its scoped UUID route in one checked function. It obtains the UUID from the selected runtime’s reverse entry, preserves every other scoped route and leaves the route table intact if the reverse entry is absent. When the UUID exists, the composed consumer resolves it through the production source lookup and obtains the exact installed handle, including when legacy aliases are present. Caller validation and replacement retargeting are separate transitions.

During replacement, checked code scans principal views for the retired identity, captures only matching principals and package keys, and retargets their slots under the registry write lock. Every principal row and package key survives. Each original slot pointing to the retired generation now points to the replacement, and every other slot retains its identity. The scan uses temporary storage proportional to the affected principals and the matching packages in the current row. It removes scoped source routes to the retired identity, then enumerates the post-retarget views. It writes the replacement source route for each principal whose view contains that exact generation. Every other route retains its prior membership and value. Starting from the pre-replacement package slot, the composed check returns the retired and replacement handles, establishes the exact installed instance map and resolves the viewer to the new handle. A non-viewer loses a route only if it referred to the retired generation. A separate composition checks the reverse generation-to-source map and the public package-name map across replacement. Withdrawal removes the retired generation. Its old public name is removed only if no other generation retains that source. Publication records the new generation’s source and package, including when the replacement reuses the old UUID. The native wrapper now calls one checked replacement transition over six maps under its exclusive registry borrow. A stale expected generation returns no handle and preserves all six maps. Success returns the precise retired handle, installs the candidate and its owner alias, updates package views and scoped routes, replaces the reverse source and public name, and prunes aliases for the old artifact only if no installed generation still uses it. The dispatch consumer calls this production transition and resolves a pre-existing viewer to the installed replacement. The native wrapper supplies the expected and reserved identities, candidate, owner alias, and derived source UUID. For a principal replacement, the checked preflight binds the reserved package and scope to the admitted UID, refuses a candidate declaring uplinks, and checks the expected scope and current principal/package slot. The composed consumer runs this preflight before the six-map transition. A refusal or missing expected instance preserves all six maps. An admitted replacement resolves under the same principal and carries that principal’s owner alias.

The native directory reads the supplied alias in its forward map and the captured UID in its reverse map through a checked pair lookup while holding one read guard. A separate consumer over canonical byte keys composes these observations with the production binding comparison. An intact pair forwards the original candidate to its callback. Any missing or inconsistent side returns the original candidate. The concrete key-to-byte projections, acquisition and duration of the native guard, construction of the prepared candidate, and manifest provenance remain caller obligations. Cross-process persistence, previous-engine quiescence and delivery to an already captured handle remain separate obligations.

When the kernel unloads one view, the registry first detaches the authenticated principal and capsule slot under its write lock. The checked detachment returns the full runtime identity from that slot and the installed handle indexed by that identity. A missing slot preserves all views. Removing the last package prunes the owner row. Other packages and foreign owners retain their mappings at this step. A dangling slot has no installed handle and the native registry treats it as an invariant violation. Subsequent owner-departure processing can deliberately remove dependent views. The registry then uses checked code to decide whether to retain the runtime. A principal-scoped runtime is removed. Departure of a system runtime’s owner selects removal of that runtime and its dependent views. Other callers retain a system runtime exactly when at least one remaining view refers to its full runtime identity. The composed two-principal theorem allows the peer’s package slot to point to another generation. It binds the returned handle and teardown decision to the installed entry. On departure of the owner of a system-resident runtime, the checked transition sweeps every dependent view. It removes all package slots that point to the retired generation, preserves every other slot and value, and prunes empty principal rows. It appends each principal whose view actually lost a slot once to the existing report. An already-empty row generates no notification. The composed theorem allows the owner to hold other packages and starts before detachment. Provided the retiring identity occurs in only its own package slot in the owner’s row, the complete report contains the owner first and each affected peer exactly once. Every other owner slot retains its generation. The same checked function now reads the owner alias from the selected instance, reads the scope from the full runtime identity and updates the instance table. Teardown removes exactly that identity. Retention preserves the entire table, including the installed handle. Under the same write lock, teardown removes every scoped source UUID route whose value equals the full retired identity and preserves all other routes. For a retained runtime the reverse source map supplies the UUID. The transition removes only the pair of that UUID and the departing principal, or preserves the routing table if the reverse lookup is absent. The composed theorems use the teardown decision from the actual installed instance. Teardown removes the reverse lookup for exactly that runtime. Its public UUID-to-package mapping disappears only when no surviving reverse entry uses that UUID. A retained runtime keeps both indices intact. The legacy UUID map associates aliases with an artifact shared across generations. After removal the checked registry scans installed identities for that artifact. If any survive, every alias is preserved. Otherwise it removes all aliases of that artifact and preserves all other mappings. Population and consistency of the source maps, uplink cleanup, delivery of notifications, queue cancellation and the wait for quiescence remain separate obligations.

### Stable source UUIDs and registry reconstruction

The wire source UUID is derived from capsule name and artifact hash and can recur after daemon restart. Scoped lookup first reads the exact (UUID, principal) entry from the current registry and resolves its full runtime identity in the current instance map. A stale scoped entry refuses a handle even when a legacy alias also exists. Only a missing scoped entry permits lookup by legacy artifact. The checked iterator examines the selected principal’s view and accepts exactly one slot with that artifact and a live instance. Zero or multiple matching slots refuse. The proof assumes the documented Rust key laws, well-formed indexes and their supplied contents. The native reconstruction test starts each registry at generation one. A different owner UID rejects the old runtime identity. Reusing the same owner, package and artifact can reissue the entire identity. In that case restart selection accepts the captured identity and returns the newly installed handle. Runtime identity comparison alone cannot fence work across daemon lifetimes. Authenticating the principal at ingress, establishing the contents of rebuilt indexes, and fencing work already admitted by a previous daemon remain separate obligations.

### Durable workspace promotion and rollback

A workspace finish first samples the alias’s current principal UID and the principal’s storage owner. Under the binding-map mutex, the checked lookup selects the record at that UID only when it equals the full requested kernel lease. The selected lease carries the acting UID, storage owner and durable branch identifier. The service reads the durable attachment for that owner and branch. Its checked dispatcher admits only a live attachment with the selected principal UID and the exact configured content-name bytes. An admitted promotion or rollback makes one call with the selected owner and branch and propagates the corresponding storage result. A lease or attachment mismatch produces no storage call. The native fleet regression uses two different branches under the same storage owner, submits each operation against a mismatched lease, then checks a valid rollback and a durable promotion receipt.

The proof assumes the native equality and hashing of the typed IDs and lease, the directory and ownership samples, the decoding of durable binding metadata, and the native storage callbacks. Lookup, attachment read, branch mutation and cache removal are separate steps. Their concurrent ordering with ownership transfer, retirement or a fresh bind, durable commit recovery and the portal filesystem path remain open obligations.

In the storage backend, promotion and rollback both rewrite the concrete references in the candidate owner root. The checked byte decoder accepts the historic bare and prefixed branch identifiers, upper- or lowercase hexadecimal, and the corresponding promotion-receipt spellings. Both transitions remove exactly the records matched by the checked label predicate, preserving the full contents and order of records outside that predicate. Whether the predicate agrees with ownership in the application schema is a separate refinement obligation. Promotion appends one owning reference to the supplied receipt object with the canonical lowercase label. A composed theorem checks that receipt lookup recovers its exact workspace ID, live-branch lookup rejects the receipt, and subsequently dropping the same ID yields only the original survivors. These statements cover preparation of the candidate root. The retry control flow and its calls are covered below. Receipt hashing, catalog merging, and durable root selection after restart remain separate obligations.

During durable group commit, the checked staging function installs the accepted replacement under its prepared owner and preserves all other pending entries. The next preparation looks up its owner in that pending map first and falls back to the published root for that same owner. The composed admission theorem uses full commit identity and generation and checks stale rejection, exhaustion, and the successor generation. The group writer now invokes the checked admission function on its native root maps and expected RootState. The verifier follows RootGeneration and ObjectId into the comparison and checks that conflict is equivalent to inequality of the complete native roots. Its premises include native key ordering and cloning and the engine holding its writer lock across the batch. Two workspace regressions interpose a competing commit before the first CAS on the durable engine. They close and reopen the store after the retry. Promotion recovers the winning branch write and its completion receipt. Rollback preserves a peer created during its first attempt.

The content transaction encoder constructs a checked candidate from the owner, header root, preserved commit references and candidate state object. Before sorting, its references retain every preserved entry and append a parent lineage link exactly when the header names a previous root. The final link owns the supplied state object. On successful encoding the transaction constructor receives the original owner and full expected root together with the returned commit identity and record batch. An encoding failure propagates its error. The proof assumes the native encoder sorts and hashes the supplied records faithfully and the native constructor stores its arguments.

Promotion and rollback share a checked retry loop. Each mutation attempt uses the same owner and branch and the exact header returned by the immediately preceding read. Only a root conflict requests a new read. A failed read stops before another mutation, and the loop returns the terminal read or attempt result. Verus checks the order for arbitrarily many conflicts. Termination under sustained contention is outside this guarantee. The native adapter calls the store header reader and classifies the engine result.

The durable header reader uses a checked lookup in the published owner-root map under the native usable-engine lock. On a cache hit the checked selector requires the sampled owner, the commit key and the complete cached root (generation and commit). An absent root, absent entry, or mismatched root uses the decoder for the sampled owner and root and propagates its result. The composed theorem assumes the cache supplies the observed entry for that lookup and the native adapter reports the root field of the returned header. A durable regression republishes an identical commit at a later generation, retains the prior header, and verifies one new decode followed by reuse of the refreshed header.

Header decoding and live-catalog handoff use the same checked commit-to-state traversal. The first load uses the sampled owner's commit ID. Before the second load, the traversal checks the commit kind, format version, empty payload, zero logical bytes and metadata class. It searches the commit's references for the state label and requires an owning edge. The second load uses the same owner and the selected edge's object ID, and must return a structural principal-state record of the same format version. A loader error can originate only at the selected commit or at the owning state target. The error and success theorems identify the exact reference returned by binary search. For a record with strictly increasing adjacent labels, including labels of different lengths, a matching reference is returned at its unique index. The loader contract ties each result to its owner argument and object ID. The durable engine uses that owner for cache selection and resolves object IDs through shared WAL and arena indexes. The proof assumes the loader returns the record for the requested ID. Native object identity and durable acknowledgement still require end-to-end refinement.

For an arbitrary sequence of state references, the production header decoder checks each owning edge before dispatch. It passes the selected owner, target and sampled root to the catalog reader for a content reference and to the corresponding quota reader for a KV or workspace reference. On success, the header carries the last catalog returned, the exact sum of returned charges and the original non-content references in order. A non-owning edge, reader error or overflowing sum stops the fold at the failing reference. The proof covers dispatch and accounting. For the path-copy catalog, the production leaf charge equals the logical file size plus the byte length of its name. Joining child summaries adds their logical sizes, charges and entry counts separately. Both operations succeed exactly when their totals fit in 64 bits. The catalog leaf validator now loads the file ID named by the leaf and parses the record returned for that ID. On success, bytes 24 through 31 of its 40-byte descriptor encode the declared logical length in little-endian order. The shared file decoder requires a metadata file of the expected version with zero object-level accounting. An empty file has no content edge. A nonempty file returns the exact target of its single owning content edge, subject to the decoded chunk count and profile threshold. The writer and reader round-trip all six persisted fields. For a nonempty requested range in a decoded chunk tree, the production reader selects intersecting children in order, retaining their IDs, original indices, chunk counts, lengths and absolute file offsets. Overflow refuses the plan before the batch load. A chunk can supply bytes only when its kind, version, accounting class, references, payload length, expected count and depth agree. The output routine appends the selected payload slice to the existing buffer, or adds its length in counting mode. Refusal preserves the previous output. For a range crossing two adjacent leaf chunks, the composed theorem yields the left suffix followed by the right prefix under the assumption that the loader supplies the record for each selected ID. The reader requests the exact sequence of child IDs from the plan and pairs returned records with their original visits. It propagates source errors, rejects a wrong batch length, and identifies the first missing child. On the durable path each initial cache lookup uses the selected owner and object ID. The batch records every miss at its original index. Publishing a fetched object supplies that same owner, ID and record to the cache and fills exactly the missing positions for that ID, including duplicates. This proves the request-to-slot mapping. The object identity of records supplied by the cache, pending WAL and arena, generation revalidation under the locks, traversal of arbitrary tree depth, catalog and KV validation, and crash recovery remain obligations.

### Ephemeral process retirement

Registration ignores PID zero and associates a nonzero PID with its supplied principal and optional call identifier. Unregistration removes only that PID. For principal retirement the checked map traversal takes a snapshot under the process tracker mutex. On Unix the dispatcher calls the native group-kill adapter once per distinct PID in that snapshot whose recorded creator matches the retiring principal. An absent call identifier and duplicate identifiers across principals do not affect this choice. The composed proof covers an existing map, a registration that can replace an older record at the same PID, selection, callback dispatch and unregistration. It assumes the native principal encoding and excludes zero in the initial map, an invariant preserved by the checked registration and removal paths.

The snapshot is unlocked before the OS call. Connecting a selected PID to the same live OS process at signal delivery remains an obligation. Cooperative cancellation by call ID, delayed escalation, and non-Unix delivery are outside this theorem.

### Persistent child process selection and signalling

The production persistent-spawn adapter invokes a checked admission sequence before storage preparation. A successful trace checks the principal policy for the requested command, checks host-process authority for the same capsule and command, requires the exact persistence capability and an authenticated caller, rejects zero idle timeout, samples cancellation, and calls the write-ahead admission callback for that command. Only then does the trace permit one storage-preparation callback with that caller and command. Policy, caller, timeout, cancellation, and audit refusals reach no preparation callback. A preparation failure propagates its error. On success the caller and projection returned to the guest host adapter are the ones in the trace.

The native adapter reads caller context and live policy, selects the admitted storage UID, and calls the projection broker when pathless storage requires it. An absent audit sink can accept the admission callback without a durable write. The theorem covers these callback arguments and outcomes. It does not establish generation continuity through later waits, an atomic OS-spawn quota reservation, or recovery of a child after daemon failure.

Before returning a token, the registry tests its keyed digest under the registry mutex. The checked publication loop uses only a vacant slot. On success the only map change is the new entry at that token’s digest. If all nine digests collide, the map is unchanged and the pending monitor is returned for cancellation. The proof composes publication with lookup by another caller, allowing collisions among the candidate digests and foreign entries already in the map. Its assumptions include the token generator, digest function and native constructor that records the child and its owner. The native regression checks both exhaustion and a fresh final attempt.

Release checks the token, creator, capsule and observed liveness while holding the registry mutex. Verus checks that an absent, foreign or observed-live entry leaves the entire map unchanged. A successful removal returns the exact selected entry for reaping and preserves every other slot. The proof assumes the native liveness observation is accurate. Establishing that the OS child has actually exited requires a separate argument about the monitor and its synchronization. Actual OS cleanup after removal remains a separate obligation.

Each loaded Wasm engine creates one persistent-process registry in `WasmEngine::load` and shares it with that engine’s pooled stores. Principal retirement scans that registry under its mutex. The checked traversal selects every entry whose recorded creator matches the retiring principal, regardless of the capsule label on the entry. Extending that result to the daemon requires showing that retirement reaches every registry that can own a child of that principal, including registries in runtimes being replaced. Removing them preserves every foreign entry and produces one cleanup entry per distinct selected key, with the original value from that key. The registry releases its mutex before reaping those entries. A composed theorem starts before publication and follows the minted digest into the subsequent drain. Retiring the creator hands that exact child to cleanup. Retiring a different principal preserves the published entry. The proof covers the map at the instant of the drain. It assumes the native principal encoding and leaves later publication, OS termination and restart recovery as separate obligations.

After unlocking the registry, principal retirement invokes the cleanup callback on each returned entry exactly once, in batch order. When the capsule cancellation listener observes cancellation and calls registry shutdown, the registry swaps the entire map out under its mutex, then consumes it outside the lock. Scheduling the listener and ordering shutdown with later spawn attempts are separate obligations. The checked dispatcher accounts for every original token-entry pair, even when two entries have equal modeled values. The process reaper passes the detached entry’s sampled liveness, numeric PID and monitor handle into checked disposal. A live observation requests a kill for that PID before requesting abort of that monitor. An exited observation requests only the monitor abort. This counts requests even when the kill fails. Liveness sampling and extracting those two fields from the entry are native. A regression separately observes that shutdown removes two principals’ tokens and finishes both monitor tasks. OS signal delivery, monitor-to-child identity, and abrupt daemon death remain outside these guarantees.

A token lookup hashes the presented token under the registry key and checks the entry at that digest under the registry lock. The checked selector returns that exact entry only when both the creator principal and capsule spelling match. Status reads and handle resolution use this selector. Batched status omits missing and foreign entries. Release preserves its existing distinction between an absent token (idempotent success) and a foreign entry (refusal). List filters by the same owner comparison. Token generation, keyed hashing and extraction of the two native owner fields remain trusted inputs to this selection proof.

On Unix the signal adapter rejects zero and out-of-range PIDs. It submits the selected positive PID and signal to the process-group callback first. A failed group call permits a direct-process call with the same PID and signal. Native tests check callback order and operands. The composed consumer uses a modeled entry carrying its PID. The native mutex, phase observation, signal mapping, PID reuse, OS delivery and continuing owner rights during waits remain outside this proof. A numeric PID alone cannot establish child identity across exit and reuse. Linux's bubblewrap launcher requests parent-death cleanup. The opted-in macOS persistent child can survive a hard daemon crash inside its Seatbelt sandbox. Reconstructing the in-memory registry does not demonstrate that the old child lost its OS authority.

### Lifetime of a live TCP handle

Outbound connect and accepted connections install a `NetStream::Tcp` entry containing the socket and its timeout settings. That entry carries no creation-time principal UID or device generation. The resource table belongs to one Wasmtime Store. For a completed free checkout, the pool's checked return policy retires an instance if its table contains any resource. A successful persistent host-process checkout preserves the table. Run-loop Stores also live across events. On interceptor admission, a principal-scoped runtime requires the caller's observed UID to equal its reserved UID. A system-resident runtime has no reserved principal UID. Table locality alone therefore cannot establish which caller or device may reuse a live socket in every hosted configuration. Persistent checkouts, run-loop dispatch and listener readiness still need a proof connecting socket creation and later use to the authorized caller and generation.

## Native MCP network authority

Native stdio MCP capsules requesting network domains or outbound TCP destinations fail during load. The process sandbox accepts only a Boolean network setting and cannot express the manifest's destination policy. Accepted native capsule configurations request networking disabled, including for uplinks. The scope of this decision is the capsule host engine. Standalone MCP server configurations and operator-selected sandbox policies require separate treatment in the hosted security argument.

The manifest check and stdio command selection are production Verus inputs. For a nonempty domain or TCP destination list, the composition produces no command and no builder call. For two empty lists it returns exactly the result of one sandboxed build for the supplied program and configuration, with networking disabled. A sandbox preparation error is returned unchanged and produces no direct build. The load test checks all four empty/nonempty combinations on a fresh engine, including the transport and both authority flags in the actual prepared configuration. The composition assumes that activation retrieves this configuration for the same runtime and that the server manager passes its actual program and fields to the selector.

A sandboxed build requests the platform wrapper. Under the required policy, unavailable containment fails preparation. An explicit operator opt-out permits an unwrapped process, and an explicitly trusted standalone server takes the direct builder. Neither mode supplies OS isolation for an untrusted child. Executing the selected command, validating a platform wrapper, and enforcing its network policy in the OS remain outside the command-selection proof.

For sandboxed preparation, the verified workspace selector validates paths for either operator policy before requesting a platform prefix. Required mode can succeed only with the exact prefix returned for that configuration. A path or platform error produces no child command. Off mode can return an empty prefix only after successful validation and makes no platform request. The MCP assembly step takes the selected prefix and the resolved child program and arguments. The composition records exactly one wrapped command under Required, or one bare command under Off. The native manager translates workspace I/O errors to named MCP startup errors before assembly. The platform callbacks, construction of the inner argv and subsequent environment setup, spawn, and kernel enforcement remain native boundaries. A regression inspects the real platform wrapper and the complete child argv suffix on supported hosts and checks that unavailable required containment refuses command preparation.

The native encoders now consume the admitted network setting. On Linux the checked finalizer preserves the preceding mount arguments exactly, then appends `--unshare-all`, an optional `--share-net`, `--die-with-parent`, and the option terminator in that order. On macOS the checked renderer constructs the complete Seatbelt text from validated path lists and a writable root. It starts with version 1 and default denial, grants process execution and fork, and emits the general network grant only in enabled mode at that position. The consumer composes both encoders with native capsule admission, for which only the disabled case is reachable. It assumes the Linux argument conversion preserves each literal and the earlier mount sequence is valid. For path-derived Seatbelt rules, the checked validator rejects exactly UTF-8 strings containing a double quote, backslash or NUL byte and returns the original string on success. The checked encoder preserves that path in the selected literal, subpath, injection write deny or paired hidden-path denies. Verus checks that each list retains its order and duplicates. Hidden paths classified as ancestors of grants are denied before the explicit grants. Other hidden paths are denied afterward. One injection list determines both the read literals and the final write denies in the same order. The independent harness specifies the placement and operation of each group for arbitrary inputs. The checked classifier marks a hidden path as scoped exactly when its components prefix the writable root or a member of the extra read, extra write or injection-target lists. Neither injection sources nor metadata ancestors participate. The native adapter supplies the result of one Rust Path::starts_with comparison for the two specified strings. Its component semantics, ancestor collection, native path selection and shape checks, and kernel interpretation remain outside the theorem. This is an encoding theorem; the platform kernel remains a trust assumption. A native macOS test applies both profiles, runs a child under each, and checks connectivity at a local TCP listener.

The native capsule engine registers a manager key formed from the capsule, server, runtime scope and generation. Its interceptor invokes the fixed `astrid_hook_intercept` tool with the hook and payload on the key retained by teardown. Under one registry read guard, the production selector looks up the borrowed server name and obtains the handle from that entry's service. Verus checks that a missing-name result has no matching key, a disconnected result observes no peer on a matching entry, and an accepted handle is the callback result for that entry. The tool client sends through the owned peer after releasing the guard. A native duplex test registers two live peers and checks that the tool request reaches the selected peer exactly once and the other sees no request.

The native encoder reads the capsule ID, scope and generation from the registry-issued runtime. Verus checks the exact manager name against the capsule and scope projections, server text and unsigned decimal generation. Two different generations produce different names even if every preceding component differs. A composed consumer obtains the handle or lookup error for the encoded name. Native tests check both scope variants, server names containing a colon and decimal boundaries up to the last reservable generation. The capsule text accessor and the principal display adapter remain trusted at this boundary. The latter uses the separately checked principal hex encoder.

For outbound tool calls, the production manager binds the tool name and complete argument value to the selected peer while holding its registry read guard. Dispatch consumes that bound request after the guard is released. The checked hook constructor fixes the tool to `astrid_hook_intercept` and supplies the original action and decoded payload to its argument encoder. The consumer composes generation-specific name construction, hook preparation, registration lookup and the send callback. Native duplex coverage checks the remote peer's parsed arguments, including a nested field also named `hook`. JSON decoding and encoding, rmcp request construction and transmission, and authorization of the originating call are separate obligations.

A mutex now serializes the teardown owner's transitions. Starting cleanup freezes the last registered name, including the empty case, and issues one worker token. Later registration and duplicate starts preserve that state. The checked completion transition accepts a token with the retained name and clears it. A consumer composes the native encoder with registration, worker election, replacement refusal and completion. A token for a different generation cannot complete that cleanup. Native tests exercise two waiters before registration, a cancelled owner, a failed disconnect, and retry against the same target. The mutex and wakeup implementation, the async disconnect and absence observations, and actual transport termination remain trusted.

The queued interceptor entry calls through `dispatcher/queues.rs`, with a device-access recheck for stamped messages. Direct entries also exist. The tool-discovery helpers request `tool_describe` with a principal view or no caller, and the kernel restart handler requests `handle_lifecycle_restart` without a caller. Each currently supplies empty bytes. When the native MCP engine reaches payload decoding it rejects those bytes before calling the tool. A proof of dispatcher admission alone would miss these callers. The native adapter ignores the optional caller when constructing the MCP hook arguments.

The uniqueness result covers distinct generation numbers. Preventing reuse across restart, identifying an occupant through handshake and reconnect, hook-dispatch authority, and cancellation relative to sending still need refinement. The peer-clone semantics and rmcp transport are trusted here.

### External MCP broker entry points

The CLI stdio broker implements `AstridMcpServer::call_tool` in `crates/astrid-cli/src/commands/mcp/server.rs`. Its HTTP adapter delegates to the same handler. The broker captures the requested tool and arguments, processes multi-round continuations, and publishes tool requests on `astrid.v1.request.mcp.tool.call`. Ingress trust, capsule grants and approval decisions have separate response topics. Listing tools uses `astrid.v1.request.mcp.tools.list`. The CLI stamps its principal on outgoing IPC and matches a reply to its request. Its loss-of-connection policy while awaiting a reply permits retry for tool enumeration. A send failure has a separate reconnect-and-republish path. Proof obligations include authenticated ingress, target continuity across consent and reconnect, classification of send failures, and broker-side admission before the eventual capsule effect. The outbound peer theorem above covers a different call path.

Both issuance and resumption of a multi-round consent token call the same production associated-data encoder. Verus checks the bytes supplied to the incremental digest, in order: the v1 domain with its terminating NUL, principal text, NUL, tool text, NUL, and serialized arguments. If neither principal text nor serialized arguments contain a raw NUL, equal transcripts imply equal principals, tools and argument bytes. A consumer discharges the principal delimiter condition from the production principal-ID grammar. The tool itself can contain NUL. The production resolve path opens the token against that context and claims the same token in the redemption store before returning the pending consent and lease. The proof covers the inputs and outcomes of those two callbacks. Principal text conversion, JSON serialization (including its empty-vector fallback on error), BLAKE3, the signed-state codec, and the redemption store's synchronization and expiration remain trust or refinement obligations. Native tests compare a v1 digest with embedded NULs in the logical inputs and exercise refusal of a changed principal, tool or argument value.

The stdio broker borrows the inbound tool name and normalizes missing arguments to JSON null. The same invocation supplies both fields to consent issuance and redemption, and to the encoder on initial and resumed tool calls. The checked publisher passes the tool-call topic, the same correlation id supplied to the encoder, and its returned body to the transport callback. The native encoder regression checks null and structured arguments across two request ids. JSON serialization, insertion of the workspace, socket writes and authenticated principal/generation at the receiving broker remain outside this argument.

Inside the process-local redemption lock, reserving a digest writes the new deadline and issues a lease exactly when that digest was absent. A duplicate refreshes the deadline and receives no lease. A committed lease preserves the entry on drop. An uncommitted lease removes its own digest. For a fresh digest and two serialized reservations, Verus proves these outcomes and preservation of every other entry under the standard hash and equality laws for the 32-byte key. The native test starts two callers together against the same signed state, holds both results, and checks that only one obtained a lease. Dropping the winner allows retry and committing the retry prevents another redemption. The ingress, grant and approval handlers pass their local decision or transport result into the lease. The checked transition returns that exact result. Any successful response, including a denial, consumes the claim. An error releases it on ordinary drop if the lock can be acquired. A poisoned mutex can leave the claim reserved. A continuing ingress or grant response settles the lease before the subsequent tool publication. A lost reply can follow an already executed remote operation. The proof starts after expiry pruning and presumes the entry stays in the same table during the lease. A broker reconnect also needs an argument that the principal text still denotes the authorized durable identity and generation. Process restart, token expiration and the point at which the broker effect becomes irreversible remain outstanding.

## Evidence and trust

The current verifier entry point imports production modules directly alongside an abstract model of grant and principal authority. Their contracts cover fuel arithmetic, per-principal operation tracking, static pattern matching and containment, token status transitions, the startup marker fold, guest owner selection, KV address encoding, overlay lookup and update, filesystem gate paths, native transport and device identity decisions, and native mount callback admission. The model's theorems state what every trace of the grant, tracker and fuel transitions preserves, conditional on the stated storage, settlement and lifecycle obligations: an acknowledged revocation keeps the grant revoked across recovery and an acknowledged consumption keeps it used, a revocation keeps the grant revoked until the next recovery whether or not its write completed, retirement keeps the principal closed until a resume, and committed fuel exceeds the budget only by the fuel charged beyond a promise. Its `apply_*` and `fuel_*` functions show that the production transitions compute the model's steps. The verifier also checks durable root encoding and parsing, logical WAL record position and body, physical envelope bounds and bytewise interior search, WAL measurement and digest framing, commit-marker confirmation, ordered replay descriptors, group identity through the publication frontier, and WAL sync accounting. The hosted guest KV regressions exercise abrupt exit and reopening with journal and WAL writes. The WAL case checks that the on-disk volume still contains a nonempty WAL before opening with new WAL writes disabled. Complete mediation of hosted effects and concurrent runtime refinement remain open.

The hosted security argument must state its assumptions about the OS, hardware, Wasmtime, cryptography, persistent storage, compiler and verifier. Release evidence must identify the source, build configuration, binary digest and proof result. Evidence about an installed instance must also identify the running binary and security-relevant configuration through a measurement mechanism whose trust assumptions are disclosed.


### Physical and logical filesystem authorization paths

For native workspace, home and temporary mounts, the resolver canonicalizes the root and the deepest existing ancestor. It collects missing child names from leaf to ancestor. The production reconstruction appends them in the reverse order and calls platform prefix removal on that exact result and the canonical root. Success retains the physical gate path and its relative VFS address together. Eight guest VFS operations pass their policy gate, relative address and selected mount through the checked admission function. Successful admission returns the policy guard with that mount and address. The eight guest path adapters retain the guard in their resolved VFS address through the synchronous, non-cancellable host bridge. The child-process path helpers return a path and release their local guard. Verus checks the admission and path reconstruction routines. The surrounding Rust resolver, guard lifetime and host adapters are linked by source inspection and native tests. A component-sequence consumer proves that binding succeeds exactly when the gate allows the reconstructed path, the selected mount exists and the root is a prefix. Rejoining the root and address recovers the path recorded in the guard. The native tests also check the relative address for an existing in-root link and for absent children. The resolver takes each missing name from `Path::file_name`; its native append relies on that name being one component, because an absolute argument would replace the prefix in `PathBuf::push`. The platform path push and strip operations, filesystem observations under concurrent rename, correspondence of native roots to registered handles, and conversion of OS paths to VFS strings remain assumptions or open obligations. This theorem starts after the ancestor has been identified.

In HostVfs, seven directory operations retain the registered directory under the handle-table read lock, normalize the requested path and submit that owned pair to the blocking worker. File reads and writes use the same checked table lookup to retain their file entry. The composed directory proof selects among mount tables that may use identical handle numbers. A denied policy check or missing handle yields no worker address. Success supplies the directory from the selected table and the output of normalization for the admitted relative path. The native HostVfs wrapper is outside Verus. Both native tables use the checked installation and removal transitions. Installation updates only the supplied key, and close reports whether it removed a live entry. A second proof closes the key, checks that a second close fails, and rebinds it before dispatch and distinguishes the previously captured directory from the replacement. The native regression reads different bytes from those two real directories after rebinding. The handle hash/equality laws, faithful platform normalization, the retained reference's association with an OS descriptor, and the actual cap-std and Tokio operations remain assumptions. A WIT write regression retires the principal during write-ahead admission. It checks the active count and file bytes at admission and at completion, then checks that a later write is refused. Removal of a handle prevents fresh lookup during the vacancy. It does not retract work that already owns a reference.

Guest file admission retains the access variant alongside its policy guard. The composed proof follows that variant through mount selection, directory lookup and native option construction. A read requests read access alone. A guest write requests read, write, create and truncate on the selected directory and path. Probe and delete cannot open a file through this dispatch. The builder proof also covers direct callers that request write without truncation. A native regression uses manifest permissions to check denied writes and creation, permitted creation, and replacement with shorter content. Native policy evaluation, the cap-std option setters and the operating system's interpretation of the path and flags remain trusted. The proof ends at the open callback.

The storage-backed VFS has a different publication point. After stat accepts a regular file or reports a vacant path, `storage_file::open_at` constructs the production descriptor. For a preserving open it reads the classified path at the reported length, or propagates the read error. A read of a missing file and a read-only truncate retain distinct refusal cases. A write that creates or truncates starts with an empty dirty buffer. The guest replacement proof composes write admission, open dispatch, descriptor creation, overwrite and close-time publication selection. For arbitrary replacement bytes, including zero bytes, success offers exactly those bytes at the backend path supplied to open. For any valid table size, a lookup and retirement on the same snapshot agree on presence and slot identity. A second proof follows two simultaneously registered file handles through a refused duplicate registration, write lookup, close of the other handle, retirement and repeat close. It uses the production handle table and descriptor transitions, representing distinct mutexes with two slots. The callback receives the first descriptor’s path and exact written bytes, and the other buffer stays empty. Coupling those slots to the real Tokio mutexes and ordering their operations under the table lock remains a refinement obligation. The backend path join, native locks, publication callback and crash durability require separate evidence.

The owner and workspace filesystem writers both use the checked replacement constructor. It requires a successful parent lookup, a target that is not a directory and a valid content key. The constructor carries the selected owner or owner/branch pair, key and full byte slice into the store callback. The actual UTF-8 key constructor preserves every character and rejects empty or NUL-containing names. A composed proof starts at directory/suffix joining, performs a buffered replacement and follows its close callback through key validation and catalog submission. Another consumer checks refusal and backend-error propagation. The runtime regression reads the same Unicode key from the selected branch, a sibling branch, the owner catalog and a second owner after a replacement. The proof assumes the parent and target observations describe the intended snapshot. The production adapters supply the owner and branch, and the store callbacks still owe refinement for content construction, concurrent root publication and crash recovery.

Workspace writes, streaming writes, name removal and batch rename now use the same checked retry loop as promotion and rollback. Every completed attempt consumes the header sampled for the selected owner and receives the original branch ID. Only a root conflict requests another sample. Rename repeats its source and destination checks on that new sample. The native adapter maps storage outcomes to retry decisions. The attempt body, including catalog insertion, selection of quota inputs, removal of old references and root encoding, still needs refinement. The production branch-edge constructor appends one owning reference to the supplied record ID. Its checked encoder and recovery parsers agree on the branch UID and distinguish this live edge from a promotion receipt. The proof preserves the entire list supplied to the append, so correctness of the caller’s earlier filtering remains a separate obligation. A durable-engine regression interleaves two writes to the same key in sibling branches and reads both values and the owner catalog after reopening.

Content-DAG construction, catalog node interning and principal transaction assembly now stage records through the same checked identity and insertion function. An identical declaration is idempotent. A different record under the same computed ID leaves the staged map unchanged and returns that ID as a collision. Owner and workspace transaction encoding also use the checked metadata constructor for both the principal state and its commit. Given the reference list after native sorting, it rejects noncanonical labels or stages the supplied kind, format version, references, empty payload and zero metadata charge. A consumer follows the staged state ID into the owning link of the pending commit while preserving the owner and expected root for CAS. The content builder, catalog interner, transaction encoder and KV staging callers are outside the verifier. Their calls into the checked primitives were confirmed by source inspection. The identity callback, preservation of the input references by the native sort, and durable publication of this candidate remain refinement boundaries.

The public root transaction constructor places its principal, expected root, proposed commit and declared immutable records into an unsealed declaration. Both engines use the same checked admission method. On unsealed input it checks every row before returning the original update, or reports the first mismatched declaration. The durable writer selects the next generation against the pending root for that owner, falling back to the published root for that owner. A consumer follows an unsealed transaction through both decisions. It proves the observed and expected roots on conflict, exhaustion at the maximum generation, and the exact replacement commit and next generation on success. Source inspection confirms that the native durable writer retains that selection while it validates the closure and prepares object frames. The sealed-declaration consumer invokes the production checkpoint handoff used by both engines. The adapter supplies the engine’s pointer-identity comparison. Only the issuer may receive the private checkpoint. Foreign admission verifies the supplied rows, and an identity mismatch preserves the checkpoint and reports the first offending row. The journal encoder and WAL handoff consume the retained owner, expected root and replacement together with the bytes produced for that transition. The in-memory and durable adapters supply the engine identity function and the comparison of process-local seal authorities. Map-to-vector collection before transaction construction, the native writer lock and the correspondence between successful preparation and durable acknowledgement still require refinement.

For a configured owner limit, the production catalog quota decision compares the new owner-wide total with both the limit and the previous total. An over-limit owner can retain or reduce existing usage. Replacing a branch subtracts its sampled charge from the other-components total before adding its new charge. Promotion removes the consumed branch charge and replaces the previous owner catalog with the merged catalog. A proof checks the resulting total, including every other component, and the exact refusal when a promotion would grow an over-limit owner. All three paths reject an unrepresentable total, and a branch charge larger than its containing total is an accounting error. A consumer composes catalog leaf and join accounting with this decision, including the UTF-8 name length in the charge for a newly inserted leaf. The runtime still supplies the policy lookup, header fields and catalog summaries. Their correspondence to the committed objects, and enforcement for every publication path, remain separate obligations.

Invocation setup can also affect the host filesystem before any guest file call. The kernel passes an overlay registry into the capsule context. After principal selection and fuel reservation, `WasmEngine` resolves a cache entry before pool checkout. A miss opens the workspace root, creates a temporary upper directory, registers both directory handles and races to install the result under the invoking principal. Eviction or a lost insertion race can release the last reference and trigger temporary-directory cleanup. The returned overlay is dropped at this call site. Guest workspace I/O uses the effective principal branch, registered git workspace or registered OS copy-on-write merged directory selected at load or invocation. These registry allocations and cleanup effects are outstanding obligations distinct from file-open mediation. The configured cache limit counts entries and does not bound concurrent builders or retained references.

For a storage-backed home or workspace, the filesystem host passes the validated
relative path to `LogicalRoot::bind_path`. Its checked result couples the gate
string, the relative path and the mount selector. The home case prepends
`home://` and selects the home mount. The workspace case prepends
`workspace://` and selects the workspace mount. Both preserve the entire
relative path, including an empty root path. The adapter converts the returned
suffix to a platform path. Native path resolution, platform path conversion,
profile matching and backend publication remain separate obligations.


For native child-process storage, the guest adapter supplies an admitted UID
to the kernel broker. Workspace binding checks this UID. It also identifies the
private home, the process projection cache key and the caller checked at lease
issuance. For a fleet view, authorization still depends on the ownership graph
and workspace branch descriptor. The proof of UID selection does not discharge
provider startup, cache lifetime, fleet ownership changes or callback teardown.


Native mount callbacks decode a V1 operation directly or translate a V2 request
to that operation. The checked callback gate consumes the decoded operation.
A revoked lease or an observation after expiry yields a stale response. A live
lease with a failed token comparison yields an unauthorized response. A write on a read-only lease yields a read-only response. On success, the gate
issues a single-use value. Its checked destination binding borrows the target
and backing from the issued lease. Both effect variants retain the lease.
The Unix restart regression exits after a real callback without shutdown,
reopens the same home, and checks old and fresh credentials against the
replacement callback. The test observes kernel and local transport behavior on
the tested platform. The clock adapter samples both monotonic idle time and wall time. The checked
gate requires both deadlines and a valid epoch reading. The deadline mutex
latches an observed expiry. Sampling clocks, binding the deadline to issuance
and ordering the revocation read with those samples are runtime obligations.
The proof still needs the correspondence to a coherent concurrent observation,
the V2 decoder, token hashing, backend execution and durable completion.


The native backend dispatcher exhaustively classifies all V1 operations.
Stat, directory enumeration, range reads and volume information are reads.
Write, set-length, create, remove and rename require a writable lease. Sync
is permitted on a read-only lease and takes the same serialization lock as
mutations. Verus imports the production V1 wire enum and checks the classification of
every variant. Admission computes that class from the decoded operation and
checks its write permission before issuing the executor value. It also proves
the class-specific serialization decision. The actual
OS lock, worker lifetime and stable-storage semantics remain obligations.


For serialized writes and sync, worker preparation checks for a guard and a
live lease after waiting. The production blocking worker owns that guard. The
checked synchronous handoff invokes its sink with the admitted work and a
borrow of the guard. The sink performs the filesystem operation and publishes
the dirty bit before returning. The trace consumer connects the sink's result
to the issued scope and operation under the observed phase, liveness and
credential conditions. The concrete sink implementation, Tokio mutex semantics
and the order of revocation acknowledgement remain refinement obligations. The worker-drain integration test cancels the async waiter while the worker
is active and exercises revocation before and after release. This is execution
evidence. Concurrent refinement still requires proving the correspondence
between the lock, lifecycle transitions, worker effects and durable storage.


At lease issue, the native subtree selector accepts the exact spellings
`home` and `shared`. The checked binding function carries the original
principal UID into a home target and the original fleet UID into a shared
target. A mismatched owner kind or the system owner yields no binding.
The callback worker and administrative sync consume that typed destination.
Both filesystem adapters route relative paths through the checked join used
by `FilesystemPath`. Rename joins each of its two paths independently.
Owner lookup, workspace branch membership, physical storage key resolution
and crash durability remain separate refinement obligations.

### Principal retirement and native lease lifetime

Native lease issue registers a reservation before checking the requester's live
directory binding, profile and retirement fence. Registered requesters are
matched by durable UID. Profile-only management requesters are matched by
alias. Disable, deletion and failed initialization close matching reservations
and issued leases. Publication and retirement share a lock. Re-enable requires
a fresh lease. Integration tests exercise the management handlers, failed late
publication, and survival of an unrelated requester's lease.

The production reservation transitions are checked. A matching retirement
closes a reservation; a publication claim consumes it. A closed reservation
cannot publish. The lease trace model represents preparation, publication,
callback admission, explicit revoke, requester retirement and restart for one
mount identity. Revocation, matching retirement and restart permanently close
that identity in the model. A verified consumer takes a runtime phase equal to
the trace prefix and proves the composed dispatcher returns no effect after
closure, even for authenticated writable access. Establishing that phase
relation under concurrency is a production refinement obligation.
The callback refinement uses the production liveness
and operation admission functions and preserves the supplied lease and operation.
The callback executor consumes a checked destination choice from the issued
lease. The scope fixes the mount ID, requester identity and logical target at
issuance. The backing captures the principal store,
runtime home and mutation lock at issue. Volume queries use that home.
Filesystem operations preserve the issued target, lease, operation and access
class. The checked backend selector routes only writes on the system owner root to
the admin projection. All other filesystem calls keep the exact issued owner,
workspace branch or subtree target. The production admin projection uses the
captured runtime home. Owner conversion, filesystem construction, confinement,
host filesystem operations and worker completion require further refinement.

The remaining proof must establish that publication, enumeration of affected
leases, profile transitions, callback observations and worker completion refine
those events under concurrency. Restart in this model discards process-local
authority; recovery must prove that no old listener, worker or credential can
admit an effect in the replacement daemon. The backing volume described by
`VolumeInfo` is a distinct target from the mounted subtree.
