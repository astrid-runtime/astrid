# Security contract for hosted Astrid

## Claim to be established

For each supported hosted configuration, every privileged effect caused by an untrusted guest or external caller must correspond to an admission permitted by the authority policy. The admission identifies the effective principal, its generation, the operation and its target. A forwarded request must retain authenticated provenance. Redirects, aliases, transferred handles and deferred work must preserve the authorization for the actual effect.

The specification must identify the admission point for each operation. Revocation prevents subsequent admissions under the revoked grant. A previously admitted operation may finish where the interface permits it. Acknowledged durable revocation survives every supported restart. A single-use grant permits at most one successful admission across retries and restarts. Reissuing an alias must never transfer the authority of its previous owner.

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

Fourteen HTTP, network, IPC and process adapter call sites currently allocate placeholder resources. Their successful allocation returns an always-ready pollable, a closed input stream or a closed output stream. These methods do not attach the returned resource to the underlying transport or process. The constructors propagate allocation errors through trappable host imports. A failed pollable subscription releases its partially allocated parent. Resource identity, accounting and guest-visible trap refinement remain proof obligations. The file-handle destructor above is distinct from the internal storage-backed file publication described below.

### Guest command approvals

A guest prompt subscribes to its UUID-specific reply topic before publication. Command approval and local-egress consent use the same checked comparison of the responder's stamped principal and authenticated request owner. Both classify the reply bytes using the exact three wire spellings for one-shot, session and persistent consent. Every other byte string yields denial.

For a persistent command approval, the checked dispatcher supplies the persistence callback with the pending prompt's principal and sanitized action. A successful persistent result requires that callback to succeed. Any error from the callback propagates to the hostcall, which records a denial. The persistence selector sends a hosted grant to the profile writer with the selected pristine workspace path and sends an Astrid-workspace grant to the path-free writer for that principal. A theorem composes the responder check, wire classification and both persistence destinations. It distinguishes the two workspace kinds, a different path, a different command family or principal, and a storage error.

The native adapter supplies the event fields, workspace selection and actual profile writer. The theorem assumes the request topic and sampled stamps are authentic. The admitted action is a command family. Concrete allowance matching and consumption, session-grant insertion, device or principal retirement during the wait, and durable profile publication remain separate obligations.

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

For a stable table of checksum-validated frames, the reverse-coverage theorem follows a walk from byte zero. Each visited identity has either the visited location in the map or an earlier indexed frame with the same complete payload. A single retained row followed by a second equal-length frame admits exactly when the two payloads match, under the stated valid header and tail assumptions. The native adapter supplies bounded checksum-validated reads. Indexed rows in the normal path still defer payload hashing until use. Crash persistence, a matching media generation, and the concrete sync and rename operations remain open.

The lookup used by `ClosureObjects::load` checks the incoming map first, the optional pending WAL map next, and the arena index last. On a disk lookup the result comes from the reader invoked with the original object id and its mapped location, including when that reader fails. When all layers miss, the error constructor receives the same id. The theorem assumes the ordered-map invariants and specifies the in-memory clone and media-reader callbacks at their interfaces. For transactions without a matching engine seal, the live preparation path checks every declared id against the identity computed over its corresponding record. A mismatch reports the first offending declaration and computed digest. Snapshot restore uses that same per-record check before inserting a record.

Both the durable and in-memory commit paths run the same checked admission decision. An unsealed transaction always takes the per-record check. With an engine seal, the production adapter calls `Arc::ptr_eq` on the retained and current authority. Only a match can skip that check and take a KV checkpoint for publication. A foreign seal takes the full identity check and retains no publication authority. A proof consumer checks all three cases for an exact authority comparison. The engine adapters still supply the identity and the allocation comparison.

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
The gate’s checked byte transition opens a staged gate, preserves a published
gate and maps every other value to retirement. The checked release function
returns the exact pending payload only for the published byte. Single receive,
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

The handshake and established connection writers both use `framing::write_frame`.
The checked header constructor rejects lengths above the four-byte wire limit
and encodes every representable body length exactly in big-endian order.
For that header and serialized body, `FrameSegments::next` returns
a prefix of exactly the remaining bytes. It is empty exactly at completion.
An accepted short write drops precisely the count reported for that offered
slice. Zero or excessive counts leave the cursor unchanged. The async driver
passes each offered slice to Tokio, advances after a successful write, and
flushes once all bytes have been accepted. These proofs cover selection and
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

## Native MCP network authority

Native stdio MCP capsules requesting network domains or outbound TCP destinations fail during load. The process sandbox accepts only a Boolean network setting and cannot express the manifest's destination policy. Accepted native capsule configurations request networking disabled, including for uplinks. The scope of this decision is the capsule host engine. Standalone MCP server configurations and operator-selected sandbox policies require separate treatment in the hosted security argument.

## Evidence and trust

The current verifier entry point imports production modules directly alongside an abstract model of grant and principal authority. Their contracts cover fuel arithmetic, per-principal operation tracking, static pattern matching and containment, token status transitions, the startup marker fold, guest owner selection, KV address encoding, overlay lookup and update, filesystem gate paths, native transport and device identity decisions, and native mount callback admission. The model's theorems state what every trace of the grant, tracker and fuel transitions preserves, conditional on the stated storage, settlement and lifecycle obligations: an acknowledged revocation keeps the grant revoked across recovery and an acknowledged consumption keeps it used, a revocation keeps the grant revoked until the next recovery whether or not its write completed, retirement keeps the principal closed until a resume, and committed fuel exceeds the budget only by the fuel charged beyond a promise. Its `apply_*` and `fuel_*` functions show that the production transitions compute the model's steps. The verifier also checks durable root encoding and parsing, logical WAL record position and body, physical envelope bounds and bytewise interior search, WAL measurement and digest framing, commit-marker confirmation, ordered replay descriptors, group identity through the publication frontier, and WAL sync accounting. The hosted guest KV regressions exercise abrupt exit and reopening with journal and WAL writes. The WAL case checks that the on-disk volume still contains a nonempty WAL before opening with new WAL writes disabled. Complete mediation of hosted effects and concurrent runtime refinement remain open.

The hosted security argument must state its assumptions about the OS, hardware, Wasmtime, cryptography, persistent storage, compiler and verifier. Release evidence must identify the source, build configuration, binary digest and proof result. Evidence about an installed instance must also identify the running binary and security-relevant configuration through a measurement mechanism whose trust assumptions are disclosed.


### Logical filesystem authorization paths

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
