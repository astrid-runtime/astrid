# Security contract for hosted Astrid

## Claim to be established

For each supported hosted configuration, every privileged effect caused by an untrusted guest or external caller must correspond to an admission permitted by the authority policy. The admission identifies the effective principal, its generation, the operation and its target. A forwarded request must retain authenticated provenance. Redirects, aliases, transferred handles and deferred work must preserve the authorization for the actual effect.

The specification must identify the admission point for each operation. Revocation prevents subsequent admissions under the revoked grant. A previously admitted operation may finish where the interface permits it. Acknowledged durable revocation survives every supported restart. A single-use grant permits at most one successful admission across retries and restarts. Reissuing an alias must never transfer the authority of its previous owner.

## How to discharge the claim

A refinement proof must map each production execution to a permitted sequence of abstract events. Internal steps may leave the abstract state unchanged. Each externally visible effect requires a matching admission. Recovery must reconstruct a state consistent with the acknowledged durable history. The argument must include concurrent calls, canceled futures, errors after a durable write and recovery before admission reopens.

The production Wasmtime linker and the inventory test resolve the same checked-in world in `crates/astrid-capsule/wit-staging/kernel.wit`. Its 18 versioned interfaces declare 202 functions and 15 owned resource types with implicit drop operations. The [host import inventory](../crates/astrid-capsule/tests/fixtures/host-imports.txt) names each function and destructor, including resource methods in both HTTP and process versions. The guest lifecycle interface contributes types only. Run `cargo test --locked -p astrid-capsule --test host_import_inventory` to compare the list against the resolved world. The inventory checks names and versions. Signatures, call-site mediation and the effects of implementation changes require separate evidence. Component loading and lifecycle hooks use the same linker configuration.

Kernel management IPC, enrollment and redemption, MCP invocation, and native capsule execution also require coverage. Their authority may come from authenticated management policy, durable reservations or trusted runtime ownership. Each path needs a specification for its own authorization decision and a connection between that decision and the eventual effect.

## Guest key-value storage

All seven operations in `astrid:kv/host@1.0.0` enter through `impl kv::Host for HostState` in `crates/astrid-capsule/src/engine/wasm/host/kv.rs`. Get, set, delete and compare-and-swap take a key. List, paginated list and clear take a prefix. Both list operations call the same backend prefix listing. The cursor and limit select a page after that listing returns.

The shared host adapter checks invocation authority and, where installed, acquires the effective principal's tracker guard before handing the selected scoped store to the operation. It holds admission through the semaphore wait and completion of the storage future. The scoped store supplies the namespace to the backend independently of the guest's key or prefix.

The retirement regression exercises all seven WIT methods. A second regression starts the actual WIT set method, holds its backend write at a barrier, and observes retirement waiting for it. The hosted tree view keeps the original namespace encoding and pins the principal UID when the view is constructed. The production selector proves that a storage operation selects an owner exactly when both the namespace bytes and the current directory UID match the admitted values. The tree adapter uses the returned UID for storage access. A native storage regression rebinds an alias and checks that the former view loses access while the new view and the ordinary backend agree on the replacement's data.

Install and upgrade hooks pass the UID admitted for their secret and environment scopes into construction of the durable guest KV view and home mount. A changed alias denies startup, and an existing durable guest KV view can only select its admitted UID. Independently injected KV backends retain their original scope.

The production point-address encoder in `kv/encoding.rs` proves its output is the complete namespace, a zero byte, and the complete key. For zero-free namespaces the checked injectivity theorem shows that equal physical addresses imply equal namespaces and keys. This applies to point addressing in the tree adapter. The production prefix upper-bound constructor proves that its half-open byte interval contains exactly the addresses starting with the complete lower bound. For validated namespaces, `logical_prefix_range` proves membership is equivalent to namespace equality and a matching logical key prefix, including the empty prefix. Checkpoint leaves apply a checked interval predicate to the stored entry key. The checked branch decision preserves any child whose declared fences contain a matching key. Overlay iteration calls the checked byte comparator at both fences. For an ordered overlay snapshot, the production lookup used to suppress a shadowed checkpoint entry returns the value or explicit tombstone of that exact key iff it occurs anywhere in the overlay. The production overlay update preserves this ordering across recursive insertion and rebalancing. Lookup on its new root returns the supplied value or tombstone for the written key and is unchanged for every other key. Tree summaries, traversal stacks, pagination and durable application of deletion replacements still require refinement.

These results still depend on correct invocation provenance, the directory lookup, and backend confinement of each operation to its selected owner and key or prefix. An operation which already obtained its owner may finish against that owner. Serialization with deletion and reclamation, lifecycle retirement tracking, and the neutral system fallback remain runtime refinement obligations.

## Management request targets

The management wire API defines 20 `KernelRequest` variants and 48
`AdminRequestKind` variants in `astrid-core/src/kernel_api/mod.rs`.
The admin listener also dispatches agent derivation before deserializing the
admin enum. The two variant counts therefore do not exhaust management ingress.

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

## Native local socket transport

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

Before serving the accepted socket, the native connection handler compares
its handshake owner with the owner registered on the queue. The checked
binding function returns the supplied handle exactly when the full owner IDs
match. The normal writer and shutdown drain use this handle. The checked
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

The current verifier entry point imports production modules directly alongside an abstract model of grant and principal authority. Their contracts cover fuel arithmetic, per-principal operation tracking, static pattern matching and containment, token status transitions, the startup marker fold, guest owner selection, KV address encoding, and overlay lookup and update. The model's theorems state what every trace of the grant, tracker and fuel transitions preserves, conditional on the stated storage, settlement and lifecycle obligations: an acknowledged revocation keeps the grant revoked across recovery and an acknowledged consumption keeps it used, a revocation keeps the grant revoked until the next recovery whether or not its write completed, retirement keeps the principal closed until a resume, and committed fuel exceeds the budget only by the fuel charged beyond a promise. Its `apply_*` and `fuel_*` functions show that the production transitions compute the model's steps. The hosted backend regression exercises abrupt exit and reopening. Complete mediation of hosted effects and concurrent runtime refinement remain open.

The hosted security argument must state its assumptions about the OS, hardware, Wasmtime, cryptography, persistent storage, compiler and verifier. Release evidence must identify the source, build configuration, binary digest and proof result. Evidence about an installed instance must also identify the running binary and security-relevant configuration through a measurement mechanism whose trust assumptions are disclosed.
