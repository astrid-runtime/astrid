# Capsule Index repository operations

This runbook governs an Index repository created from
`docs/capsule-index/repository-template/`.  It is intentionally implementation
neutral at the trust boundary: the repository records claims and signed TUF
metadata, while the pinned Index/TUF tool performs canonical generation and
cryptographic verification.  Replace every `REPLACE_*` value before enabling
Actions.  No step creates a remote repository or transmits root key material.

## Authority and custody

The Index identity is `(index_id, trust-root fingerprint)`.  Protected `main`
is the authoritative append-only source; Pages and release assets are
eventually consistent mirrors.  The publisher may submit a publication claim,
but the Index maintainers decide admission and the local installer decides
capability grants.  A publication digest, coordinate, source binding, package
claims, event history, and lock binding are never rewritten in place.

Root signing keys are generated and held offline by a documented threshold
ceremony (for example, two of three geographically separated holders).  Root
private material MUST NOT appear in Git, Actions secrets, runner disks, Pages,
release assets, or issue attachments.  The `tuf-signing` GitHub Environment may
hold only explicit targets, snapshot, and timestamp role keys approved for one
generation (one unwrapped base64-encoded DER key per line in each template
secret); an HSM/KMS integration is preferred.  Role thresholds are enforced by
the signer, so missing approved key files fail closed.

## SECURITY LIMITATION: CI signing authority

The role keys in `tuf-signing` are authorized catalog signers.  An approved or
compromised Actions run that can use those keys can sign malicious records,
events, or target metadata; TUF protects clients against tampered mirrors,
rollback, freeze, and cross-role inconsistency, not against an authorized
signer making a bad statement.  Keep targets and snapshot signing offline (or
behind an independently controlled HSM and approval path) when that stronger
guarantee is required.  The template performs two clean `generate` runs and
compares a sorted SHA-256 manifest before signing, which is reproducibility
evidence only, not an independent review.  A separate reviewer should rebuild
from the protected commit/tool SHA and compare the manifest and publication
digests before approving deployment.

## One-time repository setup

1. Copy the template into a dedicated repository and set `index_id`, Pages URL,
   release URL, trust-root fingerprint, tool repository, and tool commit in
   `config/index.toml`.  Verify that the commit is a 40-character immutable
   Git object and is identical in every workflow.
2. Configure branch protection for `main`: pull requests required, force-push
   and deletion disabled, CODEOWNERS review required, and both `Validate
   Capsule Index PR` and the real TUF verification check required.  Require at
   least two humans for publications, namespace claims/transfers, and trust
   metadata changes.
3. Create the `tuf-signing` Environment with required reviewers and the
   explicitly approved role-key secrets consumed by `sign-pages`.  Create the
   separate `github-pages` Environment with deployment reviewers.  Restrict
   who can use both Environments; never store root private keys there.
4. Complete the offline root ceremony below.  Commit only the resulting public
   signed `config/trust-root.json` and a non-sensitive ceremony receipt (date,
   root version, fingerprint, signers' public fingerprints, and quorum).
5. Run the template linter and validator locally.  Push a harmless configuration
   PR and verify that branch protection blocks an unsigned or unpinned change.

## Publication pull requests

Every publication PR is validated against the base and head commit, not only
the working tree:

* `records/`, `events/`, and `objects/` are append-only.  A modified or deleted
  path is rejected; a new path is accepted only after schema and digest checks.
  Event files use `events/{sequence:020}-{event_digest_without_tag}.json`; a
  filename that does not bind the sealed envelope is rejected.
* `(index_id, namespace, name, version)` is write-once.  Repeating the exact
  immutable record is idempotent; any other digest is equivocation and is
  permanently rejected.  A correction gets a new canonical version.
* Namespace claims use the lower-case name grammar and, for reserved
  namespaces, the explicit authority marker.  Ownership changes use a typed
  `NamespaceTransfer` body with outgoing-owner, incoming-owner, and Index-review
  authorization; a normal publication PR cannot smuggle a transfer.
* Events are `event-envelope-v1`: sequence starts at one, each later envelope
  binds `prior_event_digest`, the envelope/body/authorization actors agree, and
  the event digest matches the domain-separated canonical projection.  Lifecycle
  transition checks reject illegal unyank, duplicate mirror/attestation,
  post-tombstone non-mirror, and revoked-publication operations.
* Names, versions, source IDs, artifact locations, tagged digests, and lock
  bindings are checked with the conformance runner.  Symlinks, traversal,
  oversized JSON, duplicate keys, and private-key material fail closed.

The PR workflow may call an external validator only after cloning it at the
configured commit SHA.  It invokes `validate --base ... --candidate ...` with
`--event-authorization curator-review`, so every authoritative envelope must
carry digest-bound curator evidence.  The repository must fail if the
placeholder remains, if the fetched object is not that commit, or if the tool
executable is absent.  Reviewers inspect the generated diff and the
machine-readable validation result; passing a local script without the
pinned-tool check is not sufficient.

## Protected-main generation

After merge, `publish-pages.yml` performs the following ordered operation:

1. Check out the protected commit and run key-hygiene/append-only checks.
2. Clone the Index tool with `--no-checkout`, verify the exact commit object,
   and detach at that SHA.  Floating tags, branch names, downloaded binaries,
   and unpinned Actions are prohibited.
3. Generate a clean unsigned tree from `records/`, `events/`, `namespaces/`,
   and `objects/` using canonical serialization.  Generation MUST be
   deterministic: repeated builds at the same source/tool commits produce
   byte-identical records, Pages paths, and `_tuf-input/` projections.  The
   generator never creates trust-role signatures.
4. Upload `_tuf-input/` as a short-retention CI artifact.  The approved
   `sign-pages` job downloads it, writes explicit role keys from the
   `tuf-signing` Environment, and invokes the exact signer CLI.  `sign-pages`
   atomically emits versioned `N.root.json`, `N.snapshot.json`, and
   `N.targets.json` plus `timestamp.json`, then reloads the result through
   `astrid-capsule-index-tuf`.  It reports `deployment_ready=true` only after
   real threshold/signature, expiry, cross-role-reference, and target checks.
   Supply `--previous` when a prior signed tree is available to enforce
   publisher-side monotonic rollback/equivocation checks; clients still retain
   their own last-trusted TUF versions.
5. Only after `sign-pages` succeeds, stage the Pages artifact and deploy it in
   the `github-pages` Environment.  The deploy job has no signing key and no
   write permission to records.  If signing or verification fails, no Pages or
   release asset is published.

The generated sparse layout is:

```text
v1/<root-version>.root.json
v1/timestamp.json
v1/<snapshot-version>.snapshot.json
v1/<targets-version>.targets.json
v1/objects/<algorithm>/<digest-prefix>/<digest>.json
v1/shards/<identity-shard>.json
v1/search.json
v1/<sha256>.<target-path>
```

The signed metadata, not an unsigned path, determines which object is valid.
`_tuf-input/` exists only between generation and signing and is never a
deployable Pages path.
Clients use the Pages URL and content-addressed release assets anonymously;
they do not call the GitHub API, search repository contents, or infer state from
labels and mutable release URLs.

## TUF role operations

### Offline root creation and rotation

Perform this procedure on an audited, network-disconnected workstation:

1. Verify the current root version/fingerprint and the ceremony participant
   identities from the previous receipt.  If the current root is unavailable,
   stop; do not bootstrap from Pages.
2. Generate or load the new threshold root key shares using the approved
   hardware/offline process.  Record public key IDs and the quorum, never the
   private shares.
3. Build the new root metadata with an incremented version, explicit role
   thresholds, and both old-root and new-root signatures where the TUF
   transition requires them.  Review key IDs, expiry policy, and delegated
   targets before signing.
4. Each holder verifies the canonical bytes and signs independently.  Combine
   signatures only after quorum; compute and record the new SHA-256 root
   fingerprint and a ceremony receipt.
5. Transfer only the public signed root and receipt to a clean staging tree.
   Open a PR that changes `config/trust-root.json` and the generated root role;
   never commit a key share.  The protected-main TUF verifier must accept the
   old-to-new transition and reject a rollback.
6. After merge, verify the deployed Pages root from an anonymous client and
   archive the old public root, generated tree, and receipt.  Keep old private
   shares offline according to the retention policy.

Emergency root compromise uses the same ceremony with an expedited quorum and
an explicit incident identifier.  Do not rotate root keys through the online
timestamp workflow.

### Targets and snapshot review

Targets and snapshot metadata bind the publication/event object set and each
length/digest.  A release reviewer compares the generated target list with the
PR diff, verifies no object was removed or rewritten, and checks the configured
threshold before accepting the offline signatures.  A changed target or
snapshot version is a new signed generation; never reuse a prior signature over
different bytes.

### Online timestamp rotation

Timestamp-only rotation is currently **blocked**: the pinned
`astrid-index-tool` exposes `generate`, `validate`, and `sign-pages`, but no
standalone `rotate-timestamp` operation.  The template therefore contains no
scheduled rotation workflow and must not emulate one with an invented command
or by editing `timestamp.json` in place.  Until a reviewed tool/API adds a
timestamp-only operation, run the full approved `sign-pages` generation with
explicit role keys and fresh role versions/expirations.  A future rotation
workflow must preserve the same root, snapshot, and targets bytes, enforce
monotonic versions and bounded expiry, run the real TUF verifier, and publish
only through protected review.

## Emergency lifecycle and mirror actions

* **Revoke:** open an emergency PR with a signed `Revoke` body and a concise
  reason.  Require the emergency Environment/reviewer quorum.  Once merged, the
  publication is blocked for fresh and locked resolution; do not delete its
  record or attempt an un-revoke.
* **Tombstone:** use a signed `Tombstone` body for legal/removal requests.  Keep
  the minimum transparency record and reject subsequent non-mirror events.
* **Mirror:** use `AddMirror` only for an HTTPS locator of bytes already matching
  the sealed digest set, size, and media type.  Fetch and verify the bytes before
  publishing the mirror event.  A mirror cannot repair an artifact mismatch or
  mutate the publication.

The emergency PR must include the event-envelope digest, authorization receipt,
operator identity, incident reference, and a deterministic rebuild result.  If
Pages is stale, publish nothing unsigned and do not silently switch to another
Index; announce the authoritative commit/snapshot version and retry bounded
edge propagation.

## Deterministic rebuild and archival

For every protected-main generation and emergency operation:

1. Record source `main` commit, tool repository/commit, configuration digest,
   conformance-runner version, root fingerprint, metadata versions, and UTC
   build time in an external receipt.
2. Build twice in clean workspaces with the same tool SHA.  Compare a sorted
   SHA-256 manifest of every generated file, including object bytes and signed
   role envelopes.  Any difference is a release blocker.
3. Archive the source commit, generated Pages tree, manifest, public root,
   signed metadata, event/record inputs, verifier output, and ceremony/approval
   receipts in write-once storage.  Never archive private key material in the
   repository or CI artifact.
4. After deployment, perform an anonymous HTTPS fetch of `v1/search.json`, root,
   timestamp, snapshot, targets, and one object.  Verify the same generation
   and digest locally; record the observed Pages URL and snapshot version.

If an edge serves a stale or mixed generation, retain the valid prior
generation, retry within the bounded client policy, and investigate CDN/cache
propagation.  Do not publish an unsigned replacement, rewrite history, or use
the GitHub API as a read path.
