# Capsule Index repository template

This directory is a copyable starting point for one Astrid/AOS Capsule Index.
Copy its contents into a dedicated GitHub repository; do not point two Index
identities at the same repository.  The template intentionally contains no
repository identity, signing key, root private key, or secret.  Until the
`REPLACE_*` values and tool commit are replaced, the workflows fail closed.

## Required substitutions

Before enabling Actions, replace every placeholder in `config/index.toml`, the
workflow `INDEX_TOOL_REPOSITORY`/`INDEX_TOOL_SHA` values, and the Pages URL.
`INDEX_TOOL_SHA` must be a full 40-hex commit, never a tag or branch.  Pin the
same reviewed commit in every workflow.  Supply only the public trust-root
metadata at `config/trust-root.json`; root private keys stay in an offline
ceremony.  The signing workflow consumes one-line-per-key, unwrapped
base64-encoded DER role-key secrets (`TUF_TARGETS_SIGNING_KEYS_B64`,
`TUF_SNAPSHOT_SIGNING_KEYS_B64`, and `TUF_TIMESTAMP_SIGNING_KEYS_B64`) in an
approved Environment, or an equivalent external HSM integration.

Configure the following repository controls before the first publication (the
placeholder CODEOWNERS and pull-request checklist are included):

1. Protect `main`: require pull requests, the PR validation workflow, the
   signed-metadata/TUF check, and two human reviewers for record or namespace
   changes.  Disallow force-pushes and branch deletion.
2. Create the `tuf-signing` Environment with required reviewers and the three
   explicit role-key secrets named above (one unwrapped base64 DER key per
   line).  Create the separate `github-pages` Environment with the deployment
   reviewer gate.  Do not put a root private key in Actions secrets; every
   role threshold must be met by distinct authorized key lines, otherwise
   signing fails closed.
3. Complete the offline root ceremony and commit only its public signed
   `config/trust-root.json`.  Record the ceremony transcript and key-holder
   fingerprints outside this repository.
4. Review `OPERATIONS.md` and verify the pinned tool's `validate`, `generate`,
   and `sign-pages` invocations before enabling the Pages workflow.  The
   generator intentionally emits unsigned `_tuf-input/` files; only
   `sign-pages` output is deployable.

## Layout

* `records/` contains immutable publication records.  A coordinate may be
  added once; a different digest at the same `(index_id, namespace, name,
  version)` is equivocation.
* `events/` contains signed `event-envelope-v1` objects.  Files are append-only
  and hash chained; lifecycle bodies are never edited in place.
* `namespaces/` contains typed namespace claims and ownership transfers.
* `objects/` contains content-addressed record/event/artifact objects.  A
  mirror is an additional locator for already sealed bytes, never a replacement
  artifact.
* The signer emits `v1/<version>.root.json`, `v1/<version>.snapshot.json`,
  `v1/<version>.targets.json`, and `v1/timestamp.json`.  These TUF trust roles
  must contain real threshold signatures.  The generator's `_tuf-input/`
  directory is unsigned and is never published.
* `config/` contains public identity/configuration only.  `config/index.toml`
  binds the Index ID and Pages/release URLs; it must not contain private keys.

## Anonymous read path

Clients consume the signed sparse Pages tree and content-addressed release
assets, for example `https://OWNER.github.io/REPOSITORY/v1/...` and the GitHub
Release asset URL recorded in a publication.  They do **not** use the GitHub
API, repository search, mutable labels, or an unsigned raw file.  Pages/CDN
eventual consistency is handled by verifying a complete TUF generation and
retrying a bounded number of times.

## Operational boundaries

The workflows generate and verify metadata; they do not create a GitHub
repository, mint root keys, or bypass branch protection.  Emergency revoke,
tombstone, and mirror operations remain signed event-envelope changes reviewed
under the procedure in `docs/capsule-index/OPERATIONS.md`.  Every generated
tree is reproducible from a commit-pinned tool and archived with its hashes
before deployment.

### Security limitation

The `tuf-signing` Environment is an authorized catalog-signing boundary.  A
compromised or improperly approved run can sign malicious catalog state; TUF
protects clients from mirror tampering and rollback, not from an authorized
signer making a false statement.  Keep targets/snapshot signing offline or
behind an independently controlled HSM for stronger assurance.  The workflow
does two clean generations and compares sorted SHA-256 manifests before
signing, but that is reproducibility evidence rather than independent review.
