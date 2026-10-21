# Fresh hosted owner provisioning

Hosted provisioning separates the controlling host account, the human owner, the deployment authority, and the native device. It is an explicit setup operation for a fresh installation. Ordinary CLI login does not establish ownership.

This path trusts the host account, private runtime volume, and selected daemon executable. It does not attest firmware or the host kernel, defend against an equivalent host account, or detect restoration of an entire older host snapshot. Standalone authenticated boot remains a separate path. Existing populated ownership graphs require a migration adapter; this command refuses to import or replace them.

## Configure a stopped installation

Supply a public JSON policy containing:

- `deployment_key`: the independent deployment signer's 32-byte Ed25519 public key, as a JSON byte array;
- `generation`: a positive integer, increased for each explicit policy replacement;
- `expires_at`: a future Unix second;
- `target`: the admitted principal UID and registered device public key, unless explicitly selecting the native default below.

For a fresh native workstation:

```sh
astrid owner inspect
astrid owner configure --policy deployment-policy.json --target-default
```

An offline inspection does not create a home or start a daemon; it reports durable status as unavailable. Configuration invokes the co-installed daemon's dedicated offline administration mode. It acquires the normal private-home lifecycle and boot locks before opening the volume. It does not run ordinary kernel bootstrap or capsules. Configuration refuses a running daemon.

`--target-default` explicitly admits the normal default execution identity and native transport key, then pins their exact UID and public key in the stored policy. The existing `cli/local` frontend identity link and default administrator profile are execution-schema records, not human ownership, fleet membership, a payer, or user delegation. None of those ownership grants exist until enrollment commits. A supplied `target` and `--target-default` are mutually exclusive.

Public input validation and existing-ownership checks precede execution admission. If later policy persistence fails, a key/profile/execution identity may remain. Retrying uses those exact durable records rather than minting a substitute owner or device. Until the policy and independently signed enrollment complete, the installation has no owner authority. Increase `generation` when replacing an already-persisted policy; an enrolled policy cannot be replaced by this fresh-only command.

## Sign outside the runtime

Start the configured daemon normally, then prepare owner and fleet genesis and request a challenge:

```sh
astrid start
astrid owner prepare --owner-public-key OWNER_PUBLIC_KEY_HEX > genesis.json
astrid owner challenge --genesis genesis.json --expires-at UNIX_SECOND > challenge.json
```

The challenge commits to the configured deployment authority and target, installation, session, device incarnation, selected daemon artifact, owner/fleet genesis, authority counters, nonce, and finite expiry. Inspect the packet through an independently trusted channel before signing. Merely finding a public key in a packet does not authenticate the intended installation or owner.

The two external signer roles must use different keys. On each signer's trusted machine:

```sh
astrid owner sign-owner --challenge challenge.json --signing-key owner.key > owner-signed.json
astrid owner authorize --envelope owner-signed.json --signing-key deployment.key > authorized.json
```

These local commands accept raw 32-byte Ed25519 secret-key files. Neither private keys nor their paths are sent to the daemon. Distribute only the resulting public envelope to the intended registered native device:

```sh
astrid owner provision --envelope authorized.json
astrid owner inspect
```

Provisioning requires an authenticated native connection whose current registered principal and device match the configured target. The direct control is consumed before event-bus admission; guest capsules cannot configure an anchor, issue these controls, or forge their socket responses. Socket provisioning cannot install or replace the deployment key.

The owner signs the frozen 349-byte `AFOv1` statement. The deployment signer separately signs the versioned hosted domain, deployment key, canonical owner statement, and owner's signature. Verified Pending evidence is durable but grants no authority. One graph compare-and-swap installs owner, fleet, membership, principal ownership, payer relationships, initial device delegation, initialization marker, and completion receipt together. Time, policy, and counter checks repeat after a lost compare-and-swap.

## Retry, cancellation, and retirement

A daemon restart can resume verified Pending evidence. Exact completed replay returns the historical completion receipt and does not restore a retired device delegation. Device revocation removes matching hosted user bindings, including additional delegated devices. Re-pairing the same public key requires a fresh explicit user binding; it does not revive an earlier delegation.

Before completion, `astrid owner cancel` invalidates the current target's session and evidence. Request and independently sign a fresh challenge afterward. An expired or replaced policy needs explicit stopped-host configuration before a new challenge. Completion is one-shot and cannot be cancelled into a new first owner.

Hosted configuration writes graph format 3 at the existing `graph-v1` key from the outset. Older readers must refuse that graph rather than treating a separate sidecar as optional or bootstrapping replacement authority. Unchanged standalone format 2 remains supported; this path does not reinterpret fixture values or host paths as authenticated standalone boot.
