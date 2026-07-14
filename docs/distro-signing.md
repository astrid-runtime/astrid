# Distro signing & trust

A distro can be sealed into a single, offline-installable `.shuttle`
archive (`astrid distro seal`) and signed so consumers can verify who
produced it and that its contents haven't changed. This document is for
**maintainers** cutting signed releases and **operators** installing
them.

If you just want to publish an online distro (a `Distro.toml` in a repo,
installed with `astrid init --distro @org/distro`), signing is optional — but the
strong, offline, supply-chain-resistant path is a signed `.shuttle`, and
that's what this covers.

## 1. The model in one paragraph

A `.shuttle` carries `Distro.toml`, a resolved `Distro.lock` (every
capsule pinned by BLAKE3 + a `manifest_hash` over `Distro.toml`), one
pre-built `capsules/<name>.capsule` per entry, and `Distro.sig`. The
signature is an **ed25519** signature over a domain-separated digest of
the lock. Because the lock pins every artifact's hash, one signature
transitively covers the whole archive. Two distinct guarantees stack:

- **Signature → authenticity.** "Key K vouches for this release."
- **Lock hashes → integrity.** "These exact bytes, unchanged." Verified
  bottom-up on install: each capsule's BLAKE3 against the lock, the
  manifest against `manifest_hash`, the lock against the signature.

A signature does **not** survive key theft on its own (a thief re-signs).
The durable guarantee is to **vendor the `.shuttle` / pin its sha256** —
see §6.

## 2. Trust: TOFU, pinning, official keys

Trust is per-distro and lives at `~/.astrid/trust/<distro-id>.pub` (one
pinned `ed25519:<base64>` per distro id):

- **First install of a third-party distro** → trust-on-first-use: the
  key is pinned and reported so you can verify it out of band.
- **Official distros** → their key is compiled into the `astrid` binary
  (`OFFICIAL_KEYS`) and pins on first contact with no TOFU window.
- **A later install signed by a *different* key** → hard fail. Re-pin
  only with `--accept-new-key`, and only if you trust the new key.
- **An invalid signature** → hard fail, no override.

This catches a *key swap* (attacker uses their own key). It does **not**
catch *key theft* (attacker uses the real stolen key) — for that, see §6
and the roadmap (transparency log) at the end.

## 3. Maintainer: signing a release

### 3.1 Generate a signing key (once)

```sh
astrid keypair generate --name example-distro-release
# → secret at ~/.astrid/keys/local/example-distro-release.ed25519 (raw 32 bytes, 0600)
```

**Back this key up offline.** It is the trust root for every release
signed with it; there is no recovery if it's lost, and a leak lets an
attacker sign malicious releases under your identity. For CI signing,
store it as an injected secret file, never in the repo. (Hardware-key
backing — TPM / Yubikey — is a reserved `backend` slot, not yet wired.)

### 3.2 Declare the public key in the distro

Get the public key in the wire form the manifest expects, and paste it
into `Distro.toml`:

```sh
astrid keypair pubkey example-distro-release --format wire
# → ed25519:AAAA...
```

```toml
# Distro.toml
[distro.signing]
pubkey = "ed25519:AAAA..."
# Optional successor key for rotation (parsed, chain-verify is future):
# endorses = "ed25519:BBBB..."
```

### 3.3 Seal + sign

```sh
astrid distro seal ./Distro.toml \
  --output example-distro-0.1.0.shuttle \
  --key ~/.astrid/keys/local/example-distro-release.ed25519
```

`seal` resolves each capsule to its released `.capsule` (no clone, no
compile), records the **actually-resolved** ref + BLAKE3 in the lock,
signs the lock, and packs a deterministic archive (re-sealing identical
inputs yields byte-identical output).

Distros are **release-only**: a capsule pinned to `branch`/`rev` is
rejected by `seal` — those require building from source. Pin a
`version` or `tag`; for a bleeding-edge capsule, build it and use
`astrid capsule install ./local.capsule` outside the distro.

### 3.4 Distribute

Attach the `.shuttle` to the GitHub release (or host it anywhere).
Consumers install with `astrid init --distro ./example-distro-0.1.0.shuttle`.

### 3.5 Make it an *official* key (first-contact pinning)

To let consumers pin your key on their very first install (no TOFU
window), add the same `ed25519:<base64>` to the `OFFICIAL_KEYS` table in
the `astrid` source and ship a new binary. Until then, even your own
distro takes the TOFU path.

## 4. Operator: installing a signed distro

```sh
astrid init --distro ./example-distro-0.1.0.shuttle
```

The install runs, in order: unpack (hardened — traversal/symlink/size
defended) → verify signature + apply trust policy → verify
`manifest_hash` binds `Distro.toml` to the signed lock → verify every
capsule's BLAKE3 → install offline from the verified mirror. All
*verification* gates (signature + trust, manifest-hash binding, every
capsule's BLAKE3) run **before** any capsule is installed, so a
tampered, unsigned, or mismatched bundle installs nothing. Capsule
installation itself is sequential and not transactional, so a failure
partway through can leave earlier capsules installed.

Relevant flags (also on `astrid distro apply`):

| Flag | Effect |
|------|--------|
| `--yes` | Non-interactive: take group defaults, resolve variables from `--var` / `ASTRID_VAR_<KEY>` / manifest defaults, error if a required one is unset. |
| `--offline` | Forbid all network. A non-local capsule source is a hard error. |
| `--allow-unsigned` | Install a distro that ships no signature (see §5). |
| `--accept-new-key` | Re-pin when a valid signature is under a key different from the pinned one. |

## 5. Is signing optional?

Yes — layered, and fail-closed where it matters:

- **Producing:** optional. No `[distro.signing]` / no `--key` → an
  unsigned distro. Local development (`astrid init --distro ./Distro.toml`) stays
  frictionless.
- **Consuming:** fail-closed. A sealed/remote artifact with no signature
  is **refused** unless the operator passes `--allow-unsigned`. Skipping
  signing never silently weakens trust — it forces the consumer to opt
  into the risk.
- **Official distros:** effectively mandatory — once the key is in
  `OFFICIAL_KEYS`, an unsigned build under that distro id is refused.

## 6. The strong guarantee: vendor the `.shuttle`

The in-archive hash check proves the bundle is *self-consistent*, not
that it matches what you trusted *last time* — a key thief rewrites the
lock and re-signs. To get "break rather than install something
dangerous," put the pin where the key-holder can't reach it:

- **Vendor the `.shuttle`** in your repo / Docker build context, or pin
  its `sha256`. Your CI then installs *your* bytes every time; a
  malicious re-publish is a different file with a different hash you'd
  notice. This is unaffected by upstream key theft.

```dockerfile
COPY example-distro-0.1.0.shuttle /tmp/
RUN echo "<sha256>  /tmp/example-distro-0.1.0.shuttle" | sha256sum -c - \
 && astrid init --distro /tmp/example-distro-0.1.0.shuttle --yes
```

## 7. Roadmap (not yet implemented)

- **Per-capsule signatures** for standalone `astrid capsule install
  @org/repo` (the distro signature already covers capsules inside a
  shuttle). The `meta.json` provenance fields exist; per-capsule
  verify + TOFU-pin + `--require-signed` are planned.
- **Key rotation chains** via `[distro.signing].endorses` (today a
  rotation requires `--accept-new-key`).
- **Transparency log** for first-contact and cross-consumer detection of
  key compromise — the global complement to per-consumer pinning.
