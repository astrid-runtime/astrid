# Generating a gateway API client

The `astrid-gateway` HTTP API is **web-facing consumer code's** entry
point into Astrid — browser dashboards, mobile apps, and CI tooling
that cannot dial the daemon's Unix socket and must go through
`POST /api/auth/redeem` + a bearer token. This document is the
canonical guidance for how to build a client against it.

If you're standing the gateway *up*, see the
[deployment runbook](gateway-deployment.md) instead.

## TL;DR

- **Generate the client from the OpenAPI spec** the gateway already
  emits at `GET /api/openapi.json`. That spec is the authoritative
  contract — don't hand-write the operation surface.
- **Don't put the client in `sdk-rust` / `sdk-js`.** Those are
  capsule-author SDKs that compile to WASM components; a gateway
  client is native (`tokio`/`reqwest`) or browser/Node (`fetch`) code
  with the opposite runtime profile and a different audience. See
  [Why not the capsule SDKs?](#why-not-the-capsule-sdks) below.
- A handful of things the spec *can't* express cleanly still need a
  thin hand-written layer — see [What to hand-write](#what-to-hand-write).

## Generating

The spec is rendered from `#[utoipa::path]` / `#[derive(ToSchema)]`
annotations at compile time and served unauthenticated. Point any
OpenAPI 3.x toolchain at a running daemon:

```sh
curl http://127.0.0.1:2787/api/openapi.json > openapi.json
```

| Language | Recommended generator | Notes |
|---|---|---|
| TypeScript | [`openapi-typescript`](https://github.com/openapi-ts/openapi-typescript) + [`openapi-fetch`](https://github.com/openapi-ts/openapi-typescript/tree/main/packages/openapi-fetch) | Emits a `paths`/`components` type tree plus a thin typed `fetch` wrapper. Targets browser + Node. |
| Rust | [`progenitor`](https://github.com/oxidecomputer/progenitor) (static-crate mode) | Emits one async `Client` with a method per operation, over `reqwest`. |
| Browsable | Swagger UI / Redoc / Scalar | Drop the spec URL straight in. |

**Pin the generator version and record the spec hash** (e.g. the
`sha256` of `openapi.json`) alongside the generated output. The
gateway is workspace-locked to `core` and ships breaking changes on
`core` version bumps — the bearer wire format already went
`v1 → v2` (3 → 4 segments) this way — so a client must be able to say
which gateway revision it was generated against.

Add a CI check that re-fetches the spec from a known-good gateway and
fails on diff against your committed `openapi.json`, so the snapshot
doesn't silently age.

## What to hand-write

Generated output covers the request/response models and the operation
surface. Three things it does *not* cover well — write these by hand
on top of the generated types:

1. **SSE streams.** Two routes are Server-Sent Events, not
   request/response, and REST generators model them poorly:
   - `POST /api/agent/prompt` — events `ready`, `delta`, `response`,
     `session_changed`, `elicit`.
   - `GET /api/events` — the audit firehose, with a 15 s keep-alive
     heartbeat and per-principal filtering.

   Write a purpose-built async iterator (Rust) / `EventSource`-style
   consumer (TS) for each.

2. **Typed IDs for the `String` stand-ins.** A few types that cross
   the gateway boundary originate in `astrid-core` (`PrincipalId`,
   `Quotas`, kernel enums) and don't carry a `ToSchema` derive — the
   gateway substitutes `#[schema(value_type = String)]` placeholders
   (see `crates/astrid-gateway/src/openapi.rs`). Generated clients
   therefore see opaque `String`s for those fields. Wrap them in
   newtypes and cross-reference the `astrid-core` docs for the real
   shape. (Closing this gap at the source — enriching the schema
   stand-ins — is tracked separately and benefits every client.)

3. **The auth lifecycle.** `POST /api/auth/redeem` to exchange an
   invite token + public key for a bearer, `POST /api/auth/refresh`
   to extend it. **Treat the bearer as opaque:** store it, send it as
   `Authorization: Bearer …`, and on `401` re-redeem or refresh. Do
   **not** try to verify the bearer signature client-side — it is
   signed by the gateway's private boot-time key and re-verified
   server-side on every request, so a client has no trust anchor for
   it and gains nothing by checking. At most, base64url-*decode* (not
   verify) the `exp` segment to refresh proactively before expiry.

Error responses are already typed: the gateway attaches a
`ToSchema`-derived `ErrorBody` (`{ error, reason?, retry_after_secs? }`)
to its `4xx`/`5xx` responses, so a spec-aware generator surfaces them —
just honour `retry_after_secs` on `429`.

## Why not the capsule SDKs?

`sdk-rust` and `sdk-js` exist to build **capsules**: every workspace
member compiles to a `wasm32` Component Model artifact with a
deliberately minimal, WASM-safe dependency surface. A gateway client
is the opposite:

- **Runtime conflict.** The client needs `tokio`/`reqwest`/TLS (Rust)
  or `fetch`/`undici` (Node) — native/browser dependencies that have
  no place in a WASM-guest build. In the Rust SDK workspace, Cargo's
  feature unification can leak those features into the WASM builds of
  sibling capsule crates.
- **Audience mismatch.** SDK consumers are capsule authors; gateway
  clients are dashboard/mobile/CI developers. Different product.
- **Versioning.** The SDKs release on their own SemVer cadence; a
  gateway client tracks the gateway's HTTP surface. Folding them
  together forces unrelated lockstep bumps.

When a generated client graduates into a maintained, externally
consumed library, it gets **its own repo** under the `unicity-astrid`
org (per the polyrepo convention) — not a module inside the capsule
SDKs. Until then, generate from the spec as described above.

## See also

- [Gateway deployment runbook](gateway-deployment.md) — standing the
  gateway up behind a reverse proxy or with native TLS.
- `GET /api/openapi.json` on a running daemon — the authoritative
  contract.
- `scripts/e2e-stories.sh` — exercises the full admin loop end to
  end; useful as a smoke test for a freshly generated client.
