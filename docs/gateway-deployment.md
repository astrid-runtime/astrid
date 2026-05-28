# Gateway deployment runbook

The `astrid-gateway` is the HTTP front for the Astrid admin API. It
runs inside the `astrid-daemon` process, fronts the kernel's
`astrid.v1.admin.*` + `astrid.v1.request.*` IPC surfaces, and is the
contract dashboards (browser, web, CLI tooling) speak to.

This document is for operators standing the gateway up. If you're
looking for the *contract* (route shapes, schemas), point at
`GET /api/openapi.json` from a running daemon — it's the
authoritative spec.

## 1. Quickstart (single-tenant)

The smallest possible gateway:

```toml
# $ASTRID_HOME/etc/gateway-http.toml
enabled = true
listen = "127.0.0.1:7777"
```

Restart the daemon. The gateway is now serving plain HTTP on
loopback. Hit `/healthz` to confirm:

```sh
curl http://127.0.0.1:7777/healthz   # → ok
```

For single-box installs that don't need an HTTP front at all,
**delete** the config file (or set `enabled = false`) and the
gateway is a no-op — the rest of the daemon behaves exactly as it
did pre-v0.7.

## 2. Behind a reverse proxy (recommended)

Plain HTTP is fine on loopback but never on a public interface. The
recommended posture is "TLS upstream": the gateway listens on
loopback, nginx / Caddy / Cloudflare / your cloud LB terminates TLS
and forwards plain HTTP to the gateway.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name astrid.example.com;

    ssl_certificate     /etc/letsencrypt/live/astrid.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/astrid.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:7777;
        proxy_http_version 1.1;

        # SSE needs the response to stream as it arrives.
        proxy_buffering off;
        proxy_set_header Connection "";

        # Surface the real client IP so the redeem rate limiter
        # doesn't collapse every request onto the proxy's IP.
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Caddy

```caddy
astrid.example.com {
    reverse_proxy 127.0.0.1:7777 {
        flush_interval -1            # SSE
        header_up X-Real-IP {remote}
    }
}
```

### Trust the forwarded headers

By default the gateway treats the immediate peer's IP as the client
IP. Behind a proxy that means *every* request appears to come from
the proxy and a single abusive client trips the redeem rate-limiter
for everyone. You **must** tell the gateway which proxies to trust:

```toml
trust-forwarded-from = ["127.0.0.1"]   # only loopback
# or, in a cloud LB scenario:
trust-forwarded-from = ["10.0.0.0/8"]  # CIDR not yet supported — list individual IPs
```

The gateway only honours `X-Forwarded-For` / `X-Real-IP` when the
immediate peer's IP is in this list.

## 3. Native TLS (no reverse proxy)

For single-box installs that don't want to run a proxy, the gateway
can terminate TLS itself via rustls:

```toml
enabled = true
listen = "0.0.0.0:443"

[tls]
cert-path = "/etc/astrid/tls/cert.pem"
key-path  = "/etc/astrid/tls/key.pem"
```

### Cert workflow

1. **Bootstrap:** `certbot certonly --standalone -d astrid.example.com`.
2. **Symlink** into `/etc/astrid/tls/` (or point `cert-path` /
   `key-path` directly at the certbot output).
3. **Permissions:** `chmod 0600` on the key file. The gateway
   `WARN`-logs at boot if the key is group- or world-readable.
4. **Renewal:** today the gateway picks up new cert bytes only on
   daemon restart. Add a `--deploy-hook 'systemctl restart astrid'`
   to the certbot renew cron. (SIGHUP reload is tracked as a
   follow-up.)

### Boot-time validation

`GatewayConfig::validate` runs at daemon boot. It refuses to start
the gateway if:

- `cert-path` or `key-path` don't exist
- either points at a directory rather than a file
- both point at the same file

The error message tells you which knob; check `journalctl -u astrid`
or wherever you're collecting daemon logs.

### What you don't get yet

Tracked as follow-ups on the closed TLS issue:

- ACME / Let's Encrypt automation in-process.
- HTTP/2 / h2 ALPN (today negotiates HTTP/1.1 only).
- mTLS / client-cert auth.

## 4. Monitoring

The gateway exposes `/metrics` in Prometheus text-exposition format.
Unauthenticated by design — restrict access via firewall or your
reverse proxy.

### Counters

| Metric | Type | Labels | What it tells you |
|---|---|---|---|
| `astrid_gateway_requests_total` | counter | `method`, `route`, `status` | Request rate decomposed by status code. A 5xx spike here is the first thing to alert on. |
| `astrid_gateway_request_duration_seconds` | histogram | `method`, `route`, `status` | Per-route latency. Compute `histogram_quantile(0.99, …)` for p99. |
| `astrid_gateway_auth_failures_total` | counter | — | Bearer verification failures. A high rate alongside redeem attempts suggests credential-stuffing pressure. |
| `astrid_gateway_redeem_attempts_total` | counter | — | Total invite-redemption attempts. |
| `astrid_gateway_redeem_rate_limited_total` | counter | — | Redeem requests rejected by the rate limiter. If this is non-zero and you have legitimate dashboard traffic, your `trust-forwarded-from` is misconfigured. |

### Suggested alerts

```promql
# p99 admin latency > 500 ms over 5 min
histogram_quantile(0.99,
  sum by (route, le) (
    rate(astrid_gateway_request_duration_seconds_bucket{route=~"/api/sys/.*"}[5m])
  )) > 0.5

# any sustained 5xx rate
sum by (route) (rate(astrid_gateway_requests_total{status=~"5.."}[5m])) > 0.01

# auth failures > 10/sec
rate(astrid_gateway_auth_failures_total[1m]) > 10
```

### Per-request structured logs

Every request emits one `tracing` event with `method`, `route`
(matched template, not the raw URL), `status`, and `duration_ms`.
`/healthz` and `/metrics` log at DEBUG so liveness probes don't
drown the INFO stream. Pipe to your log aggregator of choice.

## 5. Authentication flow

```
operator                gateway                 kernel
   │ astrid invite issue  │                       │
   │ (CLI, on the box)    │                       │
   │─────────────────────────────────────────────▶│ persists hash to etc/invites.toml
   │ ◀──────────────────────────────────────────── │ returns raw token (one-shot)
   │
   │ hands raw token to a user out-of-band
   │
user
   │ POST /api/auth/redeem│                       │
   │ {token, public_key}  │                       │
   │─────────────────────▶│ verifies token,       │
   │                      │──────────────────────▶│ mints principal, persists key
   │                      │ mints bearer (signed) │
   │ ◀────────────────────│ {bearer, principal}   │
   │ stores bearer        │                       │
   │ for subsequent calls │                       │
```

### Bearer lifecycle

- Lifetime: 8 hours by default (`session-lifetime-secs` in config).
- Refresh: `POST /api/auth/refresh` extends without re-redeeming.
- Wire format v2: `b64url(principal).b64url(iat).b64url(exp).hex(sig)`.
- Signed with the gateway's ed25519 key at
  `$ASTRID_HOME/keys/gateway.ed25519`.

### Revocation

`POST /api/sys/principals/{id}` with DELETE method publishes an
`AgentDelete` audit event. The gateway subscribes to that feed and
records the deletion time in
`$ASTRID_HOME/etc/gateway-revocations.json`. Every bearer with
`iat <= revoked_at` is rejected on the next request. Backs up
to disk so revocations survive daemon restart.

**There is a sub-second window** between the audit event firing and
the revocation map being written. A request riding that window will
succeed. If you need immediate hard cut-off (e.g. compromised
admin), rotate the gateway signing key (see § 7).

## 6. CORS

`cors_allow_origins` controls which browser origins the gateway
accepts cross-origin requests from:

```toml
cors-allow-origins = [
    "https://app.example.com",
    "http://localhost:5173",   # dev
]
```

Rules (enforced at config-load time):

- Each entry must parse as `scheme://host[:port]` — no path, query,
  fragment, trailing slash, or userinfo.
- Scheme must be `http` or `https`.
- Internationalised domains must be supplied in their Punycode
  (ASCII) form (`xn--…`) because that's what browsers send in the
  `Origin:` header.

Empty allowlist = no `Access-Control-Allow-Origin` header on any
response = browsers reject cross-origin requests. That's the secure
default; only widen it when you have a real dashboard.

## 7. Key rotation

### Gateway signing key (`keys/gateway.ed25519`)

Used to sign session bearers. Rotating invalidates **all** active
sessions — every dashboard user is logged out and must re-redeem.
Procedure:

```sh
systemctl stop astrid
rm $ASTRID_HOME/keys/gateway.ed25519
systemctl start astrid
```

The daemon regenerates a fresh keypair on first boot. Same
posture as the kernel's `runtime.ed25519` runtime key.

### TLS cert/key

See § 3.4 "Renewal" — today, replace the files on disk and restart
the daemon.

## 8. Backup + restore

What to back up:

- `$ASTRID_HOME/etc/` — config, invite tokens, revocation map,
  any custom group definitions.
- `$ASTRID_HOME/keys/` — gateway signing key, kernel runtime key.
  Treat as secret material; `chmod 0700` the directory.
- `$ASTRID_HOME/audit.db/` — persistent audit log. Operators
  legally required to retain audit history must back this up;
  others can let it rotate per their own policy.
- Per-principal state under `$ASTRID_HOME/<principal>/` —
  per-principal capsule env, secret stores, KV.

Restore order:

1. Stop the daemon.
2. Restore `etc/`, `keys/`, and the principal homes.
3. Restore `audit.db/` only if you need history; the daemon will
   create a fresh empty log otherwise.
4. Start the daemon.

The gateway loads its config + signing key at boot; nothing to
re-run.

## 9. Troubleshooting

### "gateway not configured" — no HTTP on the listen port

Check `$ASTRID_HOME/etc/gateway-http.toml` exists and `enabled = true`.
On missing-file the daemon silently skips spawning the gateway (this
is the single-tenant default). On `enabled = false` it logs a DEBUG
line saying so.

### Every request returns 401

The bearer either isn't being sent or doesn't verify.

```sh
curl -v -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7777/api/auth/me
```

If the daemon log shows `Authorization` header missing, the proxy
is stripping it — re-check the reverse proxy's `proxy_set_header`
config. If the bearer is present but rejected, it's either expired
or signed by a different keypair (i.e. the gateway was restarted
and regenerated its key — see § 7).

### Rate limiter locks out every user

`astrid_gateway_redeem_rate_limited_total` climbing alongside
legitimate traffic almost always means `trust-forwarded-from` is
missing the proxy's IP — every redeem is being attributed to the
proxy and one client trips the limit for all. Add the proxy IP to
`trust-forwarded-from` and restart.

### CORS preflight fails for an origin that's in the allowlist

The allowlist is matched byte-for-byte against the browser's
`Origin:` header. Browsers strip trailing slashes and userinfo, send
IDNs as Punycode, and never include path/query. The boot-time
validator catches every common typo; if a request still fails,
`tcpdump`-capture the actual `Origin:` header and diff it against
your config.

### `/api/sys/audit` returns 502

The route requires the gateway to hold a live `Arc<AuditLog>` +
`SessionId`. The daemon plumbs both at boot; if `502` is returned
in production, the daemon binary was likely upgraded to a release
that ships the route but the daemon wasn't restarted to pick up the
new wiring. Restart and re-check.

## 10. Where to read more

- **API contract:** `GET /api/openapi.json` from a running daemon.
  Drop the URL into Swagger UI / Redoc / Scalar for a browsable
  surface; into `openapi-typescript` / `openapi-generator` /
  `kiota` for a typed client.
- **End-to-end test plan:** `scripts/e2e-stories.sh` walks the
  full admin loop from three perspectives (bootstrap admin, team
  operator, regular agent). Useful as a smoke test against any
  freshly-deployed instance — just point `GATEWAY=` at your URL.
- **Architecture:** the gateway is a Layer-2 "in-daemon library"
  rather than a kernel module or a capsule — see the
  in-daemon-services slot discussion under the v0.7 admin gateway
  PR (#768).
