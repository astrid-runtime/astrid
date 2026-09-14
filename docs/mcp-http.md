# MCP over Streamable HTTP

`astrid mcp http` exposes the existing capsule MCP broker through RMCP's
Streamable HTTP service at `/mcp`. It does not implement a second broker or the
retired HTTP+SSE transport. Stdio and Unix-socket attach remain unchanged.

## Start locally

Create a random bearer credential outside the managed runtime directory:

```sh
umask 077
openssl rand -hex 32 > /private/path/mcp-http.token
```

Start from the running runtime's directory, as the principal whose tools the
endpoint should expose:

```sh
astrid --principal my-agent mcp http \
  --listen 127.0.0.1:8081 \
  --token-file /private/path/mcp-http.token \
  --workspace /path/to/project
```

Every request needs `Authorization: Bearer <token>`. Keep the token out of URLs,
command arguments, source control, and logs. The file must be private, regular,
and not a symlink. Restart the listener after rotating it.

The equivalent non-secret settings are available in runtime configuration:

```toml
[gateway.mcp_http]
listen = "127.0.0.1:8081"
token_file = "/private/path/mcp-http.token"
```

CLI options take precedence over these settings. No listener starts merely
because configuration exists. This explicit foreground service stays available
until Ctrl-C or SIGTERM; it is not tied to an individual client's TCP connection.
Shutdown releases its uplinks without terminating an operator-owned daemon.

## Authority and compatibility

- One endpoint has one operator-selected principal and workspace. Requests
  cannot select another principal or project through client metadata.
- All tools still pass through the existing broker, capability and consent
  checks. Sharing a bearer shares that principal's authority.
- MCP `2026-07-28` requests are stateless, without `Mcp-Session-Id`.
  `subscriptions/listen` carries tool-change notifications on its POST stream.
  MRTR state and its one-time redemption fence are shared across requests in
  this process; this is not a replicated, load-balanced service.
- Older supported clients use RMCP's session compatibility on the same `/mcp`
  endpoint. Their initialized sessions own and clean up their change watchers.
- HTTP requests can overlap; the existing broker socket still serializes its
  round trips. This change makes no throughput claim.
- Only loopback binds are accepted. Native clients only: browser Origin headers
  are rejected, and RMCP validates Host. Remote use requires an authenticated
  HTTPS reverse proxy or tunnel to loopback; the process itself never binds a
  public address. Private token-file permission validation currently requires
  Unix; Windows refuses startup rather than silently omitting that validation.

## OAuth 2.1 protected resource

Token-file bearer auth and OAuth are mutually exclusive. Configure one, not
both. `--token-file` also fails if `[gateway.mcp_http.oauth]` is set. The
listener still binds loopback; publish the canonical HTTPS resource URL through
a reverse proxy that terminates TLS.

```toml
[gateway.mcp_http]
listen = "127.0.0.1:8081"

[gateway.mcp_http.oauth]
resource = "https://mcp.example.com/mcp"
issuer = "https://issuer.example.com"
jwks_url = "https://issuer.example.com/jwks"
scopes = ["mcp"]
principal_claim = "sub"
allowed_azp = ["trusted-client"]
```

Equivalent non-secret environment fallbacks, applied only when the file did not
set the field:

- `ASTRID_GATEWAY_MCP_HTTP_OAUTH_RESOURCE`
- `ASTRID_GATEWAY_MCP_HTTP_OAUTH_ISSUER`
- `ASTRID_GATEWAY_MCP_HTTP_OAUTH_JWKS_URL`
- `ASTRID_GATEWAY_MCP_HTTP_OAUTH_PRINCIPAL_CLAIM`

Astrid is the resource server, not an authorization server. It fetches JWKS
over HTTPS before bind, then validates asymmetric JWTs (`alg=none` and HMAC
are rejected). Declared JWK `use`, `key_ops`, and `alg` values must permit the
requested signature verification. Cached JWKS material older than five minutes
is refreshed before token verification, with unknown-key refresh attempts
rate-limited to prevent request amplification. `iss` must match `issuer`,
`aud` must contain `resource`,
`exp`/`nbf` use no leeway, required `scopes` must be present, and
`principal_claim` must equal the process principal. `scope` and `azp` cannot be
used as the principal claim because they have separate authorization semantics.
`allowed_azp` is optional.

Unauthenticated RFC 9728 metadata is served at the canonical well-known URL for
the configured resource path. For the example above, that is
`/.well-known/oauth-protected-resource/mcp`. A 401 on `/mcp` advertises that
exact URL through `WWW-Authenticate`; an otherwise valid token lacking a
required scope receives the standard 403 `insufficient_scope` challenge.
Token-file mode does not serve metadata and continues to challenge with
`Bearer` only. The public resource host is added to RMCP's Host allowlist so a
proxy can present the canonical Host; Origin headers are still rejected.

## Rehearse the real broker

`scripts/test_mcp_http_live.py` starts only the candidate frontend, checks a wrong
bearer, lists tools, invokes the supplied read-only tool, and verifies clean
frontend shutdown. It requires an already-running runtime socket. It does not
install capsules or edit plugin configuration.

For a branded distribution, preserve its actual runtime environment, including
`ASTRID_RUN_DIR` and `ASTRID_WORKSPACE_STATE_DIR`; the durable home alone is not
the complete socket identity. Supply the candidate executable, runtime home,
workspace, principal, tool name, and JSON arguments explicitly with the script's
options.

Successful HTTP discovery and invocation do not prove that any particular host
refreshes its model-visible catalog after a tool change. That remains a separate
client integration test, not a promise of this transport.

In the September 12 Codex desktop trial, existing HTTP tools were callable, but
a newly installed tool did not enter the same conversation's catalog on the
next turn, despite server notification emission and an updated `tools/list`.
A new session or connection toggle is currently needed in that tested client.
Changing from stdio to HTTP does not itself solve client catalog refresh.
