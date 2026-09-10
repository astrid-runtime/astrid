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
  tunnel to loopback; direct public listening and an OAuth deployment are not
  implemented here. Private token-file permission validation currently requires
  Unix; Windows refuses startup rather than silently omitting that validation.

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
