# Astrid Native Uplink Boundary

The canonical local control plane belongs to Astrid, not to an Astrid
distribution. A clean installation can start the daemon and use the native CLI
with zero capsules installed.

## Ownership

At boot the kernel binds the host-local endpoint and creates the per-boot
session token. The daemon immediately claims that listener for
`astrid-uplink`'s native server before capsule discovery begins. Once claimed,
the listener is not exposed to capsule contexts. This gives the endpoint one
accept loop and makes distribution failure independent from base runtime
readiness.

The native server owns only transport concerns:

- same-OS-user peer verification;
- session-token and protocol-version verification;
- signed principal challenge verification and device-key attribution;
- bounded length-prefixed JSON framing;
- host stamping of principal, device key, and local transport origin;
- a narrow CLI ingress/egress topic policy;
- principal, correlation-topic, and chat-session response demultiplexing;
- connection lifecycle accounting and fail-closed handling of bus loss.

Requests still flow through the ordinary event bus and existing kernel routers.
The uplink does not implement capsule management, policy, storage, or other
kernel business logic.

## One-way distribution dependency

The dependency direction is:

```text
AOS or another distribution -> Astrid CLI and runtime -> native uplink
```

It must never reverse. A distribution can install capsules and add HTTP, UI,
remote, or domain-specific frontends. It cannot replace the canonical local
listener, and removing or breaking every distribution capsule cannot make
`astrid start`, `astrid status`, `astrid stop`, or `astrid restart` unusable.

Legacy socket-proxy capsules remain installable and loadable, but receive no
canonical listener after the daemon claims it. Their old transport role becomes
inert while the native uplink preserves the established client wire protocol.
This avoids archive or manifest incompatibility and prevents two accept loops
from nondeterministically splitting connections.

## Compatibility contract

The native server speaks the existing protocol version and reuses the current
`IpcMessage` wire schema. Clients retain their existing request topics,
correlation suffixes, inactivity/ceiling timeouts, and principal key material.
Changing those surfaces follows their normal compatibility policy; merely
moving endpoint ownership into Astrid does not authorize a wire break.

The runtime E2E harness begins with a capsule-free home and proves
start/handshake/status/stop/restart before installing any distribution. Unit
coverage additionally proves that a legacy token-only peer is reduced to
`anonymous` and that client-supplied authority metadata is overwritten at the
host boundary.
