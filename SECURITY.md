# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://github.com/astrid-runtime/astrid/security/advisories/new) to submit a report. This ensures the issue is triaged privately before any public disclosure.

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected components (crate name, module)
- Severity assessment (if known)

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

## Scope

The following are in scope:

- Sandbox escapes (WASM guest accessing host resources outside granted capabilities)
- Capability token forgery or privilege escalation
- Cryptographic weaknesses in ed25519 signing, blake3 verification, or audit chain
- SSRF or injection through capsule host functions
- Audit log tampering or bypass

The following are out of scope:

- Denial of service through resource exhaustion (covered by capability limits)
- Vulnerabilities in upstream dependencies (report to the upstream project)
- Issues requiring physical access to the host machine
