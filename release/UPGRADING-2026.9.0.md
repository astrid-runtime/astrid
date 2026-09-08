# Upgrading to Astrid 2026.9.0

This release follows 0.10.4. Repairs to unreleased implementations are
consolidated into the final behavior in CHANGELOG.md.

- Legacy host `[model]` settings must migrate to capsule-owned providers;
  unsupported settings are rejected with guidance.
- One resize or write may synthesize at most 4 MiB of zero-filled gap. Larger
  sparse extensions are unsupported; contiguous growth is not capped at 4 MiB.
- Mounting requires the platform frontend and its permission setup. Windows
  native checks do not establish a shipped Windows filesystem mount.
- Performance is workload-dependent; no universal native-filesystem or
  state-of-the-art performance claim is made.
