# Astrid Documentation

This directory is the source-of-truth index for the Astrid documentation
vault and for GitHub readers. Links use ordinary relative Markdown, so the
same files work in GitHub and in an optional Obsidian view.

## Start here

- [The Astrid Book](https://github.com/astrid-runtime/book) is the canonical
  architecture and runtime reference.
- [Contributor Handbook](https://github.com/astrid-runtime/handbook) covers
  contribution and repository workflow.
- [RFCs repository](https://github.com/astrid-runtime/rfcs) contains proposed
  changes to WIT, IPC, and other contract surfaces.

## Architecture

### WP0 foundations

Locked architecture contracts. Compatibility landings stay at the original
GitHub paths; later numbered chapters live beside them.

- [Astrid Universal Application Substrate](astrid-universal-application-substrate.md)
- [Applications and deployments](architecture/universal-application-substrate/applications-and-deployments.md)
- [Programme and evidence](architecture/universal-application-substrate/programme-and-evidence.md)
- [Astrid Resource Ownership Model](astrid-resource-ownership-model.md)
- [Code and structure](architecture/resource-ownership-model/code-and-structure.md)
- [Programme and review](architecture/resource-ownership-model/programme-and-review.md)

### Architecture programmes

- [AI-native OS workplan](architecture/astrid-ai-native-os-workplan.md)
- [Driver domain contract](architecture/astrid-driver-domain-contract.md)
- [Fleet computer](architecture/astrid-fleet-computer.md)
- [Kernel charter](architecture/astrid-kernel-charter.md)
- [Kernel threat model](architecture/astrid-kernel-threat-model.md)
- [Native uplink boundary](architecture/astrid-native-uplink.md)
- [Principal store](architecture/astrid-principal-store.md)
- [User and fleet ownership](architecture/astrid-user-fleet-ownership.md)
- [Resident-memory authority](architecture/astrid-resident-memory-authority.md)

Two oversize documents remain at their original paths pending a dedicated
split-and-move successor:

- [Native component kernel](astrid-native-kernel.md)
- [Tensor Logic composition](astrid-tensor-logic-composition.md)

Compatibility stubs remain at the previous `docs/*.md` paths.

## Concepts

- [Conservation of computation](concepts/astrid-conservation-of-computation.md)
- [Huginn](concepts/astrid-huginn.md)
- [Muninn](concepts/astrid-muninn.md)
- [Refinery](concepts/astrid-refinery.md)
- [Semantic representations](concepts/astrid-semantic-representations.md)
- [Physical representations](concepts/astrid-physical-representations.md)
- [Principal content DAG](concepts/astrid-principal-content-dag.md)
- [Content catalog tree](concepts/astrid-content-catalog-tree.md)
- [Sync reconciliation](concepts/astrid-sync-reconciliation.md)
- [Public content crypto roadmap](concepts/astrid-public-content-crypto-roadmap.md)

## Decisions

- [Kernel ADRs](decisions/astrid-kernel-adrs.md)
- [Forge as a Muninn consumer](decisions/astrid-forge-muninn.md)
- [Audit store anchoring](decisions/astrid-audit-store-anchoring.md)
- [Durable compaction](decisions/astrid-durable-compaction.md)
- [Storage freeze audit](decisions/astrid-storage-freeze-audit.md)
- [Storage FTO triage](decisions/astrid-storage-fto-triage.md)

## Guides

- [Gateway API client](guides/gateway-client.md)
- [LLM model selection](guides/models.md)
- [SDK ergonomics](guides/sdk-ergonomics.md)

## Reference

- [Configuration](reference/config.md)
- [Kernel evidence matrix](reference/astrid-kernel-evidence-matrix.md)
- [Kernel support policy](reference/astrid-kernel-support-policy.md)
- [Principal store engine](reference/astrid-principal-store-engine.md)
- [Principal store runtime](reference/astrid-principal-store-runtime.md)
- [Principal store evidence](reference/astrid-principal-store-evidence.md)
- [WinFsp storage provider](reference/astrid-storage-provider-winfsp.md)
- [Storage performance](reference/astrid-storage-performance.md)
- [Storage chunker evidence](reference/astrid-storage-chunker-evidence.md)

## Operations

- [Gateway deployment](operations/gateway-deployment.md)
- [Distro signing](operations/distro-signing.md)
- [Release channels](operations/release-channels.md)
- [Self-update security](operations/self-update-security.md)
- [Principal store operations](operations/astrid-principal-store-operations.md)
- [Operational metrics](operations/metrics.md)

## Benchmarks

- [Storage I/O evidence](benchmarks/storage-io/README.md)

## Repository documents

- [Repository README](../README.md)
- [Contributing](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [Changelog](../CHANGELOG.md)
