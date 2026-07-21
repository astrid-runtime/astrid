# Astrid Kernel Support-Policy Vocabulary

Status: Milestone 0 exit artifact; the words that keep claims honest

Last reviewed: 2026-07-21

Companions: [kernel charter](astrid-kernel-charter.md),
[threat model](astrid-kernel-threat-model.md),
[requirement-to-evidence matrix](astrid-kernel-evidence-matrix.md)

The charter's evidence discipline (charter §8) is only enforceable if the
words used to describe the kernel's maturity mean fixed things. This document
fixes them. Every release note, PR, doc, and status claim about the native
kernel must use these terms in these senses, so that "supported" and
"verified" cannot quietly inflate over time. A claim that does not fit one of
these terms is not a weaker claim — it is an unmade claim, and must be
phrased as an open item.

This vocabulary is itself governed by the charter's amendment procedure
(charter §10). Widening any definition requires an ADR naming the evidence
that justifies the wider promise.

## Machine maturity

**Experimental machine.** A hardware or virtual target the kernel can boot
under, with no promise of isolation completeness, recovery, or stability. Its
purpose is to exercise the architecture, not to run anything trusted. The
first x86-64 QEMU/KVM target is an experimental machine until every
Milestone-gated evidence row for its surface passes. An experimental machine
may be withdrawn or reshaped without deprecation notice.

**Supported host.** A target for which the kernel makes the full charter
promise — isolation, capability enforcement, revocation completeness, fault
containment, IOMMU-mediated DMA where DMA exists, recovery, and audit — with
every corresponding evidence-matrix row passing in CI, and with a stated
recovery and update story. A supported host carries a compatibility promise:
it does not regress without a deprecation cycle. No target is a supported
host until its evidence is green; the phrase is never aspirational.

The distinction is load-bearing because the charter's honesty rule (threat
model §2, §3) means the daemon-hosted and microVM deployments are, against a
hostile host, at most experimental for confidentiality until a
hardware-rooted confidential-computing substrate is in scope. Calling them
"supported" in that threat model would be a false claim.

## Contract maturity

**Supported capsule contract.** A `wasm32-unknown-unknown` capsule targeting
the stable `astrid:*` WIT worlds runs unchanged on every supported host. This
is the promise the charter protects by keeping native-kernel ABI mechanics
private (charter §4.1): capsule authors depend on the WIT contract, never on
whether the host is the daemon or the native kernel. A capsule contract is
supported only when the component conformance corpus passes on that host —
for the native kernel, that includes the Pulley conformance gate (charter §5;
REQ-RT-3).

The native ABI between ring 0 and the runtime host is explicitly **not** a
supported contract: it is private and versioned, and may change without a
capsule-visible deprecation, precisely so that hardening it never breaks a
capsule (charter §4.1).

## Claim maturity

**Verified claim.** A property with a passing, non-skippable evidence-matrix
test whose failure would disprove the property (charter §8; matrix
"no silent green"). Only a verified claim may be stated without hedging in a
release note or doc. "Verified" names the existence of the falsifying test,
not merely a belief or a manual check. A one-time manual observation is
recorded as such and is not a verified claim.

**Measured result.** A recorded measurement with raw samples, exact
toolchain/image/machine identity, and its boundary stated, never promoted
across boundaries (charter §8; the Realm program's benchmark discipline). A
native microbenchmark is a measured result for that boundary only, never
quoted as end-to-end latency.

## Risk maturity

**Known residual risk.** A threat the model names but does not fully close,
recorded openly with its current mitigation and roadmap rather than hidden or
overclaimed. The canonical entries as of this writing:

- **Microarchitectural timing channels** (threat model §10): cross-domain
  cache/TLB/branch-predictor channels are not fully closed; the flush-on-
  domain-switch primitive (ADR-K6; REQ-CHAN-1) and ring-0 cache colouring are
  the committed mitigations, and full time protection (Ge/Heiser) is the
  roadmap, not a shipped claim. seL4 itself does not close this by default.
- **Hostile-host confidentiality** in hosted/microVM deployments (threat
  model §2, §3): not promised absent a hardware-rooted confidential-computing
  substrate (SEV-SNP/TDX with a hardware-bound vTPM).
- **Physical fault injection** against tamper-evident hardware (threat model
  §9): a T0 hardware limit on the bare-metal target, acknowledged, not
  software-closable.

A known residual risk is a first-class, published status — the charter's
evidence discipline treats an undocumented residual as a worse failure than a
documented one, because the undocumented one reads as a false "closed" claim.

## Using the vocabulary

One rule ties it together: **downgrade before you overclaim.** If a property
is not a verified claim, it is an open item. If a target is not a supported
host, it is an experimental machine. If a residual is not closed, it is a
known residual risk, named. The vocabulary exists so that the honest thing to
say is always available and always shorter than the dishonest thing.
