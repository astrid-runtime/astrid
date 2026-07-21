# Astrid Kernel Threat Model

Status: Milestone 0 exit artifact; companion to the kernel charter

Last reviewed: 2026-07-21

Companions: [kernel charter](astrid-kernel-charter.md),
[native-kernel scope](astrid-native-kernel.md),
[driver domain contract](astrid-driver-domain-contract.md)

This document states what the Astrid native kernel defends against, what it
explicitly does not, and where each defence lives. It is evidence-driven:
every threat class is anchored to a documented real-world attack or a
primary security source, so that a reviewer can check the claim rather than
trust the author. Threats are keyed to the charter clause that answers them,
and where the charter has no answer yet, that gap is stated as an open item
rather than hidden.

The scope is the first machine contract from the [scope
document](astrid-native-kernel.md): x86-64 under QEMU/KVM with UEFI, one
CPU, fixed memory, serial, and virtio RNG/block/net/vsock, IOMMU emulation
enabled before any untrusted domain receives direct DMA. Threats specific to
later hardware (SMP, real IOMMU silicon, direct-DMA fast paths, AArch64) are
noted where they change a decision but are not the primary subject.

## 1. Trust model

The kernel divides the system into trust domains with a strict order. A
compromise at one level must not silently confer the authority of a level
below it in this list.

| Level | Component | Trusted for | Compromise impact |
|---|---|---|---|
| T0 | Hardware, firmware, measured loader | Root of measurement and initial integrity | Total; outside the kernel's power to repair |
| T1 | Ring-0 native kernel | Isolation, capability enforcement, IOMMU/DMA mediation, revocation, audit anchoring | Total loss of the security model |
| T2 | Init/recovery domain (ring 3, no Wasmtime) | Verifying the system distro, plan-bounded domain construction, supervision policy | Loss of recovery integrity; bounded by the measured plan |
| T3 | System-host domain (ring 3) | Storage, audit, network, ingress services within granted authority | Loss of the union of that host's grants |
| T4 | Driver-host domain (ring 3) | One device's protocol behind mediated queues | Loss of that device and its granted DMA/IRQ authority |
| T5 | Application/tool/agent capsules (ring 3, Wasmtime) | Nothing beyond explicitly granted capabilities | Bounded by the domain's capability table |
| T6 | The guest inside a Realm, untrusted input, the reasoner | Nothing; assumed adversarial | Bounded by the capsule that hosts it |

The adversary is assumed to be able to: supply arbitrary capsule bytes and
arbitrary Wasm; supply arbitrary input to any capsule; operate a malicious
or buggy virtio backend; operate a malicious DMA-capable device once direct
DMA exists; attempt to forge, replay, or widen capabilities; and, in the
daemon-hosted and microVM deployments, act as a hostile host underneath the
kernel. The adversary is not assumed to have defeated ed25519, BLAKE3, or
the measured-boot root — those are T0/cryptographic assumptions, and their
failure is out of scope by definition, not by neglect.

## 2. Firmware and boot (T0)

The kernel cannot out-compute its own root of trust; this section states
what that root can and cannot promise, so that no downstream clause leans on
a guarantee the boot chain does not actually provide.

**Threats.** A signed-but-vulnerable pre-patch bootloader remains bootable
until actively revoked (BlackLotus, CVE-2022-21894; Microsoft MSRC, Apr
2023). Firmware image parsers hijack execution before the kernel exists
(LogoFAIL, CVE-2023-40238; Binarly, Dec 2023). The Secure Boot root itself
may be a shared test key (PKfail, Binarly BRLY-2024-005, 2024). In any
virtualized deployment, a host-run vTPM shares the hostile host's trust
domain and can forge PCR values, replay quotes, or fabricate the event log
(LWN, "Rethinking the Linux cloud stack for confidential VMs"; ACSAC 2023
ephemeral-vTPM work). Measured boot makes no integrity judgment — it only
produces a log for an external verifier — and the log-to-guest propagation
can silently break (Noodles' Emptiness, Jul 2024).

**Posture.** Two consequences are load-bearing for the rest of the design.
First, **revocation, not just signature, is mandatory**: the update and
recovery scheme (section 9) must carry an active revocation list, because
version and signature checks alone are defeated by a validly-signed old
artifact. Second, **on a hostile host, host-supplied measurement is not a
security boundary**. The single-purpose bare-metal machine is where measured
boot is a real boundary; the daemon-hosted and microVM deployments must
treat attestation as drift-detection, not as proof against the host, until a
hardware-rooted confidential-computing path (SEV-SNP/TDX with a
hardware-bound vTPM) is in scope. This is stated as a deployment-support
boundary, not papered over.

## 3. The hostile host (T0/T1, hosted deployments)

The charter's serialization-cleanliness rule and the scope document's
hosted/native duality mean the kernel runs three ways: bare metal, inside a
microVM, and as today's daemon. In the latter two, the host is a distinct
trust domain and may be adversarial.

**Threats.** A malicious hypervisor can inject crafted interrupts into a
confidential VM to break confidentiality and integrity even under memory
encryption (Heckler, arXiv:2404.03387, 2024). The host owns PCI config space
and MMIO allocation and can feed the guest untrusted topology the guest must
verify (Linux SEV-SNP/TDX threat model, kernel.org). Virtio's protocol
assumes a trusted backend; a hostile backend hands the front-end arbitrary
descriptor and ring data (RT-Thread #11326 as an in-driver corruption
example; CVE-2024-7730 virtio-snd OOB write).

**Posture.** The bare-metal machine is the deployment where the kernel owns
the whole stack and these threats reduce to the device surface in section 6.
For hosted deployments, the charter's honesty requirement applies: the
kernel does not claim protection against the host it runs on unless a
confidential-computing substrate provides it. This is why the first machine
contract is a single-purpose bare-metal target, not a multi-tenant guest.

## 4. Ring-0 kernel integrity (T1)

This is the level whose compromise is total, so its own attack surface must
be minimal and every input validated once at the boundary.

**Threats.** A user-pointer or IPC-descriptor validation bug turns a ring-3
compromise into a ring-0 compromise. A forged or stale capability grants
authority never derived. Pool exhaustion or allocator failure under
adversarial pressure denies service to the whole machine, including
recovery. A revocation that is not complete leaves a live handle to a
supposedly-dead resource.

**Posture — charter clauses do the work.** The covenant (charter §2) keeps
the surface small: no filesystem, no network stack, no inference, no dynamic
kernel code, no strings-as-authority, so whole classes of parser and
policy bugs cannot exist in ring 0. Handles are unforgeable per-domain table
indices that only ever shrink on transfer (charter §4), so forgery and
widening are unrepresentable rather than merely checked. Fixed per-class
pools with fallible mints and reserved recovery capacity (charter §6) make
exhaustion attributable and survivable, and close the Fiasco.OC
fragmentation-DoS class (eprint 2014/984) by construction, since fixed-slot
pools cannot fragment. Externally-atomic, internally-preemptible revocation
(charter §7) means no partially-torn-down object is ever observable — the
seL4 lesson that revoke is long-running and preemptible (seL4 whitepaper;
`cteRevoke` preemption points) is inherited as the mechanism, and the
self-referential edge cases seL4 tells user space to avoid are made
unrepresentable by sourcing teardown authority only from the measured plan.
All user-supplied structures are copied and validated exactly once, and ABI
parsers are host-fuzzable by construction (charter §4; fuzzing plan in
section 7).

## 5. Runtime-host (Wasmtime) compromise (T3/T5)

Wasmtime is explicitly outside the ring-0 TCB, and this section is why: it
has a real and recurring vulnerability history, so its compromise must be a
contained domain event, not a kernel event.

**Threats.** Wasmtime carries roughly 44 security advisories from May 2021
through June 2026, including a coordinated batch of ~12 in April 2026.
Documented classes: sandbox escapes to arbitrary host read/write via
miscompiled bounds checks (CVE-2026-34971, aarch64 Cranelift heap access);
linear-memory escape via backend offset mishandling (CVE-2026-34987, Winch);
Component-Model canonical-ABI memory bugs (RUSTSEC-2026-0091, string
transcoding OOB write); cross-instance residual reads via incomplete
pooling-allocator reset (CVE-2026-34988); and a long SIMD-miscompilation
cluster (i8x16/i64x2/f64x2, 2022–2026). Bytecode Alliance's own retrospective
admits there was no continuous aarch64 Cranelift/Winch fuzzing before April
2026, so aarch64-specific bugs had a longer undiscovered window.

**Posture.** The charter's ring-3 placement of Wasmtime (charter §2 item 6)
means any of these becomes a runtime-domain fault: the domain is torn down,
its handles and DMA maps revoked, its supervisor notified with exactly one
death record, and it is restarted — without widening grants or touching ring
0 (charter §7). Two design consequences sharpen this. First, the charter's
authority-union rule (charter §1, §7): a runtime host holds only its domain's
grants, so an escape reaches that union and no further, which is why
high-authority capsules must not be co-located to save memory. Second, the
Pulley-first decision (charter §5) is also a security decision here: the
April 2026 escape-class bugs were disproportionately in the native compilers
(Cranelift aarch64, Winch), and the Pulley interpreter avoids the
native-code-generation and executable-mapping surface entirely. AOT remains
admissible only behind the compatibility-hash binding and the conformance
gate. The residual risk — a Pulley interpreter bug — is real but is a
smaller, non-codegen surface, and remains domain-contained regardless.

## 6. Devices, DMA, and the IOMMU (T4)

Direct DMA is the one place where a ring-3 domain can, absent hardware
mediation, reach memory outside its grants; the charter calls the IOMMU
non-negotiable, and this section is the evidence for why.

**Threats.** WASM linear-memory isolation does not constrain a bus-mastering
device (driver domain contract; kernel WASM-driver literature). Documented
IOMMU limits: an MSI to the `0xFEE` range triggers an NMI/SERR path exempt
from VT-d interrupt remapping (CVE-2013-3495/XSA-59); a device can mark a
PCIe TLP as already-translated via ATS and skip translation entirely (Google
Cloud PCIe fuzzing, 2017); a malicious Thunderbolt peripheral DMA-reads
secrets and gets a root shell despite an enabled IOMMU (Thunderclap, NDSS
2019); lazy IOTLB invalidation leaves a stale-mapping window (DATE 2024);
page-granular protection exposes unrelated data sharing a 4 KiB DMA page
(ASPLOS 2016); and devices in one IOMMU group can peer-DMA each other.

**Posture.** The charter and driver domain contract answer these with a
discipline, not a single mechanism. First split (driver domain contract):
descriptor validation, notification, and DMA mapping stay in native code; the
driver capsule manages protocol over a mediated queue with no direct DMA — so
the majority of the device surface never has bus-master authority. Where
direct DMA is later granted: IOMMU domains per device; mappings minted only
for broker-owned buffers (the ASPLOS "DMA shadowing" posture — never
zero-copy-map live kernel memory, closing the sub-page-sharing leak); strict
synchronous IOTLB invalidation (closing the DATE 2024 window; Linux now
defaults strict for exactly this reason); ATS disabled for untrusted devices
(closing the already-translated bypass); interrupt remapping with the
NMI/SERR exemption mitigated by disabling chipset error signalling on
assigned devices; and the IOMMU *group*, not the device, treated as the unit
of assignment. The charter's honesty rule binds here too: on a machine
without a usable IOMMU, "untrusted hot-swappable WASM DMA driver" is not an
honest claim, and the first machine contract enables IOMMU emulation before
any untrusted domain receives DMA.

## 7. The ABI and parser boundary (T1 surface)

Every cross-domain byte is attacker-influenced, so the ABI parsers are the
concentrated attack surface on ring 0 and must be tested as adversarially as
they will be used.

**Threats.** A deserialization or bounds bug in the syscall/IPC ABI parser
is the classic ring-3-to-ring-0 escalation. Random or malformed virtqueue
descriptors corrupt guest memory or drive undefined device behavior (crosvm's
`virtio_queue` fuzz target exists for exactly this). Rust OS kernels are not
immune: unhandled-exception-class bugs on malformed syscall/exception paths
are a documented finding class (RusyFuzz, ICSE 2026, against Asterinas/Redox/
RuxOS — flagged as abstract-only).

**Posture.** The charter requires copy-and-validate-once, total fallible
operations over bounded typed messages, and host-fuzzable parsers (charter
§4). This section commits the practice: spec-driven fuzzing of the ABI in the
manner of syzkaller (proven portable to non-Linux ABIs including Fuchsia/
Zircon), plus `cargo-fuzz`/`afl.rs` host targets for every boundary parser,
run in CI, in the shape rust-vmm and crosvm already use for their virtio
boundary. The Milestone 0 exit gate's requirement-to-evidence matrix carries
these as concrete targets, and the absence of such a harness in seL4
(formal-verification-only), Hubris, and Redox is noted as the gap this
project chooses not to inherit.

## 8. Artifact supply chain (T2/T5)

A capsule is precompiled outside the machine, so the path from source to the
bytes the runtime executes is itself an attack surface the kernel must bind.

**Threats.** Wasmtime's own docs state it "cannot fully validate pre-compiled
modules for safety — only create modules from bytes you control and trust";
the compatibility hash is an engine/config check, not a provenance check. A
`.cwasm` that passes the hash can still carry attacker bytes. Build-cache
poisoning is a live, exploited class: a low-privilege fork PR poisons a
shared cache later restored by a privileged job (Adnan Khan, 2024), realized
in the TanStack npm compromise of 42 packages in ~6 minutes (May 2026).

**Posture.** The canonical `.capsule` archive and its signature are the sole
source identity (charter §5); a compiled artifact is never a silent
substitute for the component hash, and is bound by
`source hash + host ABI set + engine compatibility hash + target ISA ->
artifact identity`. The measured boot plan and recorded derivations, not a
manifest, are authority (charter §2 item 10). Beyond the charter, this
section adopts the industry posture the evidence supports: reproducible
builds (`SOURCE_DATE_EPOCH`) so an artifact is independently regeneratable,
and signed provenance in the sigstore/in-toto/SLSA shape so a poisoned cache
entry fails verification rather than executing. Provenance makes tampering
detectable; the fixed source-identity binding makes an unverified artifact
inert.

## 9. Recovery and update (T2)

Recovery is the last line, so its own integrity must survive the failures it
exists to repair, including an adversary who controls the artifacts.

**Threats.** Version-index checks alone are defeated by a validly-signed old
artifact (BlackLotus again). On an unlocked device, rollback-index checks are
non-fatal by design and an old image still boots (AOSP device-state docs). The
tamper-evident storage backing a rollback index is itself physically
attackable (eMMC RPMB EMFI, arXiv:2511.22340, Dec 2025). Freeze attacks
replay stale metadata; mix-and-match attacks assemble individually-valid files
from different times; a single compromised online key breaks clients absent
role separation (TUF threat catalog).

**Posture.** The charter mandates A/B system slots, monotonic rollback
metadata, a reserved recovery domain in ring 3 that is system TCB without
Wasmtime, and immutable init/recovery bounded by the measured plan (charter
§7; scope §4). This section binds the update *metadata* to the TUF discipline
the evidence validates: monotonic version enforcement *and* mandatory
expiration (freeze) *and* snapshot hash-binding (mix-and-match) *and* declared
sizes *and* threshold-signed roles with offline root keys — because TUF's own
spec is explicit that version-monotonicity alone is insufficient. And per
section 2, an active revocation list accompanies version checks, so a
validly-signed old artifact is refused, not merely out-ranked. The physical
RPMB attack is acknowledged as a T0 hardware limit on the bare-metal target,
not a software-closable gap.

## 10. Side and covert channels (T5/T6)

Timing channels are the class a capability system's usual proofs do not
cover, so they are stated here honestly as partially-open rather than
claimed closed.

**Threats.** Stock, unmodified microkernels carry measurable cross-domain
timing channels via shared cache, TLB, and branch predictor ("The Last
Mile," Cock/Ge/Murray/Heiser). seL4's formal confidentiality proofs cover
storage channels but explicitly exclude timing channels (HotOS 2019, "Can We
Prove Time Protection?"). Transient-execution channels (Spectre/Meltdown
class) cross domain boundaries beneath the ABI. Separately, the charter's own
legibility surface is a `/proc`-shaped risk: any typed introspection feed
carrying timing-correlated counters is a covert-channel vector by extension
of the procfs side-channel literature (ProcHarvester, ASIACCS 2018).

**Posture — partially open, and marked so.** Two mechanisms are already in
the charter: the legibility surface is capability-gated per relation with
rate-limiting and quantization on timing-correlated relations (charter §3),
which addresses the introspection-channel vector directly. The
microarchitectural channels are a known-residual: time protection (Ge/Heiser,
EuroSys 2019 — deterministic flush on switch, cache colouring, kernel
cloning) is the research direction, but it is a prototype not shipped by
default even in seL4, and closing it fully is documented as open work. This
model therefore does **not** claim timing-channel freedom. It commits to: the
flush-on-domain-switch primitive as an early kernel capability; cache
colouring of ring-0 code and data; and honest documentation of residual
timing risk per the charter's evidence discipline. This is the one section
where the correct posture is a named open problem with a mitigation roadmap,
not a solved claim.

## 11. Requirement-to-evidence seed

Each threat class above must graduate from "addressed by clause" to "a test
fails if the property is lost." The Milestone 0 requirement-to-evidence
matrix (a separate exit-gate artifact) carries at least:

- forged handle, widened-rights transfer, out-of-range memory/IPC → rejected
  (charter §4);
- per-class pool exhaustion → attributable, recoverable, no fragmentation
  starvation (charter §6);
- domain fault under trap/page-fault/infinite-loop → teardown, complete
  revocation, exactly-one death record, ring 0 survives (charter §7);
- ABI parser corpus (spec-driven + coverage-guided) → no OOB, no panic
  (section 7);
- unverified/mismatched artifact → inert; poisoned provenance → refused
  (section 8);
- rollback/freeze/mix-and-match update inputs → refused (section 9);
- IOMMU discipline (strict invalidation, no ATS for untrusted, broker-owned
  DMA buffers) → device cannot reach ungranted memory (section 6);
- legibility relation carrying timing data → rate-limited and quantized
  (section 10).

## 12. Explicit non-goals

Stated plainly so no reader mistakes silence for a claim:

- defeat of ed25519, BLAKE3, or the measured-boot cryptographic root;
- protection against a hostile host in hosted/microVM deployments absent a
  hardware-rooted confidential-computing substrate (section 3);
- physical fault-injection against tamper-evident hardware (section 9);
- complete microarchitectural timing-channel elimination (section 10, open);
- correctness of a capsule's own business logic — the kernel bounds a
  capsule's authority, not its behaviour within that authority (this is the
  charter's kernel-is-dumb line, and it is a boundary, not a weakness).
