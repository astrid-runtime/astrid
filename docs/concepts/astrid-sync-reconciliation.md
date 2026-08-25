# Multi-Device Object-Set Reconciliation

Status: protocol design note. Product conflict semantics, peer authority, and
the public sync trust domain remain deferred.

Astrid sync ultimately asks one mechanical question after authorization:

> Which tagged ObjectIds in this selected closure does the peer not have?

The selected reconciliation primitive is Rateless IBLT (RIBLT), based on
[Practical Rateless Set Reconciliation](https://arxiv.org/abs/2402.02668).
Its rateless stream adapts without pre-negotiating the set-difference size;
the receiver consumes coded symbols until it decodes the difference and then
acknowledges completion. Protocol bytes, hash functions, failure probability,
resource bounds, and fallback behavior still require fixtures and benchmarks
before a wire format freezes.

## Protocol shape

1. Authenticate the peer and authorize the exact root/view being shared.
2. Freeze each side's tagged ObjectId set and root generation.
3. Reconcile the set difference using bounded RIBLT symbols.
4. Request missing objects or representation closures.
5. Recompute every identity and validate complete closures on receipt.
6. Publish an accepted successor root through ordinary compare-and-swap.

RIBLT only discovers set difference. It does not resolve concurrent mutable
roots, grant read authority, choose history retention, trust client-supplied
identities, or make an incomplete closure acceptable.

## Failure and privacy

Decode failure, malformed symbols, budget exhaustion, or an adversarial peer
falls back to a bounded explicit inventory protocol or aborts without changing
roots. The protocol never guesses missing objects.

Object-set exchange leaks membership within the selected sync domain. Transport
confidentiality, peer authorization, private representation domains, and the
future public-content crypto policy are separate requirements. Guest-visible
responses must not reveal whether unrelated domains already store matching
objects.

## Acceptance before a wire contract

- Communication and CPU are measured across differences from one object to
  large divergent closures.
- Unknown difference size does not require restarting with larger tables.
- Adversarial symbols cannot cause unbounded allocation or root publication.
- Every received object and closure is independently verified.
- Decode failure leaves both roots unchanged.
- A full-inventory fallback produces the same exact difference.
