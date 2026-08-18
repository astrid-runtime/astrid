## Index change

- [ ] This change adds files only; no record, event, object, or trust role was
      edited/deleted in place.
- [ ] The publication coordinate and digest were checked for idempotence or
      same-coordinate equivocation.
- [ ] Namespace authority and event-envelope actor/chain checks pass.
- [ ] The pinned validator ran with `--event-authorization curator-review` and
      every authoritative envelope carries digest-bound curator evidence.
- [ ] No root/private/signing key or secret is present in the diff.
- [ ] The pinned Index tool commit and TUF verifier were used.
- [ ] If the public trust root changed, the offline ceremony receipt and
      threshold review are attached; no unsigned `_tuf-input/` tree is being
      published.

Describe the source commit, publication/event digests, and any emergency or
namespace authority receipt.  Do not paste credentials or private key material.
