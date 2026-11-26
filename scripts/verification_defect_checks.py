#!/usr/bin/env python3
"""Check that deliberate defects fail the pinned Verus entry point.

Every defect is an exact edit applied to a scratch copy of the verifier's
inputs. A defect that still verifies shows that the proof does not constrain
what it claims. The unmodified copy must verify with zero errors first. A
defect counts as rejected only when the verifier reports an error in the
edited file or the named consumer of a weakened contract, so a defect that fails to parse is reported as a failure.

This checks only the defects listed here and establishes no other property.
A weaker statement that is still true is not a defect, unless a proof listed
here derives its conclusion from the stronger one.
"""

import argparse
import os.path
from collections.abc import Callable
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
ENTRY = Path("verification/hosted_authority.rs")
MODEL = Path("verification/hosted_authority_model.rs")
AUTHORITY = Path("crates/astrid-capabilities/src/store/authority.rs")
GUEST_AUTHORITY = Path("crates/astrid-storage/src/principal_state/guest_authority.rs")
KV_ENCODING = Path("crates/astrid-storage/src/kv/encoding.rs")
OVERLAY = Path("crates/astrid-storage/src/kv/tree/overlay/traversal.rs")
OVERLAY_UPDATE = Path("crates/astrid-storage/src/kv/tree/overlay/update.rs")
PRINCIPAL_SCOPE = Path("crates/astrid-kernel/src/kernel_router/principal_scope.rs")
BINDING = Path("crates/astrid-storage/src/principal_directory/binding.rs")
CACHE_ADDRESS = Path("crates/astrid-kernel/src/capsule_materialization/cache_address.rs")
GENERATION = Path("crates/astrid-capsule/src/registry/generation.rs")
VIEW_OWNER = Path("crates/astrid-capsule/src/registry/view_owner.rs")
ORDERED_DISPATCH = Path("crates/astrid-events/src/ordered_dispatch.rs")
DELIVERY_COMMIT = Path("crates/astrid-events/src/admission/commit.rs")
ROUTE_GATE = Path("crates/astrid-events/src/route/gate/state.rs")
ROUTE_SCOPE = Path("crates/astrid-events/src/route/scope.rs")
PRINCIPAL_SYNTAX = Path("crates/astrid-core/src/principal/syntax.rs")
INGRESS_FRAME = Path("crates/astrid-capsule/src/engine/wasm/host/net/ingress_frame.rs")
DEVICE_ADMISSION = Path("crates/astrid-core/src/profile/device_admission.rs")
CONSENT_IDENTITY = Path("crates/astrid-capsule/src/engine/wasm/host/consent_identity.rs")
NATIVE_TOPIC = Path("crates/astrid-uplink/src/native/topic_policy.rs")
NATIVE_RECIPIENT = Path("crates/astrid-uplink/src/native/recipient.rs")
NATIVE_QUEUE = Path("crates/astrid-uplink/src/native/delivery_queue.rs")
NATIVE_REPLY = Path("crates/astrid-uplink/src/native/reply_claim.rs")
NATIVE_FRAME = Path("crates/astrid-uplink/src/native/frame_segments.rs")
DEVICE_SESSIONS = Path("crates/astrid-core/src/profile/device_sessions/phase.rs")
DEVICE_REGISTRATION = Path("crates/astrid-core/src/profile/device_registration.rs")
DEVICE_CHALLENGE = Path("crates/astrid-core/src/profile/device_challenge.rs")
REGISTERED_BEARER = Path("crates/astrid-core/src/session_token/registered_bearer.rs")
PRIVATE_RESPONDER = Path("crates/astrid-capsule/src/elicitation/responder.rs")
PAIR_DENIES = Path("crates/astrid-kernel/src/kernel_router/admin/pair_device_handlers/deny_patterns.rs")
RECEIPT = Path("crates/astrid-kernel/src/kernel_router/resume_receipt/validation.rs")
UID_TEXT = Path("crates/astrid-core/src/identity/principal/text.rs")
FILESYSTEM_PATH = Path("crates/astrid-storage/src/filesystem/path_validation.rs")
STORAGE_HANDLES = Path("crates/astrid-capsule/src/engine/wasm/storage_handles.rs")
STORAGE_FILE = Path("crates/astrid-capsule/src/engine/wasm/storage_file.rs")
LEASE_RESERVATION = Path("crates/astrid-kernel/src/storage_mount/lease_authority/reservation.rs")
LEASE_SUBTREE = Path("crates/astrid-kernel/src/storage_mount/lease_authority/subtree.rs")
LEASE_CALLBACK = Path("crates/astrid-kernel/src/storage_mount/lease_authority/callback.rs")
LEASE_REQUESTER = Path("crates/astrid-kernel/src/storage_mount/lease_authority/requester.rs")
INVOCATION_OWNER = Path("crates/astrid-capsule/src/engine/wasm/invocation_owner/admission.rs")
MOUNT = Path("crates/astrid-capsule/src/engine/wasm/mount_selection.rs")
PAIR_RESULT = Path("crates/astrid-kernel/src/kernel_router/admin/pair_issue_result.rs")
INPUTS = [
    UID_TEXT,
    FILESYSTEM_PATH,
    STORAGE_HANDLES,
    STORAGE_FILE,
    PAIR_RESULT,
    LEASE_CALLBACK,
    Path("crates/astrid-capsule/src/engine/wasm/guest_kv.rs"),
    Path("crates/astrid-capsule/src/security/identity.rs"),
    Path("crates/astrid-kernel/src/storage_mount/lease_authority/destination.rs"),
    Path("crates/astrid-kernel/src/storage_mount/lease_authority/worker.rs"),
    LEASE_SUBTREE,
    LEASE_RESERVATION,
    Path("verification/hosted_lease_model.rs"),
    Path("verification/hosted_kv_model.rs"),
    Path("crates/astrid-core/src/storage_filesystem/operation.rs"),
    LEASE_REQUESTER,
    INVOCATION_OWNER,
    MOUNT,
    RECEIPT,
    PAIR_DENIES,
    PRIVATE_RESPONDER,
    REGISTERED_BEARER,
    ORDERED_DISPATCH,
    DELIVERY_COMMIT,
    DEVICE_CHALLENGE,
    DEVICE_REGISTRATION,
    DEVICE_SESSIONS,
    NATIVE_FRAME,
    NATIVE_REPLY,
    NATIVE_QUEUE,
    NATIVE_TOPIC,
    NATIVE_RECIPIENT,
    CONSENT_IDENTITY,
    DEVICE_ADMISSION,
    INGRESS_FRAME,
    PRINCIPAL_SYNTAX,
    ROUTE_SCOPE,
    ROUTE_GATE,
    VIEW_OWNER,
    GENERATION,
    CACHE_ADDRESS,
    BINDING,
    PRINCIPAL_SCOPE,
    OVERLAY_UPDATE,
    OVERLAY,
    KV_ENCODING,
    GUEST_AUTHORITY,
    Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
    Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
    Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
    Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
    Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
    ENTRY,
    MODEL,
    AUTHORITY,
    Path("crates/astrid-capsule-types/src/fuel_ledger/arithmetic.rs"),
    Path("crates/astrid-capsule/src/engine/wasm/principal_tracker/state.rs"),
    Path("crates/astrid-core/src/capability_grammar/matcher.rs"),
]
PROOF_ITEMS = [
    "theorem_acknowledged_revocation_keeps_grant_revoked",
    "acknowledged_revocation_denies_reusable_admission",
    "theorem_single_use_grant_admits_one_consumption",
    "theorem_acknowledged_consumption_keeps_grant_used",
    "acknowledged_consumption_survives_a_later_revocation",
    "acknowledged_consumption_is_used_at_index",
    "theorem_revocation_keeps_grant_revoked_until_recovery",
    "revocation_denies_reusable_admission_until_recovery",
    "witness_unacknowledged_revocation_reopens_at_recovery",
    "theorem_retirement_admits_no_operation",
    "retirement_closes_after_an_earlier_resume",
    "witness_earlier_resume_does_not_reopen_retirement",
    "theorem_committed_fuel_is_budget_plus_charged_excess",
    "theorem_committed_fuel_stays_within_budget",
    "witness_charged_excess_is_the_only_overshoot",
]
RESULT = re.compile(r"verification results:: (\d+) verified, (\d+) errors")
LOCATION = re.compile(r"^error[^\n]*\n\s+--> (\S+):\d+:\d+", re.MULTILINE)


def replace_once(text: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in `text`."""
    if text.count(old) != 1:
        raise ValueError(f"expected one occurrence of {old!r}, found {text.count(old)}")
    return text.replace(old, new, 1)


def item(text: str, function: str) -> tuple[int, int]:
    """Locate a top-level proof item, from its signature to its closing brace.

    The scope includes the requires and ensures clauses.
    """
    start = text.index(f"fn {function}(")
    closing = text.index("\n}\n", start) + 1
    return start, closing


def edit_function(text: str, function: str, old: str, new: str) -> str:
    """Replace the one occurrence of `old` in a top-level proof item."""
    start, closing = item(text, function)
    item_text = text[start:closing]
    return text[:start] + replace_once(item_text, old, new) + text[closing:]


def contradict_function(text: str, function: str) -> str:
    """Put a false assertion first in the body of a proof item."""
    signature = text.index(f"proof fn {function}(")
    opening = text.index("{\n", signature) + 2
    return text[:opening] + "    assert(false);\n" + text[opening:]


def verified_counts(output: str) -> tuple[int, int] | None:
    """Read the verifier's counts, or None when it reported no result."""
    found = RESULT.search(output)
    if found is None:
        return None
    return int(found.group(1)), int(found.group(2))


def error_in(output: str, relative: Path) -> bool:
    """Report whether the verifier located an error in `relative`."""
    return any(Path(os.path.normpath(location)) == relative for location in LOCATION.findall(output))


def defects() -> list[tuple[str, Path, Callable[[str], str]]]:
    """Each defect names the claim it would falsify."""
    storage = "recovery_observes_acknowledged_markers"
    vacuity = [
        (f"false assertion in the body of {item}", MODEL, lambda text, item=item: contradict_function(text, item))
        for item in PROOF_ITEMS
    ]
    return [
        (
            "reserved handoff leaks into ordinary dispatch",
            ORDERED_DISPATCH,
            lambda text: replace_once(text, "Ok(deliver(reserved, event))", "Err(event)"),
        ),
        (
            "publication accepts a missing delivery reservation",
            DELIVERY_COMMIT,
            lambda text: replace_once(text, "if delivery.is_none() && delivery_required", "if false"),
        ),
        (
            "publication ignores inbox installation",
            DELIVERY_COMMIT,
            lambda text: replace_once(text, "None if inbox_required => return None,", "None if inbox_required => None,"),
        ),
        (
            "publication ignores captured inbox closure",
            DELIVERY_COMMIT,
            lambda text: replace_once(text, "Some((_, true)) => return None,", "Some((handoff, true)) => Some(handoff),"),
        ),
        (
            "publication discards captured delivery",
            DELIVERY_COMMIT,
            lambda text: replace_once(text, "Some((delivery, handoff))", "Some((None, handoff))"),
        ),
        (
            "publication discards captured handoff",
            DELIVERY_COMMIT,
            lambda text: replace_once(text, "Some((delivery, handoff))", "Some((delivery, None))"),
        ),
        (
            "publication rejects all valid reservations",
            DELIVERY_COMMIT,
            lambda text: replace_once(text, "    Some((delivery, handoff))", "    None"),
        ),
        (
            "publication accepts a mismatched forward binding",
            BINDING,
            lambda text: replace_once(text, "f.as_slice() != uid.as_slice() || ", ""),
        ),
        (
            "publication accepts a mismatched reverse binding",
            BINDING,
            lambda text: replace_once(text, " || r != alias", ""),
        ),
        (
            "view accepts a different runtime owner",
            VIEW_OWNER,
            lambda text: replace_once(text, "if uid.as_slice() != viewer.as_slice()", "if false"),
        ),
        (
            "shared runtime rejects its separately admitted viewer",
            VIEW_OWNER,
            lambda text: replace_once(text, "else { return true; }", "else { return false; }"),
        ),
        (
            "publication reopens retired gates",
            ROUTE_GATE,
            lambda text: replace_once(text, "_ => RETIRED", "_ => PUBLISHED"),
        ),
        (
            "route admission accepts staged gates",
            ROUTE_GATE,
            lambda text: replace_once(text, "    current == PUBLISHED\n", "    current != RETIRED\n"),
        ),
        (
            "retired receiver releases its buffered payload",
            ROUTE_GATE,
            lambda text: replace_once(text, "if admits(current) { Some(pending)", "if true { Some(pending)"),
        ),
        (
            "frame consumption drops the captured operation",
            INGRESS_FRAME,
            lambda text: replace_once(text, "    slot.take()", "    *slot = None; None"),
        ),
        (
            "receipt validation accepts a different capsule identifier",
            RECEIPT,
            lambda text: replace_once(text, "    id == key && digest", "    id != key && digest"),
        ),
        (
            "receipt validation omits the installed authority digest",
            RECEIPT,
            lambda text: replace_once(text, "&& digest(authority)", "&& digest(metadata)"),
        ),
        (
            "receipt read-back proceeds after a failed compare-and-swap",
            RECEIPT,
            lambda text: replace_once(text, "    if swapped { Some(target)", "    if true { Some(target)"),
        ),
        (
            "receipt acknowledgement accepts equal length but different bytes",
            RECEIPT,
            lambda text: replace_once(text, "Some(bytes) => bytes == expected", "Some(bytes) => bytes.len() == expected.len()"),
        ),
        (
            "principal UID text loses the upper nibble",
            UID_TEXT,
            lambda text: replace_once(text, "digit(uid[i] / 16)", "digit(uid[i] % 16)"),
        ),
        (
            "a principal UID decoder interchanges nibbles",
            UID_TEXT,
            lambda text: replace_once(text, "high * 16 + low", "low * 16 + high"),
        ),
        (
            "a content name admits a terminal parent component",
            FILESYSTEM_PATH,
            lambda text: replace_once(text, "after < path.len() && path[after] != b'/'", "after == path.len() || path[after] != b'/'"),
        ),
        (
            "a content name joins the suffix without a component separator",
            FILESYSTEM_PATH,
            lambda text: replace_once(text, "path.push('/');", "path.push('.');"),
        ),
        (
            "a storage mount omits its supplied root handle",
            STORAGE_HANDLES,
            lambda text: replace_once(text, "table.register(key, root);", "let _ = (key, root);"),
        ),
        (
            "directory registration discards the resolved subdirectory",
            STORAGE_HANDLES,
            lambda text: replace_once(text, "self.entries.insert(key, directory);", "let _ = directory;"),
        ),
        (
            "storage registration reports a collision as successful",
            STORAGE_HANDLES,
            lambda text: replace_once(text, "Entry::Occupied(_) => false", "Entry::Occupied(_) => true"),
        ),
        (
            "storage lookup suppresses a live binding",
            STORAGE_HANDLES,
            lambda text: replace_once(text, "self.entries.get(key)", "None"),
        ),
        (
            "storage retirement leaves the handle usable",
            STORAGE_HANDLES,
            lambda text: replace_once(text, "self.entries.remove(key)", "None"),
        ),
        (
            "a storage read exposes bytes before the open cursor",
            STORAGE_FILE,
            lambda text: replace_once(text, "as_slice().split_at(self.offset)", "as_slice().split_at(0)"),
        ),
        (
            "a buffered storage write discards the supplied content",
            STORAGE_FILE,
            lambda text: replace_once(text, "destination.copy_from_slice(content);", "let _ = destination;"),
        ),
        (
            "a dirty storage handle publishes without write authority",
            STORAGE_FILE,
            lambda text: replace_once(text, "if self.writable && self.dirty { Some", "if self.dirty { Some"),
        ),
        (
            "a buffered storage write ignores its open offset",
            STORAGE_FILE,
            lambda text: replace_once(text, "Some(end) => WriteRange::End(end)", "Some(end) => WriteRange::End(length)"),
        ),
        (
            "logical home gate selects a workspace destination",
            MOUNT,
            lambda text: replace_once(text, '("home://", VfsTarget::Home)', '("home://", VfsTarget::Workspace)'),
        ),
        (
            "logical capability gate omits the destination suffix",
            MOUNT,
            lambda text: replace_once(text, "gate.push_str(relative);", 'gate.push_str("");'),
        ),
        (
            "logical storage operation drops the admitted relative path",
            MOUNT,
            lambda text: replace_once(text, "(gate, relative, target)", '(gate, "", target)'),
        ),
        (
            "missing invocation workspace falls back to the runtime despite required binding",
            MOUNT,
            lambda text: replace_once(text, "if requires_binding { invocation }", "if requires_binding { runtime }"),
        ),
        (
            "restart retains a published native lease",
            Path("verification/hosted_lease_model.rs"),
            lambda text: replace_once(text, "| Event::Revoke | Event::Restart => Phase::Closed", "| Event::Revoke => Phase::Closed"),
        ),
        (
            "late publication reopens a retired lease identity",
            Path("verification/hosted_lease_model.rs"),
            lambda text: replace_once(text, "Event::Publish if phase == Phase::Preparing => Phase::Published", "Event::Publish => Phase::Published"),
        ),
        (
            "retiring a requester keeps its preparation open",
            LEASE_RESERVATION,
            lambda text: replace_once(text, "if affected { *self = Self::Closed; }", "if !affected { *self = Self::Closed; }"),
        ),
        (
            "one reservation allows repeated callback listener publication",
            LEASE_RESERVATION,
            lambda text: replace_once(text, "        *self = Self::Closed;\n        admitted", "        admitted"),
        ),
        (
            "retired preparation grants publication",
            LEASE_RESERVATION,
            lambda text: replace_once(text, "let admitted = matches!(self, Self::Preparing(_));", "let admitted = true;"),
        ),
        (
            "profile-only retirement closes unrelated management requesters",
            LEASE_RESERVATION,
            lambda text: replace_once(text, "Self::Management(name) => name == alias,", "Self::Management(name) => true,"),
        ),
        (
            "native mount recognizes home as the shared subtree",
            LEASE_SUBTREE,
            lambda text: replace_once(text, 'if prefix == "home" { Some(Self::PrincipalHome) }', 'if prefix == "home" { Some(Self::FleetShared) }'),
        ),
        (
            "fleet subtree reports the principal home prefix",
            LEASE_SUBTREE,
            lambda text: replace_once(text, 'Self::FleetShared => "shared" }', 'Self::FleetShared => "home" }'),
        ),
        (
            "native mount drops the owner of an admitted home",
            LEASE_SUBTREE,
            lambda text: replace_once(text, "\n        match (self, owner) {\n            (Self::PrincipalHome, Owner::Principal(uid)) => Some(BoundSubtree::PrincipalHome(uid)),", "\n        match (self, owner) {\n            (Self::PrincipalHome, Owner::Principal(_)) => None,"),
        ),
        (
            "native mount wire rename is classified as a read",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "| Operation::Rename { .. } => OperationClass::Write,\n        Operation::Sync", "=> OperationClass::Write,\n        Operation::Rename { .. } => OperationClass::Read,\n        Operation::Sync"),
        ),
        (
            "callback ticket downgrades a write to a read before execution",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "destinations.backing, operation, self.class)", "destinations.backing, operation, OperationClass::Read)"),
        ),
        (
            "false assertion in the lease closure consumer",
            Path("verification/hosted_lease_model.rs"),
            lambda source: replace_once(source, "proof { no_admission_after_close(events, closed, count); }",
                "proof { assert(false); no_admission_after_close(events, closed, count); }"),
        ),
        (
            "trace closure no longer establishes the runtime phase for dispatch",
            Path("verification/hosted_lease_model.rs"),
            lambda source: replace_once(source, "self.phase() == after(events, count),", "true,"),
        ),
        (
            "published authenticated callback loses its authorized effect",
            Path("verification/hosted_lease_model.rs"),
            lambda text: replace_once(text, "Admission::Accepted(ticket) => Some(ticket.into_effect())", "Admission::Accepted(_) => None"),
        ),
        (
            "system reads select the host administration projection",
            Path("crates/astrid-kernel/src/storage_mount/lease_authority/destination.rs"),
            lambda source: replace_once(source, "(Self::OwnerRoot(Owner::System), OperationClass::Write) =>", "(Self::OwnerRoot(Owner::System), _) =>"),
        ),
        (
            "workspace writes select the host administration projection",
            Path("crates/astrid-kernel/src/storage_mount/lease_authority/destination.rs"),
            lambda source: replace_once(source, "(Self::OwnerRoot(Owner::System), OperationClass::Write) =>", "(_, OperationClass::Write) =>"),
        ),
        (
            "stale KV view falls back to neutral and completes the request",
            Path("verification/hosted_kv_model.rs"),
            lambda source: replace_once(source, "Some(uid) => Some(Destination::Principal(uid)),\n                None => None,", "Some(uid) => Some(Destination::Principal(uid)),\n                None => Some(Destination::Neutral),"),
        ),
        (
            "WAL record header repeats the sequence in the ordinal field",
            Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
            lambda source: replace_once(source, "encoded.extend_from_slice(&self.ordinal);", "encoded.extend_from_slice(&self.sequence);"),
        ),
        (
            "WAL scanner skips the first logical body byte",
            Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
            lambda source: replace_once(source, "let body = &payload[HEADER_LEN..];", "let body = &payload[HEADER_LEN.saturating_add(1).min(payload.len())..];"),
        ),
        (
            "WAL dispatch accepts a record with an old ordinal",
            Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
            lambda source: replace_once(source, "if ordinal != expected_ordinal", "if ordinal > expected_ordinal"),
        ),
        (
            "WAL writer binds a different prepared replacement",
            Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
            lambda source: replace_once(source, "!equal_root(replacement,next)", "!equal_root(replacement,replacement)"),
        ),
        (
            "WAL sync failure leaves the writer usable",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "*poisoned = true;", "*poisoned = false;"),
        ),
        (
            "successful WAL sync acknowledges an empty group",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "Ok(count)", "Ok(0)"),
        ),
        (
            "WAL frontier rewinds to a shorter arena",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "Ordering::Less => None", "Ordering::Less => Some((observed, tail))"),
        ),
        (
            "unchanged WAL frontier replaces the published tail",
            Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source: replace_once(source, "Ordering::Equal => Some((current, tail))", "Ordering::Equal => Some((current, pending))"),
        ),
        (
            "transition journals record the construction in place of the algorithm",
            Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
            lambda source: replace_once(source, "bytes.extend_from_slice(&scheme.algorithm);", "bytes.extend_from_slice(&scheme.construction);"),
        ),
        (
            "root payload reader skips the last byte of a field",
            Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
            lambda source: replace_once(source, "*cursor = end;", "*cursor = end.saturating_sub(1);"),
        ),
        (
            "WAL transition accepts trailing bytes",
            Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
            lambda source: replace_once(source, "if *cursor != bytes.len()", "if *cursor > bytes.len()"),
        ),
        (
            "durable principal encoded as fleet",
            Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
            lambda source: replace_once(source, "Self::Principal(id) => (1u8, id)", "Self::Principal(id) => (2u8, id)"),
        ),
        (
            "owner recovery substitutes the first UID byte",
            Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
            lambda source: replace_once(source, "id[i] = bytes[i.saturating_add(1)]", "id[i] = bytes[1]"),
        ),
        (
            "prepared root encodes a different expected root",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "encode(&owner,expected,replacement)?", "encode(&owner,None,replacement)?"),
        ),
        (
            "WAL staging discards prepared journal bytes",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "write(&self.owner,self.expected,self.replacement,&self.journal)", "write(&self.owner,self.expected,self.replacement,&Vec::new())"),
        ),
        (
            "durable root admission ignores the commit digest",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, " || a.commit.as_slice() != b.commit.as_slice()", ""),
        ),
        (
            "durable root admission accepts a mismatched generation",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "a.generation != b.generation || ", ""),
        ),
        (
            "WAL replay publishes an already committed replacement",
            Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source: replace_once(source, "{ Replay::AlreadyPublished }", "{ Replay::Apply }"),
        ),
        (
            "guest KV releases admission before invoking the sink",
            Path("verification/hosted_kv_model.rs"),
            lambda source: replace_once(
                replace_once(source, "    tracker.finish();", ""),
                "if !tracker.begin() { return None; }",
                "if !tracker.begin() { return None; } tracker.finish();",
            ),
        ),
        (
            "KV completion fails to release its acquired owner count",
            Path("verification/hosted_kv_model.rs"),
            lambda source: replace_once(source, "    tracker.finish();", ""),
        ),
        (
            "guest KV substitutes the runtime namespace for a present invocation",
            Path("crates/astrid-capsule/src/engine/wasm/guest_kv.rs"),
            lambda source: replace_once(source, "match invocation { Some(store) => store, None => runtime }\n}", "runtime\n}"),
        ),
        (
            "resolve grant authorizes identity link modification",
            Path("crates/astrid-capsule/src/security/identity.rs"),
            lambda source: replace_once(source, 'required == "resolve" && grant == "link"', 'required == "link" && grant == "resolve"'),
        ),
        (
            "identity gate checks only the first declared manifest grant",
            Path("crates/astrid-capsule/src/security/identity.rs"),
            lambda source: replace_once(source, "while i < grants.len()", "while i < grants.len() && i == 0"),
        ),
        (
            "serialized worker accepts a stale lease after its wait",
            LEASE_CALLBACK,
            lambda source: replace_once(source, "guard.is_none() || !live_after_wait", "guard.is_none()"),
        ),
        (
            "serialized worker accepts a missing serialization guard",
            LEASE_CALLBACK,
            lambda source: replace_once(source, "guard.is_none() || !live_after_wait", "!live_after_wait"),
        ),
        (
            "filesystem operation is redirected to backing capacity",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "operation => Effect::Filesystem", "Operation::Sync => Effect::Volume(destinations.lease, destinations.mount, destinations.backing),\n            operation => Effect::Filesystem"),
        ),
        (
            "callback admission issues a ticket for a read-only write",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "else if !class.permits(writable)", "else if false"),
        ),
        (
            "read-only mount accepts a mutating callback",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "Self::Write => writable", "Self::Write => true"),
        ),
        (
            "mount callback sync bypasses mutation serialization",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "Self::Write | Self::Sync => true", "Self::Write => true, Self::Sync => false"),
        ),
        (
            "restart enumerates revoked markers twice and drops consumption",
            AUTHORITY,
            lambda text: replace_once(text, "[Self::Revoked, Self::Consumed]", "[Self::Revoked, Self::Revoked]"),
        ),
        (
            "revoked tokens are written to the used marker namespace",
            AUTHORITY,
            lambda text: replace_once(text, 'Self::Revoked => "caps:revoked", Self::Consumed => "caps:used"', 'Self::Revoked => "caps:used", Self::Consumed => "caps:used"'),
        ),
        (
            "mount clock ignores monotonic idle expiration",
            LEASE_CALLBACK,
            lambda source: replace_once(source, "Some(sec) => self.within_idle && sec <= self.expires", "Some(sec) => sec <= self.expires"),
        ),
        (
            "mount clock admits an unavailable wall clock",
            LEASE_CALLBACK,
            lambda source: replace_once(source, "None => false,", "None => true,"),
        ),
        (
            "revoked callback lease is live before its expiry",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "\n    !revoked && within_deadlines\n", "\n    within_deadlines\n"),
        ),
        (
            "callback drops the inclusive expiry boundary",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "Some(sec) => self.within_idle && sec <= self.expires", "Some(sec) => self.within_idle && sec < self.expires"),
        ),
        (
            "private callback executes without token authentication",
            LEASE_CALLBACK,
            lambda text: replace_once(text, "else if !authenticated { Admission::Unauthorized }", "else if false { Admission::Unauthorized }"),
        ),
        (
            "missing lease requester can control a native mount",
            LEASE_REQUESTER,
            lambda text: replace_once(text, "else { return false; }", "else { return true; }"),
        ),
        (
            "lease control ignores the captured requester identity",
            LEASE_REQUESTER,
            lambda text: replace_once(text, "uid.as_slice() != owner.as_slice()", "uid.as_slice() != uid.as_slice()"),
        ),
        (
            "typed runtime accepts an unregistered owner",
            INVOCATION_OWNER,
            lambda text: replace_once(text, "(Some(_), None) => false", "(Some(_), None) => true"),
        ),
        (
            "interceptor compares its observed UID to itself",
            INVOCATION_OWNER,
            lambda text: replace_once(text, "uid.as_slice() != owner.as_slice()", "uid.as_slice() != uid.as_slice()"),
        ),
        (
            "mount selection discards the invocation override",
            MOUNT,
            lambda text: replace_once(text, "Some(value) => Some(value), None => runtime", "Some(_) => runtime, None => runtime"),
        ),
        (
            "home file operation captures the workspace bundle",
            MOUNT,
            lambda text: replace_once(text, "            Self::Home => home,", "            Self::Home => workspace,"),
        ),
        (
            "pair token is returned after a storage collision",
            PAIR_RESULT,
            lambda text: replace_once(text, "Ok(false) => Inserted::Collision", "Ok(false) => Inserted::Issued(token)"),
        ),
        (
            "pair token is returned after a storage error",
            PAIR_RESULT,
            lambda text: replace_once(text, "Err(_) => Inserted::Unavailable", "Err(_) => Inserted::Issued(token)"),
        ),
        (
            "pair authorization refusal emits a successful audit outcome",
            PAIR_RESULT,
            lambda text: replace_once(text, "=> Audit::Denied(error)", "=> Audit::Success"),
        ),
        (
            "wire header misstates the low byte of the body length",
            NATIVE_FRAME,
            lambda text: replace_once(text, "(n % 256) as u8", "(upper % 256) as u8"),
        ),
        (
            "incoming socket frame consumes a byte of its successor",
            NATIVE_FRAME,
            lambda text: replace_once(text, "consumed: 4 + len as usize", "consumed: 5 + len as usize"),
        ),
        (
            "incoming socket frame admits an oversized declaration",
            NATIVE_FRAME,
            lambda text: replace_once(text, "if len as usize > limit", "if false && len as usize > limit"),
        ),
        (
            "incoming socket frame supplies the suffix as its body",
            NATIVE_FRAME,
            lambda text: replace_once(text, "let (body, _) = payload.split_at", "let (_, body) = payload.split_at"),
        ),
        (
            "socket starts with the body instead of the length prefix",
            NATIVE_FRAME,
            lambda text: replace_once(text, "else { self.prefix }", "else { self.body }"),
        ),
        (
            "socket repeats a previously accepted byte after a short write",
            NATIVE_FRAME,
            lambda text: replace_once(text, "segment.split_at(count)", "segment.split_at(count - 1)"),
        ),
        (
            "socket reports progress for a zero-byte write",
            NATIVE_FRAME,
            lambda text: replace_once(text, "count == 0 || count >", "count >"),
        ),
        (
            "claimed native reply can be claimed twice",
            NATIVE_REPLY,
            lambda text: replace_once(text, "|| !matches!(self, Phase::Available)", "|| false"),
        ),
        (
            "native queue claims a reply for another owner",
            NATIVE_REPLY,
            lambda text: replace_once(text, "if closed || registered != offered", "if closed"),
        ),
        (
            "cancelling a native reply loses its retry",
            NATIVE_REPLY,
            lambda text: replace_once(text, "*self = Phase::Available", "*self = Phase::Spent"),
        ),
        (
            "foreign completion consumes a native reply",
            NATIVE_REPLY,
            lambda text: replace_once(text, "if registered != offered || !matches!(self, Phase::Claimed)", "if !matches!(self, Phase::Claimed)"),
        ),
        (
            "socket writer binds another connection's queue",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "registered.owner != handshake.owner || ", ""),
        ),
        (
            "native writer accepts a replacement registration",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "(Some(a), Some(b)) if a == b => Some(handle)", "(Some(_), Some(_)) => Some(handle)"),
        ),
        (
            "native FIFO delivers the newest event first",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "self.events.pop_front()", "self.events.pop_back()"),
        ),
        (
            "native FIFO puts new events ahead of queued events",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "self.events.push_back((event, bytes))", "self.events.push_front((event, bytes))"),
        ),
        (
            "overflow discards the closure fence",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "self.closed = true;", "self.closed = false;"),
        ),
        (
            "empty closed socket appears temporarily idle",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "if self.closed { return Receipt::Closed; }", "if self.closed { return Receipt::Empty; }"),
        ),
        (
            "native FIFO ignores reply overflow",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "self.closed || reply_overflow ||", "self.closed ||"),
        ),
        (
            "native FIFO fails to charge an admitted event",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "self.bytes.saturating_add(bytes)", "self.bytes"),
        ),
        (
            "native FIFO fails to release a dequeued byte charge",
            NATIVE_QUEUE,
            lambda text: replace_once(text, "self.bytes.saturating_sub(bytes)", "self.bytes"),
        ),
        (
            "native approval accepts an untrusted producer",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "    source == 0 && stamp", "    true && stamp"),
        ),
        (
            "native approval ignores the payload owner",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "&& same(Some(payload_owner), Some(client_text))", "&& true"),
        ),
        (
            "native ordinary frame ignores an explicit owner",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "Some(actual) => actual == expected", "Some(actual) => true"),
        ),
        (
            "exact native topic accepts a suffix",
            NATIVE_TOPIC,
            lambda text: replace_once(text, "    listed(rules, topic, false)", "    listed(rules, topic, true)"),
        ),
        (
            "native prefix lookup accepts unlisted bytes",
            NATIVE_TOPIC,
            lambda text: replace_once(text, "if candidate != rule", "if false"),
        ),
        (
            "blocked native request inherits control prefix access",
            NATIVE_TOPIC,
            lambda text: replace_once(text, "    !blocked && (capsule || control)", "    capsule || control"),
        ),
        (
            "native egress delivers disallowed topics",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "    allowed\n        && match", "    true\n        && match"),
        ),
        (
            "untargeted native message is broadcast on every topic",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "None => broadcast,", "None => true,"),
        ),
        (
            "pairing child omits an issuer deny",
            PAIR_DENIES,
            lambda text: replace_once(text, "child.push(copy);", "let _ = copy;"),
        ),
        (
            "pairing child repeats a deny already in its policy",
            PAIR_DENIES,
            lambda text: replace_once(text, "if !contains(child, pattern.as_str()) {", "if true {"),
        ),
        (
            "pairing child discards restrictions already inherited at admission",
            PAIR_DENIES,
            lambda text: replace_once(text, "let mut i = 0usize;", "child.clear(); let mut i = 0usize;"),
        ),
        (
            "private answer consumes a slot for another principal",
            PRIVATE_RESPONDER,
            lambda text: replace_once(text, "if owner != caller { return false; }", ""),
        ),
        (
            "private answer consumes a slot for another registration",
            PRIVATE_RESPONDER,
            lambda text: replace_once(text, "(Some(a), Some(b)) => a == b", "(Some(a), Some(b)) => true"),
        ),
        (
            "native egress ignores the target principal",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "Some(_) => same(target.principal, client.principal)", "Some(_) => true"),
        ),
        (
            "native egress ignores device restriction",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "Some(_) => same(target.device, client.device) && match", "Some(_) => true && match"),
        ),
        (
            "native egress admits another registration of the same key",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "(Some(a), Some(b)) => a == b,", "(Some(a), Some(b)) => true,"),
        ),
        (
            "native egress accepts a versioned target on an unversioned socket",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "(None, None) => true,", "(None, None) | (Some(_), None) => true,"),
        ),
        (
            "chat delivery accepts another session",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "|| same(target.session, client.session)", "|| true"),
        ),
        (
            "foreign explicit owner uses autonomous correlation",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "if stamp.is_some() || !completed", "if !completed"),
        ),
        (
            "unowned completion accepts another producer",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "saved.producer == producer && saved.nonce == actual", "saved.nonce == actual"),
        ),
        (
            "unowned completion accepts another nonce",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "saved.producer == producer && saved.nonce == actual", "saved.producer == producer"),
        ),
        (
            "owned response can replace an established correlation",
            NATIVE_RECIPIENT,
            lambda text: replace_once(text, "!completed && binding.is_none() && producer", "!completed && producer"),
        ),
        (
            "egress consent accepts a different principal",
            CONSENT_IDENTITY,
            lambda text: replace_once(text, "if bytes != principal", "if false"),
        ),
        (
            "egress consent accepts a different request owner",
            CONSENT_IDENTITY,
            lambda text: replace_once(text, "Some(actual) => actual == owner", "Some(actual) => true"),
        ),
        (
            "registration compares the challenge channel with itself",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "if same_channel(challenge, &entries[i].signal)", "if same_channel(challenge, challenge)"),
        ),
        (
            "registration binds the first entry instead of the matched channel",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "if entries[i].phase.bind(key)", "if entries[0].phase.bind(key)"),
        ),
        (
            "registration reports success after a rejected binding",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "return Binding::Retired;", "return Binding::Bound;"),
        ),
        (
            "retired challenge accepts its removed key",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "if retired.contains(&key) { return false; }", "if false { return false; }"),
        ),
        (
            "foreign principal is retired",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "if owner != requested { return false; }", "if false { return false; }"),
        ),
        (
            "retirement omits the pending challenge exclusion",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "keys.insert(key.to_owned()); false", "false"),
        ),
        (
            "retirement drains the wrong serving device",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "bound.as_str() == key", "bound.as_str() != key"),
        ),
        (
            "registry never visits its last session",
            DEVICE_SESSIONS,
            lambda text: edit_function(text, "retire_entries<S>", "while i < entries.len()", "while i < entries.len() && entries.len() - i > 1"),
        ),
        (
            "registry substitutes the first drain slot",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "drains.push(i);", "drains.push(0);"),
        ),
        (
            "acknowledgement skips the first registered device session",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "let mut confirmed = 0usize;", "let mut confirmed = 1usize;"),
        ),
        (
            "retirement confirms a socket whose receiver is still live",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "if !closed(signal) {", "if false {"),
        ),
        (
            "device retirement captures another registration's channel",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "capture(&entries[slot].signal)", "capture(&entries[0].signal)"),
        ),
        (
            "native revocation receipt acknowledges another device",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "owner: self.owner, key: self.key", "owner: self.owner, key: self.owner"),
        ),
        (
            "native revocation receipt checks the first channel twice",
            DEVICE_SESSIONS,
            lambda text: replace_once(text, "&self.signals[confirmed]", "&self.signals[0]"),
        ),
        (
            "profile removal selects an unrelated key",
            DEVICE_REGISTRATION,
            lambda text: replace_once(text, "if k == requested {", "if k != requested {"),
        ),
        (
            "profile removal drops the first record instead of its unique match",
            DEVICE_REGISTRATION,
            lambda text: replace_once(text, "registrations.remove(index)", "registrations.remove(0)"),
        ),
        (
            "signed challenge omits the principal separator",
            DEVICE_CHALLENGE,
            lambda text: replace_once(text, "message.push(':');", ""),
        ),
        (
            "signed challenge substitutes the principal for the nonce",
            DEVICE_CHALLENGE,
            lambda text: replace_once(text, "message.push_str(nonce);", "message.push_str(principal);"),
        ),
        (
            "dispatch accepts a different live registration",
            DEVICE_REGISTRATION,
            lambda text: replace_once(text, "(Some(a), Some(b)) => a == b", "(Some(a), Some(b)) => a != b"),
        ),
        (
            "dispatch accepts a missing generation for a versioned record",
            DEVICE_REGISTRATION,
            lambda text: replace_once(text, "(None, None) => true,", "(None, None) | (Some(_), None) => true,"),
        ),
        (
            "registered bearer omits the pairing generation",
            REGISTERED_BEARER,
            lambda text: replace_once(text, "signed.push_str(registration);", "signed.push_str(claims);"),
        ),
        (
            "signature selects another registered device",
            DEVICE_CHALLENGE,
            lambda text: replace_once(text, "return Some(record);", "return Some(&records[0]);"),
        ),
        (
            "device verification drops the signed message",
            DEVICE_CHALLENGE,
            lambda text: replace_once(text, "Some(k) => verify(signature, k, message)", "Some(k) => verify(signature, k, &[])"),
        ),
        (
            "registration without a canonical public key authenticates",
            DEVICE_CHALLENGE,
            lambda text: replace_once(text, "None => false,", "None => true,"),
        ),
        (
            "disabled profile supplies device keys",
            DEVICE_ADMISSION,
            lambda text: replace_once(text, "    if enabled && keypair", "    if keypair"),
        ),
        (
            "disabled keypair method supplies device keys",
            DEVICE_ADMISSION,
            lambda text: replace_once(text, "    if enabled && keypair", "    if enabled"),
        ),
        (
            "device admission returns the first record instead of its unique match",
            DEVICE_REGISTRATION,
            lambda text: replace_once(text, "Some(&registrations[index])", "Some(&registrations[0])"),
        ),
        (
            "duplicate device records authorize the first registration",
            DEVICE_REGISTRATION,
            lambda text: replace_once(text, "                return None;", "                return Some(_previous);"),
        ),
        (
            "authenticated forward ignores topic",
            INGRESS_FRAME,
            lambda text: replace_once(text, "if topic != offered_topic", "if false"),
        ),
        (
            "device-stamped forward without a session takes the unguarded path",
            INGRESS_FRAME,
            lambda text: replace_once(text, "return if key.is_none()", "return if true"),
        ),
        (
            "signed forward ignores the captured device",
            INGRESS_FRAME,
            lambda text: replace_once(text, "if a != b || peer != principal", "if peer != principal"),
        ),
        (
            "signed forward ignores the captured principal",
            INGRESS_FRAME,
            lambda text: replace_once(text, "if a != b || peer != principal", "if a != b"),
        ),
        (
            "signed forward ignores the connection generation",
            INGRESS_FRAME,
            lambda text: replace_once(text, "|| owner != Some(connection) { return", "{ return"),
        ),
        (
            "matching signed forward skips the lease",
            INGRESS_FRAME,
            lambda text: replace_once(text, "    PublicationGuard::Signed(lease)\n}", "    PublicationGuard::Unbound\n}"),
        ),
        (
            "authenticated forward ignores payload",
            INGRESS_FRAME,
            lambda text: replace_once(text, "if body != offered_body", "if false"),
        ),
        (
            "non-uplink read earns ingress identity",
            INGRESS_FRAME,
            lambda text: replace_once(text, "    if uplink && data", "    if data"),
        ),
        (
            "empty read earns ingress identity",
            INGRESS_FRAME,
            lambda text: replace_once(text, "    if uplink && data", "    if uplink"),
        ),
        (
            "scoped IPC route accepts foreign publisher bytes",
            ROUTE_SCOPE,
            lambda text: replace_once(text, "if *owner != actual", "if false"),
        ),
        (
            "principal-only IPC route admits system events",
            ROUTE_SCOPE,
            lambda text: replace_once(text, "Scope::System | Scope::PrincipalOrSystem(_), None", "Scope::System | Scope::PrincipalOrSystem(_) | Scope::Principal(_), None"),
        ),
        (
            "request-owner route accepts unstamped traffic",
            ROUTE_SCOPE,
            lambda text: replace_once(text, "(Some(_), None) => false", "(Some(_), None) => true"),
        ),
        (
            "request-owner route accepts another request",
            ROUTE_SCOPE,
            lambda text: replace_once(text, "=> expected == actual", "=> true"),
        ),
        (
            "principal parser accepts the empty stamp",
            PRINCIPAL_SYNTAX,
            lambda text: replace_once(text, "return Syntax::Empty;", "return Syntax::Valid;"),
        ),
        (
            "principal parser accepts an invalid byte",
            PRINCIPAL_SYNTAX,
            lambda text: replace_once(text, "return Syntax::InvalidAt(i);", "return Syntax::Valid;"),
        ),
        (
            "registry reuses the same generation",
            GENERATION,
            lambda text: replace_once(text, "*next = successor;", "*next = current;"),
        ),
        (
            "registry returns the successor instead of the reserved generation",
            GENERATION,
            lambda text: replace_once(text, "Some(current)", "Some(successor)"),
        ),
        (
            "cache repair accepts a different owner",
            CACHE_ADDRESS,
            lambda text: replace_once(text, "self.owner != expected.owner || ", ""),
        ),
        (
            "cache repair accepts a different capsule",
            CACHE_ADDRESS,
            lambda text: replace_once(text, "self.capsule != expected.capsule ||", ""),
        ),
        (
            "cache repair accepts a different archive",
            CACHE_ADDRESS,
            lambda text: replace_once(text, "self.digest != expected.digest", "false"),
        ),
        (
            "stale install ownership follows a reassigned alias",
            BINDING,
            lambda text: replace_once(text, "uid.as_slice() != observed.as_slice() => None",
                                      "uid.as_slice() != observed.as_slice() => Some(observed)"),
        ),
        (
            "shared state accepts a self-scoped grant",
            PRINCIPAL_SCOPE,
            lambda text: replace_once(text, "if shared || caller != target", "if caller != target"),
        ),
        (
            "another principal accepts a self-scoped grant",
            PRINCIPAL_SCOPE,
            lambda text: replace_once(text, "if shared || caller != target", "if shared"),
        ),
        (
            "ordered overlay replacement retains its old value",
            OVERLAY_UPDATE,
            lambda text: replace_once(text, "make_node(entry, node.left.clone(), node.right.clone())",
                                      "make_node(Arc::clone(&node.entry), node.left.clone(), node.right.clone())"),
        ),
        (
            "left rotation drops the inner subtree",
            OVERLAY_UPDATE,
            lambda text: edit_function(text, "rotate_left", "right.left.clone()", "None"),
        ),
        (
            "right rotation drops the inner subtree",
            OVERLAY_UPDATE,
            lambda text: edit_function(text, "rotate_right", "left.right.clone()", "None"),
        ),
        (
            "overlay drops an exact key including its tombstone",
            OVERLAY,
            lambda text: replace_once(text, "Ordering::Equal => return Some(&node.entry.value)", "Ordering::Equal => return None"),
        ),
        (
            "overlay searches the wrong subtree",
            OVERLAY,
            lambda text: replace_once(text, "Ordering::Less => node.left.as_ref()", "Ordering::Less => node.right.as_ref()"),
        ),
        (
            "checkpoint leaf ignores the lower fence",
            KV_ENCODING,
            lambda text: replace_once(text, "!bytewise_less(key, start) && bytewise_less(key, end)", "bytewise_less(key, end)"),
        ),
        (
            "checkpoint traversal skips the last child",
            KV_ENCODING,
            lambda text: replace_once(text, "_ => bytewise_less(lower, end),", "None => false, _ => bytewise_less(lower, end),"),
        ),
        (
            "byte order reverses strict-prefix ties",
            KV_ENCODING,
            lambda text: edit_function(text, "bytewise_cmp", "left.len().cmp(&right.len())", "right.len().cmp(&left.len())"),
        ),
        (
            "prefix range includes sibling namespaces",
            KV_ENCODING,
            lambda text: edit_function(
                text, "logical_prefix_range", "== (ns == other && matches_prefix(key, prefix))",
                "== matches_prefix(key, prefix)",
            ),
        ),
        (
            "prefix range excludes the exact prefix",
            KV_ENCODING,
            lambda text: replace_once(text, "end[pivot] = byte.saturating_add(1);", "end[pivot] = byte;"),
        ),
        (
            "prefix interval ignores its lower bound",
            KV_ENCODING,
            lambda text: edit_function(
                text, "prefix_interval", "(!below(key, start) && below(key, end))", "below(key, end)"
            ),
        ),
        (
            "physical entry drops the requested key",
            KV_ENCODING,
            lambda text: replace_once(text, "address.extend_from_slice(key);", ""),
        ),
        (
            "physical address loses namespace separation",
            KV_ENCODING,
            lambda text: replace_once(text, "address.push(0);", ""),
        ),
        (
            "guest namespace can follow a replacement owner",
            GUEST_AUTHORITY,
            lambda text: replace_once(text, " && same_bytes(pinned.as_slice(), observed.as_slice())", ""),
        ),
        (
            "guest owner can access a sibling namespace",
            GUEST_AUTHORITY,
            lambda text: replace_once(text, "same_bytes(admitted, requested) && ", ""),
        ),
        (
            "admit ignores revocation for reusable tokens",
            AUTHORITY,
            lambda text: replace_once(
                text,
                "if self.revoked {\n            Admission::Revoked",
                "if self.revoked && single_use {\n            Admission::Revoked",
            ),
        ),
        (
            "recover_markers drops its last marker",
            AUTHORITY,
            lambda text: replace_once(text, "status.restore(*last);", "let _ = last;"),
        ),
        (
            "recovery forgets an acknowledged revocation",
            MODEL,
            lambda text: edit_function(
                text,
                storage,
                "(revocation_acknowledged_before(events, i) ==> markers.contains(Marker::Revoked))",
                "true",
            ),
        ),
        (
            "recovery forgets an acknowledged consumption",
            MODEL,
            lambda text: edit_function(
                text,
                storage,
                "(consumption_acknowledged_before(events, i) ==> markers.contains(Marker::Consumed))",
                "true",
            ),
        ),
        (
            "a revoke keeps the grant's prior state",
            MODEL,
            lambda text: edit_function(
                text,
                "grant_step",
                "GrantEvent::Revoke { .. } => GrantState { revoked: true, used: state.used },",
                "GrantEvent::Revoke { .. } => state,",
            ),
        ),
        (
            "recovery ignores revoked markers",
            MODEL,
            lambda text: edit_function(
                text,
                "grant_step",
                "revoked: markers.contains(Marker::Revoked),",
                "revoked: false,",
            ),
        ),
        (
            "recovery ignores consumed markers",
            MODEL,
            lambda text: edit_function(
                text,
                "grant_step",
                "used: markers.contains(Marker::Consumed),",
                "used: false,",
            ),
        ),
        (
            "revocation theorem stated without the storage condition",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_revocation_keeps_grant_revoked",
                "        recovery_observes_acknowledged_markers(events),\n",
                "",
            ),
        ),
        (
            "acknowledged revocation theorem reports only single-use denial",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_revocation_keeps_grant_revoked",
                "        forall|j: int| i <= j <= events.len()"
                " ==> (#[trigger] grant_run(events, j)).revoked,\n",
                "        forall|j: int| i <= j <= events.len()"
                " ==> !grant_admits(#[trigger] grant_run(events, j), true),\n",
            ),
        ),
        (
            "recovery-fence theorem reports only single-use denial",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_revocation_keeps_grant_revoked_until_recovery",
                "            ==> (grant_run(events, k)).revoked,",
                "            ==> !grant_admits(grant_run(events, k), true),",
            ),
        ),
        (
            "consumption theorem reports only single-use denial",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_consumption_keeps_grant_used",
                "        forall|j: int| i <= j <= events.len() ==> (#[trigger] grant_run(events, j)).used,\n",
                "        forall|j: int| i <= j <= events.len()"
                " ==> !grant_admits(#[trigger] grant_run(events, j), true),\n",
            ),
        ),
        (
            "consumption theorem omits the index itself",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_acknowledged_consumption_keeps_grant_used",
                "        forall|j: int| i <= j <= events.len() ==> (#[trigger] grant_run(events, j)).used,\n",
                "        forall|j: int| i < j <= events.len() ==> (#[trigger] grant_run(events, j)).used,\n",
            ),
        ),
        (
            "retirement proof ignores resumes after the retirement",
            MODEL,
            lambda text: edit_function(
                text, "retired_until_resume", "no_resume_between(events, i, k),", "true,"
            ),
        ),
        (
            "retirement theorem counts a resume before the retirement",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_retirement_admits_no_operation",
                "            && #[trigger] no_resume_between(events, i, k)\n"
                "            ==> !operation_admits(operation_run(events, k)),",
                "            && !(events.take(k).contains(OperationEvent::Resume))\n"
                "                ==> !operation_admits(operation_run(events, k)),",
            ),
        ),
        (
            "single-use proof loses the consumption lemma",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_single_use_grant_admits_one_consumption",
                "acknowledged_consumption_closes(events, first);",
                "",
            ),
        ),
        (
            "a reservation is admitted without fitting",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_transition_is_admitted",
                "FuelEvent::Reserve { requested } => fuel_admits(state, requested as int, limit),",
                "FuelEvent::Reserve { .. } => true,",
            ),
        ),
        (
            "a settlement releases more than it promised",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_transition_is_admitted",
                "FuelEvent::Settle { released, .. } => released as int <= state.reserved,",
                "FuelEvent::Settle { .. } => true,",
            ),
        ),
        (
            "a settlement hides the fuel charged beyond its promise",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_step",
                "+ if actual as int > released as int { actual as int - released as int } else { 0 },",
                "+ 0,",
            ),
        ),
        (
            "budget corollary stated without its no-excess condition",
            MODEL,
            lambda text: edit_function(
                text,
                "theorem_committed_fuel_stays_within_budget",
                "        forall|m: int| 0 <= m < events.len()"
                " ==> #[trigger] settlement_charges_within_promise(events, m),\n",
                "",
            ),
        ),
        (
            "apply_revocation records consumption",
            MODEL,
            lambda text: edit_function(
                text, "apply_revocation", "status.record_revocation();", "status.record_consumption();"
            ),
        ),
        (
            "apply_consumption records a revocation",
            MODEL,
            lambda text: edit_function(
                text,
                "apply_consumption",
                "status.confirm_consumption(won)",
                "{ status.record_revocation(); false }",
            ),
        ),
        (
            "store_admission allows everything",
            MODEL,
            lambda text: edit_function(
                text,
                "store_admission",
                "matches!(status.admit(single_use), Admission::Allowed)",
                "true",
            ),
        ),
        (
            "apply_recovery ignores the markers",
            MODEL,
            lambda text: edit_function(
                text,
                "apply_recovery",
                "TokenStatus::recover_markers(markers)",
                "TokenStatus::recover(false, false)",
            ),
        ),
        (
            "apply_operation skips finish",
            MODEL,
            lambda text: edit_function(
                text,
                "apply_operation",
                "OperationEvent::Finish => {\n            state.finish();\n            false\n        },",
                "OperationEvent::Finish => false,",
            ),
        ),
        (
            "fuel_reservation_fits confuses the request with the limit",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_reservation_fits",
                "crate::arithmetic::reservation_fits(spent, reserved, requested, limit)",
                "crate::arithmetic::reservation_fits(spent, reserved, limit, requested)",
            ),
        ),
        (
            "fuel_settlement confuses the release with the charge",
            MODEL,
            lambda text: edit_function(
                text,
                "fuel_settlement",
                "crate::arithmetic::settle_amounts(spent, reserved, released, actual)",
                "crate::arithmetic::settle_amounts(spent, reserved, actual, released)",
            ),
        ),
        *vacuity,
    ]


def verify(verus: str, tree: Path) -> tuple[int, str]:
    result = subprocess.run(
        [
            verus,
            "--edition=2024",
            "--crate-type=lib",
            "--no-cheating",
            ENTRY.as_posix(),
        ],
        cwd=tree,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def copy_inputs(source: Path, tree: Path) -> None:
    for relative in INPUTS:
        (tree / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, tree / relative)


def consumer_defects():
    """Weaken a production guarantee and require its trace consumer to fail."""
    yield (
        "KV handoff no longer guarantees the exact sink receipt",
        Path("crates/astrid-capsule/src/engine/wasm/guest_kv.rs"),
        lambda source: replace_once(source, "ensures sink.ensures((&guard, store, effect), result)", "ensures true"),
        Path("verification/hosted_kv_model.rs"),
    )
    yield (
        "WAL replay contract loses idempotent publication",
        Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
        lambda source: replace_once(
            replace_once(source, "(decision is AlreadyPublished) == matches_root(actual, Some(replacement)),", ""),
            "(decision is Apply) == (!matches_root(actual, Some(replacement)) && matches_root(actual, expected)),",
            "",
        ),
        Path("verification/hosted_kv_model.rs"),
    )
    yield (
        "owner decoding contract omits the recovered UID",
        Path("crates/astrid-storage/src/principal_state/owner_codec.rs"),
        lambda source: replace_once(source, "owner matches Some(o) ==> o.bytes() == bytes@,", ""),
        Path("verification/hosted_kv_model.rs"),
    )
    for name, clause in [
        ("encoder omits the prepared journal postcondition", "&&& encode.ensures((&owner,expected,replacement), Ok(bytes))"),
        ("root publication loses the matching acknowledgement", "publish.ensures((&self.binding().0,self.binding().2),result.1)"),
        ("WAL append loses the matching journal postcondition", "write.ensures((&self.binding().0,self.binding().1,self.binding().2,&self.binding().3),result)"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/root_transition.rs"),
            lambda source, clause=clause: replace_once(source, clause, "&&& true" if clause.startswith("&&&") else "true"),
            Path("verification/hosted_kv_model.rs"),
        )
    yield (
        "WAL parser loses the recovered transition fields",
        Path("crates/astrid-storage/src/engine/durable/root_wire.rs"),
        lambda source: replace_once(source, "&&& bytes@.skip(*old(cursor) as int) == prior(expected,scheme) + replacement.wire(scheme)", "&&& true"),
        Path("verification/hosted_kv_model.rs"),
    )
    for name, clause in [
        ("group frontier loses the staged persistence result", "persist.ensures((&batch,), Ok(group.binding().1))"),
        ("group completion loses the matching frontier receipt", "advance.ensures((self.binding().1,), Ok(frontier))"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source, clause=clause: replace_once(source, clause, "true"),
            Path("verification/hosted_kv_model.rs"),
        )
    yield (
        "WAL position gate loses the exact admitted body",
        Path("crates/astrid-storage/src/engine/durable/wal/record_wire.rs"),
        lambda source: replace_once(source, "result matches Ok(accepted) ==> accepted == body,", ""),
        Path("verification/hosted_kv_model.rs"),
    )
    for name, clause in [
        ("staged group loses the ordered batch", "group.binding().0 == batch"),
        ("failed persistence loses the original group", "submitted == batch"),
        ("published receipts lose the persisted group", "batch == self.binding().0"),
        ("failed frontier loses the submitted group", "submitted == self.binding().0"),
        ("failed persistence loses the original error", "persist.ensures((&batch,), Err(error))"),
        ("failed frontier loses the original error", "advance.ensures((self.binding().1,), Err(error))"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source, clause=clause: replace_once(source, clause, "true"),
            Path("verification/hosted_kv_model.rs"),
        )
    for name, clause in [
        ("sync failure loses the unacknowledged batch count", "*final(pending) == if outcome.is_ok() { 0 } else { *old(pending) },"),
        ("sync failure loses writer poisoning", "*final(poisoned) == (*old(poisoned) || outcome matches Err(PublicationError::Sync(_))),"),
        ("sync success loses its connection to the physical sink", "&& exists|w: Result<(),E>| w.is_ok() && #[trigger] sync.ensures((),w)"),
        ("unchanged WAL arena loses its published tail contract", "else if observed == current { Some((current, tail)) }"),
    ]:
        yield (
            name, Path("crates/astrid-storage/src/engine/durable/frontier.rs"),
            lambda source, clause=clause: replace_once(source, clause, "else if observed == current { position }" if clause.startswith("else if") else ""),
            Path("verification/hosted_kv_model.rs"),
        )
    consumer = Path("verification/hosted_lease_model.rs")
    yield (
        "worker loses the sink's completion guarantee",
        Path("crates/astrid-kernel/src/storage_mount/lease_authority/worker.rs"),
        lambda source: replace_once(source,
            "ensures sink.ensures((&self.binding().0, self.binding().1), result)",
            "ensures true"), consumer,
    )
    for name, clause in [
        ("issued scope", "*bound.parts().1 == self.scope, "),
        ("issued backing", ", *bound.parts().2 == self.backing"),
        ("filesystem scope", "target == self.binding().0.parts().1 &&"),
        ("volume backing", " && backing == self.binding().0.parts().2"),
    ]:
        yield (
            f"callback contract omits {name}", LEASE_CALLBACK,
            lambda source, clause=clause: replace_once(source, clause, ""), consumer,
        )


def check_defect(verus: str, base: Path, name: str, relative: Path, defect, expected_error: Path | None = None) -> bool:
    """Apply one defect to a scratch copy and report whether it was rejected."""
    tree = base / "defect"
    copy_inputs(base, tree)
    source = tree / relative
    try:
        source.write_text(defect(source.read_text()))
    except ValueError as error:
        print(f"FAIL: {name}: {error}")
        return False
    _, output = verify(verus, tree)
    counts = verified_counts(output)
    if counts is None:
        print(f"FAIL: {name}: verifier did not produce verification counts")
        print(output[-2000:])
        return False
    if counts[1] == 0:
        print(f"FAIL: {name}: the verifier reported no error")
        return False
    location = expected_error or relative
    if not error_in(output, location):
        print(f"FAIL: {name}: no error in {location}")
        return False
    print(f"PASS: {name}: rejected")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--verus", default="verus", help="path to the pinned verifier")
    args = parser.parse_args()
    checks = [(*check, None) for check in defects()] + list(consumer_defects())
    with tempfile.TemporaryDirectory(prefix="astrid-verification-defects-") as scratch:
        base = Path(scratch)
        copy_inputs(ROOT, base)
        code, output = verify(args.verus, base)
        counts = verified_counts(output)
        if code != 0 or counts is None or counts[1] != 0:
            print("FAIL: the unmodified sources must verify with zero errors")
            print(output[-2000:])
            return 1
        print("PASS: unmodified sources verify with zero errors")
        passed = sum(
            check_defect(args.verus, base, *check) for check in checks
        )
    print(f"{passed} of {len(checks)} defects rejected")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
