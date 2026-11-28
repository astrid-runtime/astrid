"""Implementation mutations for mounts verification."""

from pathlib import Path
from .common import (
    FILESYSTEM_PATH,
    LEASE_CALLBACK,
    LEASE_REQUESTER,
    LEASE_RESERVATION,
    LEASE_SUBTREE,
    MOUNT,
    STORAGE_FILE,
    STORAGE_HANDLES,
    replace_once,
)


def defects():
    return [
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
            "mount selection discards the invocation override",
            MOUNT,
            lambda text: replace_once(text, "Some(value) => Some(value), None => runtime", "Some(_) => runtime, None => runtime"),
        ),
        (
            "home file operation captures the workspace bundle",
            MOUNT,
            lambda text: replace_once(text, "            Self::Home => home,", "            Self::Home => workspace,"),
        ),
    ]
