"""Implementation mutations for dispatch verification."""

from pathlib import Path
from .common import (
    CACHE_ADDRESS,
    CONSENT_IDENTITY,
    DELIVERY_COMMIT,
    DEVICE_ADMISSION,
    DEVICE_CHALLENGE,
    DEVICE_REGISTRATION,
    DEVICE_SESSIONS,
    GENERATION,
    INGRESS_FRAME,
    INVOCATION_OWNER,
    NATIVE_FRAME,
    NATIVE_QUEUE,
    NATIVE_RECIPIENT,
    NATIVE_REPLY,
    NATIVE_TOPIC,
    ORDERED_DISPATCH,
    PAIR_DENIES,
    PAIR_RESULT,
    PRINCIPAL_SCOPE,
    PRINCIPAL_SYNTAX,
    PRIVATE_RESPONDER,
    RECEIPT,
    REGISTERED_BEARER,
    ROUTE_GATE,
    ROUTE_SCOPE,
    UID_TEXT,
    VIEW_OWNER,
    edit_function,
    replace_once,
)


def defects():
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
            "guest uplink admits registrations at capacity",
            Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
            lambda source: replace_once(source, "registry.len() >= limit {", "registry.len() > limit {"),
        ),
        (
            "guest uplink rejects a different endpoint",
            Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
            lambda source: replace_once(source, "if same(&registry[i],&descriptor)", "if !same(&registry[i],&descriptor)"),
        ),
        (
            "guest uplink matches the wrong descriptor",
            Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
            lambda source: replace_once(source, "if id == requested {", "if id != requested {"),
        ),
        (
            "guest uplink loses a selected enqueue receipt",
            Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
            lambda source: replace_once(source, "return Some(result);", "return None;"),
        ),
        (
            "guest uplink accepts an endpoint with only a matching name",
            Path("crates/astrid-capsule/src/engine/wasm/guest_uplink.rs"),
            lambda source: replace_once(source, "name == other_name && platform == other_platform", "name == other_name || platform == other_platform"),
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
            "shared state accepts a self-scoped grant",
            PRINCIPAL_SCOPE,
            lambda text: replace_once(text, "if shared || caller != target", "if caller != target"),
        ),
        (
            "another principal accepts a self-scoped grant",
            PRINCIPAL_SCOPE,
            lambda text: replace_once(text, "if shared || caller != target", "if shared"),
        ),
    ]
