"""MCP peer dispatch, registration ownership, and broker consent proof checks."""
from pathlib import Path

from .common import replace_once


def defects():
    invocation = Path("crates/astrid-cli/src/commands/mcp/server/invocation.rs")
    for label, original, changed in [
        ("requested tool", "call.parts() == (name,arguments)", "call.parts().1 == arguments"),
        ("normalized arguments", "call.parts() == (name,arguments)", "call.parts().0 == name"),
        ("consent input", "ensures pair == self.parts()", "ensures true"),
        ("encoded body", "ensures exists|b:B| encode.ensures((id,self.parts().0,self.parts().1),b)", "ensures exists|b:B| true"),
        ("published envelope", "&& #[trigger] send.ensures((TOOL_CALL_TOPIC,id,b),out)", "&& (exists|other:R| #[trigger] send.ensures((TOOL_CALL_TOPIC,id,b),other))"),
        ("operation topic", '"astrid.v1.request.mcp.tool.call"', '"astrid.v1.request.mcp.tools.list"'),
    ]:
        yield (
            f"broker tool invocation loses {label}", invocation,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_mrtr_context.rs"),
        )
    frames = Path("crates/astrid-uplink/src/frame_segments.rs")
    for label, original, changed in [
        ("payload", "body@ == bytes@.subrange(4, consumed as int)", "body.len() == consumed - 4"),
        ("boundary", "consumed == 4 + declared(bytes@)", "consumed >= 4 + declared(bytes@)"),
        ("offered bytes", "bytes@ == self.remaining().take(bytes.len() as int)", "true"),
        ("advanced bytes", "old(self).remaining().skip(count as int)", "final(self).remaining()"),
    ]:
        yield (
            f"broker frame round trip loses {label}", frames,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_mrtr_context.rs"),
        )
    redemption = Path("crates/astrid-cli/src/commands/mcp/mrtr_redemption.rs")
    for label, original, changed in [
        ("exact broker outcome", "ensures reply == outcome,", "ensures true,"),
        ("successful settlement", "final(self).settled() == (old(self).settled() || outcome.is_ok())", "final(self).settled() ==> (old(self).settled() || outcome.is_ok())"),
        ("failed settlement", "final(self).settled() == (old(self).settled() || outcome.is_ok())", "(old(self).settled() || outcome.is_ok()) ==> final(self).settled()"),
        ("settlement digest", "final(self).id() == old(self).id()", "true"),
        ("duplicate refusal", "claim.is_some() == !old(entries)@.contains_key(digest)", "!old(entries)@.contains_key(digest) ==> claim.is_some()"),
        ("digest identity", "c.id() == digest && !c.settled()", "!c.settled()"),
        ("rollback eligibility", "c.id() == digest && !c.settled()", "c.id() == digest"),
        ("committed decision", "ensures yes == self.settled()", "ensures true"),
        ("retained deadline", "final(entries)@ == old(entries)@.insert(digest,expiry)", "final(entries)@.contains_key(digest)"),
        ("cancellation rollback", "else { old(entries)@.remove(self.id()) }", "else { final(entries)@ }"),
    ]:
        yield (
            f"broker replay fence loses {label}", redemption,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_mrtr_context.rs"),
        )
    context = Path("crates/astrid-cli/src/commands/mcp/mrtr_context.rs")
    context_trace = Path("verification/hosted_mrtr_context.rs")
    for label, original, changed, failure in [
        ("principal bytes", "digest.absorb(principal);", "digest.absorb(tool);", context),
        ("tool bytes", "digest.absorb(tool);", "digest.absorb(arguments);", context),
        ("argument bytes", "digest.absorb(arguments);", "digest.absorb(principal);", context),
        ("transcript guarantee", "ensures final(digest).bytes() ==", "ensures principal.len() > 0 ==> final(digest).bytes() ==", context_trace),
        ("principal uniqueness", "ensures p == q, t == u, a == b,", "ensures t == u, a == b,", context_trace),
        ("tool uniqueness", "ensures p == q, t == u, a == b,", "ensures p == q, a == b,", context_trace),
        ("argument uniqueness", "ensures p == q, t == u, a == b,", "ensures p == q, t == u,", context_trace),
        ("opened consent", "open.ensures((state,context),Ok(pending)) && redeem", "true && redeem", context_trace),
        ("claimed continuation", "&& redeem.ensures((state,),Ok(guard))", "&& true", context_trace),
        ("opening refusal", "open.ensures((state,context),Err(error)) ||", "true ||", context_trace),
    ]:
        yield (
            f"broker continuation loses {label}", context,
            lambda s, a=original, b=changed: replace_once(s, a, b), failure,
        )
    tool_call = Path("crates/astrid-mcp/src/server/tool_call.rs")
    for label, field, replacement in [
        ("fixed hook", 'call.parts().0@ == "astrid_hook_intercept"@', "true"),
        ("hook payload", "encode.ensures((action,payload),call.parts().1)", "true"),
        ("requested tool", "bound.parts().1 == call.parts().0", "true"),
        ("request arguments", "bound.parts().2 == call.parts().1", "true"),
        ("registration", "servers@.contains_key(k) && k@ == requested@", "servers@.contains_key(k)"),
        ("peer", "peer.ensures((&servers@[k],),Some(bound.parts().0))", "true"),
        ("send", "ensures send.ensures(self.parts(),out)", "ensures true"),
    ]:
        yield (
            f"MCP tool binding loses {label}", tool_call,
            lambda s, a=field, b=replacement: replace_once(s, a, b),
            Path("verification/hosted_mcp_peer.rs"),
        )
    cleanup = Path("crates/astrid-capsule/src/engine/mcp_cleanup.rs")
    for label, field, replacement in [
        ("registration target", "final(self).name() == Some(target@)", "true"),
        ("worker identity", "task.name() == old(self).name()", "true"),
        ("draining target", "final(self).name() == task.name()", "true"),
        ("duplicate start", "work.is_some() == ((*old(self)) is Open)", "((*old(self)) is Open) ==> work.is_some()"),
        ("rejected registration", "!accepted ==> *final(self) == *old(self)", "!accepted ==> true"),
        ("foreign completion", "completed == ((*old(self)) is Draining", "completed <== ((*old(self)) is Draining"),
        ("completion state", "completed ==> (*final(self)) is Done", "completed ==> true"),
    ]:
        yield (
            f"MCP cleanup loses {label}", cleanup,
            lambda s, a=field, b=replacement: replace_once(s, a, b),
            Path("verification/hosted_mcp_peer.rs"),
        )
    registration = Path("crates/astrid-capsule/src/engine/mcp_registration.rs")
    for label, field, replacement in [
        ("capsule", "registration(capsule@,", "registration(Seq::empty(),"),
        ("server", "server@, match principal", "Seq::empty(), match principal"),
        ("scope", "match principal { Some(uid) => Some(uid@), None => None }, generation),", "None, generation),"),
        ("generation", "None => None }, generation),", "None => None }, 0),"),
    ]:
        yield (
            f"MCP registration substitutes the {label}", registration,
            lambda s, a=field, b=replacement: replace_once(s, a, b), registration,
        )
    yield (
        "MCP lookup loses the zero generation registration", registration,
        lambda s: replace_once(s, "ensures result@ == registration(", "ensures generation > 0 ==> result@ == registration("), registration,
    )
    yield (
        "MCP lookup loses the registry generation", registration,
        lambda s: replace_once(s, "ensures exists|c:&str, p:Option<String>|", "ensures runtime.identity().1 != 0 ==> exists|c:&str, p:Option<String>|"),
        Path("verification/hosted_mcp_peer.rs"),
    )
    yield (
        "MCP registration permits decimal suffix collisions", registration,
        lambda s: replace_once(s, "ensures n == m,", "ensures true,"),
        Path("verification/hosted_mcp_peer.rs"),
    )
    peer = Path("crates/astrid-mcp/src/server/peer_selection.rs")
    for name, original, changed in [
        ("loses the requested registration", "k@ == requested@ && peer.ensures((&servers@[k],),Some(handle))", "peer.ensures((&servers@[k],),Some(handle))"),
        ("can substitute the connected handle", "peer.ensures((&servers@[k],),Some(handle))", "true"),
        ("can misreport a disconnected server", "peer.ensures((&servers@[k],),None)", "true"),
        ("can misreport a missing server", "servers@.contains_key(k) ==> k@ != requested@", "servers@.contains_key(k) ==> true"),
    ]:
        yield (
            f"MCP peer selection {name}", peer,
            lambda s, a=original, b=changed: replace_once(s, a, b),
            Path("verification/hosted_mcp_peer.rs"),
        )

    policy = Path("crates/astrid-capsule/src/engine/mcp/network.rs")
    command = Path("crates/astrid-mcp/src/server/stdio_policy.rs")
    consumer = Path("verification/hosted_mcp_peer.rs")
    for name, source, original, changed, error in [
        ("ignores TCP peer restrictions", policy, "domains.is_empty() && peers.is_empty()", "domains.is_empty()", policy),
        ("may admit a trusted capsule", policy, "!settings.trusted && !settings.allow_network", "!settings.allow_network", consumer),
        ("may admit unrestricted networking", policy, "!settings.trusted && !settings.allow_network", "!settings.trusted", consumer),
        ("may reject an empty manifest", policy, "None => domains.len() > 0 || peers.len() > 0", "None => true", consumer),
        ("widens the sandbox network flag", command, "builder.sandboxed(program,config,allow_network)", "builder.sandboxed(program,config,true)", command),
        ("retries a sandbox error directly", command, "builder.sandboxed(program,config,allow_network)",
         "match builder.sandboxed(program,config,allow_network) { Ok(t) => Ok(t), Err(_) => Ok(builder.direct(program,config)) }", command),
    ]:
        yield (
            f"native stdio launch {name}", source,
            lambda s, a=original, b=changed: replace_once(s, a, b), error,
        )
