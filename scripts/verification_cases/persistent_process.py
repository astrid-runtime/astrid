"""Caller, target, and token publication guarantees used by persistent process operations."""
from pathlib import Path

from .common import edit_function, replace_once


def defects():
    persistent = Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent")
    process_trace = Path("verification/hosted_process_selection.rs")
    admission = persistent.parent / "spawn_admission.rs"
    for name, original, changed in [
        ("checks a different capsule", "gate.host(capsule, command)", "gate.host(command, command)"),
        ("omits persistence capability", "if !allows_persistence(names)", "if false"),
        ("ignores zero idle timeout", "if idle == Some(0)", "if false"),
        ("skips cancellation", "if gate.cancelled()", "if false"),
        ("audits another command", "gate.audit(command)", "gate.audit(capsule)"),
        ("prepares another command", "gate.prepare(&principal, command)", "gate.prepare(&principal, capsule)"),
    ]:
        yield (
            f"persistent spawn admission {name}", admission,
            lambda s, a=original, b=changed: replace_once(s, a, b), admission,
        )
    yield (
        "persistent spawn admission loses the returned projection", admission,
        lambda s: replace_once(s,
            "after == host.push(Check::Owner(Some(p))).push(Check::Cancelled(false)).push(Check::Audit(command@,None))\n                    .push(Check::Prepare(p,command@,Ok(m))),",
            "exists|other:M| after == host.push(Check::Owner(Some(p))).push(Check::Cancelled(false)).push(Check::Audit(command@,None)).push(Check::Prepare(p,command@,Ok(other))),"),
        process_trace,
    )
    for file, name, clause, weakened in [
        ("cleanup", "shutdown may leave a live slot", "final(entries)@ == Map::<K,T>::empty()", "true"),
        ("cleanup", "shutdown can detach the wrong map", "drained@ == old(entries)@", "true"),
        ("cleanup", "shutdown cleanup may omit a registered pair", "&& order.to_set() == drained@.kv_pairs()", "&& true"),
        ("cleanup", "shutdown may clean a pair twice", "order.no_duplicates() && order.to_set()", "order.to_set()"),
        ("cleanup", "shutdown loses cleanup arguments", "&& final(reaper).calls() == old(reaper).calls() + values(order)", "&& true"),
        ("retirement", "retirement may omit an owned key", "matches.ensures((&before[k],),keys.contains(k))", "true"),
        ("retirement", "retirement loses the cleanup target", "&& removed[i] == before[keys[i]]", "&& true"),
        ("retirement", "retirement can alter a foreign slot", "&& after == before.remove_keys(keys.to_set())", "&& true"),
        ("retirement", "retirement may duplicate cleanup", "keys.no_duplicates() && keys.len()", "keys.len()"),
        ("publication", "may skip an earlier free digest", "&& forall|j:u8| j < i ==> #[trigger] collided(before,mint,digest,j)", "&& true"),
        ("publication", "can displace an existing token", "&& !before.contains_key(key)", "&& true"),
        ("publication", "can publish an unrelated entry", "&& build.ensures((&token,pending),entry)", "&& true"),
        ("publication", "can exhaust retries with a fresh digest", "&& forall|i:u8| i < TOKEN_ATTEMPTS ==> #[trigger] collided", "&& forall|i:u8| i < 8 ==> #[trigger] collided"),
        ("publication", "can discard pending child on refusal", "Err(p) => p == pending &&", "Err(p) =>"),
        ("selection", "release returns the wrong child", "&& removed == e", "&& true"),
        ("selection", "release skips exit observation", "&& live.ensures((&e,),false)", "&& true"),
        ("selection", "release can change another slot", "&& final(entries)@ == before.remove(*key)", "&& true"),
        ("selection", "release loses owner admission", "&& owns.ensures((&e,),true) && live.ensures((&e,),false)", "&& live.ensures((&e,),false)"),
        ("selection", "loses owner equality", "ensures yes == (principal@", "ensures yes ==> (principal@"),
        ("selection", "loses token target", "&& *entry == entries@[*key]", "&& true"),
        ("selection", "admits a foreign process", "&& owns.ensures((entry,),true)", "&& true"),
        ("signal_target", "loses direct signal failure", "&& process.ensures(args,Err(e))", "&& true"),
        ("signal_target", "loses successful fallback", "&& process.ensures(args,Ok::<(),E>(unit))", "&& true"),
    ]:
        yield (
            f"persistent process {name}", persistent / f"{file}.rs",
            lambda s, a=clause, b=weakened: replace_once(s, a, b), process_trace,
        )

    yield (
        "persistent process batch cleanup may skip entries", persistent.parent / "process_batch.rs",
        lambda s: replace_once(s, "ensures final(reaper).calls() == old(reaper).calls() + entries@", "ensures true"),
        process_trace,
    )

    for name, clause, weakened in [
        ("allows zero registration", "ensures allowed == (pid != 0)", "ensures true"),
        ("loses registration ownership", "final(entries)@ == old(entries)@.insert(pid,record)", "true"),
        ("leaves a removed PID", "final(entries)@ == old(entries)@.remove(pid)", "true"),
        ("may repeat a target", "ensures pids@.no_duplicates()", "ensures true"),
        ("loses creator selection", "owns.ensures((&entries@[pid].0,),pids@.contains(pid))", "entries@.contains_key(pid)"),
        ("can introduce a foreign PID", "pids@.contains(pid) ==> entries@.contains_key(pid)", "pids@.contains(pid) ==> true"),
    ]:
        yield (
            f"ephemeral process retirement {name}", persistent.parent / "tracker_registry.rs",
            lambda s, a=clause, b=weakened: replace_once(s, a, b),
            Path("verification/hosted_ephemeral_process.rs"),
        )

    for name, clause in [
        ("preserves the published foreign child", "final(entries)@ == before.restrict(before.dom().filter(|k| before[k].creator@ != principal@))"),
        ("hands the published child to cleanup", "&& removed@[i] == before[keys[i]]"),
    ]:
        yield (
            f"persistent process publication then retirement no longer {name}", process_trace,
            lambda s, a=clause: edit_function(s, "retire_principal<T>", a, "true" if not a.startswith("&&") else "&& true"),
            process_trace,
        )
