"""Caller, target, and token publication guarantees used by persistent process operations."""
from pathlib import Path

from .common import replace_once


def defects():
    persistent = Path("crates/astrid-capsule/src/engine/wasm/host/process/persistent")
    process_trace = Path("verification/hosted_process_selection.rs")
    for file, name, clause, weakened in [
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
