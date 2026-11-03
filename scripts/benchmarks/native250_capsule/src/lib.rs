#![forbid(unsafe_code)]
use astrid_sdk::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct CommandRequest {
    req_id: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
}
#[derive(Default)]
struct Driver;
#[capsule]
impl Driver {
    #[astrid::run]
    fn run(&self) -> Result<(), SysError> {
        let commands = ipc::subscribe("cli.v1.command.run.codewall-e2e-driver")?;
        let pulse = ipc::subscribe("codewall.v1.policy.activation.response")?;
        runtime::signal_ready()?;
        loop {
            let received = commands.recv(1000)?;
            for message in received.messages {
                let Ok(request) = serde_json::from_str::<CommandRequest>(&message.payload) else { continue };
                if !valid_request_id(&request.req_id) || request.command != "codewall-fixture" { continue; }
                let result = probe(&request.args, &pulse);
                let (exit_code, output, error) = match result {
                    Ok(value) => (0, value.to_string(), String::new()),
                    Err(error) => (1, String::new(), error.to_string()),
                };
                ipc::publish_json(&format!("cli.v1.command.result.{}", request.req_id), &json!({
                    "req_id": request.req_id, "exit_code": exit_code, "output": output, "error": error
                }))?;
            }
        }
    }
}
fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn encode(marker: &str, sequence: u64) -> Result<Vec<u8>, SysError> {
    Ok(serde_json::to_vec(&json!({
        "sequence": sequence, "last_sync_ms": sequence * 1000,
        "marker": marker, "stable_payload": "x".repeat(4096)
    }))?)
}
fn probe(args: &[String], pulse: &ipc::Subscription) -> Result<Value, SysError> {
    let bad = || SysError::ApiError("memory probe requires operation, writes, marker, expected sequence".into());
    if args.len() != 4 { return Err(bad()); }
    let operation = args[0].as_str();
    let writes: u64 = args[1].parse().map_err(|_| bad())?;
    let marker = &args[2];
    let sequence: u64 = args[3].parse().map_err(|_| bad())?;
    if writes > 10_000 || sequence >= 10_000 || marker.len() > 256 { return Err(bad()); }
    let key = "memory-probe/state";
    if operation == "memory-probe-empty" {
        if writes != 0 { return Err(bad()); }
        if kv::get_bytes_opt(key)?.is_some() {
            return Err(SysError::ApiError("retired alias retained capsule KV".into()));
        }
        return Ok(json!({"verified": true, "writes": 0, "marker": marker,
            "sequence": sequence, "live_value_bytes": 0, "empty": true}));
    }
    if operation != "memory-probe" || (writes != 0 && sequence != writes - 1) { return Err(bad()); }
    if writes != 0 {
        let mut prior = kv::get_bytes_opt(key)?;
        for current in 0..writes {
            let value = encode(marker, current)?;
            if !kv::cas(key, prior.as_deref(), &value)? {
                return Err(SysError::ApiError("unexpected contention".into()));
            }
            prior = Some(value);
            if current % 64 == 0 { let _ = pulse.recv(0)?; }
        }
    }
    let expected = encode(marker, sequence)?;
    let actual = kv::get_bytes_opt(key)?;
    if actual.as_deref() != Some(expected.as_slice()) {
        return Err(SysError::ApiError("external expected-content readback mismatch".into()));
    }
    Ok(json!({"verified": true, "writes": writes, "marker": marker,
        "sequence": sequence, "live_value_bytes": expected.len(), "empty": false}))
}
