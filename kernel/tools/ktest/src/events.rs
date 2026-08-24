//! Parse JSONL serial events and assert the M1 evidence contract.

use serde_json::Value;

pub fn parse_events(serial: &str) -> Vec<Value> {
    serial
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                return None;
            }
            serde_json::from_str::<Value>(trimmed)
                .ok()
                .filter(|v| v.get("ev").is_some())
        })
        .collect()
}

pub fn ev_name(v: &Value) -> &str {
    v.get("ev").and_then(Value::as_str).unwrap_or("")
}

/// Assert M1 boot/W^X/timer/self-test evidence. Returns true iff all pass.
pub fn assert_m1(events: &[Value], exit_code: Option<i32>, expect_exit: i32) -> bool {
    let mut ok = true;
    println!("\n== assertions ==");
    ok &= check(
        "boot.entry is first kernel event",
        events.first().map(ev_name) == Some("boot.entry"),
    );
    ok &= check(
        "boot.entry<mem.map<paging.wx<heap.ready<idt.ready",
        ordered(
            events,
            &[
                "boot.entry",
                "mem.map",
                "paging.wx",
                "heap.ready",
                "idt.ready",
            ],
        ),
    );
    ok &= check(
        "paging.wx rodata_nx_w=false && text_w=false",
        wx_holds(events),
    );
    let ticks = events
        .iter()
        .filter(|e| ev_name(e) == "apic.timer.tick")
        .count();
    ok &= check(&format!(">=8 apic.timer.tick (got {ticks})"), ticks >= 8);
    ok &= self_tests_hold(events);
    let halt_ok = events
        .iter()
        .find(|e| ev_name(e) == "halt")
        .and_then(|e| e.get("outcome").and_then(Value::as_str))
        == Some("ok");
    ok &= check("halt outcome=ok", halt_ok);
    ok &= check(
        &format!("QEMU exit code == {expect_exit}"),
        exit_code == Some(expect_exit),
    );
    ok
}

fn check(label: &str, pass: bool) -> bool {
    println!("  [{}] {label}", if pass { "PASS" } else { "FAIL" });
    pass
}

fn wx_holds(events: &[Value]) -> bool {
    events
        .iter()
        .find(|e| ev_name(e) == "paging.wx")
        .is_some_and(|e| {
            e.get("rodata_nx_w") == Some(&Value::Bool(false))
                && e.get("text_w") == Some(&Value::Bool(false))
        })
}

fn self_tests_hold(events: &[Value]) -> bool {
    let mut ok = true;
    for name in [
        "int3_handled",
        "wx_rodata_write",
        "nx_data_exec",
        "heap_exhaustion",
        "frame_unique",
        "frame_exhaustion",
    ] {
        let passed = events.iter().any(|e| {
            ev_name(e) == "test.pass" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        let failed = events.iter().any(|e| {
            ev_name(e) == "test.fail" && e.get("name").and_then(Value::as_str) == Some(name)
        });
        ok &= check(&format!("test.pass {name}"), passed && !failed);
    }
    ok
}

fn ordered(events: &[Value], names: &[&str]) -> bool {
    let mut last = -1i64;
    for name in names {
        match events.iter().position(|e| ev_name(e) == *name) {
            Some(idx) if (idx as i64) > last => last = idx as i64,
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing_serial() -> String {
        let mut out = String::from(
            r#"{"seq":0,"ev":"boot.entry"}
{"seq":1,"ev":"mem.map","usable_regions":1,"usable_bytes":1}
{"seq":2,"ev":"paging.wx","rodata_nx_w":false,"text_w":false}
{"seq":3,"ev":"heap.ready","bytes":1048576}
{"seq":4,"ev":"idt.ready","vectors":32}
"#,
        );
        for n in 1..=8 {
            out.push_str(&format!(
                "{{\"seq\":{},\"ev\":\"apic.timer.tick\",\"n\":{n}}}\n",
                4 + n
            ));
        }
        let mut seq = 13u64;
        for name in [
            "int3_handled",
            "wx_rodata_write",
            "nx_data_exec",
            "heap_exhaustion",
            "frame_unique",
            "frame_exhaustion",
        ] {
            out.push_str(&format!(
                "{{\"seq\":{seq},\"ev\":\"test.pass\",\"name\":\"{name}\"}}\n"
            ));
            seq += 1;
        }
        out.push_str(&format!(
            "{{\"seq\":{seq},\"ev\":\"halt\",\"outcome\":\"ok\"}}\n"
        ));
        out
    }

    #[test]
    fn parses_jsonl_and_skips_firmware_noise() {
        let serial = "Welcome to EDK2\n{\"seq\":0,\"ev\":\"boot.entry\"}\nnot json\n";
        let events = parse_events(serial);
        assert_eq!(events.len(), 1);
        assert_eq!(ev_name(&events[0]), "boot.entry");
    }

    #[test]
    fn m1_fixture_passes() {
        let events = parse_events(&passing_serial());
        assert!(assert_m1(&events, Some(33), 33));
    }

    #[test]
    fn wx_violation_fails() {
        let serial = r#"{"seq":0,"ev":"boot.entry"}
{"seq":1,"ev":"mem.map","usable_regions":1,"usable_bytes":1}
{"seq":2,"ev":"paging.wx","rodata_nx_w":true,"text_w":false}
{"seq":3,"ev":"heap.ready","bytes":1}
{"seq":4,"ev":"idt.ready","vectors":32}
{"seq":5,"ev":"halt","outcome":"ok"}"#;
        let events = parse_events(serial);
        assert!(!assert_m1(&events, Some(33), 33));
    }
}
