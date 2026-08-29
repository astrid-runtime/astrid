use super::*;

const KERNEL_IMAGE_ID: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const CLOSURE_TABLE_ID: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn kernel_id() -> String {
    "aa".repeat(32)
}

fn sysgen_id() -> String {
    "bb".repeat(32)
}

fn expected() -> ExpectedClosures<'static> {
    ExpectedClosures {
        policy_generation: 1,
        kernel_image_hex: KERNEL_IMAGE_ID,
        closure_table_hex: CLOSURE_TABLE_ID,
        kernel_id_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        sysgen_id_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        kernel_floor: 1,
        sysgen_floor: 1,
    }
}

fn passing_serial() -> String {
    passing_serial_with(&kernel_id(), &sysgen_id(), 1, 1)
}

type Emit<'a> = &'a mut dyn FnMut(String);

fn emit_pass(serial: Emit<'_>, name: &str) {
    serial(format!("\"ev\":\"test.pass\",\"name\":\"{name}\""));
}

fn emit_prepare(serial: Emit<'_>, _id: u64, _generation: u64, _scenario: u64) {
    for event in [
        "\"ev\":\"domain.exclusion\",\"alias_excluded\":true,\"kernel_excluded\":true,\"peer_excluded\":true"
            .to_string(),
        "\"ev\":\"domain.audit\",\"frames\":16,\"wx_ok\":true,\"kernel_excluded\":true,\"peer_excluded\":true"
            .to_string(),
        "\"ev\":\"domain.policy\",\"audit_ok\":true,\"stack_zeroed\":true,\"probe_zeroed\":true"
            .to_string(),
        "\"ev\":\"domain.audit\",\"frames\":16,\"wx_ok\":true,\"kernel_excluded\":true,\"peer_excluded\":true"
            .to_string(),
    ] {
        serial(event);
    }
}

fn emit_start(serial: Emit<'_>, id: u64, generation: u64, scenario: u64) {
    serial(format!(
        "\"ev\":\"domain.start\",\"id\":{id},\"generation\":{generation},\"scenario\":{scenario}"
    ));
}

fn emit_context(serial: Emit<'_>, id: u64, generation: u64, _rdi: u64) {
    let root = if id == 1 { "0xfe01000" } else { "0xfe17000" };
    serial(format!(
        "\"ev\":\"domain.entered\",\"id\":{id},\"generation\":{generation},\"cpl\":3"
    ));
    serial(format!(
        "\"ev\":\"domain.context\",\"id\":{id},\"generation\":{generation},\
            \"root\":\"{root}\",\"flags\":0,\"cpl\":3,\"fs\":0,\"gs\":0"
    ));
}

#[allow(clippy::too_many_arguments)]
fn emit_terminal(
    serial: Emit<'_>,
    id: u64,
    generation: u64,
    rdi: u64,
    kind: &str,
    vector: u64,
    address: &str,
    quota: bool,
) {
    if quota {
        serial(format!("\"ev\":\"domain.quota\",\"id\":{id},\"ticks\":64"));
    }
    serial(format!(
        "\"ev\":\"domain.registers\",\"id\":{id},\"generation\":{generation},\"cpl\":3,\
            \"rax\":0,\"rbx\":0,\"rcx\":0,\"rdx\":0,\"rsi\":0,\"rdi\":{rdi},\"rbp\":0,\
            \"r8\":0,\"r9\":0,\"r10\":0,\"r11\":0,\"r12\":0,\"r13\":0,\"r14\":0,\"r15\":0,\
            \"rsp\":\"0x1000\""
    ));
    let error_code = if vector == 14 { 6 } else { 0 };
    serial(format!(
        "\"ev\":\"domain.outcome\",\"id\":{id},\"generation\":{generation},\"kind\":\"{kind}\",\
            \"vector\":{vector},\"error_code\":{error_code},\
            \"fault_address\":\"{address}\",\"rip\":\"0x10\",\"cpl\":3"
    ));
    serial(format!(
        "\"ev\":\"domain.restore\",\"id\":{id},\"generation\":{generation},\
            \"ok\":true,\"root\":\"0x101000\",\"flags\":0"
    ));
    serial(format!(
        "\"ev\":\"domain.reclaim\",\"id\":{id},\"generation\":{generation},\"expected\":16,\"freed\":16,\"swept\":16,\"blocked\":0"
    ));
}

fn emit_cancel(serial: Emit<'_>, id: u64, generation: u64) {
    serial(format!(
        "\"ev\":\"domain.cancel.request\",\"id\":{id},\"generation\":{generation}"
    ));
    serial(format!(
        "\"ev\":\"domain.restore\",\"id\":{id},\"generation\":{generation},\
            \"ok\":true,\"root\":\"0x101000\",\"flags\":0"
    ));
    serial(format!(
        "\"ev\":\"domain.reclaim\",\"id\":{id},\"generation\":{generation},\"expected\":16,\"freed\":16,\"swept\":16,\"blocked\":0"
    ));
    serial(format!(
        "\"ev\":\"domain.cancelled\",\"id\":{id},\"generation\":{generation}"
    ));
    serial(format!(
        "\"ev\":\"domain.outcome\",\"id\":{id},\"generation\":{generation},\"kind\":\"cancelled\",\
            \"vector\":0,\"error_code\":0,\"fault_address\":\"0x0\",\"rip\":\"0x0\",\"cpl\":0"
    ));
}

fn emit_ipc_op(serial: Emit<'_>, id: u64, generation: u64, op: &str, status: &str) {
    serial(format!(
        "\"ev\":\"ipc.op\",\"id\":{id},\"generation\":{generation},\"op\":\"{op}\",\"status\":\"{status}\""
    ));
}

fn emit_ipc_park(serial: Emit<'_>, id: u64, generation: u64) {
    emit_ipc_op(serial, id, generation, "endpoint_create", "ok");
    serial(format!(
        "\"ev\":\"ipc.park\",\"id\":{id},\"generation\":{generation}"
    ));
}

fn emit_ipc_reclaim(
    serial: Emit<'_>,
    id: u64,
    generation: u64,
    capabilities: u64,
    endpoints: u64,
) {
    serial(format!(
        "\"ev\":\"ipc.reclaim\",\"id\":{id},\"generation\":{generation},\
            \"endpoints\":{endpoints},\"capabilities\":{capabilities},\"queued\":0"
    ));
}

#[allow(clippy::too_many_arguments)]
fn emit_ipc_terminal(
    serial: Emit<'_>,
    id: u64,
    generation: u64,
    rdi: u64,
    kind: &str,
    vector: u64,
    address: &str,
    rax: u64,
    endpoints: u64,
    capabilities: u64,
) {
    serial(format!(
        "\"ev\":\"domain.registers\",\"id\":{id},\"generation\":{generation},\"cpl\":3,\
            \"rax\":{rax},\"rbx\":0,\"rcx\":0,\"rdx\":0,\"rsi\":0,\"rdi\":{rdi},\"rbp\":0,\
            \"r8\":0,\"r9\":0,\"r10\":0,\"r11\":0,\"r12\":0,\"r13\":0,\"r14\":0,\"r15\":0,\
            \"rsp\":\"0x1000\""
    ));
    let error_code = if vector == 14 { 6 } else { 0 };
    serial(format!(
        "\"ev\":\"domain.outcome\",\"id\":{id},\"generation\":{generation},\"kind\":\"{kind}\",\
            \"vector\":{vector},\"error_code\":{error_code},\
            \"fault_address\":\"{address}\",\"rip\":\"0x10\",\"cpl\":3"
    ));
    emit_ipc_reclaim(serial, id, generation, capabilities, endpoints);
    serial(format!(
        "\"ev\":\"domain.restore\",\"id\":{id},\"generation\":{generation},\
            \"ok\":true,\"root\":\"0x101000\",\"flags\":0"
    ));
    serial(format!(
        "\"ev\":\"domain.reclaim\",\"id\":{id},\"generation\":{generation},\"expected\":16,\"freed\":16,\"swept\":16,\"blocked\":0"
    ));
}

fn emit_ipc_server_resume(serial: Emit<'_>, id: u64, generation: u64) {
    serial(format!(
        "\"ev\":\"ipc.wake\",\"id\":{id},\"generation\":{generation},\"status\":\"received\""
    ));
    serial(format!(
        "\"ev\":\"ipc.resume\",\"id\":{id},\"generation\":{generation}"
    ));
    emit_ipc_op(serial, id, generation, "send", "ok");
    serial(format!(
        "\"ev\":\"ipc.park\",\"id\":{id},\"generation\":{generation}"
    ));
}

fn emit_ipc_client_resume(serial: Emit<'_>, id: u64, generation: u64) {
    serial(format!(
        "\"ev\":\"ipc.wake\",\"id\":{id},\"generation\":{generation},\"status\":\"sent\""
    ));
    serial(format!(
        "\"ev\":\"ipc.resume\",\"id\":{id},\"generation\":{generation}"
    ));
    emit_ipc_terminal(serial, id, generation, 0, "clean_exit", 3, "0x0", 0, 0, 1);
}

fn emit_ipc_server_peer_release(serial: Emit<'_>, id: u64, generation: u64) {
    serial(format!(
        "\"ev\":\"ipc.reclaim\",\"id\":{id},\"generation\":{generation},\
            \"capabilities\":1,\"endpoints\":1,\"queued\":0"
    ));
    serial(format!(
        "\"ev\":\"domain.restore\",\"id\":{id},\"generation\":{generation},\
            \"ok\":true,\"root\":\"0x101000\",\"flags\":0"
    ));
    serial(format!(
        "\"ev\":\"domain.reclaim\",\"id\":{id},\"generation\":{generation},\
            \"expected\":16,\"freed\":16,\"swept\":16,\"blocked\":0"
    ));
}

fn emit_ipc_cancel_guest(serial: Emit<'_>, id: u64, generation: u64) {
    emit_ipc_op(serial, id, generation, "endpoint_create", "ok");
    emit_ipc_op(serial, id, generation, "cancel", "ok");
    emit_ipc_terminal(serial, id, generation, 0, "clean_exit", 3, "0x0", 7, 1, 1);
}

fn passing_serial_with(kernel: &str, sysgen: &str, kfloor: u64, sfloor: u64) -> String {
    let mut seq = 0u64;
    let mut out = String::new();
    let mut ev = |payload: String| {
        out.push_str(&format!("{{\"seq\":{seq},{payload}}}\n"));
        seq += 1;
    };
    for event in [
        "\"ev\":\"boot.entry\"",
        "\"ev\":\"idt.ready\",\"vectors\":32",
        "\"ev\":\"component.bound\",\"empty\":false",
    ] {
        ev(event.to_owned());
    }
    ev(format!(
        "\"ev\":\"handoff.bound\",\"policy_generation\":1,\"kernel_image\":\"{}\",\"closure_table\":\"{}\"",
        "cc".repeat(32),
        "dd".repeat(32),
    ));
    ev(format!(
        "\"ev\":\"closure.kernel\",\"kind\":\"kernel-bootstrap\",\"floor\":{kfloor},\"id\":\"{kernel}\""
    ));
    ev(format!(
        "\"ev\":\"closure.sysgen\",\"kind\":\"system-generation\",\"floor\":{sfloor},\"id\":\"{sysgen}\",\"empty\":false"
    ));
    ev(format!(
        "\"ev\":\"closure.bound\",\"kernel_floor\":{kfloor},\"sysgen_floor\":{sfloor},\"kernel_id\":\"{kernel}\",\"sysgen_id\":\"{sysgen}\""
    ));
    for event in [
        "\"ev\":\"mem.map\",\"usable_regions\":1,\"usable_bytes\":1",
        "\"ev\":\"paging.wx\",\"rodata_nx_w\":false,\"text_w\":false",
        "\"ev\":\"heap.ready\",\"bytes\":1048576",
        "\"ev\":\"apic.timer.start\"",
    ] {
        ev(event.to_owned());
    }
    for n in 1..=8 {
        ev(format!("\"ev\":\"apic.timer.tick\",\"n\":{n}"));
    }
    ev("\"ev\":\"entropy.seeded\"".into());
    ev("\"ev\":\"fault\",\"vector\":3,\"code\":0,\"rip\":\"0x10\"".into());
    emit_pass(&mut ev, REQUIRED_PASSES[0]);
    ev("\"ev\":\"fault\",\"vector\":14,\"code\":3,\"rip\":\"0x10\"".into());
    emit_pass(&mut ev, REQUIRED_PASSES[1]);
    ev("\"ev\":\"fault\",\"vector\":14,\"code\":17,\"rip\":\"0x10\"".into());
    emit_pass(&mut ev, REQUIRED_PASSES[2]);
    emit_pass(&mut ev, REQUIRED_PASSES[3]);
    emit_pass(&mut ev, REQUIRED_PASSES[4]);
    emit_pass(&mut ev, REQUIRED_PASSES[5]);
    ev("\"ev\":\"kernel.cr3\",\"root\":\"0x101000\",\"flags\":0".into());
    emit_pass(&mut ev, super::OVERFLOW_GATE);
    ev("\"ev\":\"domain.auth.reject\",\"reason\":\"tampered_component_rejected\"".into());
    emit_pass(&mut ev, DOMAIN_REQUIRED_PASSES[0]);

    emit_prepare(&mut ev, 1, 1, 0);
    emit_start(&mut ev, 1, 1, 0);
    emit_context(&mut ev, 1, 1, 0);
    emit_terminal(&mut ev, 1, 1, 0, "clean_exit", 3, "0x0", false);
    emit_pass(&mut ev, DOMAIN_REQUIRED_PASSES[1]);
    emit_pass(&mut ev, super::ENTRY_STATE_GATE);

    emit_prepare(&mut ev, 1, 2, 5);
    emit_start(&mut ev, 1, 2, 5);
    emit_context(&mut ev, 1, 2, 5);
    emit_terminal(&mut ev, 1, 2, 5, "invalid_instruction", 6, "0x0", false);
    emit_pass(&mut ev, DOMAIN_REQUIRED_PASSES[2]);
    emit_pass(&mut ev, super::RESTORE_GATE);
    emit_prepare(&mut ev, 1, 3, 1);
    emit_pass(&mut ev, super::ACTIVE_GUARD_GATE);
    ev(
        "\"ev\":\"domain.cancel.reject\",\"reason\":\"stale_handle\",\"id\":1,\"generation\":1"
            .into(),
    );
    emit_pass(&mut ev, super::STALE_GATE);

    emit_prepare(&mut ev, 2, 1, 4);
    emit_start(&mut ev, 1, 3, 1);
    emit_context(&mut ev, 1, 3, 1);
    emit_terminal(&mut ev, 1, 3, 1, "page_fault", 14, "0x0", false);
    emit_cancel(&mut ev, 2, 1);
    emit_prepare(&mut ev, 1, 4, 2);
    emit_prepare(&mut ev, 2, 2, 0);
    emit_start(&mut ev, 1, 4, 2);
    emit_context(&mut ev, 1, 4, 2);
    emit_terminal(&mut ev, 1, 4, 2, "quota_exhausted", 32, "0x0", true);
    emit_pass(&mut ev, super::QUOTA_GATE);
    emit_start(&mut ev, 2, 2, 0);
    emit_context(&mut ev, 2, 2, 0);
    emit_terminal(&mut ev, 2, 2, 0, "clean_exit", 3, "0x0", false);

    emit_prepare(&mut ev, 1, 5, 3);
    emit_start(&mut ev, 1, 5, 3);
    emit_context(&mut ev, 1, 5, 3);
    emit_terminal(
        &mut ev,
        1,
        5,
        3,
        "page_fault",
        14,
        HOSTILE_PEER_FAULT_ADDRESS,
        false,
    );
    emit_pass(&mut ev, super::PAGING_GATE);
    emit_pass(&mut ev, super::FAULT_GATE);
    emit_pass(&mut ev, super::RECLAIM_GATE);

    emit_prepare(&mut ev, 1, 6, 0);
    emit_start(&mut ev, 1, 6, 0);
    emit_context(&mut ev, 1, 6, 0);
    emit_terminal(&mut ev, 1, 6, 0, "clean_exit", 3, "0x0", false);

    emit_prepare(&mut ev, 1, 7, 6);
    emit_start(&mut ev, 1, 7, 6);
    emit_context(&mut ev, 1, 7, 0);
    emit_ipc_park(&mut ev, 1, 7);
    emit_prepare(&mut ev, 2, 3, 7);
    emit_start(&mut ev, 2, 3, 7);
    emit_context(&mut ev, 2, 3, 0);
    for (op, status) in [
        ("send", "malformed"),
        ("send", "malformed"),
        ("send", "malformed"),
        ("endpoint_create", "ok"),
        ("cap_revoke", "ok"),
        ("send", "malformed"),
        ("send", "malformed"),
        ("send", "malformed"),
    ] {
        emit_ipc_op(&mut ev, 2, 3, op, status);
    }
    ev("\"ev\":\"ipc.park\",\"id\":2,\"generation\":3".into());
    emit_ipc_server_resume(&mut ev, 1, 7);
    emit_ipc_client_resume(&mut ev, 2, 3);
    emit_ipc_server_peer_release(&mut ev, 1, 7);
    emit_pass(&mut ev, super::DOMAIN_REQUIRED_PASSES[8]);

    emit_prepare(&mut ev, 1, 8, 6);
    emit_start(&mut ev, 1, 8, 6);
    emit_context(&mut ev, 1, 8, 0);
    emit_ipc_park(&mut ev, 1, 8);
    emit_prepare(&mut ev, 2, 4, 8);
    emit_start(&mut ev, 2, 4, 8);
    emit_context(&mut ev, 2, 4, 0);
    emit_ipc_terminal(
        &mut ev,
        2,
        4,
        0,
        "page_fault",
        14,
        super::HOSTILE_IPC_FAULT_ADDRESS,
        0,
        0,
        1,
    );
    emit_ipc_server_peer_release(&mut ev, 1, 8);
    emit_pass(&mut ev, super::DOMAIN_REQUIRED_PASSES[9]);

    emit_prepare(&mut ev, 1, 9, 10);
    emit_start(&mut ev, 1, 9, 10);
    emit_context(&mut ev, 1, 9, 0);
    emit_ipc_cancel_guest(&mut ev, 1, 9);
    emit_pass(&mut ev, super::DOMAIN_REQUIRED_PASSES[10]);
    emit_pass(&mut ev, super::CLEAN_RESTART_GATE);
    ev("\"ev\":\"domain.harness\",\"outcome\":true".into());
    ev("\"ev\":\"halt\",\"outcome\":\"ok\"".into());
    out
}

fn assert_ok(serial: &str) -> bool {
    assert_boot(&parse_events(serial), Some(33), 33, &expected())
}

#[test]
fn parses_jsonl_and_skips_firmware_noise() {
    let serial = "Welcome to EDK2\n{\"seq\":0,\"ev\":\"boot.entry\"}\nnot json\n";
    let events = parse_events(serial);
    assert_eq!(events.len(), 1);
    assert_eq!(ev_name(&events[0]), "boot.entry");
}

#[test]
fn combined_fixture_passes() {
    assert!(assert_ok(&passing_serial()));
}

#[test]
fn mixed_floors_on_bound_are_independent() {
    let kernel = kernel_id();
    let sysgen = sysgen_id();
    let serial = passing_serial_with(&kernel, &sysgen, 1, 2);
    let closures = ExpectedClosures {
        policy_generation: 1,
        kernel_image_hex: KERNEL_IMAGE_ID,
        closure_table_hex: CLOSURE_TABLE_ID,
        kernel_id_hex: &kernel,
        sysgen_id_hex: &sysgen,
        kernel_floor: 1,
        sysgen_floor: 2,
    };
    assert!(assert_boot(&parse_events(&serial), Some(33), 33, &closures));
}

#[test]
fn collapsed_bound_floor_fails() {
    let serial = passing_serial().replace("\"kernel_floor\":1,\"sysgen_floor\":1", "\"floor\":1");
    assert!(!assert_ok(&serial));
}

#[test]
fn wx_violation_fails() {
    let serial = passing_serial().replace("\"rodata_nx_w\":false", "\"rodata_nx_w\":true");
    assert!(!assert_ok(&serial));
}

#[test]
fn sequence_gap_reorder_or_duplicate_fails() {
    let gap = passing_serial().replacen("\"seq\":5,", "\"seq\":50,", 1);
    let duplicate = passing_serial().replacen("\"seq\":5,", "\"seq\":4,", 1);
    let reorder = passing_serial().replacen("\"seq\":5,", "\"seq\":7,", 1);
    let reorder = reorder.replacen("\"seq\":6,", "\"seq\":5,", 1);
    assert!(!assert_ok(&gap), "gap must fail");
    assert!(!assert_ok(&duplicate), "duplicate seq must fail");
    assert!(!assert_ok(&reorder), "reordered seq must fail");
}

#[test]
fn post_halt_event_fails() {
    let mut serial = passing_serial();
    serial.push_str(r#"{"seq":99,"ev":"apic.timer.tick","n":9}"#);
    serial.push('\n');
    assert!(!assert_ok(&serial));
}

#[test]
fn test_fail_future_gate_fails() {
    let serial = passing_serial().replace(
            "\"ev\":\"halt\",\"outcome\":\"ok\"",
            "\"ev\":\"test.fail\",\"name\":\"future_gate\"}\n{\"seq\":99,\"ev\":\"halt\",\"outcome\":\"ok\"",
        );
    assert!(serial.contains("future_gate"));
    assert!(!assert_ok(&serial));
}

#[test]
fn missing_or_duplicate_domain_gate_fails() {
    let missing = passing_serial().replacen(
        "\"ev\":\"test.pass\",\"name\":\"fault_is_domain_scoped\"}\n",
        "",
        1,
    );
    assert!(!assert_ok(&missing), "missing domain gate must fail");

    let duplicate = passing_serial().replace(
            "\"ev\":\"halt\",\"outcome\":\"ok\"",
            "\"ev\":\"test.pass\",\"name\":\"fault_is_domain_scoped\"}\n{\"seq\":99,\"ev\":\"halt\",\"outcome\":\"ok\"",
        );
    assert!(!assert_ok(&duplicate), "duplicate domain gate must fail");
}

#[test]
fn duplicate_or_missing_required_event_fails() {
    let duplicate_boot =
        passing_serial().replacen("\"ev\":\"mem.map\"", "\"ev\":\"boot.entry\"", 1);
    let missing_map =
        passing_serial().replacen("\"ev\":\"mem.map\"", "\"ev\":\"apic.timer.start\"", 1);
    assert!(!assert_ok(&duplicate_boot));
    assert!(!assert_ok(&missing_map));
}

#[test]
fn reordered_closure_and_m1_events_fail() {
    let serial = passing_serial().replace("handoff.bound", "tmp.handoff");
    let serial = serial.replace("closure.kernel", "handoff.bound");
    let serial = serial.replace("tmp.handoff", "closure.kernel");
    assert!(
        !assert_ok(&serial),
        "handoff.bound after closure.kernel must fail"
    );
    let serial = passing_serial().replace("closure.bound", "tmp.bound");
    let serial = serial.replace("mem.map", "closure.bound");
    let serial = serial.replace("tmp.bound", "mem.map");
    assert!(!assert_ok(&serial), "closure.bound after mem.map must fail");
    let serial = passing_serial().replace("closure.kernel", "tmp.kernel");
    let serial = serial.replace("paging.wx", "closure.kernel");
    let serial = serial.replace("tmp.kernel", "paging.wx");
    assert!(
        !assert_ok(&serial),
        "closure.kernel after paging.wx must fail"
    );
}

#[test]
fn dual_closure_reject_or_mismatch_fails() {
    let events = parse_events(&passing_serial());
    let swapped = ExpectedClosures {
        policy_generation: 1,
        kernel_image_hex: expected().kernel_image_hex,
        closure_table_hex: expected().closure_table_hex,
        kernel_id_hex: expected().sysgen_id_hex,
        sysgen_id_hex: expected().kernel_id_hex,
        kernel_floor: 1,
        sysgen_floor: 1,
    };
    assert!(!assert_boot(&events, Some(33), 33, &swapped));
    let rejected = passing_serial().replace("closure.bound", "closure.reject");
    assert!(!assert_ok(&rejected));
}

#[test]
fn rejected_sysgen_emits_no_success_bound_events() {
    let serial = concat!(
        "{\"seq\":0,\"ev\":\"boot.entry\"}\n",
        "{\"seq\":1,\"ev\":\"idt.ready\",\"vectors\":32}\n",
        "{\"seq\":2,\"ev\":\"closure.reject\",\"reason\":\"binding\"}\n",
        "{\"seq\":3,\"ev\":\"halt\",\"outcome\":\"fail\"}\n",
    );
    let events = parse_events(serial);
    assert!(rejected_without_success_bound_events(&events));

    let contaminated = format!("{serial}{{\"seq\":4,\"ev\":\"handoff.bound\"}}\n");
    assert!(!rejected_without_success_bound_events(&parse_events(
        &contaminated
    )));

    let contaminated = format!("{serial}{{\"seq\":4,\"ev\":\"component.bound\"}}\n");
    assert!(!rejected_without_success_bound_events(&parse_events(
        &contaminated
    )));
}

#[test]
fn ring0_plan_mismatch_trace_requires_kernel_rejection_shape() {
    let serial = concat!(
        "{\"seq\":0,\"ev\":\"boot.entry\"}\n",
        "{\"seq\":1,\"ev\":\"idt.ready\",\"vectors\":32}\n",
        "{\"seq\":2,\"ev\":\"closure.reject\",\"reason\":\"plan_mismatch\"}\n",
        "{\"seq\":3,\"ev\":\"halt\",\"outcome\":\"fault\"}\n",
    );
    assert!(assert_ring0_plan_mismatch(&parse_events(serial), Some(35)));

    let loader_reject = serial.replace("plan_mismatch", "binding");
    assert!(!assert_ring0_plan_mismatch(
        &parse_events(&loader_reject),
        Some(35)
    ));
    let contaminated = format!("{}{{\"seq\":4,\"ev\":\"handoff.bound\"}}\n", serial);
    assert!(!assert_ring0_plan_mismatch(
        &parse_events(&contaminated),
        Some(35)
    ));
    let success_exit = serial.replace("\"outcome\":\"fault\"", "\"outcome\":\"ok\"");
    assert!(!assert_ring0_plan_mismatch(
        &parse_events(&success_exit),
        Some(33)
    ));
}

#[test]
fn dual_closure_missing_bound_fails() {
    let serial = passing_serial().replace("\"ev\":\"closure.bound\"", "\"ev\":\"closure.kernel\"");
    assert!(!assert_ok(&serial));
}

#[test]
fn mutated_context_identity_flags_or_root_fails() {
    let wrong_identity = passing_serial().replacen(
        "\"ev\":\"domain.context\",\"id\":1,\"generation\":1",
        "\"ev\":\"domain.context\",\"id\":9,\"generation\":1",
        1,
    );
    assert!(wrong_identity.contains("\"id\":9,\"generation\":1"));
    assert!(!assert_ok(&wrong_identity));

    let wrong_flags = passing_serial().replacen(
        "\"ev\":\"domain.context\",\"id\":1,\"generation\":1,\"root\":\"0xfe01000\",\"flags\":0",
        "\"ev\":\"domain.context\",\"id\":1,\"generation\":1,\"root\":\"0xfe01000\",\"flags\":1",
        1,
    );
    assert!(wrong_flags.contains("\"flags\":1"));
    assert!(!assert_ok(&wrong_flags));

    let kernel_root = passing_serial().replacen(
        "\"ev\":\"domain.context\",\"id\":1,\"generation\":1,\"root\":\"0xfe01000\"",
        "\"ev\":\"domain.context\",\"id\":1,\"generation\":1,\"root\":\"0x101000\"",
        1,
    );
    assert!(kernel_root.contains("\"root\":\"0x101000\""));
    assert!(!assert_ok(&kernel_root));
}

#[test]
fn mutated_restore_identity_root_or_flags_fails() {
    let wrong_identity = passing_serial().replacen(
        "\"ev\":\"domain.restore\",\"id\":1,\"generation\":1",
        "\"ev\":\"domain.restore\",\"id\":9,\"generation\":1",
        1,
    );
    assert!(wrong_identity.contains("\"id\":9,\"generation\":1"));
    assert!(!assert_ok(&wrong_identity));

    let wrong_root = passing_serial().replacen(
        "\"ev\":\"domain.restore\",\"id\":1,\"generation\":1,\"ok\":true,\"root\":\"0x101000\"",
        "\"ev\":\"domain.restore\",\"id\":1,\"generation\":1,\"ok\":true,\"root\":\"0xfe01000\"",
        1,
    );
    assert!(wrong_root.contains("\"root\":\"0xfe01000\""));
    assert!(!assert_ok(&wrong_root));

    let wrong_flags = passing_serial().replacen(
        "\"ev\":\"domain.restore\",\"id\":1,\"generation\":1,\"ok\":true,\
         \"root\":\"0x101000\",\"flags\":0",
        "\"ev\":\"domain.restore\",\"id\":1,\"generation\":1,\"ok\":true,\
         \"root\":\"0x101000\",\"flags\":1",
        1,
    );
    assert!(wrong_flags.contains("\"flags\":1"));
    assert!(!assert_ok(&wrong_flags));
}

#[test]
fn mutated_cancel_identities_fail() {
    let wrong_request = passing_serial().replacen(
        "\"ev\":\"domain.cancel.request\",\"id\":2,\"generation\":1",
        "\"ev\":\"domain.cancel.request\",\"id\":2,\"generation\":2",
        1,
    );
    assert!(wrong_request.contains("\"ev\":\"domain.cancel.request\",\"id\":2,\"generation\":2"));
    assert!(!assert_ok(&wrong_request));

    let wrong_cancelled = passing_serial().replacen(
        "\"ev\":\"domain.cancelled\",\"id\":2,\"generation\":1",
        "\"ev\":\"domain.cancelled\",\"id\":1,\"generation\":1",
        1,
    );
    assert!(wrong_cancelled.contains("\"ev\":\"domain.cancelled\",\"id\":1,\"generation\":1"));
    assert!(!assert_ok(&wrong_cancelled));
}
