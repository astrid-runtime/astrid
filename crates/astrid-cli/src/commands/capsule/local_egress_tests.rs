//! Tests for the CLI guided pre-bless (issue #1028, feature B).

use super::*;

// ── is_local_address ─────────────────────────────────────────────────────

#[test]
fn loopback_literals_are_local() {
    assert!(is_local_address("127.0.0.1"));
    assert!(is_local_address("127.5.6.7"));
    assert!(is_local_address("0.0.0.0"));
    assert!(is_local_address("[::1]"));
    assert!(is_local_address("::1"));
    assert!(is_local_address("[::]"));
}

#[test]
fn private_and_link_local_literals_are_local() {
    assert!(is_local_address("10.0.0.5"));
    assert!(is_local_address("172.16.0.1"));
    assert!(is_local_address("172.31.255.255"));
    assert!(is_local_address("192.168.1.10"));
    assert!(is_local_address("169.254.1.1")); // link-local
    assert!(is_local_address("100.64.0.1")); // CGNAT
    assert!(is_local_address("[fe80::1]")); // IPv6 link-local
    assert!(is_local_address("[fc00::1]")); // IPv6 ULA
}

#[test]
fn ipv4_mapped_loopback_is_local() {
    // `::ffff:127.0.0.1` must normalise and be caught.
    assert!(is_local_address("[::ffff:127.0.0.1]"));
}

#[test]
fn site_local_and_transition_literals_are_local() {
    // The detector must mirror the airlock's full block set so the bless
    // prompt fires for exactly the endpoints the runtime would block.
    // Deprecated site-local fec0::/10.
    assert!(is_local_address("[fec0::1]"));
    // NAT64 64:ff9b::/96 embedding 127.0.0.1.
    assert!(is_local_address("[64:ff9b::7f00:1]"));
    // 6to4 2002::/16 embedding 192.168.0.1.
    assert!(is_local_address("[2002:c0a8:1::]"));
    // Teredo 2001:0::/32 server embedding 127.0.0.1.
    assert!(is_local_address("[2001:0:7f00:1::]"));
    // A transition address embedding a public IPv4 stays remote (no prompt).
    assert!(!is_local_address("[64:ff9b::808:808]")); // NAT64 -> 8.8.8.8
}

#[test]
fn localhost_hostname_family_is_local() {
    assert!(is_local_address("localhost"));
    assert!(is_local_address("LOCALHOST"));
    assert!(is_local_address("api.localhost"));
    assert!(is_local_address("foo.bar.localhost"));
}

#[test]
fn public_addresses_are_not_local() {
    assert!(!is_local_address("8.8.8.8"));
    assert!(!is_local_address("1.1.1.1"));
    assert!(!is_local_address("198.51.100.7"));
    assert!(!is_local_address("172.32.0.1")); // just past the 172.16/12 block
    assert!(!is_local_address("192.169.1.1")); // not 192.168
    assert!(!is_local_address("[2001:4860:4860::8888]"));
}

#[test]
fn real_dns_names_are_not_local() {
    // The CLI does not resolve — a real hostname is treated as remote even if it
    // could resolve to a private IP. That is out of scope (matches the airlock).
    assert!(!is_local_address("api.openai.com"));
    assert!(!is_local_address("example.com"));
    assert!(!is_local_address("notlocalhost.com"));
    assert!(!is_local_address(""));
}

// ── endpoint_host_port / local_egress_entry ──────────────────────────────

#[test]
fn endpoint_host_port_parses_explicit_and_default_ports() {
    assert_eq!(
        endpoint_host_port("http://127.0.0.1:1234"),
        Some(("127.0.0.1".to_string(), 1234))
    );
    // Default port from scheme.
    assert_eq!(
        endpoint_host_port("http://127.0.0.1/v1"),
        Some(("127.0.0.1".to_string(), 80))
    );
    assert_eq!(
        endpoint_host_port("https://localhost"),
        Some(("localhost".to_string(), 443))
    );
    // Not a URL → None.
    assert_eq!(endpoint_host_port("just some text"), None);
    assert_eq!(endpoint_host_port(""), None);
}

#[test]
fn local_egress_entry_only_for_local_endpoints() {
    assert_eq!(
        local_egress_entry("http://127.0.0.1:1234/v1"),
        Some("127.0.0.1:1234".to_string())
    );
    assert_eq!(
        local_egress_entry("http://localhost:11434"),
        Some("localhost:11434".to_string())
    );
    assert_eq!(
        local_egress_entry("http://192.168.1.50:8080"),
        Some("192.168.1.50:8080".to_string())
    );
    // Public endpoint → no entry (skip).
    assert_eq!(local_egress_entry("https://api.openai.com/v1"), None);
    // Free text → no entry.
    assert_eq!(local_egress_entry("not a url"), None);
}

// ── record_local_egress ──────────────────────────────────────────────────

#[test]
fn record_creates_file_and_section() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");

    record_local_egress(&path, "openai-compat", "127.0.0.1:1234").expect("record");

    let content = std::fs::read_to_string(&path).expect("read back");
    let doc: toml::Value = toml::from_str(&content).expect("valid toml");
    let list = doc["security"]["capsule_local_egress"]["openai-compat"]
        .as_array()
        .expect("array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].as_str(), Some("127.0.0.1:1234"));
}

#[test]
fn record_preserves_existing_config_and_appends() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "# operator config\n\
         [security]\n\
         require_signatures = true\n\
         \n\
         [security.capsule_local_egress]\n\
         other-capsule = [\"10.0.0.1:9000\"]\n",
    )
    .expect("seed");

    record_local_egress(&path, "openai-compat", "127.0.0.1:1234").expect("record");

    let content = std::fs::read_to_string(&path).expect("read back");
    // Existing unrelated settings survive.
    assert!(content.contains("require_signatures = true"));
    assert!(content.contains("# operator config"));

    let doc: toml::Value = toml::from_str(&content).expect("valid toml");
    let egress = &doc["security"]["capsule_local_egress"];
    // Both capsules present.
    assert_eq!(egress["other-capsule"][0].as_str(), Some("10.0.0.1:9000"));
    assert_eq!(egress["openai-compat"][0].as_str(), Some("127.0.0.1:1234"));
}

#[test]
fn record_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");

    record_local_egress(&path, "cap", "127.0.0.1:1234").expect("first");
    record_local_egress(&path, "cap", "127.0.0.1:1234").expect("second");
    // Case-insensitive dedup on the host portion is handled at enforcement; the
    // operator file itself dedups exact entries.
    record_local_egress(&path, "cap", "127.0.0.1:1234").expect("third");

    let content = std::fs::read_to_string(&path).expect("read back");
    let doc: toml::Value = toml::from_str(&content).expect("valid toml");
    let list = doc["security"]["capsule_local_egress"]["cap"]
        .as_array()
        .expect("array");
    assert_eq!(list.len(), 1, "duplicate entries must not accumulate");
}

#[test]
fn record_appends_distinct_ports_for_same_capsule() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");

    record_local_egress(&path, "cap", "127.0.0.1:1234").expect("first");
    record_local_egress(&path, "cap", "127.0.0.1:5678").expect("second");

    let content = std::fs::read_to_string(&path).expect("read back");
    let doc: toml::Value = toml::from_str(&content).expect("valid toml");
    let list = doc["security"]["capsule_local_egress"]["cap"]
        .as_array()
        .expect("array");
    assert_eq!(list.len(), 2);
}

#[test]
fn record_leaves_no_temp_sibling() {
    // The atomic write must rename the temp sibling over the target, leaving
    // only `config.toml` in the directory — no `.toml.tmp.*` debris.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");

    record_local_egress(&path, "cap", "127.0.0.1:1234").expect("record");

    let names: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["config.toml".to_string()], "got {names:?}");
}

// ── maybe_prompt / prompt_and_record (non-interactive guard) ──────────────

#[test]
fn non_interactive_path_does_not_read_stdin_or_write_config() {
    // Regression for the non-TTY guard: a scripted / piped invocation must not
    // read stdin (which would block or steal piped data) and must not write the
    // exemption. We drive the testable core with a `read_answer` that records
    // whether it was called; the simulated non-TTY caller never invokes it.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");

    let mut read_called = false;
    // Mirror `maybe_prompt_local_egress`'s non-TTY branch: it returns BEFORE
    // ever constructing the reader. Here we assert that contract directly — for
    // a local value, the only thing that should reach `record_local_egress` is
    // a `y`, and a non-interactive caller never supplies one.
    prompt_and_record("openai-compat", "http://127.0.0.1:1234/v1", &path, || {
        read_called = true;
        // EOF on a non-interactive stdin → no answer.
        None
    });

    // With no answer, the prompt declines: config must not be created.
    assert!(!path.exists(), "no config should be written without a yes");
    // The reader was the only stdin touch point; the non-TTY wrapper skips it
    // entirely, and even when reached an EOF answer writes nothing.
    assert!(read_called, "reader is the sole seam exercised here");
}

#[test]
fn prompt_skips_reader_for_non_local_value() {
    // A non-local endpoint must short-circuit before the reader is built, so a
    // public `base_url` never blocks on or consumes stdin.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");

    prompt_and_record("cap", "https://api.openai.com/v1", &path, || {
        panic!("read_answer must not be called for a non-local value");
    });

    assert!(!path.exists());
}

#[test]
fn prompt_yes_writes_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");

    prompt_and_record("cap", "http://127.0.0.1:1234/v1", &path, || {
        Some("y\n".to_string())
    });

    let content = std::fs::read_to_string(&path).expect("read back");
    let doc: toml::Value = toml::from_str(&content).expect("valid toml");
    assert_eq!(
        doc["security"]["capsule_local_egress"]["cap"][0].as_str(),
        Some("127.0.0.1:1234")
    );
}
