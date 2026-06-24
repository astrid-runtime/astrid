//! Tests for the shared SSRF / local-address block-set predicate.

use super::ip_is_blocked;

use std::net::IpAddr;
use std::str::FromStr;

fn ip(s: &str) -> IpAddr {
    IpAddr::from_str(s).expect("valid IP literal")
}

#[test]
fn blocks_ipv4_loopback_and_unspecified() {
    assert!(ip_is_blocked(ip("127.0.0.1")));
    assert!(ip_is_blocked(ip("127.5.6.7")));
    assert!(ip_is_blocked(ip("0.0.0.0")));
}

#[test]
fn blocks_ipv4_private_link_local_cgnat() {
    assert!(ip_is_blocked(ip("10.0.0.5")));
    assert!(ip_is_blocked(ip("172.16.0.1")));
    assert!(ip_is_blocked(ip("172.31.255.255")));
    assert!(ip_is_blocked(ip("192.168.1.10")));
    assert!(ip_is_blocked(ip("169.254.1.1")));
    assert!(ip_is_blocked(ip("100.64.0.1")));
}

#[test]
fn blocks_ipv6_loopback_ula_link_local() {
    assert!(ip_is_blocked(ip("::1")));
    assert!(ip_is_blocked(ip("::")));
    assert!(ip_is_blocked(ip("fc00::1")));
    assert!(ip_is_blocked(ip("fd00::1")));
    assert!(ip_is_blocked(ip("fe80::1")));
}

#[test]
fn blocks_ipv6_deprecated_site_local() {
    // fec0::/10 — deprecated site-local. The airlock blocks it; the CLI
    // pre-bless must therefore detect it too.
    assert!(ip_is_blocked(ip("fec0::1")));
    assert!(ip_is_blocked(ip("feff::1")));
}

#[test]
fn blocks_ipv4_mapped_and_compatible() {
    assert!(ip_is_blocked(ip("::ffff:127.0.0.1")));
    assert!(ip_is_blocked(ip("::ffff:10.0.0.1")));
    assert!(ip_is_blocked(ip("::127.0.0.1")));
    assert!(ip_is_blocked(ip("::169.254.169.254")));
}

#[test]
fn blocks_transition_embedded_private_ipv4() {
    // NAT64 64:ff9b::/96 embedding 127.0.0.1.
    assert!(ip_is_blocked(ip("64:ff9b::7f00:1")));
    // 6to4 2002::/16 embedding 192.168.0.1.
    assert!(ip_is_blocked(ip("2002:c0a8:1::")));
    // Teredo 2001:0::/32 server embedding 127.0.0.1.
    assert!(ip_is_blocked(ip("2001:0:7f00:1::")));
    // Teredo 2001:0::/32 CLIENT arm: the obfuscated client IPv4 lives in the
    // last 32 bits, bit-inverted. Server here is the PUBLIC 8.8.8.8, so only the
    // client extraction can trip the block — !f5ff_fffe == 0a00_0001 == 10.0.0.1
    // (RFC 1918). Asserted directly on the shared predicate so a future refactor
    // cannot silently drop the Teredo-client extraction (it is otherwise only
    // exercised indirectly through the HTTP airlock tests).
    assert!(ip_is_blocked(ip("2001:0:808:808:0:0:f5ff:fffe")));
}

#[test]
fn allows_public_addresses() {
    assert!(!ip_is_blocked(ip("8.8.8.8")));
    assert!(!ip_is_blocked(ip("1.1.1.1")));
    assert!(!ip_is_blocked(ip("198.51.100.7")));
    assert!(!ip_is_blocked(ip("172.32.0.1"))); // just past 172.16/12
    assert!(!ip_is_blocked(ip("192.169.1.1"))); // not 192.168
    assert!(!ip_is_blocked(ip("2001:4860:4860::8888")));
    // A transition address embedding a *public* IPv4 must not over-block.
    assert!(!ip_is_blocked(ip("64:ff9b::808:808"))); // NAT64 -> 8.8.8.8
}
