//! Shared SSRF / local-address block-set predicate.
//!
//! [`ip_is_blocked`] is the single source of truth for "this IP is a
//! loopback / private / link-local / CGNAT / site-local / transition-embedded
//! private address that a capsule must not reach without an operator
//! exemption." Both the runtime SSRF airlock (`astrid-capsule`'s
//! `http::is_safe_ip`) and the CLI guided pre-bless (`astrid-cli`'s
//! `local_egress::ip_is_local`) consume it, so the airlock block set and the
//! set of endpoints the bless prompt fires for cannot drift.
//!
//! The predicate is **pure**: it has no environment-variable escape hatch. The
//! airlock layers its `ASTRID_ALLOW_LOCAL_IPS` bypass on top of this predicate;
//! the CLI prompt deliberately does not, so a test/CI env var never suppresses
//! the operator-facing bless prompt.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Build an [`Ipv4Addr`] from two big-endian `IPv6` segments (the low 32 bits of
/// an address).
fn v4_from_segments(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo))
}

/// True if an `IPv4` address must never be reached by a capsule: loopback,
/// unspecified, multicast/broadcast, RFC 1918 private, link-local
/// (`169.254/16`), CGNAT (`100.64/10`), or the `0.0.0.0/8` / `127.0.0.0/8`
/// blocks.
fn ipv4_blocked(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let o = ip.octets();
    o[0] == 10
        || o[0] == 0
        || o[0] == 255
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 127
}

/// True if an `IPv6` address is loopback, unspecified, multicast, ULA
/// (`fc00::/7`), link-local (`fe80::/10`), or deprecated site-local
/// (`fec0::/10`).
fn ipv6_blocked(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let s = ip.segments();
    (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0
}

/// Extract every `IPv4` address embedded in an `IPv6` transition/translation
/// address. A NAT64, 6to4, or Teredo gateway would translate these straight to
/// the embedded `IPv4`, so an embedded private/loopback address is as dangerous
/// as a bare one and must be blocked. Covers the NAT64 well-known prefix
/// (`64:ff9b::/96`, RFC 6052), 6to4 (`2002::/16`, RFC 3056), and Teredo
/// (`2001:0::/32`, RFC 4380 — server plus the bitwise-NOT-obfuscated client).
fn embedded_ipv4s(segs: [u16; 8]) -> impl Iterator<Item = Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2..6].iter().all(|&s| s == 0) {
        out.push(v4_from_segments(segs[6], segs[7]));
    }
    if segs[0] == 0x2002 {
        out.push(v4_from_segments(segs[1], segs[2]));
    }
    if segs[0] == 0x2001 && segs[1] == 0x0000 {
        out.push(v4_from_segments(segs[2], segs[3]));
        out.push(v4_from_segments(!segs[6], !segs[7]));
    }
    out.into_iter()
}

/// True if `ip` is in the SSRF / local-address block set: a loopback, private,
/// link-local, CGNAT, deprecated site-local, or transition-embedded private
/// address.
///
/// `IPv4`-mapped (`::ffff:a.b.c.d`) and `IPv4`-compatible (`::a.b.c.d`) `IPv6`
/// forms are normalised to their `IPv4` address before the `IPv4` checks, so an
/// encoding trick cannot slip a private address past the predicate. `IPv6`
/// transition/translation addresses (NAT64 / 6to4 / Teredo) are inspected for an
/// embedded private/loopback `IPv4` and blocked if one is found.
///
/// This is a pure predicate with no environment-variable bypass — callers that
/// want an escape hatch must layer it themselves.
#[must_use]
pub fn ip_is_blocked(mut ip: IpAddr) -> bool {
    // Normalize IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible
    // (`::a.b.c.d`) IPv6 forms to their IPv4 address so the encoding can't
    // slip a private address past the IPv4 checks.
    if let IpAddr::V6(ipv6) = ip {
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            ip = IpAddr::V4(ipv4);
        } else {
            let segs = ipv6.segments();
            if segs[..6].iter().all(|&s| s == 0) {
                ip = IpAddr::V4(v4_from_segments(segs[6], segs[7]));
            }
        }
    }

    match ip {
        IpAddr::V4(ipv4) => ipv4_blocked(ipv4),
        IpAddr::V6(ipv6) => {
            // A transition address embedding a private/loopback IPv4 is
            // reachable via a NAT64/6to4/Teredo gateway — block it.
            if embedded_ipv4s(ipv6.segments()).any(ipv4_blocked) {
                return true;
            }
            ipv6_blocked(ipv6)
        },
    }
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;
