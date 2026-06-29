#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use astrid_capsule::engine::wasm::host::http::fuzzing;
use astrid_core::net::ip_is_blocked;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Arbitrary)]
struct Input {
    host: String,
    allow_host: String,
    port: u16,
    ip: FuzzIp,
}

#[derive(Debug, Arbitrary)]
enum FuzzIp {
    V4([u8; 4]),
    V6([u16; 8]),
}

fuzz_target!(|data: &[u8]| {
    let mut data = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut data) else {
        return;
    };

    let ip = input.ip.to_ip_addr();
    if std::env::var_os("ASTRID_ALLOW_LOCAL_IPS").is_none() {
        assert_eq!(fuzzing::is_safe_ip(ip), !ip_is_blocked(ip));
    }

    if let Some(ip) = fuzzing::literal_ip(&input.host) {
        assert_eq!(
            fuzzing::redirect_target_blocked(Some(&input.host)),
            !fuzzing::is_safe_ip(ip)
        );
    } else {
        assert!(!fuzzing::redirect_target_blocked(Some(&input.host)));
    }

    assert!(!fuzzing::redirect_target_blocked(None));

    if is_simple_host(&input.allow_host) {
        let exact = format!("{}:{}", input.allow_host, input.port);
        let wildcard = format!("{}:*", input.allow_host);
        assert!(fuzzing::egress_allowed(
            std::slice::from_ref(&exact),
            &input.allow_host,
            input.port
        ));
        assert!(fuzzing::egress_allowed(
            std::slice::from_ref(&wildcard),
            &input.allow_host,
            input.port
        ));
    }
});

fn is_simple_host(host: &str) -> bool {
    !host.is_empty()
        && !host.contains(':')
        && !host.contains('/')
        && !host.contains('\\')
        && !host.chars().any(char::is_whitespace)
}

impl FuzzIp {
    fn to_ip_addr(&self) -> IpAddr {
        match self {
            Self::V4(octets) => IpAddr::V4(Ipv4Addr::from(*octets)),
            Self::V6(segments) => IpAddr::V6(Ipv6Addr::from(*segments)),
        }
    }
}
