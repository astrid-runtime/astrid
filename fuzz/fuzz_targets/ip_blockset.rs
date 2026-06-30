#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use astrid_core::net::ip_is_blocked;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Arbitrary)]
enum Input {
    V4([u8; 4]),
    V6([u16; 8]),
    V4Mapped([u8; 4]),
    V4Compatible([u8; 4]),
    Nat64([u8; 4]),
    SixToFour([u8; 4]),
    Teredo { server: [u8; 4], client: [u8; 4] },
}

fuzz_target!(|data: &[u8]| {
    let mut data = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut data) else {
        return;
    };

    match input {
        Input::V4(octets) => {
            let ip = Ipv4Addr::from(octets);
            let blocked = ip_is_blocked(IpAddr::V4(ip));
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.octets()[0] == 10
                || ip.octets()[0] == 127
                || ip.octets()[0] == 0
                || ip.octets()[0] == 255
                || (ip.octets()[0] == 172 && (16..=31).contains(&ip.octets()[1]))
                || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
                || (ip.octets()[0] == 169 && ip.octets()[1] == 254)
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
            {
                assert!(blocked);
            }
        },
        Input::V6(segments) => {
            let ip = Ipv6Addr::from(segments);
            let blocked = ip_is_blocked(IpAddr::V6(ip));
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
            {
                assert!(blocked);
            }
        },
        Input::V4Mapped(octets) => {
            let v4 = Ipv4Addr::from(octets);
            let v6 = v4.to_ipv6_mapped();
            assert_eq!(ip_is_blocked(IpAddr::V6(v6)), ip_is_blocked(IpAddr::V4(v4)));
        },
        Input::V4Compatible(octets) => {
            let v4 = Ipv4Addr::from(octets);
            let o = v4.octets();
            let v6 = Ipv6Addr::new(
                0,
                0,
                0,
                0,
                0,
                0,
                u16::from_be_bytes([o[0], o[1]]),
                u16::from_be_bytes([o[2], o[3]]),
            );
            assert_eq!(ip_is_blocked(IpAddr::V6(v6)), ip_is_blocked(IpAddr::V4(v4)));
        },
        Input::Nat64(octets) => {
            let v4 = Ipv4Addr::from(octets);
            let o = v4.octets();
            let v6 = Ipv6Addr::new(
                0x0064,
                0xff9b,
                0,
                0,
                0,
                0,
                u16::from_be_bytes([o[0], o[1]]),
                u16::from_be_bytes([o[2], o[3]]),
            );
            if ip_is_blocked(IpAddr::V4(v4)) {
                assert!(ip_is_blocked(IpAddr::V6(v6)));
            }
        },
        Input::SixToFour(octets) => {
            let v4 = Ipv4Addr::from(octets);
            let o = v4.octets();
            let v6 = Ipv6Addr::new(
                0x2002,
                u16::from_be_bytes([o[0], o[1]]),
                u16::from_be_bytes([o[2], o[3]]),
                0,
                0,
                0,
                0,
                1,
            );
            if ip_is_blocked(IpAddr::V4(v4)) {
                assert!(ip_is_blocked(IpAddr::V6(v6)));
            }
        },
        Input::Teredo { server, client } => {
            let server = Ipv4Addr::from(server);
            let client = Ipv4Addr::from(client);
            let so = server.octets();
            let co = (!u32::from(client)).to_be_bytes();
            let v6 = Ipv6Addr::new(
                0x2001,
                0,
                u16::from_be_bytes([so[0], so[1]]),
                u16::from_be_bytes([so[2], so[3]]),
                0,
                0,
                u16::from_be_bytes([co[0], co[1]]),
                u16::from_be_bytes([co[2], co[3]]),
            );
            if ip_is_blocked(IpAddr::V4(server)) || ip_is_blocked(IpAddr::V4(client)) {
                assert!(ip_is_blocked(IpAddr::V6(v6)));
            }
        },
    }
});
