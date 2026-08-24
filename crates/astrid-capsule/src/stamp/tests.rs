use astrid_core::{PrincipalId, PrincipalUid};
use astrid_storage::PrincipalDirectory;

use super::{IngressIdentity, StampedInvocation};

fn alias(value: &str) -> PrincipalId {
    PrincipalId::new(value).expect("test principal alias")
}

#[test]
fn ingress_identity_keeps_wire_aliases_out_of_uid_stamps() {
    let directory = PrincipalDirectory::default();
    let unknown = alias("unknown-alias");

    let identity = IngressIdentity::from_host_context(&directory, Some(&unknown), None);
    assert_eq!(identity.compatibility_principal(), Some(&unknown));
    assert!(identity.trusted_stamp().is_none());

    let unspecified = IngressIdentity::from_host_context(&directory, None, None);
    assert_eq!(unspecified, IngressIdentity::Unspecified);
}

#[test]
fn registered_alias_uses_directory_uid_not_a_local_derivation() {
    let directory = PrincipalDirectory::default();
    let alice = alias("alice");
    let registered_uid = PrincipalUid::from_bytes([0xA1; 32]);
    directory
        .register(alice.clone(), registered_uid)
        .expect("register test identity");

    let identity = IngressIdentity::from_host_context(&directory, Some(&alice), None);
    let stamp = identity.trusted_stamp().expect("directory hit is stamped");
    assert_eq!(stamp.principal(), registered_uid);
    assert_ne!(
        stamp.principal(),
        PrincipalUid::from_bytes(*blake3::hash(b"alice").as_bytes())
    );
}

#[test]
fn trusted_uid_takes_priority_over_wire_alias() {
    let directory = PrincipalDirectory::default();
    let wire = alias("wire-alias");
    let trusted_uid = PrincipalUid::from_bytes([0xB2; 32]);

    let identity = IngressIdentity::from_host_context(&directory, Some(&wire), Some(trusted_uid));
    assert_eq!(
        identity.trusted_stamp().expect("trusted stamp").principal(),
        trusted_uid
    );
}

#[test]
fn stamp_has_only_the_trusted_host_constructor() {
    let stamp = StampedInvocation::from_trusted_uid(PrincipalUid::from_bytes([0x11; 32]));
    assert_eq!(stamp.principal(), PrincipalUid::from_bytes([0x11; 32]));
}
