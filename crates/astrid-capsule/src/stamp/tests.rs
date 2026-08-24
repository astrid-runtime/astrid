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

#[test]
fn public_stamp_surface_cannot_mint_from_host_context() {
    let identity = include_str!("identity.rs");
    let invocation = include_str!("invocation.rs");
    let module = include_str!("mod.rs");

    assert!(
        identity.contains("    pub(crate) fn from_host_context(")
            && identity.contains("    pub(crate) fn revalidated_cached_uid("),
        "stamp resolution must stay crate-private"
    );
    assert!(
        !identity.contains("    pub fn from_host_context("),
        "public from_host_context would re-open the mint"
    );
    assert!(
        invocation.contains("    pub(crate) fn from_trusted_uid("),
        "trusted UID construction must stay crate-private"
    );
    assert!(
        invocation.contains("    pub fn principal("),
        "read-only principal inspection must remain public"
    );
    assert!(
        identity.contains("    pub fn trusted_stamp(")
            && identity.contains("    pub fn compatibility_principal("),
        "read-only ingress inspection must remain public"
    );
    assert!(
        !invocation.contains("Serialize")
            && !invocation.contains("Deserialize")
            && !identity.contains("Serialize"),
        "stamp types must not grow serde-as-authority"
    );
    assert!(
        module.contains("attribution") && module.contains("cannot mint"),
        "module docs must keep stamp as attribution, not a public mint"
    );
}

#[test]
fn cached_stamp_hint_is_dropped_after_alias_rename() {
    let directory = PrincipalDirectory::default();
    let alice = alias("alice");
    let renamed = alias("alice-renamed");
    let uid = PrincipalUid::from_bytes([0xA1; 32]);
    directory
        .register(alice.clone(), uid)
        .expect("register test identity");
    assert_eq!(
        IngressIdentity::revalidated_cached_uid(&directory, &alice, uid),
        Some(uid)
    );

    directory
        .rename(uid, &alice, renamed)
        .expect("rebind uid away from the captured alias");
    assert_eq!(
        IngressIdentity::revalidated_cached_uid(&directory, &alice, uid),
        None,
        "rename must drop the cached UID for the old alias"
    );

    let identity = IngressIdentity::from_host_context(&directory, Some(&alice), None);
    assert!(identity.trusted_stamp().is_none());
    assert_eq!(identity.compatibility_principal(), Some(&alice));
}

#[test]
fn cached_stamp_hint_is_not_reused_for_unbound_alias() {
    let directory = PrincipalDirectory::default();
    let owner = alias("owner");
    let stale = PrincipalUid::from_bytes([0xCC; 32]);
    assert_eq!(
        IngressIdentity::revalidated_cached_uid(&directory, &owner, stale),
        None
    );
}

#[test]
fn unspecified_wire_stays_unspecified_without_a_fresh_trusted_uid() {
    let directory = PrincipalDirectory::default();
    let identity = IngressIdentity::from_host_context(&directory, None, None);
    assert_eq!(identity, IngressIdentity::Unspecified);
    assert!(identity.trusted_stamp().is_none());
}
