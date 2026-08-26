use std::time::{Duration, Instant};

use astrid_core::PrincipalUid;
use astrid_resource_types::{
    AccountId, AuthorityEpoch, BudgetId, OwnerId, ResourceErrorCode, ResourceId, ResourceKind,
    Rights,
};

use super::{
    AdmissionOptions, Reservation, ResourceAuthorityTable, ResourceHandle, ResourceScope,
    RevocationSelector,
};
use crate::stamp::StampedInvocation;

fn stamp(byte: u8) -> StampedInvocation {
    StampedInvocation::from_trusted_uid(PrincipalUid::from_bytes([byte; 32]))
}

fn identity(byte: u8) -> ResourceId {
    ResourceId::from_bytes([byte; 32])
}

fn account(byte: u8) -> AccountId {
    AccountId::from_bytes([byte; 16])
}

fn budget(byte: u8) -> BudgetId {
    BudgetId::from_bytes([byte; 16])
}

fn rights(bits: u64) -> Rights {
    Rights::from_bits(bits).expect("test rights must be from the closed vocabulary")
}

fn reservation(units: u64) -> Reservation {
    Reservation::new(account(1), budget(2), units)
}

fn options(
    rights: Rights,
    expiry: Option<Instant>,
    revocation: Option<RevocationSelector>,
) -> AdmissionOptions {
    AdmissionOptions::new(rights, AuthorityEpoch::INITIAL, expiry, revocation)
}

fn options_at(
    rights: Rights,
    authority_epoch: AuthorityEpoch,
    expiry: Option<Instant>,
    revocation: Option<RevocationSelector>,
) -> AdmissionOptions {
    AdmissionOptions::new(rights, authority_epoch, expiry, revocation)
}

fn admit(table: &mut ResourceAuthorityTable, owner: &StampedInvocation) -> ResourceHandle {
    let object = identity(9);
    table
        .admit(
            owner,
            ResourceKind::SemanticObject,
            object,
            ResourceScope::singleton(object),
            reservation(10),
            options(
                rights(Rights::READ.bits() | Rights::USE.bits() | Rights::DELEGATE.bits()),
                None,
                None,
            ),
        )
        .expect("fixture admission should succeed")
}

#[test]
fn admission_and_preflight_bind_stamp_scope_rights_and_budget() {
    let owner = stamp(1);
    let mut table = ResourceAuthorityTable::new();
    let handle = admit(&mut table, &owner);
    let object = identity(9);
    let scope = ResourceScope::singleton(object);

    let authority = table
        .lookup(&owner, handle)
        .expect("owner should resolve its live handle");
    assert_eq!(authority.kind(), ResourceKind::SemanticObject);
    assert_eq!(authority.identity(), object);
    assert_eq!(authority.principal(), owner.principal());
    assert_eq!(authority.initiator(), owner.principal());
    assert_eq!(authority.owner(), OwnerId::from(owner.principal()));
    assert_eq!(authority.authority_epoch(), AuthorityEpoch::INITIAL);
    assert_eq!(
        authority.transfer_class(),
        astrid_resource_types::TransferClass::None
    );
    assert_eq!(
        authority.rights(),
        rights(Rights::READ.bits() | Rights::USE.bits() | Rights::DELEGATE.bits())
    );
    assert_eq!(authority.remaining_budget(), 10);
    assert_eq!(authority.account_id(), account(1));
    assert_eq!(authority.budget_id(), budget(2));
    assert_eq!(authority.scope(), &scope);
    assert_eq!(table.authority_epoch(), AuthorityEpoch::INITIAL);

    assert!(
        table
            .preflight(&owner, handle, Rights::READ, &scope, 10)
            .is_ok()
    );
    assert_eq!(
        table.preflight(&owner, handle, Rights::WRITE, &scope, 1),
        Err(ResourceErrorCode::MissingRight)
    );
    assert_eq!(
        table.preflight(
            &owner,
            handle,
            Rights::READ,
            ResourceScope::from_identities([object, identity(10)]).unwrap(),
            1,
        ),
        Err(ResourceErrorCode::InvalidDescriptor)
    );
    assert_eq!(
        table.preflight(&owner, handle, Rights::READ, &scope, 11),
        Err(ResourceErrorCode::Exhausted)
    );
}

#[test]
fn lookup_rejects_cross_principal_and_replayed_generation() {
    let owner = stamp(1);
    let other = stamp(2);
    let mut table = ResourceAuthorityTable::new();
    let handle = admit(&mut table, &owner);

    assert_eq!(
        table.lookup(&other, handle).err(),
        Some(ResourceErrorCode::WrongOwner)
    );
    assert_eq!(
        table.reclaim(&other, handle),
        Err(ResourceErrorCode::WrongOwner)
    );
    assert_eq!(table.active_reserved_units(), 10);

    let generation = handle.generation();
    table
        .reclaim(&owner, handle)
        .expect("owner reclaim should retire the slot");
    assert_eq!(table.active_reserved_units(), 0);
    assert_eq!(table.released_reserved_units(), 10);
    assert_eq!(
        table.lookup(&owner, handle).err(),
        Some(ResourceErrorCode::StaleGeneration)
    );

    let replacement = admit(&mut table, &owner);
    assert_ne!(replacement.generation(), generation);
    assert_eq!(
        table.lookup(&owner, handle).err(),
        Some(ResourceErrorCode::StaleGeneration)
    );

    table
        .drop_handle(&owner, replacement)
        .expect("drop alias should reclaim through the same stamp boundary");
    assert_eq!(table.active_reserved_units(), 0);
}

#[test]
fn attenuation_cannot_widen_rights_scope_or_budget() {
    let owner = stamp(3);
    let object = identity(9);
    let other_object = identity(10);
    let mut table = ResourceAuthorityTable::new();
    let parent = table
        .admit(
            &owner,
            ResourceKind::SemanticObject,
            object,
            ResourceScope::from_identities([object, other_object]).unwrap(),
            reservation(10),
            options(
                rights(Rights::READ.bits() | Rights::USE.bits() | Rights::DELEGATE.bits()),
                None,
                None,
            ),
        )
        .expect("parent admission should succeed");

    let child = table
        .attenuate(
            &owner,
            parent,
            Rights::READ,
            ResourceScope::singleton(object),
            4,
        )
        .expect("attenuated child should succeed");
    assert_eq!(table.lookup(&owner, parent).unwrap().remaining_budget(), 6);
    assert_eq!(table.lookup(&owner, child).unwrap().remaining_budget(), 4);
    assert_eq!(table.lookup(&owner, child).unwrap().parent(), Some(parent));

    assert_eq!(
        table.attenuate(
            &owner,
            parent,
            Rights::WRITE,
            ResourceScope::singleton(object),
            1,
        ),
        Err(ResourceErrorCode::MissingRight)
    );
    assert_eq!(
        table.attenuate(
            &owner,
            parent,
            Rights::READ,
            ResourceScope::from_identities([object, identity(11)]).unwrap(),
            1,
        ),
        Err(ResourceErrorCode::InvalidDescriptor)
    );
    assert_eq!(
        table.attenuate(
            &owner,
            parent,
            Rights::READ,
            ResourceScope::singleton(object),
            7,
        ),
        Err(ResourceErrorCode::Exhausted)
    );
}

#[test]
fn child_reclaim_refunds_parent_and_parent_reclaim_invalidates_child() {
    let owner = stamp(4);
    let mut table = ResourceAuthorityTable::new();
    let parent = admit(&mut table, &owner);
    let object = identity(9);
    let child = table
        .attenuate(
            &owner,
            parent,
            Rights::READ,
            ResourceScope::singleton(object),
            4,
        )
        .expect("child should be admitted");
    assert_eq!(table.lookup(&owner, parent).unwrap().remaining_budget(), 6);

    table
        .reclaim(&owner, child)
        .expect("child reclaim should return its unspent envelope");
    assert_eq!(table.lookup(&owner, parent).unwrap().remaining_budget(), 10);
    assert_eq!(
        table.lookup(&owner, child).err(),
        Some(ResourceErrorCode::StaleGeneration)
    );

    let child = table
        .attenuate(
            &owner,
            parent,
            Rights::READ,
            ResourceScope::singleton(object),
            3,
        )
        .expect("second child should be admitted");
    table
        .reclaim(&owner, parent)
        .expect("parent reclaim should release its own reservation");
    assert_eq!(
        table.lookup(&owner, child).err(),
        Some(ResourceErrorCode::Revoked)
    );
}

#[test]
fn expiry_revocation_and_epoch_changes_fail_closed() {
    let owner = stamp(5);
    let other = stamp(6);
    let object = identity(9);
    let mut table = ResourceAuthorityTable::new();
    let expired = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        table.admit(
            &owner,
            ResourceKind::SemanticObject,
            object,
            ResourceScope::singleton(object),
            reservation(1),
            options(Rights::READ, Some(expired), None),
        ),
        Err(ResourceErrorCode::Revoked)
    );

    let selector = RevocationSelector::new(7);
    let handle = table
        .admit(
            &owner,
            ResourceKind::SemanticObject,
            object,
            ResourceScope::singleton(object),
            reservation(2),
            options(
                Rights::READ,
                Some(Instant::now() + Duration::from_mins(1)),
                Some(selector),
            ),
        )
        .expect("future authority should be admitted");
    assert_eq!(
        table.revoke_for(&other, handle),
        Err(ResourceErrorCode::WrongOwner)
    );
    table
        .revoke_for(&owner, handle)
        .expect("host revocation should find the live slot");
    assert_eq!(
        table.lookup(&owner, handle).err(),
        Some(ResourceErrorCode::Revoked)
    );

    let next_epoch = table
        .advance_authority_epoch()
        .expect("epoch should advance");
    assert_ne!(next_epoch, AuthorityEpoch::INITIAL);
    assert_eq!(
        table.lookup(&owner, handle).err(),
        Some(ResourceErrorCode::Revoked)
    );
    assert_eq!(
        table.admit(
            &owner,
            ResourceKind::SemanticObject,
            object,
            ResourceScope::singleton(object),
            reservation(1),
            options(Rights::READ, None, None),
        ),
        Err(ResourceErrorCode::Revoked)
    );
    table.revoke_selector(selector).unwrap();
    assert_eq!(
        table.admit(
            &owner,
            ResourceKind::SemanticObject,
            object,
            ResourceScope::singleton(object),
            reservation(1),
            options_at(Rights::READ, next_epoch, None, Some(selector)),
        ),
        Err(ResourceErrorCode::Revoked)
    );
}

#[test]
fn scope_is_bounded_and_wrong_kind_is_rejected() {
    let owner = stamp(6);
    let mut table = ResourceAuthorityTable::new();
    let ids = (0..65).map(identity);
    assert_eq!(
        ResourceScope::from_identities(ids),
        Err(ResourceErrorCode::InvalidDescriptor)
    );
    let repeated = std::iter::repeat_n(identity(1), 65);
    assert_eq!(
        ResourceScope::from_identities(repeated),
        Err(ResourceErrorCode::InvalidDescriptor)
    );
    assert_eq!(
        ResourceScope::from_identities(std::iter::repeat_n(identity(1), 64))
            .expect("64 raw identities remain within the bound"),
        ResourceScope::singleton(identity(1))
    );
    let object = identity(9);
    assert_eq!(
        table.admit(
            &owner,
            ResourceKind::Storage,
            object,
            ResourceScope::singleton(object),
            reservation(1),
            options(Rights::READ, None, None),
        ),
        Err(ResourceErrorCode::InvalidDescriptor)
    );
}

#[test]
fn live_authority_surface_has_no_serialization_or_descriptor_constructor() {
    let source = [
        include_str!("mod.rs"),
        include_str!("scope.rs"),
        include_str!("table.rs"),
    ]
    .concat();
    assert!(!source.contains("Serialize"));
    assert!(!source.contains("serde::"));
    assert!(source.contains("stamp: &StampedInvocation"));
    assert!(!source.contains("IngressIdentity"));
    assert!(source.contains("pub(crate) struct ResourceAuthority"));
    assert!(source.contains("pub(crate) struct ResourceHandle"));
    assert!(source.contains("pub(crate) struct Reservation"));
    assert!(source.contains("pub(crate) const fn new("));
    assert!(source.contains("pub(crate) fn singleton("));
    assert!(!source.contains("pub fn new("));
    assert!(!source.contains("pub fn singleton("));
    assert!(!source.contains("impl From<BudgetId> for Reservation"));
    assert!(!source.contains("impl From<AccountId> for Reservation"));
}
