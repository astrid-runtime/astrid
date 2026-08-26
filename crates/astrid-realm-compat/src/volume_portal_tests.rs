use super::{MAX_OWNER_VOLUME_BYTES, OwnerVolumePortal};
use crate::fixtures::{alice_principal, bob_principal};
use astrid_provider::ProviderError;
use astrid_resource_types::ObjectGeneration;
use astrid_storage::volume::HostedFileVolume;
use std::sync::Arc;

fn volume() -> (tempfile::TempDir, Arc<HostedFileVolume>) {
    let temporary = tempfile::tempdir().expect("temporary volume directory");
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(path).expect("hosted volume");
    (temporary, volume)
}

#[test]
fn two_principals_are_isolated_in_one_reopened_volume() {
    let (temporary, volume) = volume();
    let path = temporary.path().join("astrid.volume");
    let alice = OwnerVolumePortal::open(volume.clone(), alice_principal()).unwrap();
    let bob = OwnerVolumePortal::open(volume.clone(), bob_principal()).unwrap();
    let generation = ObjectGeneration::INITIAL;
    alice
        .write_at(alice_principal(), generation, 0, b"alice")
        .unwrap();
    let alice_generation = alice.sync(alice_principal(), generation).unwrap();
    bob.write_at(bob_principal(), generation, 0, b"bob")
        .unwrap();
    let bob_generation = bob.sync(bob_principal(), generation).unwrap();

    let mut alice_bytes = [0_u8; 5];
    let mut bob_bytes = [0_u8; 3];
    assert_eq!(
        alice.read_at(alice_principal(), alice_generation, 0, &mut alice_bytes),
        Ok(5)
    );
    assert_eq!(
        bob.read_at(bob_principal(), bob_generation, 0, &mut bob_bytes),
        Ok(3)
    );
    assert_eq!(&alice_bytes, b"alice");
    assert_eq!(&bob_bytes, b"bob");
    assert_eq!(
        alice.read_at(bob_principal(), alice_generation, 0, &mut alice_bytes),
        Err(ProviderError::PrincipalMismatch)
    );
    assert_eq!(
        bob.write_at(alice_principal(), bob_generation, 0, b"nope"),
        Err(ProviderError::PrincipalMismatch)
    );

    drop(alice);
    drop(bob);
    drop(volume);
    let reopened_volume = HostedFileVolume::open(path).unwrap();
    let reopened_alice =
        OwnerVolumePortal::open(reopened_volume.clone(), alice_principal()).unwrap();
    let reopened_bob = OwnerVolumePortal::open(reopened_volume, bob_principal()).unwrap();
    let mut alice_after = [0_u8; 5];
    let mut bob_after = [0_u8; 3];
    reopened_alice
        .read_at(alice_principal(), alice_generation, 0, &mut alice_after)
        .unwrap();
    reopened_bob
        .read_at(bob_principal(), bob_generation, 0, &mut bob_after)
        .unwrap();
    assert_eq!(&alice_after, b"alice");
    assert_eq!(&bob_after, b"bob");
}

#[test]
fn foreign_sync_cannot_flush_an_unsynced_owner_tail() {
    let (temporary, volume) = volume();
    let path = temporary.path().join("astrid.volume");
    let alice = OwnerVolumePortal::open(volume.clone(), alice_principal()).unwrap();
    let bob = OwnerVolumePortal::open(volume.clone(), bob_principal()).unwrap();
    let initial = ObjectGeneration::INITIAL;
    alice
        .write_at(alice_principal(), initial, 0, b"committed")
        .unwrap();
    let generation = alice.sync(alice_principal(), initial).unwrap();
    alice
        .write_at(alice_principal(), generation, 0, b"unsynced")
        .unwrap();

    assert_eq!(
        bob.write_at(bob_principal(), initial, 0, b"blocked"),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(
        bob.sync(bob_principal(), initial),
        Err(ProviderError::NotSupported)
    );
    let crash_copy = temporary.path().join("crash.volume");
    std::fs::copy(&path, &crash_copy).unwrap();
    let committed_generation = alice.sync(alice_principal(), generation).unwrap();
    assert_eq!(committed_generation.get(), generation.get() + 1);
    assert_eq!(bob.sync(bob_principal(), initial), Ok(initial));
    drop(bob);
    drop(alice);
    drop(volume);

    let reopened_volume = HostedFileVolume::open(crash_copy).unwrap();
    let reopened_alice = OwnerVolumePortal::open(reopened_volume, alice_principal()).unwrap();
    assert_eq!(
        reopened_alice.generation(alice_principal()).unwrap(),
        generation
    );
    let mut bytes = [0_u8; 9];
    reopened_alice
        .read_at(alice_principal(), generation, 0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"committed");
}

#[test]
fn same_owner_open_handles_serialize_staging_and_release_after_sync() {
    let (_temporary, volume) = volume();
    let first = OwnerVolumePortal::open(volume.clone(), alice_principal()).unwrap();
    let second = OwnerVolumePortal::open(volume, alice_principal()).unwrap();
    let initial = ObjectGeneration::INITIAL;
    first
        .write_at(alice_principal(), initial, 0, b"first")
        .unwrap();
    assert_eq!(
        second.write_at(alice_principal(), initial, 0, b"blocked"),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(
        second.sync(alice_principal(), initial),
        Err(ProviderError::NotSupported)
    );

    let generation = first.sync(alice_principal(), initial).unwrap();
    assert_eq!(second.generation(alice_principal()), Ok(generation));
    second
        .write_at(alice_principal(), generation, 0, b"second")
        .unwrap();
    let next = second.sync(alice_principal(), generation).unwrap();
    assert_eq!(next.get(), generation.get() + 1);
}

#[test]
fn stale_generation_and_host_path_fail_closed() {
    let (_temporary, volume) = volume();
    let portal = OwnerVolumePortal::open(volume, alice_principal()).unwrap();
    assert!(portal.as_host_path().is_none());
    assert_eq!(
        portal.require_owner(bob_principal()),
        Err(ProviderError::PrincipalMismatch)
    );
    assert_eq!(
        portal.require_generation(alice_principal(), ObjectGeneration::from_raw(2).unwrap(),),
        Err(ProviderError::StaleGeneration {
            found: 1,
            requested: 2,
        })
    );
    assert_eq!(portal.owner(), alice_principal());
    assert_eq!(portal.namespace_id(), alice_principal());
}

#[test]
fn generation_advance_is_durable_and_denies_old_generation() {
    let (_temporary, volume) = volume();
    let portal = OwnerVolumePortal::open(volume, alice_principal()).unwrap();
    let next = portal
        .advance_generation(alice_principal(), ObjectGeneration::INITIAL)
        .unwrap();
    assert_eq!(next.get(), 2);
    assert_eq!(
        portal.write_at(alice_principal(), ObjectGeneration::INITIAL, 0, b"stale"),
        Err(ProviderError::StaleGeneration {
            found: 2,
            requested: 1,
        })
    );
    portal
        .write_at(alice_principal(), next, 0, b"current")
        .unwrap();
    portal.sync(alice_principal(), next).unwrap();
}

#[test]
fn unsynced_tail_is_discarded_on_reopen_without_mixed_owner_bytes() {
    let (temporary, volume) = volume();
    let path = temporary.path().join("astrid.volume");
    let portal = OwnerVolumePortal::open(volume.clone(), alice_principal()).unwrap();
    let generation = ObjectGeneration::INITIAL;
    portal
        .write_at(alice_principal(), generation, 0, b"committed")
        .unwrap();
    let generation = portal.sync(alice_principal(), generation).unwrap();
    portal
        .write_at(alice_principal(), generation, 0, b"unsynced")
        .unwrap();
    let crash_copy = temporary.path().join("crash.volume");
    std::fs::copy(&path, &crash_copy).unwrap();
    drop(portal);
    drop(volume);

    let reopened_volume = HostedFileVolume::open(crash_copy).unwrap();
    let reopened_alice =
        OwnerVolumePortal::open(reopened_volume.clone(), alice_principal()).unwrap();
    let reopened_bob = OwnerVolumePortal::open(reopened_volume, bob_principal()).unwrap();
    let mut bytes = [0_u8; 9];
    reopened_alice
        .read_at(alice_principal(), generation, 0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"committed");
    assert_eq!(
        reopened_bob.read_at(bob_principal(), ObjectGeneration::INITIAL, 0, &mut bytes,),
        Ok(0)
    );
}

#[test]
fn bounded_extent_rejects_over_capacity_before_volume_write() {
    let (_temporary, volume) = volume();
    let portal = OwnerVolumePortal::open(volume, alice_principal()).unwrap();
    assert_eq!(
        portal.write_at(
            alice_principal(),
            ObjectGeneration::INITIAL,
            MAX_OWNER_VOLUME_BYTES,
            b"x",
        ),
        Err(ProviderError::NotSupported)
    );
}

#[test]
fn cloned_portal_shares_staging_identity() {
    let (_temporary, volume) = volume();
    let first = OwnerVolumePortal::open(volume.clone(), alice_principal()).unwrap();
    let cloned = first.clone();
    let second = OwnerVolumePortal::open(volume, alice_principal()).unwrap();
    let initial = ObjectGeneration::INITIAL;
    first
        .write_at(alice_principal(), initial, 0, b"clone")
        .unwrap();
    assert_eq!(
        second.write_at(alice_principal(), initial, 0, b"blocked"),
        Err(ProviderError::NotSupported)
    );
    let generation = cloned.sync(alice_principal(), initial).unwrap();
    assert_eq!(generation.get(), 2);
    let mut bytes = [0_u8; 5];
    assert_eq!(
        first.read_at(alice_principal(), generation, 0, &mut bytes),
        Ok(5)
    );
    assert_eq!(&bytes, b"clone");
}

#[test]
fn dropping_a_stager_does_not_release_foreign_sync() {
    let (temporary, volume) = volume();
    let path = temporary.path().join("astrid.volume");
    let alice = OwnerVolumePortal::open(volume.clone(), alice_principal()).unwrap();
    let bob = OwnerVolumePortal::open(volume.clone(), bob_principal()).unwrap();
    let initial = ObjectGeneration::INITIAL;
    alice
        .write_at(alice_principal(), initial, 0, b"committed")
        .unwrap();
    let generation = alice.sync(alice_principal(), initial).unwrap();
    alice
        .write_at(alice_principal(), generation, 0, b"unsynced")
        .unwrap();
    drop(alice);
    assert_eq!(
        bob.sync(bob_principal(), initial),
        Err(ProviderError::NotSupported)
    );
    let crash_copy = temporary.path().join("crash.volume");
    std::fs::copy(&path, &crash_copy).unwrap();
    drop(bob);
    drop(volume);

    let reopened_volume = HostedFileVolume::open(crash_copy).unwrap();
    let reopened_alice = OwnerVolumePortal::open(reopened_volume, alice_principal()).unwrap();
    let mut bytes = [0_u8; 9];
    reopened_alice
        .read_at(alice_principal(), generation, 0, &mut bytes)
        .unwrap();
    assert_eq!(&bytes, b"committed");
}
