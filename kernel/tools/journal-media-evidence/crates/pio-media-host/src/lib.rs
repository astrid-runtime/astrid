#[path = "../../../shared/crash.rs"]
pub mod crash;
#[path = "../../../shared/media.rs"]
pub mod media;

#[cfg(test)]
mod tests {
    use super::media::{
        CommitMetadata, DEVICE_SERIAL_LEN, FRAME_COUNT, FRAME_LEN, KEY_ID, MEDIA_LEN, RECORD_LEN,
        Recovery, SECTOR_LEN, STATE_COMMITTED, STATE_PENDING, Slot, TAG_OFFSET,
        auth::Authenticator, build_slot_record, canonical_payload, parse_media,
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[test]
    fn hmac_is_standard_and_binds_serial_layout_padding() {
        let key = [7u8; 32];
        let authenticator = Authenticator::new(key).expect("key");
        let device_serial = [b'S'; DEVICE_SERIAL_LEN];
        let mut padded_frames = vec![0u8; FRAME_COUNT * 512];
        padded_frames[0] = b'A';
        padded_frames[8191] = b'Z';
        let mut commit_header = [0u8; 64];
        commit_header[..KEY_ID.len()].copy_from_slice(KEY_ID);

        let actual = authenticator.tag(&device_serial, &commit_header, &padded_frames);
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("valid key length");
        Mac::update(&mut mac, b"astrid.issue-1691.pio.journal.v1");
        Mac::update(&mut mac, KEY_ID);
        Mac::update(&mut mac, &device_serial);
        Mac::update(&mut mac, &commit_header);
        Mac::update(&mut mac, &padded_frames);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn build_slot_record_then_parse_media_yields_candidate() {
        let context = TestContext::new();
        let payload = canonical_payload();
        let media = context.committed_media(Slot::B, 1001);
        match parse_media(&media, 1000, &context.serial, &context.authenticator) {
            Ok(Recovery::Candidate {
                epoch,
                slot,
                payload: recovered,
            }) => {
                assert_eq!(epoch, 1001);
                assert_eq!(slot, Slot::B);
                assert_eq!(recovered, payload);
            },
            Ok(Recovery::Torn { reason }) => panic!("torn: {reason}"),
            Ok(Recovery::ConflictingSameEpoch { epoch }) => {
                panic!("conflict epoch={epoch}")
            },
            Ok(Recovery::Uncommitted { epoch }) => panic!("uncommitted epoch={epoch}"),
            Ok(Recovery::StaleEpoch { found, floor }) => {
                panic!("stale found={found} floor={floor}")
            },
            Err(reason) => panic!("parse err: {reason}"),
        }
    }

    #[test]
    fn stale_device_serial_fails_closed() {
        let context = TestContext::new();
        let media = context.committed_media(Slot::B, 1001);
        let clone_serial = [b'C'; DEVICE_SERIAL_LEN];
        expect_torn(
            parse_media(&media, 1000, &clone_serial, &context.authenticator),
            "authentication",
        );
    }

    #[test]
    fn forged_frame_fails_closed() {
        let context = TestContext::new();
        let mut media = context.committed_media(Slot::B, 1001);
        media[Slot::B.index() * RECORD_LEN] ^= 1;
        expect_torn(
            parse_media(&media, 1000, &context.serial, &context.authenticator),
            "authentication",
        );
    }

    #[test]
    fn same_epoch_records_conflict() {
        let context = TestContext::new();
        let mut media = context.committed_media(Slot::A, 1001);
        media[RECORD_LEN..].copy_from_slice(&context.committed_record(Slot::B, 1001));
        match parse_media(&media, 1000, &context.serial, &context.authenticator) {
            Ok(Recovery::ConflictingSameEpoch { epoch }) => assert_eq!(epoch, 1001),
            _ => panic!("equal epochs must not yield a candidate"),
        }
    }

    #[test]
    fn impossible_slot_order_fails_closed() {
        let context = TestContext::new();
        let mut media = context.committed_media(Slot::A, 1001);
        media[RECORD_LEN..].copy_from_slice(&context.committed_record(Slot::B, u64::MAX));
        expect_torn(
            parse_media(&media, 1000, &context.serial, &context.authenticator),
            "epoch-exhausted",
        );
    }

    #[test]
    fn reordered_slot_records_fail_closed() {
        let context = TestContext::new();
        let mut media = [0u8; MEDIA_LEN];
        media[..RECORD_LEN].copy_from_slice(&context.committed_record(Slot::B, 1002));
        media[RECORD_LEN..].copy_from_slice(&context.committed_record(Slot::A, 1001));
        expect_torn(
            parse_media(&media, 1000, &context.serial, &context.authenticator),
            "layout-or-copy",
        );
    }

    #[test]
    fn undersized_media_fails_closed() {
        let context = TestContext::new();
        let media = vec![0u8; MEDIA_LEN - 1];
        assert_eq!(
            parse_media(&media, 1000, &context.serial, &context.authenticator),
            Err("wrong-media-size")
        );
    }

    #[test]
    fn pending_commit_is_uncommitted_not_a_candidate() {
        let context = TestContext::new();
        let mut media = [0u8; MEDIA_LEN];
        media[RECORD_LEN..].copy_from_slice(&context.signed_record(
            CommitMetadata {
                state: STATE_PENDING,
                epoch: 1001,
            },
            Slot::B,
        ));
        match parse_media(&media, 1000, &context.serial, &context.authenticator) {
            Ok(Recovery::Uncommitted { epoch }) => assert_eq!(epoch, 1001),
            _ => panic!("pending commit must not yield a candidate"),
        }
    }

    #[test]
    fn invalidated_commit_leaves_no_candidate() {
        let context = TestContext::new();
        let mut media = context.committed_media(Slot::B, 1001);
        let commit_start = RECORD_LEN + FRAME_COUNT * 512;
        media[commit_start..commit_start + 8].copy_from_slice(super::media::INVALID_MAGIC);
        media[commit_start + 15] = super::media::STATE_INVALIDATED;
        expect_torn(
            parse_media(&media, 1000, &context.serial, &context.authenticator),
            "missing-commit",
        );
    }

    #[test]
    fn authenticated_commit_padding_fails_closed() {
        let context = TestContext::new();
        for offset in [13, SECTOR_LEN - 1] {
            let mut record = context.committed_record(Slot::B, 1001);
            record[FRAME_COUNT * 512 + offset] ^= 1;
            context.sign_record(&mut record);
            let mut media = [0u8; MEDIA_LEN];
            media[RECORD_LEN..].copy_from_slice(&record);
            expect_torn(
                parse_media(&media, 1000, &context.serial, &context.authenticator),
                "commit-padding",
            );
        }
    }

    #[test]
    fn forged_frame_boundary_fails_closed() {
        let context = TestContext::new();
        let mut media = context.committed_media(Slot::B, 1001);
        let start = Slot::B.index() * RECORD_LEN;
        media[start + FRAME_LEN - 1] ^= 1;
        media[start + FRAME_LEN] ^= 1;
        expect_torn(
            parse_media(&media, 1000, &context.serial, &context.authenticator),
            "authentication",
        );
    }

    #[test]
    fn torn_frames_without_commit_are_not_candidates() {
        let context = TestContext::new();
        let record = context.committed_record(Slot::B, 1001);
        let mut media = [0u8; MEDIA_LEN];
        media[RECORD_LEN..RECORD_LEN + FRAME_COUNT * 512]
            .copy_from_slice(&record[..FRAME_COUNT * 512]);
        expect_torn(
            parse_media(&media, 1000, &context.serial, &context.authenticator),
            "missing-commit",
        );
    }

    #[test]
    fn valid_record_below_floor_is_stale() {
        let context = TestContext::new();
        let media = context.committed_media(Slot::B, 1001);
        match parse_media(&media, 1002, &context.serial, &context.authenticator) {
            Ok(Recovery::StaleEpoch { found, floor }) => {
                assert_eq!((found, floor), (1001, 1002));
            },
            _ => panic!("authenticated record below floor must be stale"),
        }
    }

    #[test]
    fn parse_rejects_frame0_as_hmac_header() {
        let context = TestContext::new();
        let record = context.committed_record(Slot::B, 1001);
        let frames = &record[..FRAME_COUNT * 512];
        let commit = &record[FRAME_COUNT * 512..];
        let wrong = context
            .authenticator
            .tag(&context.serial, &frames[..TAG_OFFSET], frames);
        let stored: [u8; 32] = commit[TAG_OFFSET..TAG_OFFSET + 32].try_into().unwrap();
        assert_ne!(wrong, stored);
        let right = context
            .authenticator
            .tag(&context.serial, &commit[..TAG_OFFSET], frames);
        assert_eq!(right, stored);
    }

    struct TestContext {
        authenticator: Authenticator,
        serial: [u8; DEVICE_SERIAL_LEN],
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                authenticator: Authenticator::new([7u8; 32]).expect("key"),
                serial: *b"PIO1691-JOURNAL-0001",
            }
        }

        fn committed_record(&self, slot: Slot, epoch: u64) -> [u8; RECORD_LEN] {
            self.signed_record(
                CommitMetadata {
                    state: STATE_COMMITTED,
                    epoch,
                },
                slot,
            )
        }

        fn signed_record(&self, metadata: CommitMetadata, slot: Slot) -> [u8; RECORD_LEN] {
            build_slot_record(
                &canonical_payload(),
                metadata,
                slot,
                &self.serial,
                &self.authenticator,
            )
        }

        fn committed_media(&self, slot: Slot, epoch: u64) -> [u8; MEDIA_LEN] {
            let mut media = [0u8; MEDIA_LEN];
            let start = slot.index() * RECORD_LEN;
            media[start..start + RECORD_LEN].copy_from_slice(&self.committed_record(slot, epoch));
            media
        }

        fn sign_record(&self, record: &mut [u8; RECORD_LEN]) {
            let commit_start = FRAME_COUNT * 512;
            let tag = self.authenticator.tag(
                &self.serial,
                &record[commit_start..commit_start + TAG_OFFSET],
                &record[..commit_start],
            );
            record[commit_start + TAG_OFFSET..commit_start + TAG_OFFSET + tag.len()]
                .copy_from_slice(&tag);
        }
    }

    fn expect_torn(result: Result<Recovery, &'static str>, expected: &'static str) {
        match result {
            Ok(Recovery::Torn { reason }) => assert_eq!(reason, expected),
            Ok(Recovery::Candidate { .. }) => panic!("fail-closed result must not be a candidate"),
            Ok(Recovery::ConflictingSameEpoch { epoch }) => panic!("conflict {epoch}"),
            Ok(Recovery::Uncommitted { epoch }) => panic!("uncommitted {epoch}"),
            Ok(Recovery::StaleEpoch { found, floor }) => panic!("stale {found} {floor}"),
            Err(reason) => panic!("parse err: {reason}"),
        }
    }
}
