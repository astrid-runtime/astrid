#[path = "../../../shared/media.rs"]
pub mod media;

#[cfg(test)]
mod tests {
    use super::media::{
        auth::Authenticator, build_slot_record, canonical_payload, parse_media, CommitMetadata,
        Recovery, Slot, FRAME_COUNT, KEY_ID, MEDIA_LEN, RECORD_LEN, STATE_COMMITTED, TAG_OFFSET,
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[test]
    fn hmac_is_standard_and_binds_layout_padding() {
        let key = [7u8; 32];
        let authenticator = Authenticator::new(key).expect("key");
        let mut padded_frames = vec![0u8; FRAME_COUNT * 512];
        padded_frames[0] = b'A';
        padded_frames[8191] = b'Z';
        let mut commit_header = [0u8; 64];
        commit_header[..KEY_ID.len()].copy_from_slice(KEY_ID);

        let actual = authenticator.tag(&commit_header, &padded_frames);
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("valid key length");
        Mac::update(&mut mac, b"astrid.issue-1691.pio.journal.v1");
        Mac::update(&mut mac, KEY_ID);
        Mac::update(&mut mac, &commit_header);
        Mac::update(&mut mac, &padded_frames);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn build_slot_record_then_parse_media_yields_candidate() {
        let key = [7u8; 32];
        let authenticator = Authenticator::new(key).expect("key");
        let payload = canonical_payload();
        let record = build_slot_record(
            &payload,
            CommitMetadata {
                state: STATE_COMMITTED,
                epoch: 1001,
            },
            Slot::B,
            &authenticator,
        );
        let mut media = [0u8; MEDIA_LEN];
        media[RECORD_LEN..].copy_from_slice(&record);
        match parse_media(&media, 1000, &authenticator) {
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
    fn parse_rejects_frame0_as_hmac_header() {
        let key = [7u8; 32];
        let authenticator = Authenticator::new(key).expect("key");
        let payload = canonical_payload();
        let record = build_slot_record(
            &payload,
            CommitMetadata {
                state: STATE_COMMITTED,
                epoch: 1001,
            },
            Slot::B,
            &authenticator,
        );
        let frames = &record[..FRAME_COUNT * 512];
        let commit = &record[FRAME_COUNT * 512..];
        let wrong = authenticator.tag(&frames[..TAG_OFFSET], frames);
        let stored: [u8; 32] = commit[TAG_OFFSET..TAG_OFFSET + 32].try_into().unwrap();
        assert_ne!(wrong, stored);
        let right = authenticator.tag(&commit[..TAG_OFFSET], frames);
        assert_eq!(right, stored);
    }

    #[test]
    fn torn_frames_without_commit_are_not_candidates() {
        let key = [7u8; 32];
        let authenticator = Authenticator::new(key).expect("key");
        let payload = canonical_payload();
        let record = build_slot_record(
            &payload,
            CommitMetadata {
                state: STATE_COMMITTED,
                epoch: 1001,
            },
            Slot::B,
            &authenticator,
        );
        let mut media = [0u8; MEDIA_LEN];
        media[RECORD_LEN..RECORD_LEN + FRAME_COUNT * 512]
            .copy_from_slice(&record[..FRAME_COUNT * 512]);
        match parse_media(&media, 1000, &authenticator) {
            Ok(Recovery::Torn {
                reason: "missing-commit",
            }) => {},
            Ok(Recovery::Candidate { .. }) => panic!("partial frames must not authenticate"),
            Ok(Recovery::Torn { reason }) => panic!("unexpected torn: {reason}"),
            Ok(Recovery::ConflictingSameEpoch { epoch }) => panic!("conflict {epoch}"),
            Ok(Recovery::Uncommitted { epoch }) => panic!("uncommitted {epoch}"),
            Ok(Recovery::StaleEpoch { found, floor }) => panic!("stale {found} {floor}"),
            Err(reason) => panic!("parse err: {reason}"),
        }
    }
}
