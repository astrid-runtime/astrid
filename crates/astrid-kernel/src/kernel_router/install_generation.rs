//! Observed install-generation CAS tokens for filtered Distro refresh.

use astrid_core::kernel_api::{CapsuleInstallBatchMember, InstalledCapsuleGeneration};
use astrid_storage::CapsulePackageGeneration;
use astrid_storage::storage_model::ObjectId;

const GENERATION_HEX_LEN: usize = 64;

/// Parse one wire generation into the durable package CAS token.
pub(super) fn parse_installed_generation(
    generation: &InstalledCapsuleGeneration,
) -> Result<CapsulePackageGeneration, String> {
    Ok(CapsulePackageGeneration::new(
        ObjectId::new(parse_generation_object(&generation.archive)?),
        ObjectId::new(parse_generation_object(&generation.metadata)?),
        ObjectId::new(parse_generation_object(&generation.authority)?),
    ))
}

/// Choose the request or batch-member generation when they agree.
pub(super) fn resolve_expected_generation(
    request: Option<&InstalledCapsuleGeneration>,
    member: Option<&CapsuleInstallBatchMember>,
) -> Result<Option<InstalledCapsuleGeneration>, String> {
    match (
        request,
        member.and_then(|member| member.expected_generation.as_ref()),
    ) {
        (Some(request), Some(member)) if request != member => {
            Err("install expected_generation disagrees with the batch member".to_owned())
        },
        (Some(generation), _) | (_, Some(generation)) => Ok(Some(generation.clone())),
        (None, None) => Ok(None),
    }
}

/// Resolve then parse the durable CAS token for one install.
pub(super) fn expected_package_generation(
    request: Option<&InstalledCapsuleGeneration>,
    member: Option<&CapsuleInstallBatchMember>,
) -> Result<Option<CapsulePackageGeneration>, String> {
    match resolve_expected_generation(request, member)? {
        Some(generation) => parse_installed_generation(&generation).map(Some),
        None => Ok(None),
    }
}

fn parse_generation_object(value: &str) -> Result<[u8; 32], String> {
    if value.len() != GENERATION_HEX_LEN
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("install expected_generation must be 64 lowercase hex characters".to_owned());
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| {
        "install expected_generation must be 64 lowercase hex characters".to_owned()
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(seed: u8) -> InstalledCapsuleGeneration {
        InstalledCapsuleGeneration {
            archive: hex::encode([seed; 32]),
            metadata: hex::encode([seed.wrapping_add(1); 32]),
            authority: hex::encode([seed.wrapping_add(2); 32]),
        }
    }

    fn member(generation: Option<InstalledCapsuleGeneration>) -> CapsuleInstallBatchMember {
        CapsuleInstallBatchMember {
            id: "cas-demo".to_owned(),
            version: "1.0.0".to_owned(),
            source_digest: format!("blake3:{}", "a".repeat(64)),
            archive_digest: format!("blake3:{}", "b".repeat(64)),
            source_bytes: 12,
            expected_generation: generation,
        }
    }

    #[test]
    fn unconstrained_when_request_and_member_omit_generation() {
        assert_eq!(resolve_expected_generation(None, None).unwrap(), None);
        assert_eq!(expected_package_generation(None, None).unwrap(), None);
    }

    #[test]
    fn request_generation_is_used_when_member_omits_it() {
        let expected = generation(1);
        assert_eq!(
            resolve_expected_generation(Some(&expected), None).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn member_generation_is_used_when_request_omits_it() {
        let expected = generation(2);
        let member = member(Some(expected.clone()));
        assert_eq!(
            resolve_expected_generation(None, Some(&member)).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn disagreeing_request_and_member_fail_closed() {
        let request = generation(3);
        let member = member(Some(generation(4)));
        let error = resolve_expected_generation(Some(&request), Some(&member)).unwrap_err();
        assert_eq!(
            error,
            "install expected_generation disagrees with the batch member"
        );
    }

    #[test]
    fn uppercase_hex_is_rejected() {
        let mut expected = generation(5);
        expected.archive = "A".repeat(64);
        let error = parse_installed_generation(&expected).unwrap_err();
        assert_eq!(
            error,
            "install expected_generation must be 64 lowercase hex characters"
        );
    }

    #[test]
    fn short_hex_is_rejected() {
        let mut expected = generation(6);
        expected.metadata = "ab".to_owned();
        let error = parse_installed_generation(&expected).unwrap_err();
        assert_eq!(
            error,
            "install expected_generation must be 64 lowercase hex characters"
        );
    }

    #[test]
    fn parsed_generation_round_trips_object_ids() {
        let expected = generation(7);
        let parsed = parse_installed_generation(&expected).unwrap();
        assert_eq!(hex::encode(parsed.archive().as_bytes()), expected.archive);
        assert_eq!(hex::encode(parsed.metadata().as_bytes()), expected.metadata);
        assert_eq!(
            hex::encode(parsed.authority().as_bytes()),
            expected.authority
        );
    }
}
