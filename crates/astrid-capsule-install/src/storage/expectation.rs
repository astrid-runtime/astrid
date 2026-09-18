//! Install CAS expectation derived from an observed generation.

use astrid_storage::{CapsuleInstallExpectation, CapsulePackageGeneration, CapsulePackageSnapshot};

pub(super) fn install_expectation(
    snapshot: Option<&CapsulePackageSnapshot>,
    expected_generation: Option<CapsulePackageGeneration>,
) -> CapsuleInstallExpectation {
    match expected_generation {
        Some(generation) => CapsuleInstallExpectation::Generation(generation),
        None => snapshot.map_or(CapsuleInstallExpectation::Absent, |snapshot| {
            CapsuleInstallExpectation::Generation(snapshot.generation())
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_storage::storage_model::ObjectId;

    fn generation(seed: u8) -> CapsulePackageGeneration {
        CapsulePackageGeneration::new(
            ObjectId::new([seed; 32]),
            ObjectId::new([seed.wrapping_add(1); 32]),
            ObjectId::new([seed.wrapping_add(2); 32]),
        )
    }

    #[test]
    fn observed_generation_fail_closes_when_absent() {
        let expected = generation(1);
        assert_eq!(
            install_expectation(None, Some(expected)),
            CapsuleInstallExpectation::Generation(expected)
        );
    }

    #[test]
    fn unconstrained_absent_snapshot_installs_from_scratch() {
        assert_eq!(
            install_expectation(None, None),
            CapsuleInstallExpectation::Absent
        );
    }
}
