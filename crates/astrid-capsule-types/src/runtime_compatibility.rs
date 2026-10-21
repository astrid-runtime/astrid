//! Shared runtime-version requirements for capsule and distro manifests.

use semver::{Version, VersionReq};

/// Whether a runtime satisfies a manifest's Astrid-version requirement.
///
/// Plain release requirements describe runtime compatibility, not channel
/// selection: dev builds are compared using their release triple. Requirements
/// naming a prerelease retain exact SemVer ordering and prerelease admission.
pub fn runtime_version_satisfied(requirement: &VersionReq, running: &Version) -> bool {
    if requirement.comparators.iter().any(|c| !c.pre.is_empty()) {
        requirement.matches(running)
    } else {
        requirement.matches(&Version::new(running.major, running.minor, running.patch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_requirements_preserve_release_and_prerelease_boundaries() {
        for (requirement, running, expected) in [
            (">=0.7.0", "2026.10.0-rc.1", true),
            (">=2026.10.0", "2026.10.0-rc.1", true),
            (">=2026.10.0", "2026.9.4-dev.9", false),
            (">=2026.10.0-rc.2", "2026.10.0-rc.1", false),
            (">=2026.10.0-rc.1", "2026.10.0-rc.2", true),
            (">=2026.10.0-rc.1", "2026.10.0", true),
            (">=0.7.0, <2026.10.0", "2026.10.0-rc.1", false),
            ("^0.7.0", "2026.10.0-rc.1", false),
            ("=2026.9.4", "2026.10.0-rc.1", false),
            (">=0.7.0", "2026.9.4", true),
            ("*", "2026.10.0-rc.1", true),
        ] {
            let requirement = VersionReq::parse(requirement).unwrap();
            let running = Version::parse(running).unwrap();
            assert_eq!(
                runtime_version_satisfied(&requirement, &running),
                expected,
                "{running} against {requirement}"
            );
        }
    }
}
