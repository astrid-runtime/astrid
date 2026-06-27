//! Compatibility names for the capsule metadata mirror helper.
//!
//! The current name is [`crate::capsule_metadata_mirror`]. These aliases keep
//! the public crate surface stable for callers compiled against the earlier
//! helper names.

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

/// Mirror the read-only introspection view from the install principal's home.
pub fn materialize_principal_furniture(
    home: &AstridHome,
    target: &PrincipalId,
) -> anyhow::Result<()> {
    crate::mirror_capsule_metadata_from_install_principal(home, target)
}
