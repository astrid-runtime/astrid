use anyhow::Context as _;
use astrid_core::dirs::AstridHome;

pub(super) fn prepare(home: &AstridHome) -> anyhow::Result<()> {
    home.validate_runtime_identity_provisioning()
        .context("runtime identity provisioning is not admitted for capsule inspection")?;
    astrid_core::platform_fs::ensure_private_directory(home.root())
        .context("failed to validate private Astrid home for capsule inspection")?;
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir())
        .context("failed to provision private runtime identity directory")?;
    Ok(())
}
