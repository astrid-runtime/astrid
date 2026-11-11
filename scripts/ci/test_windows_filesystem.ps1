param(
    [Parameter(Mandatory = $true)]
    [string]$Target
)

$ErrorActionPreference = "Stop"

function Invoke-NativeCargoTest {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CargoArgs
    )

    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-core", "platform_fs",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-core", "dirs::projection_retirement",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-storage", "volume::hosted",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-storage", "--features", "legacy-surrealkv",
    "principal_state::legacy_snapshot",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-storage", "--features", "legacy-surrealkv",
    "principal_state::native_io::retirement",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-audit", "migration_source_tests",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-kernel", "legacy_audit::tests",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-kernel", "audit_retirement_tests",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-storage", "engine::durable::index_tests::cache_rebuild",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-storage", "--all-features",
    "principal_state::runtime_tree::lifecycle_tests",
    "--", "--nocapture"
)

Invoke-NativeCargoTest -CargoArgs @(
    "test", "--locked", "--target", $Target,
    "-p", "astrid-storage", "--all-features",
    "principal_state::lifecycle",
    "--", "--nocapture"
)
