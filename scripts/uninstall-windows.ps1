param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Astrid\bin"),
    [switch]$RemoveWinFsp
)

$ErrorActionPreference = "Stop"

function Invoke-MsiExec {
    param([string[]]$Arguments)
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -eq 740) {
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments `
            -Verb RunAs -Wait -PassThru
    }
    return $process.ExitCode
}

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$root = [System.IO.Path]::GetPathRoot($InstallDir)
if ($InstallDir.TrimEnd('\') -eq $root.TrimEnd('\')) {
    throw "Refusing to uninstall from a filesystem root"
}

$markerPath = Join-Path $InstallDir "astrid-install.json"
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    throw "No Astrid installation marker found in $InstallDir"
}
$marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
if ($marker.product -ne "astrid") {
    throw "The installation marker does not belong to Astrid"
}

$names = @(
    "astrid.exe",
    "astrid-daemon.exe",
    "astrid-build.exe",
    "astrid-emit.exe",
    "astrid-storage-provider-winfsp.exe",
    "winfsp-x64.dll",
    "install-windows.ps1",
    "uninstall-windows.ps1",
    $marker.winfsp_installer,
    "astrid-install.json"
) | Select-Object -Unique

if ($RemoveWinFsp -and $marker.winfsp_installed_by_astrid -eq $true) {
    $msi = Join-Path $InstallDir $marker.winfsp_installer
    if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
        throw "Cannot uninstall WinFsp because its cached installer is missing"
    }
    $exitCode = Invoke-MsiExec -Arguments @("/x", "`"$msi`"", "/qn", "/norestart")
    if ($exitCode -ne 0 -and $exitCode -ne 3010) {
        throw "WinFsp uninstall failed with exit code $exitCode"
    }
}

foreach ($name in $names) {
    $path = [System.IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    if (-not $path.StartsWith($InstallDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the install directory: $path"
    }
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Remove-Item -LiteralPath $path -Force
    }
}
if (Test-Path -LiteralPath $InstallDir -PathType Container) {
    Remove-Item -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue
}

if ($RemoveWinFsp -and $marker.winfsp_installed_by_astrid -eq $true) {
    Write-Host "Removed Astrid and its WinFsp runtime"
} else {
    Write-Host "Removed Astrid; WinFsp remains installed"
}
