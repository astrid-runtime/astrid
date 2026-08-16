param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Astrid\bin"),
    [switch]$RemoveWinFsp
)

$ErrorActionPreference = "Stop"

$WinFspMsi = "winfsp-2.1.25156.msi"
$WinFspSha256 = "073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A"

function Assert-RegularFileNotRedirected {
    param([string]$Path, [string]$Description)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must be a regular, non-redirected file"
    }
}

function Invoke-MsiExec {
    param([string[]]$Arguments)
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -eq 740) {
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments `
            -Verb RunAs -Wait -PassThru
    }
    return $process.ExitCode
}

function Invoke-VerifiedMsiExec {
    param(
        [string]$Path,
        [string]$ExpectedSha256,
        [string[]]$Arguments
    )

    Assert-RegularFileNotRedirected -Path $Path -Description "Cached WinFsp installer"
    # Keep a non-writable, non-deletable handle across the digest check and
    # elevated msiexec use so the verified bytes cannot be exchanged in the
    # check/use gap. Other readers, including msiexec, remain allowed.
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $actualHash = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
        if ($actualHash -ne $ExpectedSha256) {
            throw "Cached WinFsp installer digest mismatch: $actualHash"
        }
        $exitCode = Invoke-MsiExec -Arguments $Arguments
        return $exitCode
    } finally {
        $stream.Dispose()
    }
}

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$root = [System.IO.Path]::GetPathRoot($InstallDir)
if ($InstallDir.TrimEnd('\') -eq $root.TrimEnd('\')) {
    throw "Refusing to uninstall from a filesystem root"
}

$markerPath = Join-Path $InstallDir "astrid-install.json"
Assert-RegularFileNotRedirected -Path $markerPath `
    -Description "Astrid installation marker in $InstallDir"
$marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
if ($marker.product -ne "astrid") {
    throw "The installation marker does not belong to Astrid"
}
if ($marker.winfsp_installer -ne $WinFspMsi) {
    throw "The installation marker names an unexpected WinFsp installer"
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
    $WinFspMsi,
    "astrid-install.json"
) | Select-Object -Unique

if ($RemoveWinFsp -and $marker.winfsp_installed_by_astrid -eq $true) {
    $msi = Join-Path $InstallDir $WinFspMsi
    $exitCode = Invoke-VerifiedMsiExec -Path $msi `
        -ExpectedSha256 $WinFspSha256 `
        -Arguments @("/x", "`"$msi`"", "/qn", "/norestart")
    if ($exitCode -ne 0 -and $exitCode -ne 3010) {
        throw "WinFsp uninstall failed with exit code $exitCode"
    }
}

foreach ($name in $names) {
    $path = [System.IO.Path]::GetFullPath((Join-Path $InstallDir $name))
    $installPrefix = $InstallDir.TrimEnd('\') + '\'
    if (-not $path.StartsWith($installPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
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
