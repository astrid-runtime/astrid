param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Astrid\bin"),
    [switch]$SkipWinFsp
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

$WinFspMsi = "winfsp-2.1.25156.msi"
$WinFspSha256 = "073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A"
$Files = @(
    "install-windows.ps1",
    "uninstall-windows.ps1",
    "astrid.exe",
    "astrid-daemon.exe",
    "astrid-build.exe",
    "astrid-emit.exe",
    "astrid-storage-provider-winfsp.exe",
    "winfsp-x64.dll",
    $WinFspMsi
)

$Source = $PSScriptRoot
foreach ($name in $Files) {
    if (-not (Test-Path -LiteralPath (Join-Path $Source $name) -PathType Leaf)) {
        throw "Astrid release is incomplete; missing $name"
    }
}

$msiPath = Join-Path $Source $WinFspMsi
$actualHash = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash
if ($actualHash -ne $WinFspSha256) {
    throw "WinFsp installer digest mismatch: $actualHash"
}

$installedByAstrid = $false
$wasInstalledBefore = $false
if (-not $SkipWinFsp) {
    $registry = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\WinFsp" -ErrorAction SilentlyContinue
    $installedDll = ""
    if ($null -ne $registry -and $null -ne $registry.InstallDir) {
        $installedDll = Join-Path $registry.InstallDir "bin\winfsp-x64.dll"
    }
    $needsInstall = $true
    if (Test-Path -LiteralPath $installedDll -PathType Leaf) {
        $wasInstalledBefore = $true
        $installedVersion = [version](Get-Item -LiteralPath $installedDll).VersionInfo.FileVersion
        if ($installedVersion.Major -lt 2) {
            throw "WinFsp 1.x cannot be upgraded in place by the bundled 2.x installer; preserve dependent mounts, remove 1.x deliberately, then rerun this installer"
        }
        $needsInstall = $installedVersion -lt [version]"2.1.25156"
    }
    if ($needsInstall) {
        $exitCode = Invoke-MsiExec -Arguments @("/i", "`"$msiPath`"", "/qn", "/norestart")
        if ($exitCode -ne 0 -and $exitCode -ne 3010) {
            throw "WinFsp installer failed with exit code $exitCode"
        }
        $installedByAstrid = -not $wasInstalledBefore
    }
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$destination = [System.IO.Path]::GetFullPath($InstallDir)
if ($destination.TrimEnd('\') -eq [System.IO.Path]::GetPathRoot($destination).TrimEnd('\')) {
    throw "Refusing to install directly into a filesystem root"
}
if (Test-Path -LiteralPath $destination) {
    $attributes = Get-Item -LiteralPath $destination -Force
    if (($attributes.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to install through a redirected directory"
    }
}

foreach ($name in $Files) {
    Copy-Item -LiteralPath (Join-Path $Source $name) -Destination (Join-Path $destination $name) -Force
}
$marker = @{
    product = "astrid"
    winfsp_installed_by_astrid = $installedByAstrid
    winfsp_installer = $WinFspMsi
}
$marker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination "astrid-install.json")

Write-Host "Installed Astrid to $destination"
Write-Host "Add this directory to PATH, then run: astrid --version"
