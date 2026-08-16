param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Astrid\bin"),
    [switch]$SkipWinFsp
)

$ErrorActionPreference = "Stop"

function Get-TrustedWindowsSids {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return @(
        $currentUser,
        "S-1-5-18",       # LocalSystem
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-3-0",       # CREATOR OWNER (inheritance-only)
        # NT SERVICE\TrustedInstaller. Windows owns some filesystem roots and
        # standard parent directories with this service SID.
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
}

function Get-SidValue {
    param([object]$Identity)

    try {
        if ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
            return $Identity.Value
        }
        if ($Identity -is [System.Security.Principal.IdentityReference]) {
            return $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        $identityText = [string]$Identity
        if ($identityText.StartsWith("S-1-", [System.StringComparison]::OrdinalIgnoreCase)) {
            return [System.Security.Principal.SecurityIdentifier]::new($identityText).Value
        }
        $account = [System.Security.Principal.NTAccount]::new($identityText)
        return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Cannot resolve ACL principal '$Identity'"
    }
}

function Assert-SafeDirectoryBoundary {
    param(
        [string]$Path,
        [bool]$ProtectsMissingDestination,
        [bool]$IsDestination
    )

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        throw "Install path component is not a directory: $Path"
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to install through a redirected directory: $Path"
    }

    $trusted = Get-TrustedWindowsSids
    $acl = Get-Acl -LiteralPath $Path
    $owner = Get-SidValue -Identity $acl.Owner
    if ($trusted -notcontains $owner) {
        throw "Install path component has an untrusted owner: $Path"
    }

    $boundaryRights = [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $contentRights = [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Modify -bor
        [System.Security.AccessControl.FileSystemRights]::FullControl -bor
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [System.Security.AccessControl.FileSystemRights]::CreateFiles

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = Get-SidValue -Identity $rule.IdentityReference
        if ($trusted -contains $sid) {
            continue
        }
        $deniedRights = $boundaryRights
        if ($ProtectsMissingDestination -or $IsDestination) {
            $deniedRights = $deniedRights -bor $contentRights
        }
        if (($rule.FileSystemRights -band $deniedRights) -ne 0) {
            throw "Install path component grants mutation authority to '$sid': $Path"
        }
    }
}

function Assert-SafeDestinationChain {
    param([string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith("\\", [System.StringComparison]::Ordinal)) {
        throw "Install directory must be on a local filesystem"
    }
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root) -or
        $fullPath.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "Refusing to install directly into a filesystem root"
    }

    $paths = [System.Collections.Generic.List[string]]::new()
    $cursor = $fullPath
    while ($true) {
        $paths.Add($cursor) | Out-Null
        if ($cursor.TrimEnd('\') -eq $root.TrimEnd('\')) {
            break
        }
        $parent = [System.IO.Path]::GetDirectoryName($cursor.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($parent)) {
            throw "Install directory has an invalid parent chain"
        }
        $cursor = $parent
    }
    $chain = $paths.ToArray()
    [array]::Reverse($chain)

    $existing = [System.Collections.Generic.List[string]]::new()
    $missingSeen = $false
    foreach ($candidate in $chain) {
        if (Test-Path -LiteralPath $candidate) {
            if ($missingSeen) {
                throw "Install directory changed while its parent chain was checked"
            }
            $existing.Add($candidate) | Out-Null
        } else {
            $missingSeen = $true
        }
    }
    if ($existing.Count -eq 0) {
        throw "Install directory has no existing filesystem root"
    }

    for ($index = 0; $index -lt $existing.Count; $index++) {
        $candidate = $existing[$index]
        $isLastExisting = $index -eq ($existing.Count - 1)
        Assert-SafeDirectoryBoundary -Path $candidate `
            -ProtectsMissingDestination:($isLastExisting -and $missingSeen) `
            -IsDestination:($candidate.TrimEnd('\') -eq $fullPath.TrimEnd('\'))
    }
    return $fullPath
}

function Set-PrivateInstallDirectoryAcl {
    param([string]$Path)

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administrators = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($currentUser)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($currentUser, $system, $administrators)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl

    $applied = Get-Acl -LiteralPath $Path
    if (-not $applied.AreAccessRulesProtected -or
        (Get-SidValue -Identity $applied.Owner) -ne $currentUser.Value) {
        throw "Failed to enforce the private Astrid install-directory ACL"
    }
    $allowed = @($currentUser.Value, $system.Value, $administrators.Value)
    $present = @{}
    foreach ($rule in $applied.Access) {
        $sid = Get-SidValue -Identity $rule.IdentityReference
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $allowed -notcontains $sid) {
            throw "Astrid install-directory ACL retained an unexpected principal '$sid'"
        }
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $rule.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
            $present[$sid] = $true
        }
    }
    foreach ($sid in $allowed) {
        if (-not $present.ContainsKey($sid)) {
            throw "Astrid install-directory ACL is missing full control for '$sid'"
        }
    }
}

function Assert-PinnedWinFspMsi {
    param([string]$Path, [string]$ExpectedSha256)

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -and
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
        $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        if ($actualHash -eq $ExpectedSha256) {
            return
        }
        throw "WinFsp installer digest mismatch: $actualHash"
    }
    throw "WinFsp installer must be a regular, non-redirected file"
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

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "WinFsp installer must be a regular, non-redirected file"
    }

    # FileShare.Read lets msiexec open the package while preventing a writer or
    # delete/replace operation from racing the digest check and elevated use.
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $actualHash = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
        if ($actualHash -ne $ExpectedSha256) {
            throw "WinFsp installer digest mismatch: $actualHash"
        }
        $exitCode = Invoke-MsiExec -Arguments $Arguments
        return $exitCode
    } finally {
        $stream.Dispose()
    }
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
Assert-PinnedWinFspMsi -Path $msiPath -ExpectedSha256 $WinFspSha256

$destination = Assert-SafeDestinationChain -Path $InstallDir
$priorInstalledByAstrid = $false
if (Test-Path -LiteralPath $destination -PathType Container) {
    $priorMarkerPath = Join-Path $destination "astrid-install.json"
    if (Test-Path -LiteralPath $priorMarkerPath) {
        $priorMarkerItem = Get-Item -LiteralPath $priorMarkerPath -Force
        if ($priorMarkerItem.PSIsContainer -or
            ($priorMarkerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Existing Astrid installation marker is redirected or not a regular file"
        }
        $priorMarker = Get-Content -LiteralPath $priorMarkerPath -Raw | ConvertFrom-Json
        if ($priorMarker.product -ne "astrid" -or $priorMarker.winfsp_installer -ne $WinFspMsi) {
            throw "Existing installation marker does not authorize an Astrid upgrade"
        }
        $priorInstalledByAstrid = $priorMarker.winfsp_installed_by_astrid -eq $true
    } elseif (@(Get-ChildItem -LiteralPath $destination -Force).Count -ne 0) {
        throw "Refusing to install over a non-empty directory without an Astrid installation marker"
    }
}

New-Item -ItemType Directory -Path $destination -Force | Out-Null
Set-PrivateInstallDirectoryAcl -Path $destination
$destination = Assert-SafeDestinationChain -Path $destination

foreach ($name in $Files) {
    Copy-Item -LiteralPath (Join-Path $Source $name) -Destination (Join-Path $destination $name) -Force
}

$cachedMsiPath = Join-Path $destination $WinFspMsi
Assert-PinnedWinFspMsi -Path $cachedMsiPath -ExpectedSha256 $WinFspSha256

$installedByAstrid = $priorInstalledByAstrid
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
        # Verify the private cached copy immediately before it is handed to the
        # elevated installer. The release source may live in a mutable folder.
        $exitCode = Invoke-VerifiedMsiExec -Path $cachedMsiPath `
            -ExpectedSha256 $WinFspSha256 `
            -Arguments @("/i", "`"$cachedMsiPath`"", "/qn", "/norestart")
        if ($exitCode -ne 0 -and $exitCode -ne 3010) {
            throw "WinFsp installer failed with exit code $exitCode"
        }
        if (-not $wasInstalledBefore) {
            $installedByAstrid = $true
        }
    }
}
$marker = @{
    product = "astrid"
    winfsp_installed_by_astrid = $installedByAstrid
    winfsp_installer = $WinFspMsi
}
$marker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination "astrid-install.json")

Write-Host "Installed Astrid to $destination"
Write-Host "Add this directory to PATH, then run: astrid --version"
