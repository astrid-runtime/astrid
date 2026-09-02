param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedArchiveSha256,

    [string]$ExpectedSourceCommit = '',

    [string]$ExpectedVersion = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

function Assert-RegularFile {
    param([string]$Path, [string]$Description)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must be a regular, non-redirected file: $Path"
    }
}

function Get-Sha256 {
    param([string]$Path)

    Assert-RegularFile -Path $Path -Description 'Hashed file'
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Assert-SameFileBytes {
    param([string]$Expected, [string]$Actual, [string]$Description)

    $expectedHash = Get-Sha256 -Path $Expected
    $actualHash = Get-Sha256 -Path $Actual
    if ($expectedHash -ne $actualHash) {
        throw "$Description bytes changed during installation ($expectedHash -> $actualHash)"
    }
    return $actualHash
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
        return ([System.Security.Principal.SecurityIdentifier]::new([string]$Identity)).Value
    } catch {
        throw "cannot resolve certification ACL identity '$Identity'"
    }
}

function Get-ExpectedVersion {
    if ($ExpectedVersion) {
        return $ExpectedVersion
    }

    $cargoToml = Join-Path $PSScriptRoot '..' 'Cargo.toml' | Resolve-Path
    $match = [regex]::Match(
        (Get-Content -LiteralPath $cargoToml.Path -Raw),
        '(?m)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"',
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    if (-not $match.Success) {
        throw 'cannot derive the release version from Cargo.toml'
    }
    return $match.Groups[1].Value
}

function Get-CleanMountRegistry {
    param([string]$HomePath)

    $registryPath = Join-Path $HomePath 'run\providers\winfsp-mounts.json'
    if (-not (Test-Path -LiteralPath $registryPath -PathType Leaf)) {
        return @()
    }
    return @((Get-Content -LiteralPath $registryPath -Raw | ConvertFrom-Json).mounts)
}

function Assert-ProcessesDrained {
    param([string[]]$ProcessNames, [string]$Stage)

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $remaining = @(Get-Process -Name $ProcessNames -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) {
            Write-Host "Astrid processes drained after $stage"
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)

    $paths = @($remaining | ForEach-Object {
        $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($_.Id)"
        "$($_.Id) $($process.ExecutablePath)"
    })
    throw "Astrid processes survived $stage : $($paths -join '; ')"
}

function Assert-ExtractedProcess {
    param([string]$ExtractionRoot, [string]$ProcessName, [string]$Stage)

    $prefix = $ExtractionRoot.TrimEnd('\') + '\'
    $processes = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) {
        throw "$ProcessName was not running during $stage"
    }
    foreach ($process in $processes) {
        $record = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process.Id)"
        if (-not $record.ExecutablePath -or
            -not $record.ExecutablePath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "$ProcessName did not execute from the extracted release root during ${stage}: $($record.ExecutablePath)"
        }
    }
}

function Assert-PrivateInstallAcl {
    param([string]$InstallRoot)

    $acl = Get-Acl -LiteralPath $InstallRoot
    if (-not $acl.AreAccessRulesProtected) {
        throw 'installed Astrid directory inherited its ACL'
    }

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @(
        $currentUser,
        'S-1-5-18',
        'S-1-5-32-544'
    )
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $sid = Get-SidValue -Identity $rule.IdentityReference
        if ($allowed -notcontains $sid) {
            throw "installed Astrid directory exposes content to '$sid'"
        }
    }
    foreach ($sid in $allowed) {
        $fullControl = @($acl.Access | Where-Object {
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            (Get-SidValue -Identity $_.IdentityReference) -eq $sid -and
            ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0
        })
        if ($fullControl.Count -eq 0) {
            throw "installed Astrid directory lacks full control for '$sid'"
        }
    }
}

function Copy-RunDiagnostics {
    param([string]$HomePath, [string]$DiagnosticsPath)

    $logRoot = Join-Path $HomePath 'log'
    if (Test-Path -LiteralPath $logRoot) {
        Copy-Item -LiteralPath $logRoot -Destination (Join-Path $DiagnosticsPath 'astrid-log') -Recurse -Force
    }
}

function Save-CommandOutput {
    param([string]$Path, [object]$Value)

    $Value | Out-String | Set-Content -LiteralPath $Path -Encoding ascii
}

$certRoot = $env:CERT_ROOT
$astridHome = $env:ASTRID_HOME
$diagnostics = $env:DIAGNOSTICS
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$expectedPrefix = Join-Path ([System.IO.Path]::GetFullPath($env:RUNNER_TEMP)) 'windows-archive-cert-'
if (-not ([System.IO.Path]::GetFullPath($certRoot)).StartsWith(
        $expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "certification root is outside the workflow throwaway boundary: $certRoot"
}
if (-not ([System.IO.Path]::GetFullPath($astridHome)).StartsWith(
        [System.IO.Path]::GetFullPath($certRoot), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "ASTRID_HOME is outside the throwaway certification root: $astridHome"
}
if ([string]::IsNullOrWhiteSpace($astridHome)) {
    throw 'ASTRID_HOME is required for archive certification'
}

Push-Location $repositoryRoot
$extracted = $false
$started = $false
$mounted = $false
$mountId = ''
$mountpoint = Join-Path $certRoot 'astrid-mount'
$extractRoot = Join-Path $certRoot 'extracted'
$installRoot = Join-Path $certRoot 'installed'
$processNames = @('astrid', 'astrid-daemon', 'astrid-storage-provider-winfsp')
$transcript = Join-Path $diagnostics 'certification-transcript.txt'
$mountedFile = $null
$transcriptStarted = $false
$reader = $null

try {
    New-Item -ItemType Directory -Path $certRoot, $astridHome, $diagnostics -Force | Out-Null
    Start-Transcript -LiteralPath $transcript | Out-Null
    $transcriptStarted = $true

    $sourceHead = (git rev-parse 'HEAD^{commit}').Trim()
    if ($ExpectedSourceCommit -and $sourceHead -ne $ExpectedSourceCommit) {
        throw "certification source moved: expected $ExpectedSourceCommit, found $sourceHead"
    }
    $dirty = @(git status --porcelain)
    if ($dirty.Count -ne 0) {
        throw "certification checkout is dirty: $($dirty -join '; ')"
    }

    $version = Get-ExpectedVersion
    $expectedArchive = "astrid-$version-x86_64-pc-windows-msvc.tar.gz"
    $archiveName = [System.IO.Path]::GetFileName($ArchivePath)
    if ($archiveName -ne $expectedArchive) {
        throw "archive name does not bind version and target: $archiveName (expected $expectedArchive)"
    }
    $archiveSha256 = Get-Sha256 -Path $ArchivePath
    if ($archiveSha256 -ne $ExpectedArchiveSha256) {
        throw "archive SHA-256 changed before extraction: $archiveSha256"
    }
    $unexpectedProcesses = @(Get-Process -Name $processNames -ErrorAction SilentlyContinue)
    if ($unexpectedProcesses.Count -ne 0) {
        throw 'Astrid processes were already present before archive certification'
    }

    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
    tar -xzf $ArchivePath -C $extractRoot
    $extractionDirectories = @(
        Get-ChildItem -LiteralPath $extractRoot -Directory -Force |
            Where-Object { $_.Name -like 'astrid-*-x86_64-pc-windows-msvc' }
    )
    if ($extractionDirectories.Count -ne 1) {
        throw "archive extraction did not produce one target-bound root: $($extractionDirectories.Count)"
    }
    $releaseRoot = Join-Path $extractRoot $extractionDirectories[0].Name
    $redirected = @(
        Get-ChildItem -LiteralPath $releaseRoot -Recurse -Force |
            Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 }
    )
    if ($redirected.Count -ne 0) {
        throw 'the extracted release archive contains a redirected member'
    }

    $trustedNames = @(
        'astrid.exe',
        'astrid-daemon.exe',
        'astrid-build.exe',
        'astrid-emit.exe',
        'astrid-storage-provider-winfsp.exe',
        'winfsp-x64.dll',
        'winfsp-2.1.25156.msi',
        'install-windows.ps1',
        'uninstall-windows.ps1'
    )
    $bytesManifest = [ordered]@{}
    foreach ($name in $trustedNames) {
        $extractedPath = Join-Path $releaseRoot $name
        Assert-RegularFile -Path $extractedPath -Description "extracted $name"
        $bytesManifest[$name] = Get-Sha256 -Path $extractedPath
    }
    if ($bytesManifest['winfsp-2.1.25156.msi'] -ne
        '073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A') {
        throw 'extracted WinFsp MSI does not match the trusted pinned digest'
    }
    foreach ($scriptName in @('install-windows.ps1', 'uninstall-windows.ps1')) {
        $sourceScript = Join-Path $repositoryRoot "scripts\$scriptName"
        Assert-SameFileBytes -Expected $sourceScript -Actual (Join-Path $releaseRoot $scriptName) `
            -Description "$scriptName trusted source bytes"
    }
    ($bytesManifest | ConvertTo-Json -Depth 3) |
        Set-Content -LiteralPath (Join-Path $diagnostics 'archive-bytes.sha256.json') -Encoding ascii

    & (Join-Path $releaseRoot 'install-windows.ps1') -InstallDir $installRoot
    $markerPath = Join-Path $installRoot 'astrid-install.json'
    Assert-RegularFile -Path $markerPath -Description 'private install marker'
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.product -ne 'astrid' -or
        $marker.winfsp_installed_by_astrid -ne $true -or
        $marker.winfsp_installer -ne 'winfsp-2.1.25156.msi') {
        throw 'private installation marker has unexpected contents'
    }
    Assert-PrivateInstallAcl -InstallRoot $installRoot
    $expectedInstalled = @($trustedNames + 'astrid-install.json')
    $installedItems = @(Get-ChildItem -LiteralPath $installRoot -File -Force)
    $installedNames = @($installedItems | ForEach-Object { $_.Name } | Sort-Object)
    $expectedSorted = @($expectedInstalled | Sort-Object)
    if (($installedNames -join "`n") -ne ($expectedSorted -join "`n")) {
        throw "private installation contains unauthorized files: $($installedNames -join ', ')"
    }
    foreach ($name in $trustedNames) {
        Assert-SameFileBytes -Expected (Join-Path $releaseRoot $name) `
            -Actual (Join-Path $installRoot $name) -Description "installed $name"
    }

    $winFspRegistry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\WinFsp' -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($winFspRegistry.InstallDir)) {
        throw 'installed WinFsp did not publish its installation root'
    }
    $systemWinFspDll = Join-Path $winFspRegistry.InstallDir 'bin\winfsp-x64.dll'
    Assert-RegularFile -Path $systemWinFspDll -Description 'installed WinFsp runtime DLL'
    $winFspVersion = [version](Get-Item -LiteralPath $systemWinFspDll).VersionInfo.FileVersion
    if ($winFspVersion -lt [version]'2.1.25156') {
        throw "installed WinFsp is older than the pinned runtime: $winFspVersion"
    }
    Assert-SameFileBytes -Expected (Join-Path $releaseRoot 'winfsp-x64.dll') `
        -Actual $systemWinFspDll -Description 'installed WinFsp runtime DLL'

    $cli = Join-Path $releaseRoot 'astrid.exe'
    Push-Location $certRoot
    & $cli --principal default start
    $started = $true
    Assert-ExtractedProcess -ExtractionRoot $releaseRoot -ProcessName 'astrid-daemon' `
        -Stage 'daemon startup'

    $mountOutput = (& $cli --principal default storage mount --as default --read-write $mountpoint 2>&1 | Out-String).Trim()
    Save-CommandOutput -Path (Join-Path $diagnostics 'storage-mount.log') -Value $mountOutput
    Write-Host $mountOutput
    $mountMatch = [regex]::Match($mountOutput, '^mounted ([0-9a-f-]{36}) at ')
    if (-not $mountMatch.Success) {
        throw "storage mount did not return a mounted identity: $mountOutput"
    }
    $mountId = $mountMatch.Groups[1].Value
    $mounted = $true
    Assert-ExtractedProcess -ExtractionRoot $releaseRoot -ProcessName 'astrid-daemon' `
        -Stage 'mounted volume'
    Assert-ExtractedProcess -ExtractionRoot $releaseRoot `
        -ProcessName 'astrid-storage-provider-winfsp' -Stage 'mounted volume'

    $sentinel = "windows-archive-cert-$([guid]::NewGuid().ToString('N'))"
    $mountedFile = Join-Path $mountpoint 'certification.txt'
    Set-Content -LiteralPath $mountedFile -Value $sentinel -NoNewline -Encoding ascii
    $firstRead = Get-Content -LiteralPath $mountedFile -Raw
    if ($firstRead -ne $sentinel) {
        throw 'first read from the mounted release volume returned unexpected bytes'
    }

    $reopenStream = [System.IO.File]::Open(
        $mountedFile,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $reader = [System.IO.StreamReader]::new($reopenStream)
        $reopened = $reader.ReadToEnd()
        if ($reopened -ne $sentinel) {
            throw 'reopened read from the mounted release volume returned unexpected bytes'
        }
    } finally {
        if ($reader) {
            $reader.Dispose()
        }
        $reopenStream.Dispose()
    }

    $syncOutput = (& $cli --principal default storage sync $mountpoint 2>&1 | Out-String).Trim()
    Save-CommandOutput -Path (Join-Path $diagnostics 'storage-sync.log') -Value $syncOutput
    if ($syncOutput -ne "synced $mountId") {
        throw "storage sync did not acknowledge the certification mount: $syncOutput"
    }
    $statusOutput = (& $cli --principal default storage status $mountpoint 2>&1 | Out-String).Trim()
    Save-CommandOutput -Path (Join-Path $diagnostics 'storage-status.log') -Value $statusOutput
    Write-Host $statusOutput
    if ($statusOutput -notlike "mount $mountId at $mountpoint*" -or
        $statusOutput -notlike '*ReadWrite*' -or
        $statusOutput -notlike '*dirty=False*') {
        throw "storage status did not show a clean read-write certification mount: $statusOutput"
    }

    $unmountOutput = (& $cli --principal default storage unmount $mountpoint 2>&1 | Out-String).Trim()
    Save-CommandOutput -Path (Join-Path $diagnostics 'storage-unmount.log') -Value $unmountOutput
    if ($unmountOutput -ne "unmounted $mountId") {
        throw "storage unmount did not acknowledge the certification mount: $unmountOutput"
    }
    $mounted = $false
    if (Test-Path -LiteralPath $mountpoint) {
        throw 'provider-created Windows mountpoint survived unmount'
    }
    Assert-ProcessesDrained -ProcessNames @('astrid-storage-provider-winfsp') -Stage 'volume unmount'

    & $cli --principal default stop
    $started = $false
    Assert-ProcessesDrained -ProcessNames $processNames -Stage 'daemon stop'
    $remainingMounts = Get-CleanMountRegistry -HomePath $astridHome
    if ($remainingMounts.Count -ne 0) {
        throw "WinFsp provider registry retained a mount after unmount: $($remainingMounts.Count)"
    }
    $remainingControls = @(
        Get-ChildItem -LiteralPath (Join-Path $astridHome 'run\providers') -Filter '*.control' -Force -ErrorAction SilentlyContinue
    )
    if ($remainingControls.Count -ne 0) {
        throw "WinFsp provider control endpoints survived unmount: $($remainingControls.Count)"
    }

    & (Join-Path $releaseRoot 'uninstall-windows.ps1') -InstallDir $installRoot
    if (Test-Path -LiteralPath $installRoot) {
        throw 'private Astrid installation survived uninstall'
    }
    Assert-ProcessesDrained -ProcessNames $processNames -Stage 'uninstall'

    $winFspAfterUninstall = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\WinFsp' -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($winFspAfterUninstall.InstallDir) -or
        -not (Test-Path -LiteralPath (Join-Path $winFspAfterUninstall.InstallDir 'bin\winfsp-x64.dll') -PathType Leaf)) {
        throw 'bundled uninstall removed the authorized shared WinFsp runtime'
    }

    $receipt = [ordered]@{
        result = 'passed'
        source_commit = $sourceHead
        archive = $archiveName
        archive_sha256 = $archiveSha256
        mount_id = $mountId
        winfsp_version = $winFspVersion.ToString()
    }
    ($receipt | ConvertTo-Json -Depth 3) |
        Set-Content -LiteralPath (Join-Path $diagnostics 'certification-receipt.json') -Encoding ascii
    Write-Host "Windows x86_64 release archive certification passed: $archiveSha256"
} finally {
    if (-not $mounted -and $mountedFile -and -not (Test-Path -LiteralPath $mountedFile)) {
        Set-Content -LiteralPath (Join-Path $diagnostics 'post-unmount.txt') -Value 'absent' -Encoding ascii
    }
    $copyStatus = 0
    if ($mounted -and $releaseRoot -and (Test-Path -LiteralPath $releaseRoot)) {
        try {
            $cleanupOutput = (& (Join-Path $releaseRoot 'astrid.exe') --principal default storage unmount $mountpoint 2>&1 | Out-String)
            Write-Host $cleanupOutput
        } catch {
            Write-Warning "certification cleanup mount failed: $_"
            $copyStatus = 1
        }
    }
    if ($started -and $releaseRoot -and (Test-Path -LiteralPath $releaseRoot)) {
        try {
            & (Join-Path $releaseRoot 'astrid.exe') --principal default stop
        } catch {
            Write-Warning "certification cleanup stop failed: $_"
            $copyStatus = 1
        }
    }
    Assert-ProcessesDrained -ProcessNames $processNames -Stage 'failure cleanup'
    if ($astridHome -and (Test-Path -LiteralPath $astridHome)) {
        try {
            Copy-RunDiagnostics -HomePath $astridHome -DiagnosticsPath $diagnostics
        } catch {
            Write-Warning "could not copy runtime diagnostics: $_"
            $copyStatus = 1
        }
    }
    if ($transcriptStarted) {
        try {
            Stop-Transcript | Out-Null
        } catch {
        }
    }
    Pop-Location
    if ($copyStatus -ne 0) {
        throw 'certification cleanup could not preserve all diagnostics or drain all processes'
    }
}
