param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [string]$CapsuleSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$binaryRoot = Join-Path $env:GITHUB_WORKSPACE "target\$Target\debug"
$astrid = Join-Path $binaryRoot "astrid.exe"
$daemon = Join-Path $binaryRoot "astrid-daemon.exe"
$builder = Join-Path $binaryRoot "astrid-build.exe"
if (-not (Test-Path -LiteralPath $astrid -PathType Leaf)) {
    throw "missing lifecycle CLI binary: $astrid"
}
if (-not (Test-Path -LiteralPath $daemon -PathType Leaf)) {
    throw "missing lifecycle daemon binary: $daemon"
}
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) {
    throw "missing lifecycle capsule builder: $builder"
}
if (-not (Test-Path -LiteralPath $CapsuleSource -PathType Container)) {
    throw "missing compatible CLI uplink capsule source: $CapsuleSource"
}

$testRoot = Join-Path $env:LOCALAPPDATA ("AstridLifecycleCi-" + [guid]::NewGuid().ToString("N"))
$astridHome = Join-Path $testRoot "home"
$workspace = Join-Path $testRoot "workspace"
$pidPath = Join-Path $astridHome "run\system.pid"
$readyPath = Join-Path $astridHome "run\system.ready"
$tokenPath = Join-Path $astridHome "run\system.token"
$daemonPid = $null
$daemonProcess = $null
$completed = $false
$locationPushed = $false
$failureArtifacts = Join-Path $env:RUNNER_TEMP ("windows-daemon-lifecycle-" + $Target)

$env:ASTRID_HOME = $astridHome
$env:ASTRID_WORKSPACE_STATE_DIR = ".astrid-ci"

function Invoke-Astrid {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    $output = & $astrid @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "astrid $($Arguments -join ' ') failed with exit code $LASTEXITCODE`n$output"
    }
    return $output
}

try {
    $installOutput = Invoke-Astrid capsule install $CapsuleSource --yes --approve-untrusted
    $installOutput | Write-Host
    New-Item -ItemType Directory -Path $workspace -Force | Out-Null
    Push-Location $workspace
    $locationPushed = $true

    $startOutput = Invoke-Astrid start
    if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) {
        throw "astrid start returned success without a daemon PID file`n$startOutput"
    }
    if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
        throw "astrid start returned success without a readiness file`n$startOutput"
    }
    if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
        throw "astrid start returned success without a session-token file`n$startOutput"
    }

    $daemonPid = [uint32](Get-Content -LiteralPath $pidPath -TotalCount 1).Trim()
    $daemonProcess = Get-Process -Id $daemonPid -ErrorAction Stop
    $null = $daemonProcess.Handle
    if ($daemonProcess.HasExited) {
        throw "astrid start returned success but PID $daemonPid already exited"
    }
    $actualDaemon = [IO.Path]::GetFullPath($daemonProcess.Path)
    $expectedDaemon = [IO.Path]::GetFullPath($daemon)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actualDaemon, $expectedDaemon)) {
        throw "PID $daemonPid does not belong to the test daemon: $actualDaemon"
    }

    $statusOutput = Invoke-Astrid status
    if (-not $statusOutput.Contains("Astrid daemon (PID $daemonPid")) {
        throw "authenticated status did not report the started daemon`n$statusOutput"
    }

    $stopOutput = Invoke-Astrid stop
    if (-not $daemonProcess.HasExited) {
        throw "astrid stop returned success before PID $daemonPid exited`n$stopOutput"
    }
    if (Test-Path -LiteralPath $pidPath) {
        throw "astrid stop left the daemon PID file behind"
    }
    if (Test-Path -LiteralPath $readyPath) {
        throw "astrid stop left the daemon readiness file behind"
    }
    if (Test-Path -LiteralPath $tokenPath) {
        throw "astrid stop left the daemon session-token file behind"
    }

    $stoppedStatus = Invoke-Astrid status
    if (-not $stoppedStatus.Contains("No Astrid daemon is running.")) {
        throw "post-stop status did not confirm daemon absence`n$stoppedStatus"
    }
    $completed = $true
}
finally {
    try {
        try {
            if (
                (Test-Path -LiteralPath $pidPath) -or
                ($null -ne $daemonProcess -and -not $daemonProcess.HasExited)
            ) {
                & $astrid stop 2>&1 | Out-String | Write-Host
            }
        }
        catch {
            Write-Warning "graceful lifecycle cleanup failed: $_"
        }

        if ($null -ne $daemonProcess -and -not $daemonProcess.HasExited) {
            try {
                $daemonProcess.Kill($true)
            }
            catch {
                if (-not $daemonProcess.HasExited) {
                    throw
                }
            }
            if (-not $daemonProcess.WaitForExit(15000)) {
                throw "forced cleanup did not terminate test daemon PID $daemonPid"
            }
        }
    }
    finally {
        if (-not $completed) {
            try {
                $bootLog = Join-Path $astridHome "log\daemon-boot.log"
                if (Test-Path -LiteralPath $bootLog -PathType Leaf) {
                    New-Item -ItemType Directory -Path $failureArtifacts -Force | Out-Null
                    Copy-Item -LiteralPath $bootLog -Destination $failureArtifacts -Force
                }
            }
            catch {
                Write-Warning "could not preserve lifecycle failure artifacts: $_"
            }
        }
        if ($locationPushed) {
            Pop-Location
        }
        $processGone = $null -eq $daemonProcess -or $daemonProcess.HasExited
        if (
            $processGone -and
            -not (Test-Path -LiteralPath $pidPath) -and
            -not (Test-Path -LiteralPath $readyPath) -and
            -not (Test-Path -LiteralPath $tokenPath) -and
            (Test-Path -LiteralPath $testRoot)
        ) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force
        }
    }
}
