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
$ephemeralPid = $null
$ephemeralDaemonProcess = $null
$ephemeralClient = $null
$ephemeralClientStarted = $false
$completed = $false
$locationPushed = $false
$failureArtifacts = Join-Path $env:RUNNER_TEMP ("windows-daemon-lifecycle-" + $Target)

$env:ASTRID_HOME = $astridHome
$env:ASTRID_WORKSPACE_STATE_DIR = ".astrid-ci"

function Invoke-Astrid {
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
        [string[]]$Arguments,
        [int]$TimeoutSeconds = 120,
        [switch]$AllowNonzeroExit
    )

    $displayCommand = "astrid $($Arguments -join ' ')"
    Write-Host "Running $displayCommand"

    $location = Get-Location
    if ($location.Provider.Name -ne "FileSystem") {
        throw "$displayCommand requires a filesystem working directory"
    }
    $processInfo = [Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = $astrid
    $processInfo.WorkingDirectory = $location.ProviderPath
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $processInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $processInfo
    try {
        if (-not $process.Start()) {
            throw "failed to start $displayCommand"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                $process.Kill($true)
            }
            catch {
                throw "$displayCommand timed out after $TimeoutSeconds seconds and could not terminate its process tree: $_"
            }
            if (-not $process.WaitForExit(15000)) {
                throw "$displayCommand timed out after $TimeoutSeconds seconds and did not exit within 15 seconds after Kill(entireProcessTree)"
            }
            $streamsDrained = [Threading.Tasks.Task]::WaitAll(
                [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask),
                10000
            )
            if (-not $streamsDrained) {
                throw "$displayCommand timed out after $TimeoutSeconds seconds; its process exited after termination, but inherited redirected output handles remained open"
            }
            $timeoutOutput = "stdout:`n$($stdoutTask.Result)`nstderr:`n$($stderrTask.Result)"
            throw "$displayCommand timed out after $TimeoutSeconds seconds`n$timeoutOutput"
        }
        if (-not [Threading.Tasks.Task]::WaitAll(
            [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask),
            10000
        )) {
            throw "$displayCommand exited but inherited redirected output handles remained open"
        }

        $output = "stdout:`n$($stdoutTask.Result)`nstderr:`n$($stderrTask.Result)"
        if ($AllowNonzeroExit) {
            return [pscustomobject]@{
                ExitCode = $process.ExitCode
                Output = $output
            }
        }
        if ($process.ExitCode -ne 0) {
            throw "$displayCommand failed with exit code $($process.ExitCode)`n$output"
        }
        return $output
    }
    finally {
        $process.Dispose()
    }
}

try {
    $installOutput = Invoke-Astrid -TimeoutSeconds 600 capsule install $CapsuleSource --yes --approve-untrusted
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

    # Persistent mode must survive the post-readiness fallback that owns only
    # auto-spawned ephemeral daemons.
    Start-Sleep -Seconds 7
    $daemonProcess.Refresh()
    if ($daemonProcess.HasExited) {
        throw "persistent daemon PID $daemonPid exited while idle"
    }
    $persistentStatus = Invoke-Astrid status
    if (-not $persistentStatus.Contains("Astrid daemon (PID $daemonPid")) {
        throw "persistent daemon did not survive its idle window`n$persistentStatus"
    }

    # An authenticated principal without system:shutdown must receive a
    # kernel denial. The CLI must not reinterpret that denial as a transport
    # failure and enter identity-gated process termination recovery.
    $null = Invoke-Astrid agent create lifecycle-shutdown-denied --group agent -y
    $deniedStopResult = Invoke-Astrid `
        -TimeoutSeconds 30 `
        -AllowNonzeroExit `
        -Arguments @("--principal", "lifecycle-shutdown-denied", "stop")
    $deniedStopOutput = $deniedStopResult.Output
    $deniedStopExit = $deniedStopResult.ExitCode
    if ($deniedStopExit -eq 0) {
        throw "restricted principal unexpectedly stopped daemon PID $daemonPid`n$deniedStopOutput"
    }
    if (-not $deniedStopOutput.Contains("daemon rejected shutdown")) {
        throw "restricted principal stop did not report an authenticated denial`n$deniedStopOutput"
    }
    $daemonProcess.Refresh()
    if ($daemonProcess.HasExited) {
        throw "authenticated shutdown denial incorrectly terminated daemon PID $daemonPid"
    }
    $recordedPid = [uint32](Get-Content -LiteralPath $pidPath -TotalCount 1).Trim()
    if ($recordedPid -ne $daemonPid) {
        throw "authenticated shutdown denial replaced daemon PID $daemonPid with $recordedPid"
    }
    $postDenialStatus = Invoke-Astrid status
    if (-not $postDenialStatus.Contains("Astrid daemon (PID $daemonPid")) {
        throw "daemon stopped answering after authenticated shutdown denial`n$postDenialStatus"
    }

    $stopOutput = Invoke-Astrid stop
    if (-not $daemonProcess.WaitForExit(15000)) {
        $daemonProcess.Refresh()
        throw "astrid stop returned success before PID $daemonPid exited`n$stopOutput"
    }
    $daemonProcess.Refresh()
    if (-not $daemonProcess.HasExited) {
        throw "astrid stop returned success but PID $daemonPid still appears live after WaitForExit`n$stopOutput"
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

    # Model the real agent integration: `astrid mcp serve` auto-spawns an
    # ephemeral daemon, holds one authenticated lifecycle lease, then releases
    # it when its stdio client closes. The daemon must exit promptly on that
    # final disconnect rather than waiting for an idle timeout.
    $clientInfo = [Diagnostics.ProcessStartInfo]::new()
    $clientInfo.FileName = $astrid
    $clientInfo.WorkingDirectory = $workspace
    $clientInfo.UseShellExecute = $false
    $clientInfo.CreateNoWindow = $true
    $clientInfo.RedirectStandardInput = $true
    $clientInfo.RedirectStandardOutput = $true
    $clientInfo.RedirectStandardError = $true
    $clientInfo.ArgumentList.Add("--principal")
    $clientInfo.ArgumentList.Add("anonymous")
    $clientInfo.ArgumentList.Add("mcp")
    $clientInfo.ArgumentList.Add("serve")

    $ephemeralClient = [Diagnostics.Process]::new()
    $ephemeralClient.StartInfo = $clientInfo
    if (-not $ephemeralClient.Start()) {
        throw "failed to start the ephemeral MCP lifecycle client"
    }
    $ephemeralClientStarted = $true
    $clientErrorTask = $ephemeralClient.StandardError.ReadToEndAsync()

    $ephemeralDeadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) {
        if ($ephemeralClient.HasExited) {
            $clientOutputTask = $ephemeralClient.StandardOutput.ReadToEndAsync()
            if (-not [Threading.Tasks.Task]::WaitAll(
                [Threading.Tasks.Task[]]@($clientOutputTask, $clientErrorTask),
                10000
            )) {
                throw "ephemeral MCP client exited before daemon readiness and inherited redirected output handles remained open"
            }
            $clientOutput = $clientOutputTask.Result
            $clientError = $clientErrorTask.Result
            throw "ephemeral MCP client exited before daemon readiness (exit $($ephemeralClient.ExitCode))`n$clientOutput`n$clientError"
        }
        if ([DateTime]::UtcNow -ge $ephemeralDeadline) {
            throw "ephemeral daemon did not publish its PID within 60 seconds"
        }
        Start-Sleep -Milliseconds 100
    }

    $ephemeralPid = [uint32](Get-Content -LiteralPath $pidPath -TotalCount 1).Trim()
    $ephemeralDaemonProcess = Get-Process -Id $ephemeralPid -ErrorAction Stop
    $null = $ephemeralDaemonProcess.Handle
    if ($ephemeralDaemonProcess.HasExited) {
        throw "ephemeral daemon PID $ephemeralPid exited before its MCP client disconnected"
    }

    $initializeFrame = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"windows-lifecycle-smoke","version":"0"}}}'
    $initializedFrame = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    $clientOutputLines = [System.Collections.Generic.List[string]]::new()
    $ephemeralClient.StandardInput.WriteLine($initializeFrame)
    $ephemeralClient.StandardInput.Flush()

    $initializeResponse = $null
    $initializeDeadline = [DateTime]::UtcNow.AddSeconds(15)
    while ($null -eq $initializeResponse) {
        $remaining = [int][Math]::Max(
            1,
            ($initializeDeadline - [DateTime]::UtcNow).TotalMilliseconds
        )
        $responseTask = $ephemeralClient.StandardOutput.ReadLineAsync()
        if (-not $responseTask.Wait($remaining)) {
            throw "ephemeral MCP initialize response timed out"
        }
        $line = $responseTask.Result
        if ($null -eq $line) {
            throw "ephemeral MCP client closed stdout before initialize completed"
        }
        $clientOutputLines.Add($line)
        $frame = $line | ConvertFrom-Json
        if ($null -ne $frame.PSObject.Properties["id"] -and $frame.id -eq 1) {
            $initializeResponse = $frame
        }
    }
    if (
        $null -eq $initializeResponse -or
        $null -eq $initializeResponse.PSObject.Properties["result"]
    ) {
        throw "ephemeral MCP client did not complete its daemon-backed initialize handshake"
    }

    $ephemeralClient.StandardInput.WriteLine($initializedFrame)
    $ephemeralClient.StandardInput.Flush()
    $ephemeralDaemonProcess.Refresh()
    if ($ephemeralClient.HasExited -or $ephemeralDaemonProcess.HasExited) {
        throw "ephemeral daemon did not remain leased after the MCP initialize handshake"
    }

    # Keep both redirected pipes draining before waiting on process exit.
    $remainingOutputTask = $ephemeralClient.StandardOutput.ReadToEndAsync()
    $ephemeralClient.StandardInput.Close()
    if (-not $ephemeralClient.WaitForExit(15000)) {
        throw "ephemeral MCP client did not exit after stdin closed"
    }
    if (-not [Threading.Tasks.Task]::WaitAll(
        [Threading.Tasks.Task[]]@($remainingOutputTask, $clientErrorTask),
        10000
    )) {
        throw "ephemeral MCP client exited but inherited redirected output handles remained open"
    }
    $remainingOutput = $remainingOutputTask.Result
    $clientError = $clientErrorTask.Result
    $clientOutput = ($clientOutputLines -join "`n") + "`n" + $remainingOutput
    if ($ephemeralClient.ExitCode -ne 0) {
        throw "ephemeral MCP client failed with exit code $($ephemeralClient.ExitCode)`n$clientOutput`n$clientError"
    }
    if (-not $ephemeralDaemonProcess.WaitForExit(10000)) {
        throw "ephemeral daemon PID $ephemeralPid did not exit promptly after its final client disconnected"
    }
    if (Test-Path -LiteralPath $pidPath) {
        throw "ephemeral daemon left its PID file behind"
    }
    if (Test-Path -LiteralPath $readyPath) {
        throw "ephemeral daemon left its readiness file behind"
    }
    if (Test-Path -LiteralPath $tokenPath) {
        throw "ephemeral daemon left its session-token file behind"
    }

    $completed = $true
}
finally {
    try {
        if ($ephemeralClientStarted -and -not $ephemeralClient.HasExited) {
            try {
                $ephemeralClient.StandardInput.Close()
                if (-not $ephemeralClient.WaitForExit(5000)) {
                    $ephemeralClient.Kill($true)
                    if (-not $ephemeralClient.WaitForExit(15000)) {
                        Write-Warning "forced cleanup did not terminate the ephemeral MCP client"
                    }
                }
            }
            catch {
                Write-Warning "could not stop ephemeral MCP client during cleanup: $_"
            }
        }

        try {
            if (
                (Test-Path -LiteralPath $pidPath) -or
                ($null -ne $daemonProcess -and -not $daemonProcess.HasExited) -or
                ($null -ne $ephemeralDaemonProcess -and -not $ephemeralDaemonProcess.HasExited)
            ) {
                Invoke-Astrid -TimeoutSeconds 30 stop | Write-Host
            }
        }
        catch {
            Write-Warning "graceful lifecycle cleanup failed: $_"
        }

        if ($null -ne $daemonProcess -and -not $daemonProcess.HasExited) {
            try {
                $daemonProcess.Kill($true)
                if (-not $daemonProcess.WaitForExit(15000)) {
                    Write-Warning "forced cleanup did not terminate test daemon PID $daemonPid"
                }
            }
            catch {
                Write-Warning "could not force-clean persistent daemon PID ${daemonPid}: $_"
            }
        }
        if ($null -ne $ephemeralDaemonProcess -and -not $ephemeralDaemonProcess.HasExited) {
            try {
                $ephemeralDaemonProcess.Kill($true)
                if (-not $ephemeralDaemonProcess.WaitForExit(15000)) {
                    Write-Warning "forced cleanup did not terminate ephemeral daemon PID $ephemeralPid"
                }
            }
            catch {
                Write-Warning "could not force-clean ephemeral daemon PID ${ephemeralPid}: $_"
            }
        }
    }
    catch {
        Write-Warning "unexpected lifecycle cleanup failure: $_"
    }

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
        try {
            Pop-Location
        }
        catch {
            Write-Warning "could not restore the lifecycle test location: $_"
        }
    }

    $persistentGone = $true
    $ephemeralGone = $true
    try {
        if ($null -ne $daemonProcess) {
            $persistentGone = $daemonProcess.HasExited
        }
        if ($null -ne $ephemeralDaemonProcess) {
            $ephemeralGone = $ephemeralDaemonProcess.HasExited
        }
    }
    catch {
        $persistentGone = $false
        $ephemeralGone = $false
        Write-Warning "could not confirm lifecycle process cleanup: $_"
    }
    try {
        if (
            $persistentGone -and
            $ephemeralGone -and
            -not (Test-Path -LiteralPath $pidPath) -and
            -not (Test-Path -LiteralPath $readyPath) -and
            -not (Test-Path -LiteralPath $tokenPath) -and
            (Test-Path -LiteralPath $testRoot)
        ) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force
        }
    }
    catch {
        Write-Warning "could not remove lifecycle test root: $_"
    }
}
