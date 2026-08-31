# Windows-only certification harness for the staged kernel storage_mount tests.
# The fixed guards bound one aggregate run and diagnostic retries; they are not product policy.
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TestExecutable,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Provider,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TestFilter,

    [int]$AggregateTimeoutSeconds = 600,
    [int]$DiagnosticTimeoutSeconds = 120,
    [int]$ListTimeoutSeconds = 60,
    [int]$TeardownTimeoutSeconds = 30,
    [int]$HeartbeatSeconds = 30
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

if ($AggregateTimeoutSeconds -le 0 -or
    $DiagnosticTimeoutSeconds -le 0 -or
    $ListTimeoutSeconds -le 0 -or
    $TeardownTimeoutSeconds -le 0 -or
    $HeartbeatSeconds -le 0) {
    throw "all harness timeouts and the heartbeat interval must be positive"
}

$providerProcessName = [System.IO.Path]::GetFileNameWithoutExtension($Provider)
if ($providerProcessName -ne "astrid-storage-provider-winfsp") {
    throw "unexpected Windows process storage provider: $providerProcessName"
}

function Wait-ForOutputFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Test-Path -LiteralPath $Path -PathType Leaf) -and $Process.HasExited) {
            return
        }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return
        }
        if ($Process.HasExited) {
            return
        }
        Start-Sleep -Milliseconds 50
    }
}

function Read-OutputChunk {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ref]$Offset
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $length = (Get-Item -LiteralPath $Path).Length
    if ($length -le [long]$Offset.Value) {
        return $null
    }

    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    try {
        $null = $stream.Seek([long]$Offset.Value, [System.IO.SeekOrigin]::Begin)
        $remaining = [int][Math]::Min($length - [long]$Offset.Value, 64KB)
        $bytes = [byte[]]::new($remaining)
        $read = 0
        while ($read -lt $remaining) {
            $count = $stream.Read($bytes, $read, $remaining - $read)
            if ($count -eq 0) {
                break
            }
            $read += $count
        }
        $Offset.Value = [long]$Offset.Value + $read
        if ($read -eq 0) {
            return $null
        }
        return [System.Text.Encoding]::UTF8.GetString($bytes, 0, $read)
    } finally {
        $stream.Dispose()
    }
}

function Wait-StreamingProcess {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$HeartbeatSeconds
    )

    $stdoutOffset = 0L
    $stderrOffset = 0L
    $lastSignal = $Process.StartTime.ToUniversalTime()
    $deadline = $lastSignal.AddSeconds($TimeoutSeconds)

    Wait-ForOutputFile -Path $StdoutPath -Process $Process
    Wait-ForOutputFile -Path $StderrPath -Process $Process

    while ($true) {
        if ($Process.WaitForExit(100)) {
            foreach ($chunk in @(
                Read-OutputChunk -Path $StdoutPath -Offset ([ref]$stdoutOffset)
                Read-OutputChunk -Path $StderrPath -Offset ([ref]$stderrOffset)
            )) {
                if ($chunk) {
                    Write-Host $chunk -NoNewline
                }
            }
            Write-Host ("[{0}] exit-code={1}" -f $DisplayName, $Process.ExitCode)
            return $true
        }

        $now = [DateTime]::UtcNow
        $hadOutput = $false
        foreach ($entry in @(
            @{ Label = "stdout"; Path = $StdoutPath; Offset = [ref]$stdoutOffset }
            @{ Label = "stderr"; Path = $StderrPath; Offset = [ref]$stderrOffset }
        )) {
            $chunk = Read-OutputChunk -Path $entry.Path -Offset $entry.Offset
            if ($chunk) {
                Write-Host ("[{0} {1}] " -f $DisplayName, $entry.Label) -NoNewline
                Write-Host $chunk -NoNewline
                $hadOutput = $true
            }
        }

        if ($hadOutput) {
            $lastSignal = $now
        } elseif (($now - $lastSignal).TotalSeconds -ge $HeartbeatSeconds) {
            $message = (
                "[{0}] heartbeat alive=true pid={1} elapsed-seconds={2:F0} " +
                "stdout-bytes={3} stderr-bytes={4}"
            ) -f (
                $DisplayName,
                $Process.Id,
                ($TimeoutSeconds - ($deadline - $now).TotalSeconds),
                $stdoutOffset,
                $stderrOffset
            )
            Write-Host $message
            $lastSignal = $now
        }

        if ($now -ge $deadline) {
            foreach ($chunk in @(
                Read-OutputChunk -Path $StdoutPath -Offset ([ref]$stdoutOffset)
                Read-OutputChunk -Path $StderrPath -Offset ([ref]$stderrOffset)
            )) {
                if ($chunk) {
                    Write-Host $chunk -NoNewline
                }
            }
            Write-Host ("[{0}] timeout after {1} seconds" -f $DisplayName, $TimeoutSeconds)
            return $false
        }
    }
}

function Get-ProcessTreeSnapshot {
    param([Parameter(Mandatory = $true)][int]$RootProcessId)

    $all = @(Get-CimInstance -ClassName Win32_Process)
    $children = @{}
    $byId = @{}
    foreach ($process in $all) {
        $byId[[int]$process.ProcessId] = $process
        $parent = [int]$process.ParentProcessId
        if (-not $children.ContainsKey($parent)) {
            $children[$parent] = [System.Collections.Generic.List[int]]::new()
        }
        $children[$parent].Add([int]$process.ProcessId)
    }

    $visited = @{}
    $rows = @()
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@{ Id = $RootProcessId; Depth = 0 })
    while ($stack.Count -gt 0) {
        $entry = $stack.Pop()
        $id = [int]$entry.Id
        if ($visited.ContainsKey($id)) {
            continue
        }
        $visited[$id] = $true
        $row = $byId[$id]
        $rows += [pscustomobject]@{
            Depth = [int]$entry.Depth
            ProcessId = $id
            ParentProcessId = if ($row) { [int]$row.ParentProcessId } else { $null }
            Name = if ($row) { [string]$row.Name } else { "<exited>" }
            ExecutablePath = if ($row) { [string]$row.ExecutablePath } else { "" }
            CommandLine = if ($row) { [string]$row.CommandLine } else { "" }
        }
        if ($children.ContainsKey($id)) {
            foreach ($childId in [System.Linq.Enumerable]::Reverse($children[$id])) {
                $stack.Push(@{ Id = $childId; Depth = [int]$entry.Depth + 1 })
            }
        }
    }
    return $rows
}

function Write-ProcessTreeSnapshot {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows
    )

    if ($Rows.Count -eq 0) {
        Write-Host "process tree: empty"
        return
    }
    foreach ($row in $Rows) {
        $indent = "  " * $row.Depth
        Write-Host ("{0}pid={1} parent={2} name={3} path={4}" -f `
            $indent, $row.ProcessId, $row.ParentProcessId, $row.Name, $row.ExecutablePath)
        if ($row.CommandLine) {
            Write-Host ("{0}  command-line={1}" -f $indent, $row.CommandLine)
        }
    }
}

function Stop-ProviderProcesses {
    param([Parameter(Mandatory = $true)][int]$TimeoutSeconds)

    $filter = "Name = 'astrid-storage-provider-winfsp.exe'"
    $survivors = @(Get-CimInstance -ClassName Win32_Process -Filter $filter)
    foreach ($survivor in $survivors) {
        Write-Host (
            "terminating surviving astrid-storage-provider-winfsp process " +
            "pid=$($survivor.ProcessId) parent=$($survivor.ParentProcessId)"
        )
        Stop-Process -Id ([int]$survivor.ProcessId) -Force -ErrorAction SilentlyContinue
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $survivors = @(Get-CimInstance -ClassName Win32_Process -Filter $filter)
        if ($survivors.Count -eq 0) {
            Write-Host "astrid-storage-provider-winfsp process teardown complete"
            return
        }
        Start-Sleep -Milliseconds 100
    }
    throw "astrid-storage-provider-winfsp processes survived the bounded teardown"
}

function Stop-OwnedProcessTree {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    if (-not $Process.HasExited) {
        $rows = Get-ProcessTreeSnapshot -RootProcessId $Process.Id
        Write-Host "owned process tree before termination:"
        Write-ProcessTreeSnapshot -Rows $rows
        $taskkill = Join-Path $env:SystemRoot "System32\taskkill.exe"
        & $taskkill /PID $Process.Id /T /F | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0 -and -not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "owned process already exited before termination"
    }

    Stop-ProviderProcesses -TimeoutSeconds $TimeoutSeconds
}

function Start-TestProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $stdoutPath = Join-Path $LogDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $LogDirectory "$Name.stderr.log"
    Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue

    $process = Start-Process `
        -FilePath $Executable `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -NoNewWindow `
        -PassThru
    return [pscustomobject]@{
        Process = $process
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    }
}

function Write-CompleteOutput {
    param(
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )

    Write-Host "=== complete aggregate stdout ==="
    if (Test-Path -LiteralPath $StdoutPath -PathType Leaf) {
        Get-Content -LiteralPath $StdoutPath -Raw | Write-Host
    }
    Write-Host "=== complete aggregate stderr ==="
    if (Test-Path -LiteralPath $StderrPath -PathType Leaf) {
        Get-Content -LiteralPath $StderrPath -Raw | Write-Host
    }
}

function Get-LastCompletedTest {
    param(
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )

    $text = ""
    foreach ($path in @($StdoutPath, $StderrPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $text += (Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue)
            $text += [Environment]::NewLine
        }
    }
    $completedMatches = [System.Text.RegularExpressions.Regex]::Matches(
        $text,
        '(?m)^test\s+(?<name>.+?)\s+\.\.\.\s+(?<result>ok|FAILED|ignored)\s*(?:\r|$)'
    )
    if ($completedMatches.Count -eq 0) {
        return $null
    }
    return [pscustomobject]@{
        Name = $completedMatches[$completedMatches.Count - 1].Groups["name"].Value
        Result = $completedMatches[$completedMatches.Count - 1].Groups["result"].Value
    }
}

function Get-TestList {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$TestFilter,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$TeardownTimeoutSeconds
    )

    $run = Start-TestProcess `
        -Executable $Executable `
        -Arguments @($TestFilter, "--", "--list", "--format", "terse") `
        -WorkingDirectory $WorkingDirectory `
        -LogDirectory $LogDirectory `
        -Name "storage-mount-list"
    $completed = Wait-StreamingProcess `
        -Process $run.Process `
        -StdoutPath $run.StdoutPath `
        -StderrPath $run.StderrPath `
        -DisplayName "test-list" `
        -TimeoutSeconds $TimeoutSeconds `
        -HeartbeatSeconds $HeartbeatSeconds
    if (-not $completed) {
        Stop-OwnedProcessTree -Process $run.Process -TimeoutSeconds $TeardownTimeoutSeconds
        throw "the storage_mount test-list process exceeded ${TimeoutSeconds} seconds"
    }
    if ($run.Process.ExitCode -ne 0) {
        throw "the storage_mount test-list process failed with exit code $($run.Process.ExitCode)"
    }
    Stop-ProviderProcesses -TimeoutSeconds $TeardownTimeoutSeconds

    $names = @()
    foreach ($line in @(Get-Content -LiteralPath $run.StdoutPath)) {
        if ($line -match '^(?<name>.+): test$') {
            $names += $Matches["name"]
        }
    }
    if ($names.Count -eq 0) {
        throw "the storage_mount test list did not contain any tests"
    }
    Write-Host ("pre-enumerated {0} storage_mount tests:" -f $names.Count)
    foreach ($name in $names) {
        Write-Host "  $name"
    }
    return $names
}

if (-not (Test-Path -LiteralPath $TestExecutable -PathType Leaf)) {
    throw "staged storage_mount executable is not a file: $TestExecutable"
}
if (-not (Test-Path -LiteralPath $Provider -PathType Leaf)) {
    throw "staged Windows process storage provider is not a file: $Provider"
}

$stage = (Get-Item -LiteralPath $TestExecutable).DirectoryName
$logDirectory = Join-Path $stage "storage-mount-harness-logs"

$tests = @(Get-TestList `
    -Executable $TestExecutable `
    -TestFilter $TestFilter `
    -WorkingDirectory $stage `
    -LogDirectory $logDirectory `
    -TimeoutSeconds $ListTimeoutSeconds `
    -TeardownTimeoutSeconds $TeardownTimeoutSeconds)

$run = Start-TestProcess `
    -Executable $TestExecutable `
    -Arguments @($TestFilter, "--", "--nocapture", "--test-threads=1") `
    -WorkingDirectory $stage `
    -LogDirectory $logDirectory `
    -Name "storage-mount-aggregate"
$aggregateStarted = [DateTime]::UtcNow
$completed = Wait-StreamingProcess `
    -Process $run.Process `
    -StdoutPath $run.StdoutPath `
    -StderrPath $run.StderrPath `
    -DisplayName "storage_mount aggregate" `
    -TimeoutSeconds $AggregateTimeoutSeconds `
    -HeartbeatSeconds $HeartbeatSeconds
$aggregateElapsed = (([DateTime]::UtcNow - $aggregateStarted).TotalSeconds)

if ($completed -and $run.Process.ExitCode -eq 0) {
    $message = (
        "storage_mount aggregate certification passed in {0:F1} seconds " +
        "with {1} pre-enumerated tests"
    ) -f $aggregateElapsed, $tests.Count
    Write-Host $message
    Stop-ProviderProcesses -TimeoutSeconds $TeardownTimeoutSeconds
    exit 0
}

if (-not $completed) {
    Stop-OwnedProcessTree -Process $run.Process -TimeoutSeconds $TeardownTimeoutSeconds
} else {
    Stop-ProviderProcesses -TimeoutSeconds $TeardownTimeoutSeconds
}

Write-Host ("aggregate elapsed-seconds={0:F1}" -f $aggregateElapsed)
Write-CompleteOutput -StdoutPath $run.StdoutPath -StderrPath $run.StderrPath
$lastCompleted = Get-LastCompletedTest -StdoutPath $run.StdoutPath -StderrPath $run.StderrPath
if ($lastCompleted) {
    Write-Host (
        "last completed test: {0} ({1})" -f $lastCompleted.Name, $lastCompleted.Result
    )
} else {
    Write-Host "last completed test: none observed"
}

Write-Host "staged paths:"
Write-Host "  test-executable=$TestExecutable"
Write-Host "  provider=$Provider"
Write-Host "  stage=$stage"
Write-Host "  logs=$logDirectory"

$firstDiagnosticTimeout = $null
Write-Host "DIAGNOSTIC ONLY: exact per-test isolation begins; this does not certify the aggregate suite."
foreach ($test in $tests) {
    Write-Host "START diagnostic isolation: $test"
    try {
        $diagnostic = Start-TestProcess `
            -Executable $TestExecutable `
            -Arguments @("--exact", $test, "--nocapture", "--test-threads=1") `
            -WorkingDirectory $stage `
            -LogDirectory $logDirectory `
            -Name ("diagnostic-" + ($test -replace '[^A-Za-z0-9_.-]', '_'))
        $diagnosticCompleted = Wait-StreamingProcess `
            -Process $diagnostic.Process `
            -StdoutPath $diagnostic.StdoutPath `
            -StderrPath $diagnostic.StderrPath `
            -DisplayName "diagnostic $test" `
            -TimeoutSeconds $DiagnosticTimeoutSeconds `
            -HeartbeatSeconds $HeartbeatSeconds
        if (-not $diagnosticCompleted) {
            Stop-OwnedProcessTree -Process $diagnostic.Process -TimeoutSeconds $TeardownTimeoutSeconds
            if (-not $firstDiagnosticTimeout) {
                $firstDiagnosticTimeout = $test
            }
        } else {
            Stop-ProviderProcesses -TimeoutSeconds $TeardownTimeoutSeconds
        }
    } catch {
        Write-Host "diagnostic isolation error for ${test}: $($_.Exception.Message)"
        if (Get-Variable -Name diagnostic -ErrorAction SilentlyContinue) {
            Stop-OwnedProcessTree -Process $diagnostic.Process -TimeoutSeconds $TeardownTimeoutSeconds
            if ((Get-Variable -Name diagnosticCompleted -ErrorAction SilentlyContinue) -and
                (-not $diagnosticCompleted)) {
                $diagnosticCompleted = $true
            }
        }
    } finally {
        Write-Host "END diagnostic isolation: $test"
    }
}

if (-not $completed) {
    if ($firstDiagnosticTimeout) {
        throw "storage_mount aggregate certification timed out; first isolated timeout was $firstDiagnosticTimeout"
    }
    throw "storage_mount aggregate certification timed out; no exact per-test isolation timed out"
}

throw "storage_mount aggregate certification failed with exit code $($run.Process.ExitCode)"
