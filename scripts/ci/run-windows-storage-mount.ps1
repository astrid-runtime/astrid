# Windows-only certification harness for the staged kernel storage_mount tests.
# The fixed guards bound one aggregate run and diagnostic retries; they are not product policy.
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TestExecutable,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Provider,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TestFilter,
    [int]$AggregateTimeoutSeconds = 600,
    [int]$DiagnosticTimeoutSeconds = 120,
    [int]$ListTimeoutSeconds = 60,
    [int]$TeardownTimeoutSeconds = 30,
    [int]$HeartbeatSeconds = 30,
    [ValidateSet("List", "Aggregate", "Exact")]
    [string]$EmitLibTestArguments = "",
    [switch]$SelfTest
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"
if (@($AggregateTimeoutSeconds, $DiagnosticTimeoutSeconds, $ListTimeoutSeconds,
        $TeardownTimeoutSeconds, $HeartbeatSeconds) | Where-Object { $_ -le 0 }) {
    throw "all harness timeouts and the heartbeat interval must be positive"
}
$providerProcessName = [System.IO.Path]::GetFileNameWithoutExtension($Provider)
if ($providerProcessName -ne "astrid-storage-provider-winfsp") {
    throw "unexpected Windows process storage provider: $providerProcessName"
}
function Get-LibTestArguments {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("List", "Aggregate", "Exact")][string]$Mode,
        [Parameter(Mandatory = $true)][string]$TestFilter,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$TestName
    )
    switch ($Mode) {
        "List" { return @("--list", "--format", "terse", $TestFilter) }
        "Aggregate" { return @($TestFilter, "--nocapture", "--test-threads=1") }
        "Exact" { return @("--exact", $TestName, "--nocapture", "--test-threads=1") }
    }
}
if ($EmitLibTestArguments) {
    Get-LibTestArguments -Mode $EmitLibTestArguments -TestFilter $TestFilter -TestName "" |
        ConvertTo-Json -Compress
    exit 0
}
function Invoke-BoundedScriptSelfTest {
    $rows = @(Invoke-BoundedScript -Script {
        [pscustomobject]@{ ProcessId = 42; Name = "synthetic-cim-row" }
    } -Argument $null -TimeoutSeconds 5)
    if ($rows.Count -ne 1 -or [int]$rows[0].ProcessId -ne 42) {
        throw "the bounded PowerShell output self-test did not return the synthetic row"
    }
    try {
        $null = Invoke-BoundedScript -Script {
            Write-Output "bounded-output-evidence"
            Write-Error "synthetic bounded failure"
        } -Argument $null -TimeoutSeconds 5
    } catch {
        if ($_.Exception.Data["Output"][0] -cne "bounded-output-evidence" -or
            $_.Exception.Data["Error"][0].Exception.Message -cne "synthetic bounded failure") {
            throw "the bounded PowerShell error evidence self-test lost output or error evidence"
        }
        Write-Host "bounded PowerShell output/error self-test passed"
        return
    }
    throw "the bounded PowerShell error self-test accepted a synthetic error"
}
function Invoke-BoundedScriptTimeoutSelfTest {
    try {
        $null = Invoke-BoundedScript -Script {
            Write-Output "bounded-timeout-output-evidence"; Write-Error "bounded-timeout-error-evidence"
            Start-Sleep -Seconds 2
        } -Argument $null -TimeoutSeconds 1
    } catch {
        $output = @($_.Exception.Data["Output"])
        $errors = @($_.Exception.Data["Error"])
        if ($_.Exception.Message -ne "bounded PowerShell operation exceeded 1 seconds" -or
            -not $_.Exception.Data["TimedOut"] -or $output.Count -ne 1 -or
            [string]$output[0] -cne "bounded-timeout-output-evidence" -or
            $errors.Count -ne 1 -or $errors[0].Exception.Message -cne "bounded-timeout-error-evidence") {
            throw "the bounded PowerShell timeout self-test lost output or error evidence"
        }
        Write-Host "bounded PowerShell timeout evidence self-test passed"
        return
    }
    throw "the bounded PowerShell timeout self-test accepted an unbounded script"
}
function Invoke-GenerationSelfTest {
    $rootTime = [DateTime]::SpecifyKind([DateTime]::UtcNow, [DateTimeKind]::Utc)
    $rootPath = "C:\synthetic\exact-root.exe"
    $providerPath = "C:\synthetic\astrid-storage-provider-winfsp.exe"
    $rows = @(
        [pscustomobject]@{ ProcessId = 100; ParentProcessId = 1; Name = "exact-root.exe"; ExecutablePath = $rootPath; CreationTimeUtc = $rootTime }
        [pscustomobject]@{ ProcessId = 101; ParentProcessId = 100; Name = "owned-child.exe"; ExecutablePath = $rootPath; CreationTimeUtc = $rootTime }
        [pscustomobject]@{ ProcessId = 102; ParentProcessId = 1; Name = "exact-root.exe"; ExecutablePath = "C:\other\same-name.exe"; CreationTimeUtc = $rootTime }
    )
    $rootArguments = @{ Rows = $rows; RootProcessId = 100; RootExecutable = $rootPath
        RootCreationTimeUtc = $rootTime; StartedUtc = $rootTime; Provider = $providerPath }
    $owned = @(Select-OwnedProcessRows @rootArguments)
    if ($owned.Count -ne 2 -or (@($owned | ForEach-Object { $_.ProcessId }) -contains 102)) {
        throw "the root-generation self-test did not select exactly the valid root and child"
    }
    foreach ($case in @(
        @{ Rows = @([pscustomobject]@{ ProcessId = 100; ParentProcessId = 1; Name = "exact-root.exe"; ExecutablePath = $rootPath; CreationTimeUtc = $rootTime.AddTicks(1) }); Error = "accepted a reused PID" }
        @{ Rows = @([pscustomobject]@{ ProcessId = 100; ParentProcessId = 1; Name = "exact-root.exe"; ExecutablePath = "C:\drift\exact-root.exe"; CreationTimeUtc = $rootTime }); Error = "accepted executable-path drift" }
        @{ Rows = @([pscustomobject]@{ ProcessId = 103; ParentProcessId = 100; Name = "owned-child.exe"; ExecutablePath = $rootPath; CreationTimeUtc = $rootTime }); Error = "selected a child from a missing root" }
    )) {
        $rejected = $false
        try { $null = Select-OwnedProcessRows -Rows $case.Rows @rootArguments } catch { $rejected = $true }
        if (-not $rejected) { throw "the root-generation self-test $($case.Error)" }
    }
    $snapshot = New-OwnedGenerationSnapshot @rootArguments
    if ($snapshot.Children.Count -ne 1 -or [int]$snapshot.Children[0].ProcessId -ne 101) {
        throw "the retained-generation self-test did not retain the exact child"
    }
    $auditArguments = $rootArguments.Clone()
    $auditArguments.RetainedGeneration = $snapshot
    $auditArguments.SurvivorAudit = $true
    $absent = @(Select-OwnedProcessRows -Rows @() @auditArguments)
    if ($absent.Count -ne 0) {
        throw "the retained-generation self-test found a survivor after an empty query"
    }
    foreach ($case in @(
        @{ Time = $rootTime; Expected = 1; Error = "rejected the exact live retained child" }
        @{ Time = $rootTime.AddTicks(1); Expected = 0; Error = "accepted a reused child PID" }
    )) {
        $child = @([pscustomobject]@{ ProcessId = 101; ParentProcessId = 100; Name = "owned-child.exe"
            ExecutablePath = $rootPath; CommandLine = ""; CreationTimeUtc = $case.Time })
        $audit = @(Select-OwnedProcessRows -Rows $child @auditArguments)
        if ($audit.Count -ne $case.Expected) {
            throw "the retained-generation self-test $($case.Error)"
        }
    }
    Write-Host "exact root-generation teardown self-test passed"
}
function Wait-ForOutputFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][datetime]$Deadline
    )
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Test-Path -LiteralPath $Path -PathType Leaf) -or $Process.HasExited) { return }
        Start-Sleep -Milliseconds 50
    }
}
function Read-OutputChunk {
    param(
        [Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][ref]$Offset
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    $length = (Get-Item -LiteralPath $Path).Length
    if ($length -le [long]$Offset.Value) {
        return $null
    }
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $null = $stream.Seek([long]$Offset.Value, [System.IO.SeekOrigin]::Begin)
        $remaining = [int][Math]::Min($length - [long]$Offset.Value, 64KB)
        $bytes = [byte[]]::new($remaining)
        $read = 0
        while ($read -lt $remaining) {
            $count = $stream.Read($bytes, $read, $remaining - $read)
            if ($count -eq 0) { break }
            $read += $count
        }
        $Offset.Value = [long]$Offset.Value + $read
        if ($read -eq 0) { return $null }
        return [System.Text.Encoding]::UTF8.GetString($bytes, 0, $read)
    } finally {
        $stream.Dispose()
    }
}
function Read-OutputTail {
    param(
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath,
        [Parameter(Mandatory = $true)][ref]$StdoutOffset,
        [Parameter(Mandatory = $true)][ref]$StderrOffset
    )
    for ($drainPass = 0; $drainPass -lt 100; $drainPass++) {
        $stdoutChunk = Read-OutputChunk -Path $StdoutPath -Offset $StdoutOffset
        $stderrChunk = Read-OutputChunk -Path $StderrPath -Offset $StderrOffset
        foreach ($chunk in @($stdoutChunk, $stderrChunk)) {
            if ($chunk) { Write-Host $chunk -NoNewline }
        }
        if (-not $stdoutChunk -and -not $stderrChunk) { break }
    }
}
function Wait-StreamingProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Run,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$HeartbeatSeconds
    )
    $Process = $Run.Process
    $StdoutPath = $Run.StdoutPath
    $StderrPath = $Run.StderrPath
    $stdoutOffset = 0L
    $stderrOffset = 0L
    $lastSignal = $Process.StartTime.ToUniversalTime()
    $deadline = $lastSignal.AddSeconds($TimeoutSeconds)
    $nextCaptureUtc = $lastSignal.AddSeconds($HeartbeatSeconds)
    Wait-ForOutputFile -Path $StdoutPath -Process $Process -Deadline $deadline
    Wait-ForOutputFile -Path $StderrPath -Process $Process -Deadline $deadline
    while ($true) {
        if ($Process.WaitForExit(100)) {
            Read-OutputTail -StdoutPath $StdoutPath -StderrPath $StderrPath `
                -StdoutOffset ([ref]$stdoutOffset) -StderrOffset ([ref]$stderrOffset)
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
        }
        if (-not $Process.HasExited -and $now -ge $nextCaptureUtc) {
            $querySeconds = [Math]::Min(5, [Math]::Max(1, $HeartbeatSeconds))
            $rows = @(Get-CimProcessRows -TimeoutSeconds $querySeconds)
            $Run.GenerationSnapshot = New-OwnedGenerationSnapshot -Rows $rows `
                -RootProcessId $Run.RootProcessId -RootExecutable $Run.RootExecutable `
                -RootCreationTimeUtc $Run.RootCreationTimeUtc -StartedUtc $Run.StartedUtc `
                -Provider $Provider -PreviousGeneration $Run.GenerationSnapshot
            $nextCaptureUtc = $now.AddSeconds($HeartbeatSeconds)
        }
        if (-not $hadOutput -and ($now - $lastSignal).TotalSeconds -ge $HeartbeatSeconds) {
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
            Read-OutputTail -StdoutPath $StdoutPath -StderrPath $StderrPath `
                -StdoutOffset ([ref]$stdoutOffset) -StderrOffset ([ref]$stderrOffset)
            Write-Host ("[{0}] timeout after {1} seconds" -f $DisplayName, $TimeoutSeconds)
            return $false
        }
    }
}
function Get-BoundedTimeoutOutput {
    param([Parameter(Mandatory = $true)][System.Management.Automation.PowerShell]$PowerShell)
    ,@($PowerShell.Streams.Information | Where-Object {
        $_.Tags -contains "__AstridBoundedOutput" } | ForEach-Object { $_.MessageData })
}

function Write-BoundedScriptEvidence {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Output,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Errors
    )
    foreach ($record in $Output) { Write-Host "bounded PowerShell timeout output: $record" }
    foreach ($record in $Errors) {
        Write-Host "bounded PowerShell timeout error: $($record.Exception.Message)"
    }
}
function Invoke-BoundedScript {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Script,
        [Parameter(Mandatory = $true)][AllowNull()]$Argument,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $powerShell = [System.Management.Automation.PowerShell]::Create()
    try {
    $wrapped = "param(`$Argument)`n& {`n$($Script.ToString())`n} `$Argument | " +
            "ForEach-Object { Write-Information -MessageData `$_ -Tags '__AstridBoundedOutput'; `$_ }"
        $async = $powerShell.AddScript($wrapped).AddArgument($Argument).BeginInvoke()
        $timeoutMilliseconds = [Math]::Max(1, $TimeoutSeconds * 1000)
        if (-not $async.AsyncWaitHandle.WaitOne($timeoutMilliseconds, $false)) {
            $output = @(Get-BoundedTimeoutOutput -PowerShell $powerShell)
            $errors = @($powerShell.Streams.Error)
            Write-BoundedScriptEvidence -Output $output -Errors $errors
            $stop = $powerShell.BeginStop($null, $null)
            $stopped = $stop.AsyncWaitHandle.WaitOne(2000, $false)
            if ($stopped) {
                try { $powerShell.EndStop($stop) } catch {
                    Write-Host "bounded PowerShell stop failed: $($_.Exception.Message)"
                }
            } else {
                Write-Host "bounded PowerShell stop failed: $($_.Exception.Message)"
            }
            $output = @(Get-BoundedTimeoutOutput -PowerShell $powerShell)
            $errors = @($powerShell.Streams.Error)
            Write-BoundedScriptEvidence -Output $output -Errors $errors
            $failure = [System.InvalidOperationException]::new(
                "bounded PowerShell operation exceeded $TimeoutSeconds seconds")
            $failure.Data["TimedOut"] = $true
            $failure.Data["Output"] = $output
            $failure.Data["Error"] = $errors
            throw $failure
        }
        $completedOutput = $powerShell.EndInvoke($async)
        $output = @($completedOutput)
        $errors = @($powerShell.Streams.Error)
        foreach ($record in $errors) {
            Write-Host "bounded PowerShell error: $($record.Exception.Message)"
        }
        if ($errors.Count -gt 0) {
            $failure = [System.InvalidOperationException]::new(
                "bounded PowerShell emitted $($errors.Count) error(s)")
            $failure.Data["Output"] = $output
            $failure.Data["Error"] = $errors
            throw $failure
        }
        return @($output)
    } finally {
        $powerShell.Dispose()
    }
}
function Invoke-BoundedExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][string]$Name
    )
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    $stdoutPath = Join-Path $LogDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $LogDirectory "$Name.stderr.log"
    $process = Start-Process -FilePath $Executable -ArgumentList $Arguments `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath `
        -NoNewWindow -PassThru
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "$Name exceeded $TimeoutSeconds seconds"
    }
    Start-Sleep -Milliseconds 100
    foreach ($path in @($stdoutPath, $stderrPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $text = Get-Content -LiteralPath $path -Raw
            if ($text) { Write-Host $text -NoNewline }
        }
    }
    return [pscustomobject]@{ ExitCode = $process.ExitCode; TimedOut = $false }
}
function Get-CimProcessRows {
    param(
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $query = {
        Get-CimInstance -ClassName Win32_Process | ForEach-Object {
            $rawCreation = $_.CreationDate
            $creation = [DateTime]::MinValue
            if ($rawCreation -is [datetime]) {
                $creation = [datetime]::SpecifyKind($rawCreation, [System.DateTimeKind]::Utc)
            } elseif ($rawCreation) {
                $creation = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$rawCreation).ToUniversalTime()
            }
            [pscustomobject]@{
                ProcessId = [int]$_.ProcessId
                ParentProcessId = [int]$_.ParentProcessId
                Name = [string]$_.Name
                ExecutablePath = [string]$_.ExecutablePath
                CommandLine = [string]$_.CommandLine
                CreationTimeUtc = $creation
            }
        }
    }
    return @(Invoke-BoundedScript -Script $query -Argument $null -TimeoutSeconds $TimeoutSeconds)
}
function Test-SameWindowsPath {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Left,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Right
    )
    return [string]::Equals(
        $Left.TrimEnd('\'),
        $Right.TrimEnd('\'),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}
function Test-SameCreationTimeUtc {
    param(
        [Parameter(Mandatory = $true)][datetime]$Left,
        [Parameter(Mandatory = $true)][datetime]$Right
    )
    $leftUtc = [DateTime]::SpecifyKind($Left.ToUniversalTime(), [DateTimeKind]::Utc)
    $rightUtc = [DateTime]::SpecifyKind($Right.ToUniversalTime(), [DateTimeKind]::Utc)
    return $leftUtc.Ticks -eq $rightUtc.Ticks
}
function ConvertTo-ProcessGenerationRecord {
    param([Parameter(Mandatory = $true)][object]$Row)
    return [pscustomobject]@{ ProcessId = [int]$Row.ProcessId; ParentProcessId = [int]$Row.ParentProcessId
        Name = [string]$Row.Name; ExecutablePath = [string]$Row.ExecutablePath
        CreationTimeUtc = $Row.CreationTimeUtc }
}
function Test-SameProcessGeneration {
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][object]$Expected)
    return [int]$Row.ProcessId -eq [int]$Expected.ProcessId -and
        [int]$Row.ParentProcessId -eq [int]$Expected.ParentProcessId -and
        [string]$Row.Name -ieq [string]$Expected.Name -and
        (Test-SameWindowsPath -Left $Row.ExecutablePath -Right $Expected.ExecutablePath) -and
        (Test-SameCreationTimeUtc -Left $Row.CreationTimeUtc -Right $Expected.CreationTimeUtc)
}
function Add-ExactGenerationRow {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Survivors,
        [Parameter(Mandatory = $true)][hashtable]$SeenProcessIds,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][object]$Generation)
    $matches = @($Rows | Where-Object { Test-SameProcessGeneration -Row $_ -Expected $Generation })
    if ($matches.Count -gt 1) {
        throw "multiple process rows matched one retained generation: pid=$($Generation.ProcessId)"
    }
    if ($matches.Count -eq 0) { return }
    $processId = [int]$matches[0].ProcessId
    if (-not $SeenProcessIds.ContainsKey($processId)) {
        $SeenProcessIds[$processId] = $true
        $Survivors.Add($matches[0])
    }
}
function New-OwnedGenerationSnapshot {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][int]$RootProcessId,
        [Parameter(Mandatory = $true)][string]$RootExecutable,
        [Parameter(Mandatory = $true)][datetime]$RootCreationTimeUtc,
        [Parameter(Mandatory = $true)][datetime]$StartedUtc,
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $false)][object]$PreviousGeneration = (
            [pscustomobject]@{ Children = @(); Providers = @() }))
    $owned = @(Select-OwnedProcessRows -Rows $Rows -RootProcessId $RootProcessId `
        -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc `
        -StartedUtc $StartedUtc -Provider $Provider)
    $rootRecord = ConvertTo-ProcessGenerationRecord -Row (
        $owned | Where-Object { [int]$_.ProcessId -eq $RootProcessId } | Select-Object -First 1)
    $newChildren = @($owned | Where-Object { [int]$_.ProcessId -ne $RootProcessId } |
        ForEach-Object { ConvertTo-ProcessGenerationRecord -Row $_ })
    $newProviders = @($owned | Where-Object {
        (Test-SameWindowsPath -Left $_.ExecutablePath -Right $Provider) -and $_.CreationTimeUtc -ge $StartedUtc.AddSeconds(-2)
    } | ForEach-Object { ConvertTo-ProcessGenerationRecord -Row $_ })
    $children = [System.Collections.Generic.List[object]]::new()
    $providers = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($generation in @($PreviousGeneration.Children) + $newChildren) {
        $key = "{0}|{1}|{2}" -f $generation.ProcessId, $generation.ExecutablePath, $generation.CreationTimeUtc.Ticks
        if ($generation -and -not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $children.Add($generation)
        }
    }
    $seen = @{}
    foreach ($generation in @($PreviousGeneration.Providers) + $newProviders) {
        $key = "{0}|{1}|{2}" -f $generation.ProcessId, $generation.ExecutablePath, $generation.CreationTimeUtc.Ticks
        if ($generation -and -not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $providers.Add($generation)
        }
    }
    return [pscustomobject]@{ Root = $rootRecord; Children = @($children); Providers = @($providers) }
}
function Assert-RootProcessGeneration {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][int]$RootProcessId,
        [Parameter(Mandatory = $true)][string]$RootExecutable,
        [Parameter(Mandatory = $true)][datetime]$RootCreationTimeUtc)
    $rootRow = $Rows | Where-Object { [int]$_.ProcessId -eq $RootProcessId } |
        Select-Object -First 1
    if (-not $rootRow) { throw "root process generation row was missing: pid=$RootProcessId" }
    if (-not (Test-SameWindowsPath -Left $rootRow.ExecutablePath -Right $RootExecutable)) {
        throw "root process generation path differed: pid=$RootProcessId"
    }
    if (-not (Test-SameCreationTimeUtc -Left $rootRow.CreationTimeUtc -Right $RootCreationTimeUtc)) {
        throw "root process creation time differed, indicating PID reuse: pid=$RootProcessId"
    }
    return $rootRow
}
function Select-OwnedProcessRows {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][int]$RootProcessId,
        [Parameter(Mandatory = $true)][string]$RootExecutable,
        [Parameter(Mandatory = $true)][datetime]$RootCreationTimeUtc,
        [Parameter(Mandatory = $true)][datetime]$StartedUtc,
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $false)][AllowNull()][object]$RetainedGeneration,
        [switch]$SurvivorAudit)
    $children = @{}
    foreach ($row in $Rows) {
        $parent = [int]$row.ParentProcessId
        if (-not $children.ContainsKey($parent)) {
            $children[$parent] = [System.Collections.Generic.List[int]]::new()
        }
        $children[$parent].Add([int]$row.ProcessId)
    }
    $ownedIds = @{}
    $stack = [System.Collections.Generic.Stack[int]]::new()
    if ($SurvivorAudit) {
        if (-not $RetainedGeneration) {
            throw "survivor audit requires retained exact generation evidence"
        }
        $rootRow = $Rows | Where-Object { [int]$_.ProcessId -eq $RootProcessId } | Select-Object -First 1
        if ($rootRow) {
            $null = Assert-RootProcessGeneration -Rows $Rows -RootProcessId $RootProcessId `
                -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc
        }
        $owned = [System.Collections.Generic.List[object]]::new()
        $seen = @{}
        foreach ($generation in @($RetainedGeneration.Children) + @($RetainedGeneration.Providers)) {
            Add-ExactGenerationRow -Survivors $owned -SeenProcessIds $seen `
                -Rows $Rows -Generation $generation
        }
        foreach ($row in $Rows) {
            if ((Test-SameWindowsPath -Left $row.ExecutablePath -Right $Provider) -and $row.CreationTimeUtc -ge $StartedUtc.AddSeconds(-2)) {
                Add-ExactGenerationRow -Survivors $owned -SeenProcessIds $seen `
                    -Rows @($row) -Generation (ConvertTo-ProcessGenerationRecord -Row $row)
            }
        }
        $owned = @($owned)
    } else {
        $null = Assert-RootProcessGeneration -Rows $Rows -RootProcessId $RootProcessId `
            -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc
        $stack.Push($RootProcessId)
        while ($stack.Count -gt 0) {
            $id = $stack.Pop()
            if ($ownedIds.ContainsKey($id)) { continue }
            $ownedIds[$id] = $true
            if ($children.ContainsKey($id)) {
                foreach ($childId in $children[$id]) { $stack.Push($childId) }
            }
        }
        $owned = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $Rows) {
            $isAncestorOwned = $ownedIds.ContainsKey([int]$row.ProcessId)
            $isStagedProvider = (Test-SameWindowsPath -Left $row.ExecutablePath -Right $Provider) -and
                $row.CreationTimeUtc -ge $StartedUtc.AddSeconds(-2)
            if ($isAncestorOwned -or $isStagedProvider) {
                $owned.Add($row)
            }
        }
    }
    $byIdForDepth = @{}
    foreach ($row in $owned) { $byIdForDepth[[int]$row.ProcessId] = $row }
    foreach ($row in $owned) {
        $depth = 0
        $current = $row
        $seen = @{}
        while ($current -and -not $seen.ContainsKey([int]$current.ProcessId)) {
            $seen[[int]$current.ProcessId] = $true
            $depth++
            $current = $byIdForDepth[[int]$current.ParentProcessId]
        }
        $row | Add-Member -NotePropertyName OwnedDepth -NotePropertyValue ($depth - 1) -Force
    }
    return @($owned)
}
function Write-ProcessTreeSnapshot {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows
    )
    if ($Rows.Count -eq 0) {
        Write-Host "owned process tree: empty"
        return
    }
    foreach ($row in $Rows) {
        $indent = "  " * [Math]::Max(0, [int]$row.OwnedDepth)
        Write-Host ("{0}pid={1} parent={2} name={3} path={4}" -f `
            $indent, $row.ProcessId, $row.ParentProcessId, $row.Name, $row.ExecutablePath)
        if ($row.CommandLine) {
            Write-Host ("{0}  command-line={1}" -f $indent, $row.CommandLine)
        }
    }
}
function Add-CleanupFailure {
    param([Parameter(Mandatory = $true)][string]$Message)
    if (-not (Get-Variable -Name CleanupFailures -Scope Script -ErrorAction SilentlyContinue)) {
        $script:CleanupFailures = [System.Collections.Generic.List[string]]::new()
    }
    $script:CleanupFailures.Add($Message)
    Write-Host "CLEANUP FAILURE (secondary): $Message"
}
function Invoke-ScopedTeardown {
    param([Parameter(Mandatory = $true)][object]$Run,
        [Parameter(Mandatory = $true)][string]$Provider,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds)
    $Process = $Run.Process
    $StartedUtc = $Run.StartedUtc
    $RootExecutable = $Run.RootExecutable
    $RootCreationTimeUtc = $Run.RootCreationTimeUtc
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        $remainingSeconds = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalSeconds)
        $querySeconds = [Math]::Min(5, [Math]::Max(1, $remainingSeconds))
        $rows = @(Get-CimProcessRows -TimeoutSeconds $querySeconds)
        $generation = $Run.GenerationSnapshot
        if (-not $Process.HasExited) {
            $generation = New-OwnedGenerationSnapshot -Rows $rows -RootProcessId $Process.Id `
                -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc `
                -StartedUtc $StartedUtc -Provider $Provider -PreviousGeneration $generation
            $Run.GenerationSnapshot = $generation
        } else {
            $rootRow = $rows | Where-Object { [int]$_.ProcessId -eq $Process.Id } | Select-Object -First 1
            if ($rootRow -and $generation) {
                $generation = New-OwnedGenerationSnapshot -Rows $rows -RootProcessId $Process.Id `
                    -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc `
                    -StartedUtc $StartedUtc -Provider $Provider -PreviousGeneration $generation
                $Run.GenerationSnapshot = $generation
            }
        }
        if (-not $generation) {
            throw "completed owned root has no retained generation evidence"
        }
        $initial = @(Select-OwnedProcessRows -Rows $rows -RootProcessId $Process.Id `
            -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc `
            -StartedUtc $StartedUtc -Provider $Provider -RetainedGeneration $generation `
            -SurvivorAudit)
        Write-Host "owned process tree before termination:"
        Write-ProcessTreeSnapshot -Rows $initial
        if (-not $Process.HasExited) {
            $taskkill = Join-Path $env:SystemRoot "System32\taskkill.exe"
            $result = Invoke-BoundedExecutable -Executable $taskkill `
                -Arguments @("/PID", "$($Process.Id)", "/T", "/F") `
                -TimeoutSeconds $querySeconds -LogDirectory $LogDirectory -Name "owned-taskkill"
            if ($result.ExitCode -ne 0) {
                Write-Host "taskkill exit-code=$($result.ExitCode); falling back to owned PIDs"
            }
        } else {
            Write-Host "owned test root already exited before termination"
        }
        $querySeconds = [Math]::Min(5, [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalSeconds))
        $rows = @(Get-CimProcessRows -TimeoutSeconds $querySeconds)
        $alive = @(Select-OwnedProcessRows -Rows $rows -RootProcessId $Process.Id `
            -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc `
            -StartedUtc $StartedUtc -Provider $Provider -RetainedGeneration $generation `
            -SurvivorAudit)
        if ($alive.Count -gt 0) {
            $ids = @($alive | ForEach-Object { [int]$_.ProcessId })
            $stopSeconds = [Math]::Min(2, [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalSeconds))
            $null = Invoke-BoundedScript -Script {
                param($ProcessIds)
                foreach ($processId in $ProcessIds) {
                    Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                }
            } -Argument $ids -TimeoutSeconds $stopSeconds
        }
        $querySeconds = [Math]::Min(5, [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalSeconds))
        $rows = @(Get-CimProcessRows -TimeoutSeconds $querySeconds)
        $survivors = @(Select-OwnedProcessRows -Rows $rows -RootProcessId $Process.Id `
            -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc `
            -StartedUtc $StartedUtc -Provider $Provider -RetainedGeneration $generation `
            -SurvivorAudit)
        if ($survivors.Count -eq 0) {
            Write-Host "owned process tree after termination:"
            Write-ProcessTreeSnapshot -Rows $survivors
            Write-Host "all owned descendants and exact staged providers are dead"
            return [pscustomobject]@{ Survivors = $survivors; Failed = $false }
        }
        while ([DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
        $querySeconds = [Math]::Min(5, [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalSeconds))
        $rows = @(Get-CimProcessRows -TimeoutSeconds $querySeconds)
        $survivors = @(Select-OwnedProcessRows -Rows $rows -RootProcessId $Process.Id `
            -RootExecutable $RootExecutable -RootCreationTimeUtc $RootCreationTimeUtc `
            -StartedUtc $StartedUtc -Provider $Provider -RetainedGeneration $generation `
            -SurvivorAudit)
        Write-Host "owned process tree after termination:"
        Write-ProcessTreeSnapshot -Rows $survivors
        if ($survivors.Count -eq 0) {
            Write-Host "all owned descendants and exact staged providers are dead"
        }
        return [pscustomobject]@{ Survivors = $survivors; Failed = ($survivors.Count -gt 0) }
    } catch {
        Add-CleanupFailure -Message ("owned teardown failed: {0}" -f $_.Exception.Message)
        return [pscustomobject]@{
            Survivors = @()
            Failed = $true
        }
    }
}
function Start-TestProcess {
    param([Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][string]$Name)
    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $stdoutPath = Join-Path $LogDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $LogDirectory "$Name.stderr.log"
    Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -NoNewWindow -PassThru
    $rootExecutable = (Get-Item -LiteralPath $Executable).FullName
    $startedUtc = $process.StartTime.ToUniversalTime()
    $rows = @(Get-CimProcessRows -TimeoutSeconds 5)
    $generationSnapshot = New-OwnedGenerationSnapshot -Rows $rows -RootProcessId $process.Id `
        -RootExecutable $rootExecutable -RootCreationTimeUtc $startedUtc `
        -StartedUtc $startedUtc -Provider $Provider
    return [pscustomobject]@{
        Process = $process
        StartedUtc = $startedUtc
        RootProcessId = $process.Id
        RootExecutable = $rootExecutable
        RootCreationTimeUtc = $startedUtc
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
        GenerationSnapshot = $generationSnapshot
    }
}
function Write-CompleteOutput {
    param([Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath,
        [Parameter(Mandatory = $false)][string]$Label = "aggregate")
    Write-Host "=== complete $Label stdout ==="
    if (Test-Path -LiteralPath $StdoutPath -PathType Leaf) {
        Get-Content -LiteralPath $StdoutPath -Raw | Write-Host
    }
    Write-Host "=== complete $Label stderr ==="
    if (Test-Path -LiteralPath $StderrPath -PathType Leaf) {
        Get-Content -LiteralPath $StderrPath -Raw | Write-Host
    }
}
function Get-LastCompletedTest {
    param([Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath)
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
        -Arguments (Get-LibTestArguments -Mode List -TestFilter $TestFilter -TestName "") `
        -WorkingDirectory $WorkingDirectory `
        -LogDirectory $LogDirectory `
        -Name "storage-mount-list"
    $completed = Wait-StreamingProcess `
        -Run $run `
        -DisplayName "test-list" `
        -TimeoutSeconds $TimeoutSeconds `
        -HeartbeatSeconds $HeartbeatSeconds
    if (-not $completed) {
        Write-CompleteOutput -StdoutPath $run.StdoutPath -StderrPath $run.StderrPath -Label "test-list"
        $null = Invoke-ScopedTeardown -Run $run -Provider $Provider `
            -LogDirectory $LogDirectory -TimeoutSeconds $TeardownTimeoutSeconds
        throw "the storage_mount test-list process exceeded ${TimeoutSeconds} seconds"
    }
    Write-CompleteOutput -StdoutPath $run.StdoutPath -StderrPath $run.StderrPath -Label "test-list"
    if ($run.Process.ExitCode -ne 0) {
        $null = Invoke-ScopedTeardown -Run $run -Provider $Provider `
            -LogDirectory $LogDirectory -TimeoutSeconds $TeardownTimeoutSeconds
        throw "the storage_mount test-list process failed with exit code $($run.Process.ExitCode)"
    }
    $teardown = Invoke-ScopedTeardown -Run $run -Provider $Provider `
        -LogDirectory $LogDirectory -TimeoutSeconds $TeardownTimeoutSeconds
    if ($teardown.Failed) {
        Add-CleanupFailure -Message "the test-list owned tree was not proven dead"
    }
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
$testItem = Get-Item -LiteralPath $TestExecutable
$providerItem = Get-Item -LiteralPath $Provider
$stage = $testItem.DirectoryName
$providerBeside = Join-Path $stage (Split-Path -Leaf $Provider)
if (-not (Test-SameWindowsPath -Left $testItem.FullName -Right ([System.IO.Path]::GetFullPath($TestExecutable)))) {
    throw "the staged test executable path was not canonical"
}
if (-not (Test-SameWindowsPath -Left $providerItem.FullName -Right ([System.IO.Path]::GetFullPath($Provider)))) {
    throw "the provider argument path was not canonical"
}
if (-not (Test-SameWindowsPath -Left $providerItem.FullName -Right $providerBeside)) {
    throw "the provider is not canonically beside the staged test executable: $providerBeside"
}
if (Test-SameWindowsPath -Left $providerItem.FullName -Right $testItem.FullName) {
    throw "the staged provider and test executable must be different files"
}
$providerBesideItem = Get-Item -LiteralPath $providerBeside
if ((Get-FileHash -LiteralPath $providerItem.FullName -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $providerBesideItem.FullName -Algorithm SHA256).Hash) {
    throw "the provider identity beside the staged test executable does not match -Provider"
}
if ($SelfTest) {
    Invoke-BoundedScriptSelfTest
    Invoke-BoundedScriptTimeoutSelfTest
    Invoke-GenerationSelfTest
    exit 0
}
$logDirectory = Join-Path $stage "storage-mount-harness-logs"
$script:CleanupFailures = [System.Collections.Generic.List[string]]::new()
$activeRun = $null
$aggregateCompleted = $false
$aggregateTimedOut = $false
$aggregateExitCode = $null
$aggregateElapsedSeconds = 0.0
$primaryExitCode = 1
$activeCleanupComplete = $false
try {
    $tests = @(Get-TestList `
        -Executable $TestExecutable `
        -TestFilter $TestFilter `
        -WorkingDirectory $stage `
        -LogDirectory $logDirectory `
        -TimeoutSeconds $ListTimeoutSeconds `
        -TeardownTimeoutSeconds $TeardownTimeoutSeconds)
    $activeRun = Start-TestProcess `
        -Executable $TestExecutable `
        -Arguments (Get-LibTestArguments -Mode Aggregate -TestFilter $TestFilter -TestName "") `
        -WorkingDirectory $stage `
        -LogDirectory $logDirectory `
        -Name "storage-mount-aggregate"
    $aggregateStarted = [DateTime]::UtcNow
    $aggregateCompleted = Wait-StreamingProcess `
        -Run $activeRun `
        -DisplayName "storage_mount aggregate" `
        -TimeoutSeconds $AggregateTimeoutSeconds `
        -HeartbeatSeconds $HeartbeatSeconds
    $aggregateElapsedSeconds = (([DateTime]::UtcNow - $aggregateStarted).TotalSeconds)
    $aggregateTimedOut = -not $aggregateCompleted
    $aggregateExitCode = if ($activeRun.Process.HasExited) { $activeRun.Process.ExitCode } else { $null }
    Write-Host ("aggregate elapsed-seconds={0:F1}" -f $aggregateElapsedSeconds)
    Write-Host ("primary exit status: exit-code={0} timeout={1}" -f `
        $aggregateExitCode, $aggregateTimedOut)
    Write-CompleteOutput -StdoutPath $activeRun.StdoutPath -StderrPath $activeRun.StderrPath
    $lastCompleted = Get-LastCompletedTest `
        -StdoutPath $activeRun.StdoutPath -StderrPath $activeRun.StderrPath
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
    if ($aggregateCompleted -and $aggregateExitCode -eq 0) {
        $message = (
            "storage_mount aggregate certification passed in {0:F1} seconds " +
            "with {1} pre-enumerated tests"
        ) -f $aggregateElapsedSeconds, $tests.Count
        Write-Host $message
        $teardown = Invoke-ScopedTeardown -Run $activeRun -Provider $Provider `
            -LogDirectory $logDirectory -TimeoutSeconds $TeardownTimeoutSeconds
        $activeCleanupComplete = $true
        if ($teardown.Failed) {
            Add-CleanupFailure -Message "aggregate teardown did not prove all owned descendants dead"
            $primaryExitCode = 90
        } else {
            $primaryExitCode = 0
        }
    } else {
        $teardown = Invoke-ScopedTeardown -Run $activeRun -Provider $Provider `
            -LogDirectory $logDirectory -TimeoutSeconds $TeardownTimeoutSeconds
        $activeCleanupComplete = $true
        if ($teardown.Failed) {
            Add-CleanupFailure -Message "failing aggregate teardown did not prove all owned descendants dead"
        }
        $firstDiagnosticTimeout = $null
        Write-Host "DIAGNOSTIC ONLY: exact per-test isolation begins; this does not certify the aggregate suite."
        foreach ($test in $tests) {
            Write-Host "START diagnostic isolation: $test"
            $diagnostic = $null
            $diagnosticCompleted = $false
            try {
                $diagnostic = Start-TestProcess `
                    -Executable $TestExecutable `
                    -Arguments (Get-LibTestArguments -Mode Exact -TestFilter $TestFilter -TestName $test) `
                    -WorkingDirectory $stage `
                    -LogDirectory $logDirectory `
                    -Name ("diagnostic-" + ($test -replace '[^A-Za-z0-9_.-]', '_'))
                $diagnosticCompleted = Wait-StreamingProcess `
                    -Run $diagnostic `
                    -DisplayName "diagnostic $test" `
                    -TimeoutSeconds $DiagnosticTimeoutSeconds `
                    -HeartbeatSeconds $HeartbeatSeconds
                Write-CompleteOutput -StdoutPath $diagnostic.StdoutPath `
                    -StderrPath $diagnostic.StderrPath -Label "diagnostic $test"
                $diagnosticTeardown = Invoke-ScopedTeardown -Run $diagnostic `
                    -Provider $Provider -LogDirectory $logDirectory `
                    -TimeoutSeconds $TeardownTimeoutSeconds
                if ($diagnosticTeardown.Failed) {
                    Add-CleanupFailure -Message "diagnostic teardown for $test did not prove all owned descendants dead"
                }
                if (-not $diagnosticCompleted) {
                    if (-not $firstDiagnosticTimeout) { $firstDiagnosticTimeout = $test }
                    Write-Host "diagnostic timeout: $test"
                }
            } catch {
                Write-Host "diagnostic isolation error for ${test}: $($_.Exception.Message)"
                if ($diagnostic) {
                    try {
                        $null = Invoke-ScopedTeardown -Run $diagnostic -Provider $Provider `
                            -LogDirectory $logDirectory -TimeoutSeconds $TeardownTimeoutSeconds
                    } catch {
                        Add-CleanupFailure -Message "diagnostic unwind teardown for $test failed: $($_.Exception.Message)"
                    }
                }
            } finally {
                if ($diagnostic) {
                    if (-not $diagnostic.Process.HasExited) {
                        $null = $diagnostic.Process.WaitForExit(1000)
                    }
                    $diagnostic.Process.Dispose()
                }
                Write-Host "END diagnostic isolation: $test"
            }
        }
        if ($aggregateTimedOut) {
            if ($firstDiagnosticTimeout) {
                Write-Host (
                    "storage_mount aggregate certification timed out; " +
                    "first isolated timeout was $firstDiagnosticTimeout"
                )
            } else {
                Write-Host "storage_mount aggregate certification timed out; no exact per-test isolation timed out"
            }
            $primaryExitCode = 124
        } else {
            $primaryExitCode = $aggregateExitCode
        }
    }
} catch {
    Write-Host "harness failure before primary completion: $($_.Exception.Message)"
    Write-Host "primary exit status: unavailable timeout=$aggregateTimedOut"
    $primaryExitCode = 1
} finally {
    if ($activeRun -and -not $activeCleanupComplete) {
        try {
            $teardown = Invoke-ScopedTeardown -Run $activeRun -Provider $Provider `
                -LogDirectory $logDirectory -TimeoutSeconds $TeardownTimeoutSeconds
            if ($teardown.Failed) {
                Add-CleanupFailure -Message "unwind teardown did not prove all owned descendants dead"
            }
        } catch {
            Add-CleanupFailure -Message "unwind teardown failed: $($_.Exception.Message)"
        }
    }
    if ($activeRun) { $activeRun.Process.Dispose() }
}
if ($script:CleanupFailures.Count -gt 0) {
    Write-Host "cleanup failures are secondary but fail this run:"
    foreach ($failure in $script:CleanupFailures) {
        Write-Host "  $failure"
    }
    $primaryExitCode = 90
}
Write-Host "final exit status=$primaryExitCode"
exit $primaryExitCode
