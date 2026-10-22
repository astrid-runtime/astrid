# CI harness deadline only; this is not a runtime policy or containment proof.
param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483)][int]$TimeoutSeconds,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments = @()
)

$ErrorActionPreference = "Stop"
$process = [System.Diagnostics.Process]::new()
$started = $false
$timedOut = $false
$exitCode = 125
try {
    $process.StartInfo.FileName = $FilePath
    $process.StartInfo.UseShellExecute = $false
    # Inherit both output handles: no capture buffer delays live test diagnostics.
    foreach ($argument in $Arguments) {
        $process.StartInfo.ArgumentList.Add($argument)
    }
    $started = $process.Start()
    if (-not $started) { throw "native test process did not start" }
    if ($process.WaitForExit($TimeoutSeconds * 1000)) {
        $exitCode = $process.ExitCode
    } else {
        $timedOut = $true
        $exitCode = 124
        [Console]::Error.WriteLine("native test harness deadline expired for owned PID $($process.Id)")
    }
} catch {
    [Console]::Error.WriteLine("native test harness failure: $_")
} finally {
    if ($started) {
        try {
            if (-not $process.HasExited) {
                try {
                    # Best effort tree cleanup; escaped descendants are not certified.
                    $process.Kill($true)
                } catch {
                    if (-not $process.HasExited) { throw }
                }
            }
            if (-not $process.WaitForExit(5000)) {
                throw "owned PID $($process.Id) did not exit after bounded cleanup"
            }
            if ($timedOut) {
                [Console]::Error.WriteLine("observed owned process exit after deadline: PID $($process.Id)")
            }
        } catch {
            $exitCode = 125
            [Console]::Error.WriteLine("native test harness cleanup failure: $_")
        }
    }
    $process.Dispose()
}
exit $exitCode
