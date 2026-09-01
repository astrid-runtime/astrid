namespace Astrid.Ci.Windows;

internal enum JobOutcome
{
    Succeeded,
    ChildFailed,
    TimedOut,
    ControllerFailed,
}

internal sealed record JobRunResult(
    JobOutcome Outcome,
    uint ExitCode,
    string OriginalCause,
    bool CleanupComplete,
    uint[] ActiveProcessIds,
    string StdoutPath,
    string StderrPath,
    int ProcessId,
    TimeSpan Elapsed);

internal sealed class CertificationOptions
{
    public string TestExecutable { get; set; } = string.Empty;
    public string ProviderCanonical { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string ProviderSha256 { get; set; } = string.Empty;
    public string WorkingDirectory { get; set; } = string.Empty;
    public string LogDirectory { get; set; } = string.Empty;
    public TimeSpan ListTimeout { get; set; }
    public TimeSpan AggregateTimeout { get; set; }
    public TimeSpan DiagnosticTimeout { get; set; }
    public TimeSpan CleanupTimeout { get; set; }
    public TimeSpan HeartbeatInterval { get; set; }
}

internal sealed class ControllerException : Exception
{
    public ControllerException(string message)
        : base(message)
    {
    }

    public ControllerException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal static class JobProcessList
{
    internal static void ValidateCounts(int assignedProcesses, int processIdCount)
    {
        if (assignedProcesses < 0 || processIdCount < 0 || processIdCount > assignedProcesses)
        {
            throw new ControllerException(
                $"Job Object returned invalid process counts: assigned={assignedProcesses}, listed={processIdCount}");
        }
    }
}
