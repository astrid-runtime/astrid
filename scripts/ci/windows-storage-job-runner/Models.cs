using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

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
    bool RootHandlesReleased,
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

internal static class MarkerChild
{
    internal static int Run(string markerPathText, string exitCodeText)
    {
        var markerPath = Path.GetFullPath(markerPathText);
        if (!string.Equals(markerPath, markerPathText, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerException($"marker path is not canonical: expected {markerPath}, got {markerPathText}");
        }

        if (!int.TryParse(exitCodeText, out var requestedExitCode) ||
            requestedExitCode is < 0 or > 255)
        {
            throw new ControllerException("marker-child exit code must be between 0 and 255");
        }

        File.WriteAllText(markerPath, "ready");
        Console.Out.WriteLine($"marker-created {markerPath}");
        Console.Out.Flush();
        Console.Error.WriteLine("marker-child-ready");
        Console.Error.Flush();
        return requestedExitCode;
    }
}

internal static class RootProcessCleanup
{
    internal static bool ReleaseHandles(SafeWindowsHandle thread, SafeProcessHandle process)
    {
        if (thread.IsInvalid || thread.IsClosed || process.IsInvalid || process.IsClosed)
        {
            return false;
        }

        thread.Dispose();
        process.Dispose();
        return thread.IsClosed && process.IsClosed;
    }

    internal static bool WaitForProcessExit(SafeProcessHandle process, TimeSpan cleanupTimeout)
    {
        var stopwatch = Stopwatch.StartNew();
        do
        {
            var wait = NativeMethods.WaitForSingleObject(process, 50);
            if (wait == NativeMethods.WaitObject0)
            {
                return true;
            }

            if (wait != NativeMethods.WaitTimeout)
            {
                throw new ControllerException(
                    $"waiting for the unassigned process failed: Win32 error {Marshal.GetLastWin32Error()}");
            }
        }
        while (stopwatch.Elapsed < cleanupTimeout);

        return false;
    }
}
