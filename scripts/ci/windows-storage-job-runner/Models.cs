using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Astrid.Ci.Windows;

internal delegate bool QueryJobProcessList(
    SafeJobHandle job,
    IntPtr information,
    uint length,
    out uint returnLength,
    out int win32Error);

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
    internal const int ProcessIdListOffset = 16;
    internal const int MinimumStructureLength = 24;
    internal const int MaximumBufferLength = 16 * 1024 * 1024;

    internal static uint[] ReadIds(SafeJobHandle job, QueryJobProcessList query)
    {
        const int maximumAttempts = 12;
        var bufferLength = (uint)MinimumStructureLength;

        for (var attempt = 0; attempt < maximumAttempts; attempt++)
        {
            if (bufferLength < MinimumStructureLength || bufferLength > MaximumBufferLength)
            {
                throw new ControllerException(
                    $"Job Object process ID list capacity is invalid: {bufferLength}");
            }

            var buffer = Marshal.AllocHGlobal((int)bufferLength);
            try
            {
                if (query(
                        job,
                        buffer,
                        bufferLength,
                        out var returnLength,
                        out var win32Error))
                {
                    return ParseVerifiedList(buffer, bufferLength, returnLength);
                }

                if (win32Error != 234)
                {
                    throw new ControllerException(
                        $"QueryInformationJobObject failed: Win32 error {win32Error}");
                }

                bufferLength = GetGrownCapacity(buffer, bufferLength, returnLength);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new ControllerException("the Job Object process ID list did not stabilize");
    }

    private static uint GetGrownCapacity(IntPtr buffer, uint currentCapacity, uint returnedLength)
    {
        if (currentCapacity < ProcessIdListOffset)
        {
            throw new ControllerException("the Job Object process ID list header is too small");
        }

        var assignedProcesses = Marshal.ReadInt32(buffer, 0);
        var processIdCount = Marshal.ReadInt32(buffer, sizeof(int));
        ValidateCounts(assignedProcesses, processIdCount);
        var requiredByCounts = RequiredLength(processIdCount);
        var doubled = (long)currentCapacity * 2;
        var desired = Math.Max(Math.Max(doubled, returnedLength), requiredByCounts);
        if (desired > MaximumBufferLength)
        {
            throw new ControllerException(
                $"Job Object process ID list exceeds bounded capacity: required {desired}, maximum {MaximumBufferLength}");
        }

        var nextCapacity = (uint)desired;
        if (nextCapacity <= currentCapacity)
        {
            throw new ControllerException("the Job Object process ID list capacity did not grow after ERROR_MORE_DATA");
        }

        return nextCapacity;
    }

    private static uint[] ParseVerifiedList(IntPtr buffer, uint bufferCapacity, uint returnLength)
    {
        if (returnLength < MinimumStructureLength || returnLength > bufferCapacity)
        {
            throw new ControllerException(
                $"Job Object process ID list return length is unverified: return={returnLength}, capacity={bufferCapacity}");
        }

        var assignedProcesses = Marshal.ReadInt32(buffer, 0);
        var processIdCount = Marshal.ReadInt32(buffer, sizeof(int));
        ValidateCounts(assignedProcesses, processIdCount);
        var requiredLength = RequiredLength(processIdCount);
        if (returnLength < requiredLength)
        {
            throw new ControllerException(
                $"Job Object process ID list return length is insufficient: return={returnLength}, required={requiredLength}");
        }

        var processIds = new uint[processIdCount];
        for (var index = 0; index < processIdCount; index++)
        {
            processIds[index] = (uint)Marshal.ReadIntPtr(buffer, ProcessIdListOffset + index * IntPtr.Size);
        }

        return processIds;
    }

    private static long RequiredLength(int processIdCount)
    {
        try
        {
            return checked(ProcessIdListOffset + (long)processIdCount * IntPtr.Size);
        }
        catch (OverflowException exception)
        {
            throw new ControllerException("the Job Object process ID list length overflows", exception);
        }
    }

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
