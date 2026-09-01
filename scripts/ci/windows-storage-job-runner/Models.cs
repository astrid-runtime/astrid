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
    public Exception? CleanupFailure { get; }

    public ControllerException(string message)
        : base(message)
    {
    }

    public ControllerException(string message, Exception innerException)
        : this(message, innerException, null)
    {
    }

    public ControllerException(string message, Exception innerException, Exception? cleanupFailure)
        : base(message, innerException)
    {
        CleanupFailure = cleanupFailure;
    }
}

internal static class JobProcessList
{
    internal const int MinimumReturnedHeaderLength = 8;
    internal const int ProcessIdListOffset = 8;
    internal const int MinimumStructureLength = 16;
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
                    var processIds = ParseVerifiedList(buffer, bufferLength, returnLength, out var truncated);
                    if (!truncated)
                    {
                        return processIds;
                    }

                    bufferLength = GetGrownCapacity(buffer, bufferLength, returnLength);
                    continue;
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
        if (currentCapacity < MinimumStructureLength)
        {
            throw new ControllerException("the Job Object process ID list header is too small");
        }

        var assignedProcesses = Marshal.ReadInt32(buffer, 0);
        var processIdCount = Marshal.ReadInt32(buffer, sizeof(int));
        ValidateCounts(assignedProcesses, processIdCount);
        var requiredByCounts = RequiredLength(assignedProcesses);
        var doubled = (long)currentCapacity * 2;
        var desired = Math.Max(Math.Max(doubled, (long)returnedLength), requiredByCounts);
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

    private static uint[] ParseVerifiedList(
        IntPtr buffer,
        uint bufferCapacity,
        uint returnLength,
        out bool truncated)
    {
        if (returnLength < MinimumReturnedHeaderLength || returnLength > bufferCapacity)
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

        if (processIdCount > 0 && returnLength != requiredLength)
        {
            throw new ControllerException(
                $"Job Object process ID list return length is overlong: return={returnLength}, exact={requiredLength}");
        }

        var processIds = new uint[processIdCount];
        for (var index = 0; index < processIdCount; index++)
        {
            processIds[index] = (uint)Marshal.ReadIntPtr(buffer, ProcessIdListOffset + index * IntPtr.Size);
        }

        truncated = processIdCount < assignedProcesses;
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

internal static class ParityChild
{
    internal static int Run(string receivedPathText, IReadOnlyList<string> arguments)
    {
        var receivedPath = Path.GetFullPath(receivedPathText);
        if (!string.Equals(receivedPath, receivedPathText, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerException($"parity received path is not canonical: expected {receivedPath}, got {receivedPathText}");
        }

        if (arguments is ["--list", "--format=terse", "storage_mount"])
        {
            Console.Out.WriteLine("alpha: test");
            Console.Out.WriteLine("beta: test");
            Console.Out.Flush();
            return 0;
        }

        if (arguments is ["storage_mount", "--", "--nocapture", "--test-threads=1"])
        {
            Record(receivedPath, "aggregate");
            return 0;
        }

        if (arguments is [var testName, "--", "--exact", "--nocapture", "--test-threads=1"] &&
            testName is "alpha" or "beta")
        {
            Record(receivedPath, testName);
            return 0;
        }

        return 10;
    }

    private static void Record(string receivedPath, string phase)
    {
        File.AppendAllText(receivedPath, $"{phase}{Environment.NewLine}");
        Console.Out.WriteLine($"parity-recorded {phase}");
        Console.Out.Flush();
    }
}

internal static class LibTestChild
{
    internal static readonly string[] TestNames =
    [
        "storage_mount::process_broker::lease_atomicity_tests::cache_invalidation_tests::alpha",
        "storage_mount::process_broker::lease_atomicity_tests::cache_invalidation_tests::beta",
    ];

    internal static int Run(string journalPathText, IReadOnlyList<string> arguments)
    {
        var journalPath = Path.GetFullPath(journalPathText);
        if (!string.Equals(journalPath, journalPathText, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerException($"libtest journal path is not canonical: expected {journalPath}, got {journalPathText}");
        }

        var parsed = ParseArguments(arguments);
        var stateDirectory = Path.GetDirectoryName(journalPath);
        if (string.IsNullOrEmpty(stateDirectory))
        {
            throw new ControllerException("the libtest journal path has no directory");
        }

        Directory.CreateDirectory(stateDirectory);
        var lockPath = Path.Combine(stateDirectory, "libtest-child.lock");
        var activePath = Path.Combine(stateDirectory, "libtest-child.active");
        var lockStream = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);

        try
        {
            if (File.Exists(activePath))
            {
                Console.Error.WriteLine("cache-invalidation tests overlap: another test is active");
                return 10;
            }

            File.WriteAllText(activePath, $"{Environment.ProcessId};{parsed.Filter}");
            foreach (var testName in parsed.SelectedTests)
            {
                var begin = $"{Environment.ProcessId};begin;{testName};{Stopwatch.GetTimestamp()}";
                File.AppendAllText(journalPath, $"{begin}{Environment.NewLine}");
                if (parsed.NoCapture)
                {
                    Console.Out.WriteLine($"running {testName}");
                }

                Thread.Sleep(25);
                File.AppendAllText(journalPath, $"{begin.Replace(";begin;", ";end;")}{Environment.NewLine}");
                if (parsed.NoCapture)
                {
                    Console.Out.WriteLine($"test {testName} ok");
                }
            }

            File.Delete(activePath);
            return 0;
        }
        catch (IOException)
        {
            Console.Error.WriteLine("cache-invalidation tests overlap: execution lock was already held");
            return 10;
        }
        finally
        {
            lockStream.Dispose();
        }
    }

    private static (bool NoCapture, string Filter, IReadOnlyList<string> SelectedTests) ParseArguments(
        IReadOnlyList<string> arguments)
    {
        var noCapture = false;
        var exact = false;
        int? testThreads = null;
        var filters = new List<string>();
        var filtersStarted = false;

        foreach (var argument in arguments)
        {
            if (argument == "--")
            {
                throw new ControllerException("cargo-style separator is not accepted by direct libtest execution");
            }

            if (argument.StartsWith('-'))
            {
                if (filtersStarted)
                {
                    throw new ControllerException($"libtest option follows positional filter: {argument}");
                }

                switch (argument)
                {
                    case "--nocapture" when noCapture:
                    case "--exact" when exact:
                        throw new ControllerException($"duplicate libtest option: {argument}");
                    case "--nocapture":
                        noCapture = true;
                        break;
                    case "--exact":
                        exact = true;
                        break;
                    case "--test-threads=1" when testThreads.HasValue:
                    case var _ when argument.StartsWith("--test-threads=", StringComparison.Ordinal):
                        if (testThreads.HasValue)
                        {
                            throw new ControllerException("duplicate libtest option: --test-threads");
                        }

                        if (argument != "--test-threads=1")
                        {
                            throw new ControllerException(
                                $"libtest maximum concurrency must be 1: {argument}");
                        }

                        testThreads = 1;
                        break;
                    default:
                        throw new ControllerException($"unknown libtest option: {argument}");
                }

                continue;
            }

            filtersStarted = true;
            filters.Add(argument);
        }

        if (!noCapture || testThreads != 1 || filters.Count != 1)
        {
            throw new ControllerException(
                $"libtest arguments must require nocapture, one thread, and one filter: nocapture={noCapture}, threads={testThreads}, filters={filters.Count}");
        }

        var filter = filters[0];
        var selectedTests = exact
            ? TestNames.Where(name => string.Equals(name, filter, StringComparison.Ordinal)).ToArray()
            : TestNames.Where(name => name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (selectedTests.Length == 0)
        {
            throw new ControllerException($"libtest filter selected no cache-invalidation tests: {filter}");
        }

        return (noCapture, filter, selectedTests);
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

internal static class ControllerErrors
{
    internal static ControllerException PreservePrimaryCleanupFailure(
        ControllerException primary,
        Exception? cleanupFailure,
        string stdoutPath,
        string stderrPath)
    {
        var cleanupDetail = cleanupFailure?.Message ?? "cleanup did not reach ACTIVE_PROCESS_ZERO";
        return new ControllerException(
            $"primary cause preserved: {primary.Message}; separate cleanup failure: {cleanupDetail}; "
            + $"stdout={stdoutPath}; stderr={stderrPath}",
            primary,
            cleanupFailure);
    }
}
