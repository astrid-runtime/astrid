using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

[assembly: DisableRuntimeMarshalling]

namespace Astrid.Ci.Windows;

internal static class Program
{
    internal const int TimeoutExitCode = 124;
    internal const int ControllerFailureExitCode = 125;

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("the Windows storage certification runner requires Windows");
            return ControllerFailureExitCode;
        }

        try
        {
            return args switch
            {
                ["selftest"] => SelfTest.Run(),
                ["marker-child", var markerPath, var exitCodeText] => MarkerChild.Run(markerPath, exitCodeText),
                ["parity-child", var receivedPath, .. var parityArguments] => ParityChild.Run(receivedPath, parityArguments),
                ["libtest-child", var journalPath, .. var libtestArguments] => LibTestChild.Run(journalPath, libtestArguments),
                ["certify", .. var certificationArgs] => Certify(ParseOptions(certificationArgs)),
                _ => throw new ControllerException("expected 'selftest' or 'certify' with named options"),
            };
        }
        catch (ControllerException exception)
        {
            Console.Error.WriteLine($"controller failure: {exception.Message}");
            return ControllerFailureExitCode;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"controller failure: unexpected {exception.GetType().Name}: {exception.Message}");
            return ControllerFailureExitCode;
        }
    }

    private static int Certify(CertificationOptions options)
    {
        ValidateCommonOptions(options);
        AssertProvider(options.ProviderCanonical, options.Provider, options.ProviderSha256);

        var listArguments = BuildCanonicalListArguments();
        var listResult = RunJobProcess(
            options.TestExecutable,
            listArguments,
            options.WorkingDirectory,
            Path.Combine(options.LogDirectory, "list.stdout.log"),
            Path.Combine(options.LogDirectory, "list.stderr.log"),
            options.ListTimeout,
            options.CleanupTimeout,
            options.HeartbeatInterval);
        ReportJob("list", listResult);
        if (listResult.Outcome is JobOutcome.ControllerFailed)
        {
            return ControllerFailureExitCode;
        }

        if (listResult.Outcome is not JobOutcome.Succeeded)
        {
            throw new ControllerException(
                $"libtest discovery failed with exit code {listResult.ExitCode}; stdout={listResult.StdoutPath}; stderr={listResult.StderrPath}");
        }

        var testNames = ParseTestList(File.ReadAllLines(listResult.StdoutPath));
        if (testNames.Count == 0)
        {
            throw new ControllerException("the storage_mount libtest list was empty");
        }

        Console.WriteLine($"[storage-job] discovered {testNames.Count} storage_mount tests");
        foreach (var testName in testNames)
        {
            Console.WriteLine($"[storage-job] listed {testName}");
        }

        AssertProvider(options.ProviderCanonical, options.Provider, options.ProviderSha256);
        var aggregateResult = RunJobProcess(
            options.TestExecutable,
            BuildCanonicalAggregateArguments(),
            options.WorkingDirectory,
            Path.Combine(options.LogDirectory, "aggregate.stdout.log"),
            Path.Combine(options.LogDirectory, "aggregate.stderr.log"),
            options.AggregateTimeout,
            options.CleanupTimeout,
            options.HeartbeatInterval);
        ReportJob("aggregate", aggregateResult);

        if (aggregateResult.Outcome is JobOutcome.TimedOut)
        {
            IdentifyTimeoutWithFreshJobs(options, testNames);
            Console.Error.WriteLine(
                $"aggregate storage_mount certification timed out; diagnostics are advisory only; stdout={aggregateResult.StdoutPath}; stderr={aggregateResult.StderrPath}");
            return TimeoutExitCode;
        }

        if (aggregateResult.Outcome is JobOutcome.ControllerFailed)
        {
            return ControllerFailureExitCode;
        }

        if (aggregateResult.Outcome is not JobOutcome.Succeeded)
        {
            Console.Error.WriteLine(
                $"aggregate storage_mount certification failed with exit code {aggregateResult.ExitCode}; stdout={aggregateResult.StdoutPath}; stderr={aggregateResult.StderrPath}");
            return unchecked((int)aggregateResult.ExitCode);
        }

        Console.WriteLine("[storage-job] aggregate storage_mount certification passed");
        return 0;
    }

    private static void IdentifyTimeoutWithFreshJobs(CertificationOptions options, IReadOnlyList<string> testNames)
    {
        Console.WriteLine("[diagnostic] aggregate timeout detected; identifying tests with fresh job objects");
        var identified = new List<string>();

        foreach (var testName in testNames)
        {
            AssertProvider(options.ProviderCanonical, options.Provider, options.ProviderSha256);
            var result = RunJobProcess(
                options.TestExecutable,
                BuildCanonicalDiagnosticArguments(testName),
                options.WorkingDirectory,
                Path.Combine(options.LogDirectory, $"diagnostic.{SafeFileName(testName)}.stdout.log"),
                Path.Combine(options.LogDirectory, $"diagnostic.{SafeFileName(testName)}.stderr.log"),
                options.DiagnosticTimeout,
                options.CleanupTimeout,
                options.HeartbeatInterval);
            ReportJob($"diagnostic {testName}", result);

            if (result.Outcome is JobOutcome.ControllerFailed)
            {
                throw new ControllerException(
                    $"diagnostic controller failure for {testName}; stdout={result.StdoutPath}; stderr={result.StderrPath}");
            }

            if (result.Outcome is JobOutcome.TimedOut)
            {
                identified.Add(testName);
            }
        }

        if (identified.Count == 0)
        {
            Console.WriteLine("[diagnostic] no individual test timed out; the aggregate run exceeded its cumulative budget");
        }
        else
        {
            Console.Error.WriteLine($"[diagnostic] timed-out tests: {string.Join(", ", identified)}");
        }
    }

    private static string[] BuildCanonicalListArguments() =>
        ["--list", "--format=terse", StorageTestFilter];

    private static string[] BuildCanonicalAggregateArguments() =>
        ["--nocapture", "--test-threads=1", StorageTestFilter];

    private static string[] BuildCanonicalDiagnosticArguments(string testName) =>
        ["--exact", "--nocapture", "--test-threads=1", testName];

    private static List<string> ParseTestList(IEnumerable<string> lines)
    {
        var names = new List<string>();
        foreach (var line in lines)
        {
            const string marker = ": test";
            if (!line.EndsWith(marker, StringComparison.Ordinal))
            {
                continue;
            }

            var testName = line[..^marker.Length].Trim();
            if (testName.Length != 0)
            {
                names.Add(testName);
            }
        }

        return names;
    }

    private static void ReportJob(string phase, JobRunResult result)
    {
        var outcome = result.Outcome switch
        {
            JobOutcome.Succeeded => "succeeded",
            JobOutcome.ChildFailed => $"failed with exit code {result.ExitCode}",
            JobOutcome.TimedOut => "timed out",
            JobOutcome.ControllerFailed => "hit a controller failure",
            _ => "ended in an unknown state",
        };
        Console.WriteLine(
            $"[storage-job] {phase} {outcome} in {result.Elapsed.TotalSeconds:F1}s; cleanup={FormatCleanup(result)}; stdout={result.StdoutPath}; stderr={result.StderrPath}");
    }

    private static string FormatCleanup(JobRunResult result) =>
        result.CleanupComplete ? "ACTIVE_PROCESS_ZERO" : $"incomplete (active: {string.Join(',', result.ActiveProcessIds)})";

    private static void ValidateCommonOptions(CertificationOptions options)
    {
        var testExecutable = Path.GetFullPath(options.TestExecutable);
        if (!string.Equals(testExecutable, options.TestExecutable, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerException(
                $"the libtest executable is not canonical: expected {testExecutable}, got {options.TestExecutable}");
        }

        if (!File.Exists(testExecutable))
        {
            throw new ControllerException($"the libtest executable is not a file: {testExecutable}");
        }

        if (!Directory.Exists(options.WorkingDirectory))
        {
            throw new ControllerException($"the working directory does not exist: {options.WorkingDirectory}");
        }

        Directory.CreateDirectory(options.LogDirectory);
    }

    private static void AssertProvider(string expectedPath, string actualPath, string expectedHash)
    {
        var expectedCanonical = Path.GetFullPath(expectedPath);
        var actualCanonical = Path.GetFullPath(actualPath);
        if (!string.Equals(expectedCanonical, actualCanonical, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerException(
                $"provider path substitution rejected: expected {expectedCanonical}, got {actualCanonical}");
        }

        if (!File.Exists(actualCanonical))
        {
            throw new ControllerException($"the exact staged provider is not a file: {actualCanonical}");
        }

        var actualHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(actualCanonical))).ToLowerInvariant();
        if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerException($"staged provider SHA-256 mismatch: expected {expectedHash}, got {actualHash}");
        }
    }

    private static string SafeFileName(string testName)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(testName.Length);
        foreach (var character in testName)
        {
            builder.Append(Array.IndexOf(invalid, character) >= 0 ? '_' : character);
        }

        return builder.ToString();
    }

    internal static string ResolveExecutableForSelfTest(string executable) => ResolveExecutable(executable);

    private static string ResolveExecutable(string executable)
    {
        if (string.IsNullOrWhiteSpace(executable))
        {
            throw new ControllerException("the executable path is empty");
        }

        if (Path.IsPathRooted(executable))
        {
            var canonical = Path.GetFullPath(executable);
            if (!string.Equals(canonical, executable, StringComparison.OrdinalIgnoreCase))
            {
                throw new ControllerException(
                    $"executable path is not canonical: expected {canonical}, got {executable}");
            }

            if (!File.Exists(canonical))
            {
                throw new ControllerException($"canonical executable is not a file: {canonical}");
            }

            return canonical;
        }

        const int maxSearchLength = 32768;
        var requiredLength = NativeMethods.SearchPathW(
            IntPtr.Zero,
            executable,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            IntPtr.Zero);
        if (requiredLength == 0)
        {
            throw new ControllerException(
                $"could not resolve executable {executable}: Win32 error {Marshal.GetLastWin32Error()}");
        }

        var bufferLength = requiredLength + 1;
        if (bufferLength > maxSearchLength)
        {
            throw new ControllerException($"resolved executable path is too long: {requiredLength}");
        }

        var buffer = Marshal.AllocHGlobal((int)bufferLength * sizeof(char));
        try
        {
            var returnedLength = NativeMethods.SearchPathW(
                IntPtr.Zero,
                executable,
                IntPtr.Zero,
                bufferLength,
                buffer,
                IntPtr.Zero);
            if (returnedLength == 0 || returnedLength >= bufferLength)
            {
                throw new ControllerException(
                    $"searching for executable {executable} failed: Win32 error {Marshal.GetLastWin32Error()}");
            }

            var searched = Marshal.PtrToStringUni(buffer, (int)returnedLength)
                ?? throw new ControllerException($"SearchPathW returned an invalid executable path for {executable}");
            var canonical = Path.GetFullPath(searched);
            if (!string.Equals(canonical, searched, StringComparison.OrdinalIgnoreCase) || !File.Exists(canonical))
            {
                throw new ControllerException($"SearchPathW did not return an existing canonical executable: {searched}");
            }

            return canonical;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static JobRunResult RunJobProcess(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        string stdoutPath,
        string stderrPath,
        TimeSpan timeout,
        TimeSpan cleanupTimeout,
        TimeSpan heartbeatInterval)
    {
        if (timeout <= TimeSpan.Zero || cleanupTimeout <= TimeSpan.Zero)
        {
            throw new ControllerException("controller and cleanup timeouts must be greater than zero");
        }

        var stdoutHandle = OpenInheritableWriteFile(stdoutPath);
        var stderrHandle = OpenInheritableWriteFile(stderrPath);
        try
        {
            return ExecuteInJob(
                executable,
                arguments,
                workingDirectory,
                stdoutPath,
                stderrPath,
                stdoutHandle,
                stderrHandle,
                timeout,
                cleanupTimeout,
                heartbeatInterval,
                afterAssignment: null,
                afterResume: null,
                forceAssignmentFailure: false);
        }
        finally
        {
            stdoutHandle.Dispose();
            stderrHandle.Dispose();
        }
    }

    private static unsafe SafeFileHandle OpenInheritableWriteFile(string path)
    {
        var security = default(NativeMethods.SecurityAttributes);
        security.Length = (uint)sizeof(NativeMethods.SecurityAttributes);
        security.InheritHandle = 1;
        var handle = NativeMethods.CreateFileW(
            path,
            NativeMethods.GenericWrite,
            NativeMethods.FileShareRead,
            ref security,
            NativeMethods.CreateAlways,
            NativeMethods.FileAttributeNormal,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new ControllerException($"could not create durable output file {path}: Win32 error {Marshal.GetLastWin32Error()}");
        }

        return handle;
    }

    private static unsafe JobRunResult ExecuteInJob(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        string stdoutPath,
        string stderrPath,
        SafeFileHandle stdoutHandle,
        SafeFileHandle stderrHandle,
        TimeSpan timeout,
        TimeSpan cleanupTimeout,
        TimeSpan heartbeatInterval,
        Action? afterAssignment,
        Action<SafeJobHandle>? afterResume,
        bool forceAssignmentFailure = false,
        Func<SafeJobHandle, SafeProcessHandle?, TimeSpan, Exception?>? cleanupFailureOverride = null)
    {
        executable = ResolveExecutable(executable);
        using var job = CreateKillOnCloseJob();
        SafeProcessHandle? process = null;
        SafeWindowsHandle? thread = null;
        JobRunResult result;
        var processAssignedToJob = false;
        var directProcessCleanupComplete = false;
        try
        {
            var startup = default(NativeMethods.StartupInfoW);
            startup.cb = (uint)sizeof(NativeMethods.StartupInfoW);
            startup.dwFlags = NativeMethods.StartupUseStandardHandles;
            startup.hStdOutput = stdoutHandle.DangerousGetHandle();
            startup.hStdError = stderrHandle.DangerousGetHandle();
            startup.hStdInput = IntPtr.Zero;

            var commandLine = BuildCommandLine(executable, arguments);
            if (!NativeMethods.CreateProcessW(
                    executable,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    NativeMethods.CreateSuspended,
                    IntPtr.Zero,
                    workingDirectory,
                    ref startup,
                    out var rawProcessInformation))
            {
                throw new ControllerException(
                    $"CreateProcessW failed for {executable}: Win32 error {Marshal.GetLastWin32Error()}");
            }

            process = new SafeProcessHandle(rawProcessInformation.Process, ownsHandle: true);
            thread = new SafeWindowsHandle(rawProcessInformation.Thread, ownsHandle: true);
            var processId = rawProcessInformation.ProcessId;
            var assignmentSucceeded = !forceAssignmentFailure && NativeMethods.AssignProcessToJobObject(job, process);
            if (!assignmentSucceeded)
            {
                var assignmentFailure = forceAssignmentFailure
                    ? "forced-self-test"
                    : $"Win32 error {Marshal.GetLastWin32Error()}";
                var directCleanup = TerminateUnassignedProcessAndAwait(process, cleanupTimeout);
                directProcessCleanupComplete = directCleanup;
                throw new ControllerException(
                    $"AssignProcessToJobObject failed for process {processId}: {assignmentFailure}; "
                    + $"cleanup={(directCleanup ? "PROCESS_EXITED" : "INCOMPLETE")}; "
                    + $"stdout={stdoutPath}; stderr={stderrPath}");
            }

            processAssignedToJob = true;
            afterAssignment?.Invoke();
            var previousSuspendCount = NativeMethods.ResumeThread(thread);
            if (previousSuspendCount != 1)
            {
                throw new ControllerException(
                    $"ResumeThread did not prove CREATE_SUSPENDED for process {processId}: previous count {previousSuspendCount}");
            }

            afterResume?.Invoke(job);
            result = WaitAndCleanUpAsync(
                job,
                thread,
                process,
                processId,
                stdoutPath,
                stderrPath,
                timeout,
                cleanupTimeout,
                heartbeatInterval).GetAwaiter().GetResult();
            thread.Dispose();
            process.Dispose();
        }
        catch (Exception exception) when (exception is not ControllerException)
        {
            var cleanup = CleanupAfterFailure(
                job,
                process,
                cleanupTimeout,
                cleanupFailureOverride,
                out var genericCleanupFailure);
            throw new ControllerException(
                $"{exception.Message}; cleanup={(cleanup ? "ACTIVE_PROCESS_ZERO" : "incomplete")}; stdout={stdoutPath}; stderr={stderrPath}",
                exception,
                genericCleanupFailure);
        }
        catch (ControllerException primary)
        {
            if (!processAssignedToJob)
            {
                throw;
            }

            var cleanupSucceeded = CleanupAfterFailure(
                job,
                process,
                cleanupTimeout,
                cleanupFailureOverride,
                out var cleanupFailure);
            if (!cleanupSucceeded)
            {
                throw ControllerErrors.PreservePrimaryCleanupFailure(
                    primary,
                    cleanupFailure,
                    stdoutPath,
                    stderrPath);
            }

            throw;
        }
        finally
        {
            thread?.Dispose();
            process?.Dispose();
        }

        return result;
    }

    private static unsafe SafeJobHandle CreateKillOnCloseJob()
    {
        var job = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid)
        {
            throw new ControllerException($"CreateJobObjectW failed: Win32 error {Marshal.GetLastWin32Error()}");
        }

        var limits = default(NativeMethods.ExtendedLimitInformation);
        limits.BasicLimitInformation.LimitFlags = NativeMethods.JobObjectLimitKillOnJobClose;
        if (!NativeMethods.SetInformationJobObject(
                job,
                NativeMethods.JobObjectExtendedLimitInformation,
                ref limits,
                sizeof(NativeMethods.ExtendedLimitInformation)))
        {
            job.Dispose();
            throw new ControllerException(
                $"setting JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE failed: Win32 error {Marshal.GetLastWin32Error()}");
        }

        return job;
    }

    private static async Task<JobRunResult> WaitAndCleanUpAsync(
        SafeJobHandle job,
        SafeWindowsHandle thread,
        SafeProcessHandle process,
        int processId,
        string stdoutPath,
        string stderrPath,
        TimeSpan timeout,
        TimeSpan cleanupTimeout,
        TimeSpan heartbeatInterval)
    {
        var stdoutCounter = new StrongBox<long>();
        var stderrCounter = new StrongBox<long>();
        using var heartbeatSource = new CancellationTokenSource();
        var heartbeatToken = heartbeatSource.Token;
        var heartbeat = Task.Run(async () =>
        {
            var elapsed = Stopwatch.StartNew();
            while (!heartbeatToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(heartbeatInterval, heartbeatToken);
                    Console.WriteLine(
                        $"[heartbeat] process {processId} elapsed={elapsed.Elapsed.TotalSeconds:F0}s stdout={Interlocked.Read(ref stdoutCounter.Value)}B stderr={Interlocked.Read(ref stderrCounter.Value)}B");
                }
                catch (OperationCanceledException)
                {
                }
            }
        }, heartbeatToken);

        var stdoutTail = OutputTail.TailOutput(stdoutPath, Console.Out, stdoutCounter, heartbeatToken);
        var stderrTail = OutputTail.TailOutput(stderrPath, Console.Error, stderrCounter, heartbeatToken);
        var stopwatch = Stopwatch.StartNew();
        var outcome = JobOutcome.ControllerFailed;
        var exitCode = 0u;
        bool cleanupComplete;
        var rootHandlesReleased = false;
        var activeProcessIds = Array.Empty<uint>();
        var originalCause = string.Empty;

        try
        {
            while (stopwatch.Elapsed < timeout)
            {
                var wait = NativeMethods.WaitForSingleObject(process, 100);
                if (wait == NativeMethods.WaitObject0)
                {
                    if (!NativeMethods.GetExitCodeProcess(process, out exitCode))
                    {
                        throw new ControllerException(
                            $"GetExitCodeProcess failed for process {processId}: Win32 error {Marshal.GetLastWin32Error()}");
                    }

                    outcome = exitCode == 0 ? JobOutcome.Succeeded : JobOutcome.ChildFailed;
                    break;
                }

                if (wait != NativeMethods.WaitTimeout)
                {
                    throw new ControllerException(
                        $"waiting for process {processId} failed: Win32 error {Marshal.GetLastWin32Error()}");
                }
            }

            if (outcome is JobOutcome.ControllerFailed && stopwatch.Elapsed >= timeout)
            {
                outcome = JobOutcome.TimedOut;
                originalCause = $"controller timeout after {timeout.TotalSeconds:F0}s";
                if (!NativeMethods.TerminateJobObject(job, TimeoutExitCode))
                {
                    throw new ControllerException(
                        $"TerminateJobObject failed after timeout: Win32 error {Marshal.GetLastWin32Error()}");
                }

                if (!RootProcessCleanup.WaitForProcessExit(process, cleanupTimeout))
                {
                    throw new ControllerException(
                        $"timed-out root process {processId} did not exit within the cleanup budget");
                }

                if (!NativeMethods.GetExitCodeProcess(process, out exitCode))
                {
                    throw new ControllerException(
                        $"GetExitCodeProcess failed for timed-out process {processId}: Win32 error {Marshal.GetLastWin32Error()}");
                }
            }

            rootHandlesReleased = RootProcessCleanup.ReleaseHandles(thread, process);
            if (!rootHandlesReleased)
            {
                throw new ControllerException($"root thread/process handles were not released for process {processId}");
            }

            var descendantWait = Stopwatch.StartNew();
            while (descendantWait.Elapsed < cleanupTimeout)
            {
                activeProcessIds = GetJobProcessIds(job);
                if (activeProcessIds.Length == 0)
                {
                    break;
                }

                Thread.Sleep(50);
            }

            activeProcessIds = GetJobProcessIds(job);
            if (activeProcessIds.Length != 0)
            {
                originalCause = $"process {processId} exited while descendants remained active";
                outcome = JobOutcome.ControllerFailed;
                if (!NativeMethods.TerminateJobObject(job, ControllerFailureExitCode))
                {
                    throw new ControllerException(
                        $"TerminateJobObject failed for surviving descendants: Win32 error {Marshal.GetLastWin32Error()}");
                }
            }

            if (!WaitForActiveProcessZero(job, cleanupTimeout, out activeProcessIds))
            {
                throw new ControllerException(
                    $"job cleanup did not reach ACTIVE_PROCESS_ZERO; active {string.Join(',', activeProcessIds)}");
            }

            cleanupComplete = true;
        }
        finally
        {
            heartbeatSource.Cancel();
            await Task.WhenAll(heartbeat, stdoutTail, stderrTail);
        }

        return new JobRunResult(
            outcome,
            exitCode,
            originalCause,
            cleanupComplete,
            activeProcessIds,
            stdoutPath,
            stderrPath,
            processId,
            rootHandlesReleased,
            stopwatch.Elapsed);
    }

    private static bool TryTerminateAndAwait(
        SafeJobHandle job,
        SafeProcessHandle? process,
        TimeSpan cleanupTimeout,
        out Exception? cleanupFailure)
    {
        cleanupFailure = null;
        try
        {
            if (process is not null && !process.IsInvalid)
            {
                _ = NativeMethods.TerminateJobObject(job, ControllerFailureExitCode);
            }

            if (WaitForActiveProcessZero(job, cleanupTimeout, out var activeProcessIds))
            {
                return true;
            }

            cleanupFailure = new ControllerException(
                $"cleanup timed out with {activeProcessIds.Length} active process IDs: {string.Join(',', activeProcessIds)}");
            return false;
        }
        catch (Exception exception)
        {
            cleanupFailure = exception;
            return false;
        }
    }

    private static bool CleanupAfterFailure(
        SafeJobHandle job,
        SafeProcessHandle? process,
        TimeSpan cleanupTimeout,
        Func<SafeJobHandle, SafeProcessHandle?, TimeSpan, Exception?>? cleanupFailureOverride,
        out Exception? cleanupFailure)
    {
        if (cleanupFailureOverride is not null)
        {
            cleanupFailure = cleanupFailureOverride(job, process, cleanupTimeout);
            return cleanupFailure is null;
        }

        return TryTerminateAndAwait(job, process, cleanupTimeout, out cleanupFailure);
    }

    private static bool TerminateUnassignedProcessAndAwait(
        SafeProcessHandle? process,
        TimeSpan cleanupTimeout)
    {
        if (process is null || process.IsInvalid)
        {
            return false;
        }

        try
        {
            _ = NativeMethods.TerminateProcess(process, ControllerFailureExitCode);
            return RootProcessCleanup.WaitForProcessExit(process, cleanupTimeout);
        }
        catch
        {
            return false;
        }
    }

    private static bool WaitForActiveProcessZero(
        SafeJobHandle job,
        TimeSpan cleanupTimeout,
        out uint[] activeProcessIds)
    {
        var stopwatch = Stopwatch.StartNew();
        do
        {
            activeProcessIds = GetJobProcessIds(job);
            if (activeProcessIds.Length == 0)
            {
                return true;
            }

            Thread.Sleep(50);
        }
        while (stopwatch.Elapsed < cleanupTimeout);

        activeProcessIds = GetJobProcessIds(job);
        return activeProcessIds.Length == 0;
    }

    private static uint[] GetJobProcessIds(SafeJobHandle job)
    {
        return JobProcessList.ReadIds(job, NativeMethods.QueryJobProcessIdsNative);
    }

    internal static IReadOnlyList<string> ParseTestListForSelfTest(IEnumerable<string> lines) =>
        ParseTestList(lines);

    internal static string[] BuildCanonicalListArgumentsForSelfTest() => BuildCanonicalListArguments();

    internal static string[] BuildCanonicalAggregateArgumentsForSelfTest() => BuildCanonicalAggregateArguments();

    internal static string[] BuildCanonicalDiagnosticArgumentsForSelfTest(string testName) =>
        BuildCanonicalDiagnosticArguments(testName);

    internal static void AssertProviderForSelfTest(string expectedPath, string actualPath, string expectedHash) =>
        AssertProvider(expectedPath, actualPath, expectedHash);

    internal static uint[] GetJobProcessIdsForSelfTest(SafeJobHandle job) => GetJobProcessIds(job);

    internal static uint[] ReadJobProcessIdsForSelfTest(
        SafeJobHandle job,
        QueryJobProcessList query) =>
        JobProcessList.ReadIds(job, query);

    internal static JobRunResult RunCommandForSelfTest(
        string workingDirectory,
        IReadOnlyList<string> command,
        string stdoutPath,
        string stderrPath,
        TimeSpan timeout,
        TimeSpan cleanupTimeout,
        TimeSpan heartbeatInterval,
        Action? afterAssignment,
        Action<SafeJobHandle>? afterResume,
        bool forceAssignmentFailure = false,
        Func<SafeJobHandle, SafeProcessHandle?, TimeSpan, Exception?>? cleanupFailureOverride = null)
    {
        var stdoutHandle = OpenInheritableWriteFile(stdoutPath);
        var stderrHandle = OpenInheritableWriteFile(stderrPath);
        try
        {
            return ExecuteInJob(
                command[0],
                command.Skip(1).ToArray(),
                workingDirectory,
                stdoutPath,
                stderrPath,
                stdoutHandle,
                stderrHandle,
                timeout,
                cleanupTimeout,
                heartbeatInterval,
                afterAssignment,
                afterResume,
                forceAssignmentFailure,
                cleanupFailureOverride);
        }
        finally
        {
            stdoutHandle.Dispose();
            stderrHandle.Dispose();
        }
    }

    private static string BuildCommandLine(string executable, IReadOnlyList<string> arguments)
    {
        var builder = new StringBuilder();
        AppendCommandLineArgument(builder, executable);
        foreach (var argument in arguments)
        {
            builder.Append(' ');
            AppendCommandLineArgument(builder, argument);
        }

        return builder.ToString();
    }

    private static void AppendCommandLineArgument(StringBuilder builder, string argument)
    {
        if (argument.Length != 0 && !argument.Any(char.IsWhiteSpace) && !argument.Contains('"'))
        {
            builder.Append(argument);
            return;
        }

        builder.Append('"');
        var backslashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                ++backslashes;
            }
            else
            {
                if (backslashes > 0)
                {
                    builder.Append('\\', backslashes * 2);
                    backslashes = 0;
                }

                if (character == '"')
                {
                    builder.Append("\\\"");
                }
                else
                {
                    builder.Append(character);
                }
            }
        }

        if (backslashes > 0)
        {
            builder.Append('\\', backslashes * 2);
        }

        builder.Append('"');
    }

    private static CertificationOptions ParseOptions(string[] args)
    {
        var options = new CertificationOptions();
        for (var index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length)
            {
                throw new ControllerException($"missing value for {args[index]}");
            }

            var value = args[index + 1];
            switch (args[index])
            {
                case "--test-executable":
                    options.TestExecutable = value;
                    break;
                case "--provider-canonical":
                    options.ProviderCanonical = value;
                    break;
                case "--provider":
                    options.Provider = value;
                    break;
                case "--provider-sha256":
                    options.ProviderSha256 = value;
                    break;
                case "--working-directory":
                    options.WorkingDirectory = value;
                    break;
                case "--log-directory":
                    options.LogDirectory = value;
                    break;
                case "--list-timeout-seconds":
                    options.ListTimeout = ParsePositiveTimeSpan(args[index], value);
                    break;
                case "--aggregate-timeout-seconds":
                    options.AggregateTimeout = ParsePositiveTimeSpan(args[index], value);
                    break;
                case "--diagnostic-timeout-seconds":
                    options.DiagnosticTimeout = ParsePositiveTimeSpan(args[index], value);
                    break;
                case "--cleanup-timeout-seconds":
                    options.CleanupTimeout = ParsePositiveTimeSpan(args[index], value);
                    break;
                case "--heartbeat-seconds":
                    options.HeartbeatInterval = ParsePositiveTimeSpan(args[index], value);
                    break;
                default:
                    throw new ControllerException($"unknown certification option: {args[index]}");
            }
        }

        return options;
    }

    private static TimeSpan ParsePositiveTimeSpan(string option, string value)
    {
        if (!int.TryParse(value, out var seconds) || seconds <= 0)
        {
            throw new ControllerException($"{option} must be a positive integer");
        }

        return TimeSpan.FromSeconds(seconds);
    }

    private const string StorageTestFilter = "storage_mount";
}
