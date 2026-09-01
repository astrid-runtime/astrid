using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Text;

namespace Astrid.Ci.Windows;

internal sealed class SelfTest
{
    private static readonly string[] ListArguments = Program.BuildCanonicalListArgumentsForSelfTest();
    private static readonly string[] AggregateArguments = ["storage_mount", "--", "--nocapture", "--test-threads=1"];

    private static string RunnerExecutable =>
        Program.ResolveExecutableForSelfTest(Environment.ProcessPath
            ?? throw new ControllerException("the selftest executable path is unavailable"));

    public static int Run()
    {
        var root = Directory.CreateTempSubdirectory("astrid-storage-job-selftest-").FullName;
        try
        {
            StartupInfoLayout();
            ExecutableResolution(root);
            AssignmentBeforeExecution(root);
            ThreeGenerationDescendantTermination(root);
            UnrelatedProcessSurvival(root);
            OutputAndExitCodePreservation(root);
            HandleReleaseAndNonzeroExit(root);
            ForcedAssignmentFailure(root);
            BoundedTimeoutAndCleanup(root);
            FreshJobIsolation(root);
            ArgumentAndListSetParity(root);
            OutputTailCancellationAndFinalDrain(root);
            ProviderSubstitutionRejection(root);
            Console.WriteLine("[selftest] all Windows storage job controls passed");
            return 0;
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    private static void AssignmentBeforeExecution(string root)
    {
        var marker = Path.Combine(root, "assignment.marker");
        var observedAfterResume = false;
        var result = RunCommand(
            root,
            [RunnerExecutable, "marker-child", marker, "0"],
            15,
            afterAssignment: () =>
            {
                if (File.Exists(marker))
                {
                    throw new ControllerException("the suspended child executed before job assignment");
                }
            },
            afterResume: _ =>
            {
                var deadline = DateTime.UtcNow.AddSeconds(2);
                while (!File.Exists(marker) && DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(20);
                }

                observedAfterResume = File.Exists(marker);
            });
        AssertOutcome(result, JobOutcome.Succeeded);
        AssertCleanup(result);
        if (!observedAfterResume)
        {
            throw new ControllerException("the marker did not appear after resume");
        }

        if (!result.RootHandlesReleased)
        {
            throw new ControllerException("root handles were not released before job cleanup");
        }

        if (!File.Exists(marker))
        {
            throw new ControllerException("the assignment-before-execution marker was lost");
        }

        Console.WriteLine("[selftest] assignment occurred before child execution");
    }

    private static void ThreeGenerationDescendantTermination(string root)
    {
        uint[] observedProcessIds = [];
        var result = RunCommand(
            root,
            ["cmd.exe", "/d", "/c", "cmd.exe /d /c ping.exe -n 30 127.0.0.1 > NUL"],
            1,
            afterResume: job =>
            {
                Thread.Sleep(750);
                observedProcessIds = Program.GetJobProcessIdsForSelfTest(job);
                if (observedProcessIds.Distinct().Count() < 3)
                {
                    throw new ControllerException(
                        $"the descendant control observed only {observedProcessIds.Length} live processes");
                }
            });
        AssertOutcome(result, JobOutcome.TimedOut);
        AssertCleanup(result);
        if (!observedProcessIds.Contains((uint)result.ProcessId))
        {
            throw new ControllerException("the descendant control did not contain the assigned root process");
        }

        if (result.OriginalCause.Length == 0)
        {
            throw new ControllerException("the descendant termination test did not record its original timeout cause");
        }

        Console.WriteLine("[selftest] teardown killed three generations and observed ACTIVE_PROCESS_ZERO");
    }

    private static void UnrelatedProcessSurvival(string root)
    {
        using var unrelated = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/d /c ping.exe -n 10 127.0.0.1 > NUL",
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new ControllerException("could not launch the unrelated same-executable control");
        try
        {
            var result = RunCommand(root, ["cmd.exe", "/d", "/c", "ping.exe -n 20 127.0.0.1 > NUL"], 1);
            AssertOutcome(result, JobOutcome.TimedOut);
            AssertCleanup(result);
            if (unrelated.HasExited)
            {
                throw new ControllerException("job cleanup terminated the unrelated cmd.exe process");
            }
        }
        finally
        {
            if (!unrelated.HasExited)
            {
                unrelated.Kill(entireProcessTree: true);
                unrelated.WaitForExit(5000);
            }
        }

        Console.WriteLine("[selftest] the unrelated same-executable process remained alive");
    }

    private static void OutputAndExitCodePreservation(string root)
    {
        var marker = Path.Combine(root, "output.marker");
        var result = RunCommand(
            root,
            [RunnerExecutable, "marker-child", marker, "7"],
            15);
        AssertOutcome(result, JobOutcome.ChildFailed);
        AssertCleanup(result);
        if (!result.RootHandlesReleased)
        {
            throw new ControllerException("root handles were released in the wrong order");
        }

        if (result.ExitCode != 7)
        {
            throw new ControllerException($"injected child exit code changed: expected 7, got {result.ExitCode}");
        }

        var stdout = File.ReadAllText(result.StdoutPath);
        var stderr = File.ReadAllText(result.StderrPath);
        if (!stdout.Contains($"marker-created {marker}", StringComparison.Ordinal) ||
            !stderr.Contains("marker-child-ready", StringComparison.Ordinal) ||
            !File.Exists(marker))
        {
            throw new ControllerException("the durable child output files were incomplete");
        }

        Console.WriteLine("[selftest] durable stdout/stderr and injected exit code 7 were preserved after handle release");
    }

    private static void HandleReleaseAndNonzeroExit(string root)
    {
        var marker = Path.Combine(root, "handle-release.marker");
        var result = RunCommand(
            root,
            [RunnerExecutable, "marker-child", marker, "7"],
            15);
        AssertOutcome(result, JobOutcome.ChildFailed);
        AssertCleanup(result);
        if (result.ExitCode != 7 || !result.RootHandlesReleased || !File.Exists(marker))
        {
            throw new ControllerException(
                $"exit/handle-release cleanup evidence was incomplete: exit={result.ExitCode}, handles={result.RootHandlesReleased}, marker={File.Exists(marker)}");
        }

        Console.WriteLine("[selftest] numeric exit 7 survived root handle release before ACTIVE_PROCESS_ZERO");
    }

    private static void ForcedAssignmentFailure(string root)
    {
        var marker = Path.Combine(root, "forced-assignment.marker");
        var stopwatch = Stopwatch.StartNew();
        ControllerException? failure = null;
        try
        {
            _ = Program.RunCommandForSelfTest(
                root,
                [RunnerExecutable, "marker-child", marker, "0"],
                Path.Combine(root, $"{Guid.NewGuid():N}.stdout.log"),
                Path.Combine(root, $"{Guid.NewGuid():N}.stderr.log"),
                TimeSpan.FromSeconds(15),
                TimeSpan.FromSeconds(10),
                TimeSpan.FromSeconds(1),
                afterAssignment: null,
                afterResume: null,
                forceAssignmentFailure: true);
        }
        catch (ControllerException exception)
        {
            failure = exception;
        }

        stopwatch.Stop();
        if (failure is null)
        {
            throw new ControllerException("the forced assignment failure was accepted");
        }

        if (!failure.Message.Contains("AssignProcessToJobObject failed", StringComparison.Ordinal) ||
            !failure.Message.Contains("forced-self-test", StringComparison.Ordinal) ||
            !failure.Message.Contains("cleanup=PROCESS_EXITED", StringComparison.Ordinal))
        {
            throw new ControllerException($"forced assignment cleanup evidence was incomplete: {failure.Message}");
        }

        if (File.Exists(marker))
        {
            throw new ControllerException("the forced-assignment child executed before direct termination");
        }

        if (stopwatch.Elapsed > TimeSpan.FromSeconds(12))
        {
            throw new ControllerException($"forced assignment cleanup was unbounded: {stopwatch.Elapsed}");
        }

        Console.WriteLine("[selftest] forced assignment failure directly terminated the suspended root");
    }

    private static void BoundedTimeoutAndCleanup(string root)
    {
        var result = RunCommand(root, ["cmd.exe", "/d", "/c", "ping.exe -n 20 127.0.0.1 > NUL"], 1);
        AssertOutcome(result, JobOutcome.TimedOut);
        AssertCleanup(result);
        if (result.Elapsed > TimeSpan.FromSeconds(10))
        {
            throw new ControllerException($"timeout plus cleanup was not bounded: {result.Elapsed}");
        }

        Console.WriteLine($"[selftest] timeout and cleanup stayed bounded at {result.Elapsed.TotalSeconds:F1}s");
    }

    private static void FreshJobIsolation(string root)
    {
        var first = RunCommand(root, ["cmd.exe", "/d", "/c", "exit /b 0"], 15);
        AssertOutcome(first, JobOutcome.Succeeded);
        AssertCleanup(first);
        var second = RunCommand(root, ["cmd.exe", "/d", "/c", "exit /b 0"], 15);
        AssertOutcome(second, JobOutcome.Succeeded);
        AssertCleanup(second);
        if (first.ProcessId == second.ProcessId || IsProcessAlive(first.ProcessId))
        {
            throw new ControllerException("diagnostic job state was shared with a prior process");
        }

        Console.WriteLine("[selftest] fresh diagnostic jobs did not share process state");
    }

    private static void ArgumentAndListSetParity(string root)
    {
        var stub = Path.Combine(root, "libtest-parity.cmd");
        File.WriteAllLines(
            stub,
            [
                "@echo off",
                "if /I \"%~1\" == \"--list\" (",
                "  if /I \"%~2\" == \"--format=terse\" if \"%~3\" == \"storage_mount\" (",
                "    echo alpha: test",
                "    echo beta: test",
                "    exit /b 0",
                "  )",
                "  exit /b 10",
                ")",
                "if \"%~1\" == \"storage_mount\" (",
                "  if \"%~2\" == \"--\" if \"%~3\" == \"--nocapture\" if \"%~4\" == \"--test-threads=1\" (",
                "    echo aggregate>> received.txt",
                "    exit /b 0",
                "  )",
                "  exit /b 11",
                ")",
                "if \"%~1\" == \"alpha\" if \"%~2\" == \"--\" if \"%~3\" == \"--exact\" if \"%~4\" == \"--nocapture\" if \"%~5\" == \"--test-threads=1\" (",
                "  echo alpha>> received.txt",
                "  exit /b 0",
                ")",
                "if \"%~1\" == \"beta\" if \"%~2\" == \"--\" if \"%~3\" == \"--exact\" if \"%~4\" == \"--nocapture\" if \"%~5\" == \"--test-threads=1\" (",
                "  echo beta>> received.txt",
                "  exit /b 0",
                ")",
                "exit /b 12",
            ]);
        var received = Path.Combine(root, "received.txt");
        var listResult = RunCommand(root, ["cmd.exe", "/d", "/c", stub, .. ListArguments], 15);
        AssertOutcome(listResult, JobOutcome.Succeeded);
        var names = Program.ParseTestListForSelfTest(File.ReadAllLines(listResult.StdoutPath));
        if (names is not ["alpha", "beta"] || File.Exists(received))
        {
            throw new ControllerException("the list did not return the stable nonempty set without running tests");
        }

        var aggregate = RunCommand(root, ["cmd.exe", "/d", "/c", stub, .. AggregateArguments], 15);
        AssertOutcome(aggregate, JobOutcome.Succeeded);
        foreach (var name in names)
        {
            var diagnostic = RunCommand(
                root,
                ["cmd.exe", "/d", "/c", stub, name, "--", "--exact", "--nocapture", "--test-threads=1"],
                15);
            AssertOutcome(diagnostic, JobOutcome.Succeeded);
        }

        var receivedSets = File.ReadAllLines(received);
        if (receivedSets is not ["aggregate", "alpha", "beta"])
        {
            throw new ControllerException("canonical list, aggregate, and diagnostic argument sets diverged");
        }

        Console.WriteLine("[selftest] list, aggregate, and exact diagnostic argument sets had the same test set");
    }

    private static void ExecutableResolution(string root)
    {
        var cmd = Program.ResolveExecutableForSelfTest("cmd.exe");
        var canonicalCmd = Path.GetFullPath(cmd);
        if (!Path.IsPathRooted(cmd) ||
            !string.Equals(cmd, canonicalCmd, StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(cmd) ||
            !string.Equals(Path.GetFileName(cmd), "cmd.exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerException($"cmd.exe did not resolve to an existing canonical executable: {cmd}");
        }

        AssertControllerFailure(() => Program.ResolveExecutableForSelfTest(Path.Combine(root, "missing.exe")));
        var tool = Path.Combine(root, "tool.cmd");
        File.WriteAllText(tool, "@echo off\r\n");
        var nonCanonical = Path.Combine(root, "subdir", "..", "tool.cmd");
        AssertControllerFailure(() => Program.ResolveExecutableForSelfTest(nonCanonical));
        Console.WriteLine($"[selftest] executable resolution accepted {cmd} and rejected missing/noncanonical paths");
    }

    private static void StartupInfoLayout()
    {
        const int expectedSize = 104;
#pragma warning disable CA1421
        var actualSize = Marshal.SizeOf<NativeMethods.StartupInfoW>();
        var actualOffsets = new Dictionary<string, int>
        {
            [nameof(NativeMethods.StartupInfoW.dwFlags)] = (int)Marshal.OffsetOf<NativeMethods.StartupInfoW>(
                nameof(NativeMethods.StartupInfoW.dwFlags)),
            [nameof(NativeMethods.StartupInfoW.hStdInput)] = (int)Marshal.OffsetOf<NativeMethods.StartupInfoW>(
                nameof(NativeMethods.StartupInfoW.hStdInput)),
            [nameof(NativeMethods.StartupInfoW.hStdOutput)] = (int)Marshal.OffsetOf<NativeMethods.StartupInfoW>(
                nameof(NativeMethods.StartupInfoW.hStdOutput)),
            [nameof(NativeMethods.StartupInfoW.hStdError)] = (int)Marshal.OffsetOf<NativeMethods.StartupInfoW>(
                nameof(NativeMethods.StartupInfoW.hStdError)),
        };
#pragma warning restore CA1421
        var expectedOffsets = new Dictionary<string, int>
        {
            [nameof(NativeMethods.StartupInfoW.dwFlags)] = 60,
            [nameof(NativeMethods.StartupInfoW.hStdInput)] = 80,
            [nameof(NativeMethods.StartupInfoW.hStdOutput)] = 88,
            [nameof(NativeMethods.StartupInfoW.hStdError)] = 96,
        };

        if (actualSize != expectedSize)
        {
            throw new ControllerException($"STARTUPINFOW size changed: expected {expectedSize}, got {actualSize}");
        }

        foreach (var field in expectedOffsets)
        {
            if (actualOffsets[field.Key] != field.Value)
            {
                throw new ControllerException(
                    $"STARTUPINFOW {field.Key} offset changed: expected {field.Value}, got {actualOffsets[field.Key]}");
            }
        }

        Console.WriteLine("[selftest] STARTUPINFOW x64 layout matched the official size and critical offsets");
    }

    private static void OutputTailCancellationAndFinalDrain(string root)
    {
        OutputTailCancellationAndFinalDrainAsync(root).GetAwaiter().GetResult();
    }

    private static async Task OutputTailCancellationAndFinalDrainAsync(string root)
    {
        var path = Path.Combine(root, "tail-drain.log");
        File.WriteAllBytes(path, []);
        using var cancellation = new CancellationTokenSource();
        var bytes = new StrongBox<long>();
        using var captured = new StringWriter();
        var tail = OutputTail.TailOutput(path, captured, bytes, cancellation.Token);
        var stopwatch = Stopwatch.StartNew();

        using (var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            await WriteTailProbeAsync(stream, "before-cancel\n");
            var deadline = DateTime.UtcNow.AddSeconds(2);
            while (Interlocked.Read(ref bytes.Value) == 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            if (Interlocked.Read(ref bytes.Value) == 0)
            {
                throw new ControllerException("the output tail did not observe bytes before cancellation");
            }

            await WriteTailProbeAsync(stream, "around-cancel");
            cancellation.Cancel();
            await Task.Delay(20);
            await WriteTailProbeAsync(stream, "-final\n");
        }

        await tail;
        stopwatch.Stop();
        var durable = File.ReadAllText(path);
        var rendered = captured.ToString();
        if (!durable.Contains("before-cancel", StringComparison.Ordinal) ||
            !durable.Contains("around-cancel", StringComparison.Ordinal) ||
            !rendered.Contains("before-cancel", StringComparison.Ordinal) ||
            !rendered.Contains("around-cancel", StringComparison.Ordinal))
        {
            throw new ControllerException($"output cancellation/drain lost bytes: durable={durable}; rendered={rendered}");
        }

        if (stopwatch.Elapsed > TimeSpan.FromSeconds(5))
        {
            throw new ControllerException($"output tail did not terminate boundedly: {stopwatch.Elapsed}");
        }

        Console.WriteLine("[selftest] output cancellation preserved buffered bytes and drained terminally");
    }

    private static async Task WriteTailProbeAsync(FileStream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
    }

    private static void ProviderSubstitutionRejection(string root)
    {
        var expected = Path.Combine(root, "provider-original.exe");
        var substituted = Path.Combine(root, "provider-substitute.exe");
        var bytes = new byte[] { 1, 2, 3, 4 };
        File.WriteAllBytes(expected, bytes);
        File.WriteAllBytes(substituted, bytes);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        Program.AssertProviderForSelfTest(expected, expected, hash);
        AssertControllerFailure(() => Program.AssertProviderForSelfTest(expected, substituted, hash));
        AssertControllerFailure(() =>
            Program.AssertProviderForSelfTest(expected, expected, Convert.ToHexString(SHA256.HashData([5])).ToLowerInvariant()));
        Console.WriteLine("[selftest] provider path and SHA-256 substitution were rejected");
    }

    private static JobRunResult RunCommand(
        string root,
        string[] command,
        int timeoutSeconds,
        Action? afterAssignment = null,
        Action<SafeJobHandle>? afterResume = null) =>
        Program.RunCommandForSelfTest(
            root,
            command,
            Path.Combine(root, $"{Guid.NewGuid():N}.stdout.log"),
            Path.Combine(root, $"{Guid.NewGuid():N}.stderr.log"),
            TimeSpan.FromSeconds(timeoutSeconds),
            TimeSpan.FromSeconds(10),
            TimeSpan.FromSeconds(1),
            afterAssignment,
            afterResume);

    private static void AssertOutcome(JobRunResult result, JobOutcome expected)
    {
        if (result.Outcome != expected)
        {
            throw new ControllerException(
                $"selftest expected {expected}, got {result.Outcome} ({result.OriginalCause}); stdout={result.StdoutPath}; stderr={result.StderrPath}");
        }
    }

    private static void AssertCleanup(JobRunResult result)
    {
        if (!result.CleanupComplete || result.ActiveProcessIds.Length != 0)
        {
            throw new ControllerException("the job did not reach ACTIVE_PROCESS_ZERO");
        }
    }

    private static void AssertControllerFailure(Action action)
    {
        try
        {
            action();
        }
        catch (ControllerException)
        {
            return;
        }

        throw new ControllerException("the invalid provider binding was accepted");
    }

    private static bool IsProcessAlive(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
