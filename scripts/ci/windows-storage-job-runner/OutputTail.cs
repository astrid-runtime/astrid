using System.Runtime.CompilerServices;
using System.Text;

namespace Astrid.Ci.Windows;

internal static class OutputTail
{
    internal static async Task TailOutput(
        string path,
        TextWriter writer,
        StrongBox<long> bytes,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buffer = new byte[4096];
        var pending = new List<byte>();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken);
                if (read == 0)
                {
                    await WaitForMoreOutputAsync(cancellationToken);
                    continue;
                }

                Interlocked.Add(ref bytes.Value, read);
                await ProcessTailBytes(writer, bytes, pending, buffer, read);
            }
        }
        catch (OperationCanceledException)
        {
        }

        int drained;
        do
        {
            drained = await stream.ReadAsync(buffer.AsMemory(), CancellationToken.None);
            if (drained != 0)
            {
                Interlocked.Add(ref bytes.Value, drained);
                await ProcessTailBytes(writer, bytes, pending, buffer, drained);
            }
        }
        while (drained != 0);

        if (pending.Count != 0)
        {
            await WriteFinalTailBytes(writer, bytes, pending);
        }
    }

    private static async Task ProcessTailBytes(
        TextWriter writer,
        StrongBox<long> bytes,
        List<byte> pending,
        byte[] input,
        int count)
    {
        for (var index = 0; index < count; index++)
        {
            var value = input[index];
            pending.Add(value);
            if (value == '\n')
            {
                await WriteCompleteTailLine(writer, bytes, pending);
            }
        }
    }

    private static async Task<bool> WaitForMoreOutputAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(100, cancellationToken);
            return !cancellationToken.IsCancellationRequested;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static async Task WriteCompleteTailLine(
        TextWriter writer,
        StrongBox<long> bytes,
        List<byte> pending)
    {
        var textLength = pending.Count;
        if (textLength > 0 && pending[textLength - 1] == '\r')
        {
            --textLength;
        }

        var line = Encoding.UTF8.GetString(pending.Take(textLength).ToArray());
        await writer.WriteLineAsync(line);
        await writer.FlushAsync();
        pending.Clear();
    }

    private static async Task WriteFinalTailBytes(
        TextWriter writer,
        StrongBox<long> bytes,
        List<byte> pending)
    {
        var textLength = pending.Count;
        if (textLength > 0 && pending[textLength - 1] == '\r')
        {
            --textLength;
        }

        var line = Encoding.UTF8.GetString(pending.Take(textLength).ToArray());
        await writer.WriteLineAsync(line);
        await writer.FlushAsync();
        pending.Clear();
    }

}
