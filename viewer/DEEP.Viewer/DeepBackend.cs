// SPDX-License-Identifier: Apache-2.0
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeepViewer;

internal sealed record AppHeader(string name, string value);
internal sealed record VerifiedResource(byte[] Body, string MediaType, int Status, AppHeader[] Headers);

internal sealed class DeepBackend(ViewerOptions options)
{
    public const int MaxResourceBytes = 16 * 1024 * 1024;
    private readonly SemaphoreSlim slots = new(6);

    public async Task<VerifiedResource> FetchAsync(string uri, string method, AppHeader[] headers, byte[] requestBody, CancellationToken cancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        await slots.WaitAsync(deadline.Token);
        try
        {
            var info = new ProcessStartInfo(options.Deep)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                RedirectStandardInput = true,
                WorkingDirectory = Path.GetDirectoryName(options.Deep)!
            };
            foreach (var argument in new[] { "request", uri, "--config", options.Config, "--info",
                "--max-bytes", MaxResourceBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--timeout", "20s" }) info.ArgumentList.Add(argument);
            using var process = Process.Start(info) ?? throw new IOException("Could not start the DEEP client.");

            using var kill = deadline.Token.Register(() => { try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } });
            try
            {
                var bodyTask = ReadBoundedAsync(process.StandardOutput.BaseStream, MaxResourceBytes, deadline.Token);
                var infoTask = ReadBoundedAsync(process.StandardError.BaseStream, 65536, deadline.Token);
                // Any failed pipe read kills the child and unblocks the other pipe.
                _ = bodyTask.ContinueWith(_ => { try { deadline.Cancel(); } catch (ObjectDisposedException) { } }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
                _ = infoTask.ContinueWith(_ => { try { deadline.Cancel(); } catch (ObjectDisposedException) { } }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
                var writeTask = WriteRequestAsync(process, method, headers, requestBody, deadline.Token);
                await Task.WhenAll(bodyTask, infoTask, writeTask, process.WaitForExitAsync(deadline.Token));
                if (process.ExitCode != 0)
                    throw new IOException(Encoding.UTF8.GetString(infoTask.Result).Trim());
                using var metadata = JsonDocument.Parse(infoTask.Result);
                var root = metadata.RootElement;
                var security = root.GetProperty("security");
                if (!security.GetProperty("post_quantum_key_exchange").GetBoolean() ||
                    !security.GetProperty("post_quantum_authentication").GetBoolean() ||
                    root.GetProperty("size").GetInt64() != bodyTask.Result.Length ||
                    !string.Equals(root.GetProperty("sha256").GetString(),
                        Convert.ToHexString(SHA256.HashData(bodyTask.Result)), StringComparison.OrdinalIgnoreCase))
                    throw new IOException("DEEP resource verification failed.");
                var mediaType = root.GetProperty("media_type").GetString() ?? "application/octet-stream";
                if (mediaType.Length > 256 || mediaType.Any(c => c < 32 || c > 126))
                    throw new IOException("Invalid resource media type.");
                var status = root.GetProperty("status").GetInt32();
                var responseHeaders = root.GetProperty("headers").Deserialize<AppHeader[]>() ?? [];
                if (status < 200 || status > 599 || responseHeaders.Length > 64 ||
                    responseHeaders.Any(h => !ValidHeader(h)))
                    throw new IOException("Invalid application response.");
                return new(bodyTask.Result, mediaType, status, responseHeaders);
            }
            finally
            {
                if (!process.HasExited) { try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } }
                await process.WaitForExitAsync();
            }
        }
        finally { slots.Release(); }
    }

    internal static bool ValidHeader(AppHeader h) => h.name.Length is > 0 and <= 64 &&
        h.name.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' || "!#$%&'*+-.^_~".Contains(c) || c == (char)96 || c == '|') &&
        h.value.Length <= 4096 && h.value.All(c => c is >= ' ' and <= '~');

    private static async Task WriteRequestAsync(Process process, string method, AppHeader[] headers, byte[] body, CancellationToken cancellation)
    {
        try { await JsonSerializer.SerializeAsync(process.StandardInput.BaseStream, new { method, headers, body }, cancellationToken: cancellation); }
        finally { process.StandardInput.Close(); }
    }

    internal static async Task<byte[]> ReadBoundedAsync(Stream stream, int limit, CancellationToken cancellation)
    {
        using var output = new MemoryStream();
        var buffer = new byte[16384];
        while (true)
        {
            var count = await stream.ReadAsync(buffer, cancellation);
            if (count == 0) return output.ToArray();
            if (output.Length + count > limit) throw new IOException("Request or response exceeds the viewer size limit.");
            output.Write(buffer, 0, count);
        }
    }
}
