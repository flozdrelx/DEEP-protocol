// SPDX-License-Identifier: Apache-2.0
using System.Diagnostics;
using System.Text.Json;
namespace DeepViewer;

internal static class ViewerActivation
{
    public static async Task RequireEnabledAsync(ViewerOptions options)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var info = new ProcessStartInfo(options.Deep) {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            RedirectStandardInput = true
        };
        foreach (var argument in new[] { "viewer", "status", "--json" }) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new IOException("Could not check the viewer setting.");
        process.StandardInput.Close();
        using var kill = timeout.Token.Register(() => { try { process.Kill(entireProcessTree:true); } catch (InvalidOperationException) { } });
        try
        {
            var output = DeepBackend.ReadBoundedAsync(process.StandardOutput.BaseStream, 4096, timeout.Token);
            var errors = DeepBackend.ReadBoundedAsync(process.StandardError.BaseStream, 8192, timeout.Token);
            _ = output.ContinueWith(_ => { try { timeout.Cancel(); } catch (ObjectDisposedException) { } }, TaskContinuationOptions.OnlyOnFaulted);
            _ = errors.ContinueWith(_ => { try { timeout.Cancel(); } catch (ObjectDisposedException) { } }, TaskContinuationOptions.OnlyOnFaulted);
            await Task.WhenAll(output, errors, process.WaitForExitAsync(timeout.Token)).ConfigureAwait(false);
            if (process.ExitCode != 0) throw new IOException("Could not read the viewer setting. Run deep viewer status with DEEP 2.3 or newer.");
            using var state = JsonDocument.Parse(output.Result);
            if (state.RootElement.GetProperty("version").GetInt32() != 1 ||
                !state.RootElement.GetProperty("enabled").GetBoolean())
                throw new IOException("The optional DEEP viewer is disabled.\n\nEnable it with:\n\"" + options.Deep + "\" viewer enable\n\nDEEP remains available to other browsers and applications.");
        }
        finally
        {
            if (!process.HasExited) { try { process.Kill(entireProcessTree:true); } catch (InvalidOperationException) { } }
            await process.WaitForExitAsync().ConfigureAwait(false);
        }
    }
}
