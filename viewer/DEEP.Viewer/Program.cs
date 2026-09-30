// SPDX-License-Identifier: Apache-2.0
namespace DeepViewer;

internal sealed record ViewerOptions(string Deep, string Config, string? Uri, string? TestReport, bool ExpectRejection, bool TestApplication)
{
    public static ViewerOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is not ("--deep" or "--config" or "--uri" or "--test-report" or "--test-expect") ||
                i + 1 >= args.Length || !values.TryAdd(args[i], args[++i]))
                throw new ArgumentException("Usage: DEEP.Viewer [--uri deep://node.network/] [--config FILE] [--deep EXE]");
        }
        var deep = Path.GetFullPath(values.GetValueOrDefault("--deep",
            Path.Combine(AppContext.BaseDirectory, "..", "deep.exe")));
        var config = Path.GetFullPath(values.GetValueOrDefault("--config",
            Path.Combine(Path.GetDirectoryName(deep)!, "config.json")));
        var uri = values.GetValueOrDefault("--uri");
        if (uri != null && !NavigationPolicy.TryDeep(uri, out _))
            throw new ArgumentException("Enter a complete deep://node.network/ address.");
        if (!File.Exists(deep)) throw new FileNotFoundException("The DEEP executable is missing.", deep);
        var expectation = values.GetValueOrDefault("--test-expect");
        if (expectation != null && ((expectation != "rejection" && expectation != "application") || !values.ContainsKey("--test-report")))
            throw new ArgumentException("--test-expect rejection/application requires --test-report.");
        return new(deep, config, uri, values.GetValueOrDefault("--test-report"), expectation == "rejection", expectation == "application");
    }
}

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        try { Application.Run(new BrowserForm(ViewerOptions.Parse(args))); }
        catch (Exception ex)
        {
            Environment.ExitCode = 1;
            MessageBox.Show(ex.Message, "DEEP could not start", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
