// SPDX-License-Identifier: Apache-2.0
using System.Net;
using System.Text;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace DeepViewer;

internal sealed partial class BrowserForm : Form
{
    private readonly ViewerOptions options;
    private readonly DeepBackend backend;
    private readonly SessionCookies cookies = new();
    private readonly WebView2 web = new() { Dock = DockStyle.Fill };
    private readonly TextBox address = new() { Dock = DockStyle.Fill, PlaceholderText = "deep://node.network/", Font = new Font("Segoe UI", 11) };
    private readonly ToolStripStatusLabel status = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Button back = new() { Text = "Back", Dock = DockStyle.Fill, Enabled = false };
    private readonly Button forward = new() { Text = "Forward", Dock = DockStyle.Fill, Enabled = false };
    private readonly CancellationTokenSource lifetime = new();
    private CancellationTokenSource page = new();
    private CoreWebView2Environment? environment;
    private Uri? top;
    private int resourceCount;
    private int verifiedCount;
    private long pageBytes;
    private bool mainVerified;
    private bool pageFailed;
    private Uri? redirectTarget;
    private int redirectHops;
    private readonly List<string> failures = new();
    private readonly List<string> verifiedRequests = new();

    public BrowserForm(ViewerOptions options)
    {
        this.options = options; backend = new(options);
        Text = "DEEP"; Width = 1180; Height = 820; MinimumSize = new Size(640, 400);
        StartPosition = FormStartPosition.CenterScreen;
        if (options.TestReport != null) { ShowInTaskbar = false; Opacity = 0; }
        Font = new Font("Segoe UI", 10);
        BackColor = Color.FromArgb(245, 247, 250);
        var toolbar = new TableLayoutPanel { Dock = DockStyle.Top, Height = 54, Padding = new Padding(10), ColumnCount = 6, RowCount = 1 };
        foreach (var width in new[] { 64, 76, 72 }) toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, width));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 60));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 64));
        var reload = new Button { Text = "Reload", Dock = DockStyle.Fill };
        var go = new Button { Text = "Go", Dock = DockStyle.Fill };
        var home = new Button { Text = "Home", Dock = DockStyle.Fill };
        toolbar.Controls.Add(back, 0, 0); toolbar.Controls.Add(forward, 1, 0);
        toolbar.Controls.Add(reload, 2, 0); toolbar.Controls.Add(address, 3, 0);
        toolbar.Controls.Add(go, 4, 0); toolbar.Controls.Add(home, 5, 0);
        var footer = new StatusStrip(); footer.Items.Add(status);
        Controls.Add(web); Controls.Add(toolbar); Controls.Add(footer);
        back.Click += (_, _) => { if (web.CoreWebView2?.CanGoBack == true) web.GoBack(); };
        forward.Click += (_, _) => { if (web.CoreWebView2?.CanGoForward == true) web.GoForward(); };
        reload.Click += (_, _) => web.CoreWebView2?.Reload();
        home.Click += (_, _) => ShowHome();
        go.Click += (_, _) => Navigate(address.Text);
        address.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; Navigate(address.Text); } };
        KeyPreview = true;
        KeyDown += (_, e) =>
        {
            if (e.Control && e.KeyCode == Keys.L) { address.Focus(); address.SelectAll(); e.Handled = true; }
            if (e.KeyCode == Keys.F5) { web.CoreWebView2?.Reload(); e.Handled = true; }
        };
        Shown += async (_, _) => await InitializeAsync();
        FormClosing += (_, _) => { lifetime.Cancel(); page.Cancel(); web.Dispose(); };
    }

    private async Task InitializeAsync()
    {
        try
        {
            status.Text = "Starting DEEP viewer…";
            var scheme = new CoreWebView2CustomSchemeRegistration("deep")
            {
                HasAuthorityComponent = true, TreatAsSecure = true,
                AllowedOrigins = new List<string> { "deep://*" }
            };
            var environmentOptions = new CoreWebView2EnvironmentOptions(null, null, null, false, new List<CoreWebView2CustomSchemeRegistration> { scheme })
            {
                AllowSingleSignOnUsingOSPrimaryAccount = false,
                AreBrowserExtensionsEnabled = false
            };
            var profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DEEP", "Viewer");
            environment = await CoreWebView2Environment.CreateAsync(null, profile, environmentOptions);
            var controller = environment.CreateCoreWebView2ControllerOptions();
            controller.IsInPrivateModeEnabled = true;
            await web.EnsureCoreWebView2Async(environment, controller);
            var core = web.CoreWebView2;
            core.Settings.AreHostObjectsAllowed = false;
            core.Settings.IsWebMessageEnabled = false;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.AreDefaultScriptDialogsEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.IsPasswordAutosaveEnabled = false;
            core.Settings.IsGeneralAutofillEnabled = false;
            core.PermissionRequested += (_, e) => { e.State = CoreWebView2PermissionState.Deny; e.Handled = true; };
            core.DownloadStarting += (_, e) => { e.Cancel = true; status.Text = "Use deep fetch --output to save downloads."; };
            core.NewWindowRequested += (_, e) => { e.Handled = true; if (e.IsUserInitiated) Navigate(e.Uri); };
            core.FrameNavigationStarting += (_, e) => e.Cancel = true;
            core.NavigationStarting += OnNavigation;
            core.SourceChanged += (_, _) => { if (NavigationPolicy.TryDeep(core.Source, out _)) address.Text = core.Source; };
            core.HistoryChanged += (_, _) => { back.Enabled = core.CanGoBack; forward.Enabled = core.CanGoForward; };
            core.DocumentTitleChanged += (_, _) => Text = "DEEP - " + Clean(core.DocumentTitle);
            core.ProcessFailed += (_, _) => status.Text = "The page renderer stopped. Close this window and reopen DEEP.";
            core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All, CoreWebView2WebResourceRequestSourceKinds.All);
            core.WebResourceRequested += OnResource;
            core.NavigationCompleted += (_, e) =>
            {
                if (top == null) return;
                if (!e.IsSuccess) { status.Text = "Page could not load: " + e.WebErrorStatus; return; }
                UpdateStatus();
            };
            if (options.Uri != null) Navigate(options.Uri); else ShowHome();
            if (options.TestReport != null) await RunBrowserTestAsync();
        }
        catch (Exception ex)
        {
            status.Text = "Viewer could not start: " + Clean(ex.Message);
            if (options.TestReport != null) { await WriteTestFailureAsync(ex); Close(); }
            else MessageBox.Show(this, ex.Message + "\n\nThe Microsoft Edge WebView2 Runtime is required.", "DEEP viewer", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void Navigate(string value)
    {
        value = value.Trim();
        if (!NavigationPolicy.TryDeep(value, out _)) { status.Text = "Enter a complete deep://node.network/ address."; return; }
        if (web.CoreWebView2 == null) return;
        web.CoreWebView2.Navigate(value);
    }

    private void ResetPage()
    {
        page.Cancel(); page.Dispose();
        page = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        resourceCount = verifiedCount = 0; pageBytes = 0; mainVerified = pageFailed = false;
        failures.Clear(); verifiedRequests.Clear();
    }

    private void OnNavigation(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (e.Uri == "about:blank") { ResetPage(); top = null; return; }
        if (!NavigationPolicy.TryDeep(e.Uri, out var target))
        {
            e.Cancel = true; status.Text = "This viewer opens deep:// sites. External and local-file navigation is blocked."; return;
        }
        if (redirectTarget != target) { redirectHops = 0; pendingRedirect = null; }
        redirectTarget = null;
        ResetPage(); top = target; address.Text = e.Uri;
        status.Text = "Connecting securely to " + target.Host + "…";
    }

    private async void OnResource(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
    {
        var deferral = e.GetDeferral();
        var cancellation = page.Token;
        try
        {
            if (!NavigationPolicy.TryDeep(e.Request.Uri, out var uri) || top == null ||
                !NavigationPolicy.SameOrigin(uri, top))
            { Respond(e, 403, "Blocked", "text/plain", Encoding.UTF8.GetBytes("Only resources from the current DEEP site are allowed.")); return; }
            if (e.Request.Method is not ("GET" or "HEAD" or "POST" or "PUT" or "PATCH" or "DELETE" or "OPTIONS"))
            { Respond(e, 405, "Unsupported method", "text/plain", Encoding.UTF8.GetBytes("Unsupported application method.")); return; }

            var headers = new List<AppHeader>();
            foreach (var pair in e.Request.Headers)
            {
                var name = pair.Key.ToLowerInvariant();
                if (name is "cookie" or "host" or "content-length" or "accept-encoding" or "connection") continue;
                var header = new AppHeader(name, pair.Value);
                if (!DeepBackend.ValidHeader(header)) throw new IOException("Invalid request header.");
                headers.Add(header);
            }
            var requestBody = e.Request.Content == null ? [] :
                await DeepBackend.ReadBoundedAsync(e.Request.Content, 1024 * 1024, cancellation);
            var method = e.Request.Method;
            if (e.ResourceContext == CoreWebView2WebResourceContext.Document && pendingRedirect?.Target == uri)
            {
                method = pendingRedirect.Method; requestBody = pendingRedirect.Body;
                headers.Clear(); headers.AddRange(pendingRedirect.Headers);
                pendingRedirect = null;
            }
            VerifiedResource resource;
            for (var hop = 0; ; hop++)
            {
                if (++resourceCount > 512) throw new IOException("This page exceeds the 512-resource limit.");
                headers.RemoveAll(h => h.name == "cookie");
                var cookie = cookies.Get(uri);
                if (cookie.Length > 0) headers.Add(new("cookie", cookie));
                resource = await backend.FetchAsync(uri.AbsoluteUri, method, headers.ToArray(), requestBody, cancellation);
                cancellation.ThrowIfCancellationRequested();
                if (pageBytes + resource.Body.Length > 128 * 1024 * 1024) throw new IOException("This page exceeds the 128 MiB viewer limit.");
                pageBytes += resource.Body.Length; verifiedCount++;
                verifiedRequests.Add(uri.AbsoluteUri);
                cookies.Store(uri, resource.Headers);
                var location = resource.Headers.FirstOrDefault(h => h.name == "location")?.value;
                if (resource.Status is not (301 or 302 or 303 or 307 or 308) || location == null) break;
                if (hop >= 10 || !Uri.TryCreate(uri, location, out var next) ||
                    !NavigationPolicy.TryDeep(next.AbsoluteUri, out _) || !NavigationPolicy.SameOrigin(next, uri))
                    throw new IOException("Redirect loop or redirect outside the current DEEP site.");
                if ((resource.Status == 303 && method != "HEAD") || (resource.Status is 301 or 302 && method == "POST"))
                {
                    method = "GET"; requestBody = [];
                    headers.RemoveAll(h => h.name.StartsWith("content-", StringComparison.Ordinal));
                }
                if (e.ResourceContext == CoreWebView2WebResourceContext.Document)
                {
                    if (++redirectHops > 10) throw new IOException("Too many page redirects.");
                    Respond(e, 200, "Redirecting", "text/html; charset=utf-8", Encoding.UTF8.GetBytes("<!doctype html><title>Following redirect</title>"));
                    ScheduleRedirect(next, method, requestBody, headers, cancellation);
                    return;
                }
                uri = next;
            }
            if (e.ResourceContext == CoreWebView2WebResourceContext.Document) mainVerified = true;
            Respond(e, resource.Status, "DEEP application response", resource.MediaType, resource.Body, resource.Headers);
            UpdateStatus();
        }
        catch (OperationCanceledException)
        { TryError(e, "The request was cancelled or timed out."); }
        catch (Exception ex)
        {
            if (!cancellation.IsCancellationRequested)
            {
                pageFailed = true; failures.Add(Clean(ex.Message)); UpdateStatus();
            }
            TryError(e, ex.Message);
        }
        finally { try { deferral.Complete(); } catch (Exception) when (lifetime.IsCancellationRequested) { } }
    }

    private void UpdateStatus()
    {
        if (IsDisposed || lifetime.IsCancellationRequested) return;
        status.Text = pageFailed ? "Some content could not load - " + failures.LastOrDefault() :
            mainVerified ? $"Verified DEEP connection · Post-quantum encryption · {verifiedCount} resources" : "Loading…";
    }

    private void Respond(CoreWebView2WebResourceRequestedEventArgs e, int code, string reason, string type, byte[] bytes, AppHeader[]? headers = null)
    {
        // These are WebView2's in-process response objects, not an HTTP server.
        // The only network content fetch above is performed by the DEEP client.
        var extra = new StringBuilder();
        foreach (var header in headers ?? [])
        {
            if (header.name is "set-cookie" or "content-length" or "content-type" or "cache-control" or "x-content-type-options" or
                "referrer-policy" or "connection" or "transfer-encoding" or "content-encoding") continue;
            extra.Append(header.name).Append(": ").Append(header.value).Append("\r\n");
        }
        e.Response = environment!.CreateWebResourceResponse(new MemoryStream(bytes, writable: false), code, reason,
            "Content-Type: " + type + "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n" +
            "Referrer-Policy: no-referrer\r\nContent-Security-Policy: " + NavigationPolicy.ContentPolicy + "\r\n" + extra);
    }

    private void TryError(CoreWebView2WebResourceRequestedEventArgs e, string message)
    {
        try
        {
            var html = "<!doctype html><meta charset=utf-8><title>Could not load this resource</title>" +
                "<style>body{font:17px system-ui;max-width:760px;margin:80px auto;padding:24px;color:#182235}h1{font-size:30px}pre{white-space:pre-wrap}</style>" +
                "<h1>Could not load this resource</h1><pre>" + WebUtility.HtmlEncode(Clean(message)) +
                "</pre><p>Check the address and keep the network adapter connected. For a failed form submission, check whether it succeeded before submitting again.</p>";
            Respond(e, message.Contains("NOT_FOUND", StringComparison.Ordinal) ? 404 : 502, "Resource unavailable", "text/html; charset=utf-8", Encoding.UTF8.GetBytes(html));
        }
        catch (Exception) when (lifetime.IsCancellationRequested || page.IsCancellationRequested) { }
    }

    private void ShowHome()
    {
        if (web.CoreWebView2 == null) return;
        ResetPage(); top = null; pendingRedirect = null; redirectTarget = null; redirectHops = 0; address.Text = "";
        web.NavigateToString("""
            <!doctype html><html><head><meta charset="utf-8"><title>Explore with DEEP</title>
            <style>body{margin:0;background:#f6f8fb;color:#182235;font:18px system-ui}main{max-width:820px;margin:12vh auto;padding:40px}
            .label{font-size:13px;letter-spacing:3px;color:#365be8;font-weight:700}h1{font-size:58px;letter-spacing:-2px;margin:20px 0}
            p{line-height:1.7;color:#536077}code{display:block;border:1px solid #dce2ef;background:white;padding:24px;border-radius:14px;color:#2446ba}
            .note{margin-top:35px;font-size:15px}</style></head><body><main><div class="label">DEEP / WEBSITE VIEWER</div>
            <h1>Your networks.<br>Your destinations.</h1><p>Enter a DEEP address above to open a site. Pages, styles, scripts, and images travel through your configured network adapter.</p>
            <code>deep://node.network/</code><p class="note">Keep your network provider running while browsing. This viewer supports content folders and running web apps, including forms and temporary login sessions.</p>
            </main></body></html>
            """);
        status.Text = "Ready · Enter a deep:// address · Ctrl+L to focus the address bar";
    }

    private static string Clean(string text) => new(text.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.Format).Take(400).ToArray());
}
