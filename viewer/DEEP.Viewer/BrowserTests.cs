// SPDX-License-Identifier: Apache-2.0
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
namespace DeepViewer;

// Explicit local test mode; no page can invoke it. Exercises the real renderer,
// adapter, certificate verification, resource interception and navigation.
internal sealed partial class BrowserForm
{
    private async Task RunBrowserTestAsync()
    {
        var checks = new List<string>();
        try
        {
            if (options.TestApplication) { await RunApplicationTestAsync(); return; }
            if (options.ExpectRejection)
            {
                await WaitForScriptAsync("document.title === 'Could not load this resource' && /pin/i.test(document.body.textContent)");
                if (verifiedRequests.Count != 0 || mainVerified) throw new IOException("Untrusted content was accepted.");
                await File.WriteAllTextAsync(options.TestReport!, "{\"ok\":true,\"checks\":[\"wrong_pin_rejected_before_rendering\"]}");
                Environment.ExitCode = 0;
                return;
            }
            await WaitForScriptAsync("window.deepDemoReady === true && window.deepModuleReady === true && document.querySelector('#data-status')?.textContent === 'Connected through DEEP'");
            checks.Add("javascript_module_and_same_origin_fetch");
            var json = await web.CoreWebView2.ExecuteScriptAsync("""
                JSON.stringify({
                  css: getComputedStyle(document.querySelector('#hero')).color,
                  image: document.querySelector('#network-image').complete && document.querySelector('#network-image').naturalWidth > 0,
                  imported: getComputedStyle(document.querySelector('#eyebrow')).letterSpacing,
                  origin: location.origin,
                  font: document.fonts.check('16px DeepTest')
                })
                """);
            using var state = JsonDocument.Parse(JsonSerializer.Deserialize<string>(json)!);
            if (state.RootElement.GetProperty("css").GetString() != "rgb(35, 63, 110)" ||
                state.RootElement.GetProperty("imported").GetString() != "3px" ||
                !state.RootElement.GetProperty("image").GetBoolean() ||
                !state.RootElement.GetProperty("origin").GetString()!.StartsWith("deep://", StringComparison.Ordinal))
                throw new IOException("Rendered CSS, image, import or origin did not match the fixture: " + state.RootElement);
            checks.Add("html_css_import_svg_and_deep_origin");
            // Force font decoding instead of counting a CSS request as success.
            await web.CoreWebView2.ExecuteScriptAsync("document.fonts.load('16px DeepTest').then(()=>window.deepFontLoaded=document.fonts.check('16px DeepTest'))");
            await WaitForScriptAsync("window.deepFontLoaded === true");
            checks.Add("font_decoded_by_renderer");
            var pageRequests = verifiedRequests.Count;
            await web.CoreWebView2.ExecuteScriptAsync("location.hash='local-section'");
            await WaitForScriptAsync("location.hash === '#local-section'");
            if (!mainVerified || pageFailed || verifiedRequests.Count != pageRequests)
                throw new IOException("Fragment navigation lost verification or fetched another resource.");
            await web.CoreWebView2.ExecuteScriptAsync("fetch('./data.json').then(r=>window.fragmentFetchOK=r.ok)");
            await WaitForScriptAsync("window.fragmentFetchOK === true");
            checks.Add("fragment_navigation_preserves_verified_page_and_fetch");

            await web.CoreWebView2.ExecuteScriptAsync("""
                window.deepBlocked = {};
                for (const [name,url,options] of [
                  ['https','https://example.com/',{}],
                  ['file','file:///C:/Windows/win.ini',{}],
                  ['crossOrigin','deep://other.network/data.json',{}],
                  ['post','./data.json',{method:'POST',body:'test'}]
                ]) {
                  fetch(url,options).then(r=>window.deepBlocked[name]=!r.ok,()=>window.deepBlocked[name]=true);
                }
                """);
            await WaitForScriptAsync("Object.keys(window.deepBlocked).length===4 && Object.values(window.deepBlocked).every(Boolean)");
            checks.Add("http_file_cross_origin_and_post_blocked");
            if (!mainVerified || pageFailed) throw new IOException("Page verification failed: " + string.Join("; ", failures));
            var firstRequests = verifiedRequests.ToArray();
            var screenshot = Path.ChangeExtension(Path.GetFullPath(options.TestReport!), ".png");
            using (var stream = File.Create(screenshot))
                await web.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, stream);
            await web.CoreWebView2.ExecuteScriptAsync("document.querySelector('#next-link').click()");
            await WaitForScriptAsync("document.title === 'Another DEEP page' && location.pathname === '/pages/next.html'");
            checks.Add("relative_link_navigation");
            web.GoBack();
            await WaitForScriptAsync("document.title === 'A site through DEEP'");
            checks.Add("back_navigation");
            web.GoForward();
            await WaitForScriptAsync("document.title === 'Another DEEP page'");
            checks.Add("forward_navigation");
            web.GoBack();
            await WaitForScriptAsync("document.title === 'A site through DEEP'");
            web.Reload();
            await WaitForScriptAsync("window.deepDemoReady === true && window.deepModuleReady === true");
            checks.Add("reload");
            // A missing resource must become a readable in-viewer error.
            Navigate(new Uri(new Uri(options.Uri!), "/does-not-exist.html").AbsoluteUri);
            await WaitForScriptAsync("document.title === 'Could not load this resource'");
            checks.Add("missing_resource_error_page");
            await File.WriteAllTextAsync(options.TestReport!, JsonSerializer.Serialize(new {
                ok = true, checks, resources = firstRequests, screenshot,
                renderer = environment!.BrowserVersionString
            }, new JsonSerializerOptions { WriteIndented = true }));
            Environment.ExitCode = 0;
        }
        catch (Exception ex) { await WriteTestFailureAsync(ex); }
        finally { Close(); }
    }

    private async Task WaitForScriptAsync(string script)
    {
        var until = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < until)
        {
            lifetime.Token.ThrowIfCancellationRequested();
            try { if (await web.CoreWebView2.ExecuteScriptAsync(script) == "true") return; }
            catch (InvalidOperationException) { }
            await Task.Delay(150, lifetime.Token);
        }
        var state = await web.CoreWebView2.ExecuteScriptAsync("JSON.stringify({title:document.title,url:location.href,text:document.body?.textContent?.slice(0,700)})");
        throw new TimeoutException("Renderer check timed out: " + script + " | " + status.Text + " | " + state);
    }

    private async Task WriteTestFailureAsync(Exception ex)
    {
        Environment.ExitCode = 1;
        await File.WriteAllTextAsync(options.TestReport!, JsonSerializer.Serialize(new {
            ok = false, error = ex.ToString(), status = status.Text, failures, resources = verifiedRequests
        }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
