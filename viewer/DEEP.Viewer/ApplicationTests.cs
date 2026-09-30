// SPDX-License-Identifier: Apache-2.0
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
namespace DeepViewer;

internal sealed partial class BrowserForm
{
    private async Task RunApplicationTestAsync()
    {
        var checks = new List<string>();
        var jar = new SessionCookies();
        var a = new Uri("deep://alpha.test/account/login");
        jar.Store(a, [new("set-cookie","sid=one; Path=/; Secure; HttpOnly"),new("set-cookie","narrow=two; Path=/account"),new("set-cookie","bad=three; Domain=test; Path=/")]);
        if (!jar.Get(a).Contains("sid=one") || !jar.Get(a).Contains("narrow=two") || jar.Get(a).Contains("bad=") ||
            jar.Get(new Uri("deep://beta.test/account")).Length != 0 || jar.Get(new Uri("deep://alpha.test/")).Contains("narrow="))
            throw new IOException("Session cookie isolation failed.");
        jar.Store(a,[new("set-cookie","sid=gone; Path=/; Max-Age=0")]);
        if (jar.Get(a).Contains("sid=")) throw new IOException("Session deletion failed.");
        checks.Add("secure_cookie_path_authority_isolation_and_deletion");

        await WaitForScriptAsync("document.title === 'Flask on DEEP' && !!document.querySelector('#login')");
        await WaitForScriptAsync("getComputedStyle(document.querySelector('h1')).color === 'rgb(35, 63, 110)' && document.querySelector('img').naturalWidth > 0");
        checks.Add("flask_template_css_and_image");
        await web.CoreWebView2.ExecuteScriptAsync("document.querySelector('[name=username]').value='tester';document.querySelector('[name=password]').value='deep-test';document.querySelector('#login').requestSubmit()");
        await WaitForScriptAsync("document.title === 'Your DEEP session' && document.querySelector('#user').textContent === 'tester'");
        checks.Add("form_post_307_body_preservation_csrf_cookies_and_absolute_303_redirect");
        web.Reload();
        await WaitForScriptAsync("document.title === 'Your DEEP session' && document.querySelector('#user').textContent === 'tester'");
        checks.Add("login_survives_reload");
        await web.CoreWebView2.ExecuteScriptAsync("""
            fetch('/api/echo?check=a%2Bb',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('#csrf').content},body:JSON.stringify({message:'hello from DEEP'})})
              .then(async r=>window.appResult={status:r.status,data:await r.json()});
            """);
        await WaitForScriptAsync("window.appResult?.status===201 && window.appResult.data.user==='tester' && window.appResult.data.message==='hello from DEEP' && window.appResult.data.check==='a+b'");
        checks.Add("authenticated_javascript_post_json_query_and_201_status");
        await web.CoreWebView2.ExecuteScriptAsync("fetch('/missing').then(r=>window.missingStatus=r.status)");
        await WaitForScriptAsync("window.missingStatus===404");
        checks.Add("application_404_preserved");
        if (!mainVerified || pageFailed) throw new IOException("Application verification failed: " + string.Join("; ", failures));
        var screenshot = Path.ChangeExtension(Path.GetFullPath(options.TestReport!), ".png");
        using (var stream = File.Create(screenshot)) await web.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, stream);
        await web.CoreWebView2.ExecuteScriptAsync("document.querySelector('#logout').requestSubmit()");
        await WaitForScriptAsync("document.title === 'Flask on DEEP' && !!document.querySelector('#login')");
        Navigate(new Uri(new Uri(options.Uri!), "/account").AbsoluteUri);
        await WaitForScriptAsync("document.title === 'Flask on DEEP' && location.pathname === '/'");
        checks.Add("logout_clears_session_and_protected_route_redirects");
        await File.WriteAllTextAsync(options.TestReport!, JsonSerializer.Serialize(new {ok=true,checks,screenshot,renderer=environment!.BrowserVersionString},
            new JsonSerializerOptions {WriteIndented=true}));
        Environment.ExitCode = 0;
    }
}
