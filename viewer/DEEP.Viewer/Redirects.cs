// SPDX-License-Identifier: Apache-2.0
namespace DeepViewer;

internal sealed partial class BrowserForm
{
    private sealed record RedirectRequest(Uri Target, string Method, byte[] Body, AppHeader[] Headers);
    private RedirectRequest? pendingRedirect;

    // Custom-scheme 3xx responses do not trigger navigation automatically.
    // A one-use request, scoped to the exact document target, preserves POST
    // bodies on 307/308 without relying on the HTTP-only native POST API.
    private void ScheduleRedirect(Uri next, string method, byte[] body, List<AppHeader> headers, CancellationToken cancellation)
    {
        if (method is not ("GET" or "POST")) throw new IOException("Unsupported document redirect method.");
        var request = new RedirectRequest(next, method, body, headers.Where(h => h.name != "cookie").ToArray());
        BeginInvoke((Action)(() =>
        {
            if (lifetime.IsCancellationRequested || cancellation.IsCancellationRequested) return;
            redirectTarget = next;
            pendingRedirect = request;
            web.CoreWebView2.Navigate(next.AbsoluteUri);
        }));
    }
}
