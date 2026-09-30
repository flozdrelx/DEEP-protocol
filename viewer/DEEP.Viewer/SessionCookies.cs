// SPDX-License-Identifier: Apache-2.0
using System.Net;
namespace DeepViewer;

// A separate in-memory jar for each exact DEEP authority. Synthetic HTTPS URIs
// are only CookieContainer keys: no HTTP connection is made here. HttpOnly
// cookies never enter JavaScript. Closing the window discards all sessions.
internal sealed class SessionCookies
{
    private readonly Dictionary<string, CookieContainer> jars = new(StringComparer.Ordinal);
    private static Uri Key(Uri uri) => new("https://" + uri.Host + uri.PathAndQuery);
    private CookieContainer Jar(Uri uri)
    {
        if (!jars.TryGetValue(uri.Host, out var jar))
        {
            if (jars.Count >= 128) throw new IOException("Too many site sessions; reopen this window.");
            jars.Add(uri.Host, jar = new CookieContainer(64, 64, 4096));
        }
        return jar;
    }
    public string Get(Uri uri) => Jar(uri).GetCookieHeader(Key(uri));
    public void Store(Uri uri, IEnumerable<AppHeader> headers)
    {
        foreach (var header in headers)
        {
            if (header.name != "set-cookie") continue;
            var domains = header.value.Split(';').Select(p => p.Trim()).Where(p => p.StartsWith("Domain=", StringComparison.OrdinalIgnoreCase));
            if (domains.Any(p => !string.Equals(p[7..].Trim().TrimStart('.'), uri.Host, StringComparison.OrdinalIgnoreCase))) continue;
            try { Jar(uri).SetCookies(Key(uri), header.value); }
            catch (CookieException) { /* Invalid cookies do not become credentials. */ }
        }
    }
}
