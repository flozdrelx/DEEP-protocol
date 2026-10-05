// SPDX-License-Identifier: Apache-2.0
using System.Text.RegularExpressions;
namespace DeepViewer;

internal static partial class NavigationPolicy
{
    [GeneratedRegex(@"^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex HostPattern();

    public static bool TryDeep(string value, out Uri uri)
    {
        uri = null!;
        if (value.Length is 0 or > 4096 || value.Any(c => c <= 32 || c >= 127 || c == '\\')) return false;
        if (!value.StartsWith("deep://", StringComparison.OrdinalIgnoreCase) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != "deep" || parsed.UserInfo.Length != 0 ||
            parsed.Port != -1 || !HostPattern().IsMatch(parsed.Host)) return false;
        // A port delimiter is forbidden even if System.Uri normalizes it away.
        var authority = value[7..].Split('/', '?', '#')[0];
        if (authority.Contains(':') || authority.Contains('%')) return false;
        // System.Uri repairs invalid percent escapes and punctuation. Reject them
        // before rendering so the viewer and the DEEP backend accept the same URI.
        var tail = value[(7 + authority.Length)..];
        var fragments = 0;
        for (var i = 0; i < tail.Length; i++)
        {
            var c = tail[i];
            if (c == '%')
            {
                if (i + 2 >= tail.Length || !Uri.IsHexDigit(tail[i + 1]) || !Uri.IsHexDigit(tail[i + 2])) return false;
                i += 2;
            }
            else if (c == '#') { if (++fragments > 1) return false; }
            else if (!char.IsAsciiLetterOrDigit(c) && !"-._~!$&'()*+,;=:@/?".Contains(c)) return false;
        }
        uri = parsed;
        return true;
    }

    public static bool SameOrigin(Uri a, Uri b) =>
        a.Scheme == b.Scheme && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase);

    public const string ContentPolicy =
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; " +
        "connect-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'none'; " +
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
}
