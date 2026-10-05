// SPDX-License-Identifier: Apache-2.0
using DeepViewer;
foreach (var value in new[] {
    "deep://node.alpha", "DEEP://MiXeD.BeTa/A%2fb?q=UP%20Down#Local?Only",
    "deep://local_start.alpha/path?q=%20#ok", "deep://n-1.net-2/", "deep://node.alpha/%00"
}) {
    if (!NavigationPolicy.TryDeep(value, out _)) throw new Exception("Valid URI rejected: " + value);
}
foreach (var value in new[] {
    "deep://node.alpha/%", "deep://node.alpha/%gg", "deep://node.alpha/%0",
    "deep://node.alpha/a[0]", "deep://node.alpha/<a>", "deep://node.alpha/#one#two",
    "deep://node.alpha:80/", "deep://user@node.alpha/", "deep://node.net_work/",
    "deep://_node.alpha/", "deep://node_.alpha/", "deep://node.alpha/\\evil", "https://node.alpha/"
}) {
    if (NavigationPolicy.TryDeep(value, out _)) throw new Exception("Invalid URI accepted: " + value);
}
var jar = new SessionCookies();
var site = new Uri("deep://local_start.alpha/account");
jar.Store(site, [new("set-cookie", "sid=one; Path=/; Secure; HttpOnly")]);
if (!jar.Get(site).Contains("sid=one") || jar.Get(new Uri("deep://other.alpha/")).Length != 0)
    throw new Exception("Cookie isolation failed for underscore authority.");
Console.WriteLine("PASS: strict DEEP URI grammar and cookie isolation.");
namespace DeepViewer { internal sealed record AppHeader(string name, string value); }
