# DEEP 3.x validation

## 3.0.1 local website patch - 2026-10-08

The patch was tested on Windows amd64 with Go 1.27.1 and .NET SDK 10.0.401.
The earlier 3.0.0 results below remain a historical record.

- Go suites, race detection, and static analysis passed for DEEP and HellNet
  3.3.2, with the external DEEP tests enabled in HellNet.
- The original provider reproduced an empty 200 response from a host-matched
  local server. The fixed provider passed HTML/CSS and local Host/Origin/Referer
  regressions with numeric loopback and localhost targets.
- IPv6-only localhost fallback passed. Untrusted HTTPS certificates were
  rejected; an explicitly trusted test certificate worked.
- A generic server and real Caddy sites bound to numeric loopback and localhost
  returned HTML and every fixture asset through isolated HellNet instances.
- WebView2 154.0.4258.62 passed Caddy CSS imports, images, fonts, modules, fetch,
  fragment/page navigation, history, reload, and a verified application 404.
- Flask forms, CSRF, 307/303 redirects, cookies, authenticated JSON, reload,
  login and logout passed through the viewer. Hosting created only an identity
  folder, and stopping the host left the web application running.
- Viewer URI/cookie policy tests passed. Windows, Linux, and macOS amd64
  cross-builds passed; only Windows executables were run locally.

These checks used temporary identities/settings and a local encrypted relay.
No public tunnel, remote CI, or other-laptop result is claimed for this patch.

## 3.0.0 release - 2026-10-03

Checked locally on Windows amd64 on October 3, 2026, with Go 1.27.1 and
.NET SDK 10.0.401. This records automated checks, not an independent security audit.

## Reproduced defects and regression checks

- A POST carrying Idempotency-Key ran twice when a local backend accepted it
  and closed the connection before replying. The application provider now uses
  fresh loopback connections. Regression tests cover empty and nonempty bodies,
  preserving the caller's header and reporting the lost response.
- Direct application-provider calls accepted embedded query/fragment delimiters,
  relative paths, and bodies on GET/HEAD. They now fail before backend invocation.
- The viewer accepted malformed percent escapes through System.Uri repair.
  Policy tests now enforce the backend's lexical rules, including underscores
  in node labels and exact cookie-origin separation.
- HellNet's release/version checks and child readiness parser rejected 3.x.
  HellNet 3.3.1 fixes both, including port hosting, without changing wire profiles.

## Completed checks

- DEEP: 314 Go test/subtest runs passed with the race detector; no failures or
  skips. Package completion events are excluded from this count.
- HellNet compatibility: 95 Go test/subtest runs passed with the race detector;
  external DEEP integration enabled, no failures or skips.
- Static analysis passed in both Go projects. The final CLI help/text changes
  also passed the CLI package tests.
- Bounded fuzzing passed: 123,879 frame-parser inputs and 107,303 URI-parser
  inputs, eight seconds per target with two workers.
- Five independent Python protocol-vector/hostile-stream tests passed.
- Private/public process tests verified native transfer, rejected unauthenticated
  clients and incorrect server pins, and checked a 3 MiB payload.
- The standalone demo verified two independent private networks without HTTP
  or HellNet, mutual authentication, session reuse, and streamed content.
- Previous-client/current-server and current-client/previous-server transfers
  passed with DEEP 2.3.3 and 3.0.0, existing-format private identities/configuration.
- Pure viewer policy tests passed. Real WebView2 154.0.4258.53 passed HTML, CSS
  imports, SVG, an actual local font, modules, same-origin fetch, fragments,
  relative links, history, reload, missing resources, and wrong-pin rejection.
- HellNet's two-broker smoke test passed with DEEP 3.0.0, using a local WebSocket
  relay. Unset/unreachable proxies, invalid pins, and plain HTTP were rejected.
- The real Flask/viewer test passed forms, 307 body preservation, CSRF checks,
  session cookies, 303 redirects, authenticated JSON requests, reload and logout.
- The local introduction passed at deep://this_is_not_the_end.hell/ with live
  edits and no peer, public tunnel, or implicit configuration changes.
- Official govulncheck v1.8.0 reported "No vulnerabilities found." The NuGet
  advisory check reported no vulnerable packages in the viewer's dependency tree.
- Packaging tests exclude identities, configuration, and browser profiles from
  the desktop payload and require a matching win-x64 viewer release.

## Reproduction

Use the normal build scripts and go test -race ./..., go vet ./..., and the
Python scripts under scripts/. Renderer tests need Windows, WebView2, and the
portable viewer build. Policy tests use:

~~~powershell
dotnet run --project viewer/DEEP.Viewer.PolicyTests -c Release
python -m unittest discover -s scripts -p test_release.py -v
python scripts/test_upgrade.py --previous PATH_TO_DEEP_2_3_3 --current bin/deep.exe
~~~

The installed settings and identities are not used by these process tests.

## Limits of this validation

Public Cloudflare tunnels and live Python/OpenSSL TLS interoperability were
not retested for this release. The Python checks above validate wire vectors.
Only Windows amd64 binaries were executed here; other target archives are
cross-builds, not evidence of execution on those operating systems. Existing
CI is configured for Linux, macOS, and Windows, but a remote CI run is not claimed.
Dependency scanners only cover known advisories available at scan time.
