# DEEP 3.0.0 validation

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
