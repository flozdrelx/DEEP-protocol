# DEEP 2.2 application validation

Validated on Windows on 2026-09-30 with Go 1.27.1, .NET SDK 10.0.401,
WebView2 SDK 1.0.4258.31, and WebView2 Runtime 154.0.4258.37.

- All Go tests passed under the race detector: 295 passing test/subtest events,
  with no failures or skips. Static analysis passed.
- Five independent Python framing/conformance tests passed.
- Separate-process native transfers passed, including private client enforcement,
  wrong-pin rejection without output, and explicitly public access.
- app/1 tests covered form/query preservation, response status and duplicate
  cookies, redirects without backend following, HEAD, static-provider 405,
  reuse of authenticated sessions, request/header limits, and upload rejection
  before application dispatch for wrong IDs, bad digests, and missing fields.
- Loopback provider tests rejected remote/DNS/credential-bearing destinations
  and excessive/compressed backend responses.
- The real Windows renderer passed CSS, image, font, JavaScript/module,
  same-origin fetch, navigation, reload, and wrong-pin regression checks.

The Flask integration used two isolated HellNet 3.1 brokers and the local
WebSocket byte relay. The actual viewer verified:
- Flask templates, CSS, and images.
- POST form bodies preserved across 307, then an absolute 303 redirect.
- CSRF tokens, secure HttpOnly session cookies, and login after reload.
- Authenticated JavaScript POST with JSON, query preservation, and a 201 response.
- Application 404 status and logout/protected-route redirects.
- Cookie authority/path isolation, expiry/deletion, and parent-domain rejection.

The test also checked that port hosting creates no content directories, that
the relay HTTP root cannot serve the website, and that stopping HellNet leaves
the user's Flask process running. Test processes and identities were temporary.

This run used the local HellNet relay. It did not repeat a public Cloudflare
tunnel test, multi-machine deployment, independent app/1 implementation, fuzz
campaign, performance audit, or external security review. Existing transport
cryptography was retained rather than redesigned.
