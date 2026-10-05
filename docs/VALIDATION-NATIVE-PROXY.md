# Native proxy validation - 2026-10-02

Tested release: DEEP 2.3.1 with HellNet 3.2.0, Windows, Go 1.27.1.

- DEEP complete race suite: 306 pass events, zero failures or skips (including
  subtests and package completion). Static analysis passed.
- HellNet complete race suite with the new external DEEP executable: 82 pass
  events, zero failures or skips. Static analysis passed.
- Proxy/1 framing, malformed/oversized/ambiguous input, following TLS bytes,
  literal loopback address validation, cancellation and changed-pin rejection.
- Real DEEP TLS and binary resource transfer through the generic proxy adapter.
- CLI set/status/unset, backups, preservation of other networks/identity paths,
  refusal to replace another adapter, and explicit disabled behavior.
- HellNet migration from its owned exec adapter without automatic opt-in.
- Real two-process HellNet host/client integration with isolated identities:
  3 MiB transfer through the native proxy and local WebSocket relay, required
  TLS 1.3/X25519MLKEM768/ML-DSA-65 security, incorrect pin rejection, unknown
  routes, unset/unreachable proxy rejection without fallback, HTTP rejection,
  host/peer lease cleanup.
- Windows DEEP viewer and temporary Flask app through the native proxy:
  templates, CSS/images, POST form with 307 body preservation, CSRF, duplicate
  secure cookies, absolute 303 redirect, login/reload, authenticated JavaScript
  JSON POST with query and 201 status, application 404, logout/protected-route
  redirect. WebView2 renderer: 154.0.4258.48.
- HellNet menu exit/input checks with isolated settings and no public tunnel.

Reproduce native adapter checks with go test -race ./... and go vet ./... in
both projects. Set DEEP_TEST_BINARY to the new DEEP executable for HellNet's
external-runtime tests. HellNet scripts/smoke_test.py and
scripts/test_port_viewer.py exercise the process boundary and renderer.

Tests used local relay mode only. Public Cloudflare connectivity was not
retested for this change. No claim of macOS/Linux runtime testing or an
independent security audit is made here. Existing protocol validation records
remain separate.
