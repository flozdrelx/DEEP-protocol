# Generic proxy validation - 2026-10-03

Tested: DEEP 2.3.2 and HellNet 3.2.1, Windows, Go 1.27.1.

- DEEP's standalone demo passed with two independent private networks, mutual
  ML-DSA authentication and no proxy or external network application.
- The full DEEP race suite passed: 308 pass events including subtests/package
  completion, zero failures/skips. Static analysis passed.
- The full HellNet race suite with the new DEEP executable passed: 84 pass
  events, zero failures/skips. Static analysis passed.
- Generic proxy tests verified no default address/port/provider or CLI network
  selector; a top-level proxy with no network entries; all suffixes routed to
  the selected proxy; no direct fallback on a proxy failure; direct adapters
  working after unset; preserved identity paths and concurrent setting changes.
- HellNet setup removes its legacy exec/per-network proxy entries with a backup,
  adds no .hell entry, does not enable a generic proxy, and preserves a generic
  proxy explicitly configured for any provider.
- The isolated process test passed a 3 MiB transfer through the generic proxy,
  required DEEP TLS/PQC, incorrect pins, HTTP rejection, unset/unreachable
  proxy failures, unknown routes, and host/client cleanup.
- The real Windows viewer passed page/CSS/image rendering, form POST,
  307/303 redirects, CSRF, secure cookies, login/reload, authenticated JSON,
  404 and logout through the generic proxy. WebView2: 154.0.4258.53.

Run go test -race ./... and go vet ./... in each project. For HellNet set
DEEP_TEST_BINARY to the new executable and run scripts/smoke_test.py.
scripts/test_port_viewer.py checks the real renderer using temporary identities.

Public Cloudflare connectivity was not retested; the transport and Proxy/1
wire format did not change. These are Windows results, not a claim of runtime
validation on other platforms or an independent audit. The 2.3.1 native proxy
validation document records the previous per-network configuration design;
use docs/DEEP-PROXY.md for the current generic configuration.
