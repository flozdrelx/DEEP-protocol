# Changelog

## 3.0.1 - 2026-10-08

- Route the optional application provider to the selected local Host instead
  of the DEEP authority, fixing blank pages from Caddy and other virtual hosts.
- Adapt same-authority Origin/Referer to the selected local origin while retaining
  the DEEP authority in trusted forwarding metadata.
- Accept localhost and numeric loopback HTTP(S) origins with explicit ports;
  dial localhost via literal IPv4/IPv6 loopback without DNS and verify HTTPS
  certificates using the hosting computer's trusted roots.
- Cover local routing, spoofed forwarding fields, assets, IPv6-only servers,
  HTTPS trust, and verified application 404 responses in regression tests.
- Preserve wire/configuration version 2, app/1, Proxy/1, and existing identities.

## 3.0.0 � 2026-10-03

- Prevent the optional loopback application provider from silently replaying
  submitted actions when a response is lost.
- Validate application paths and queries separately; reject GET/HEAD bodies
  before contacting the local backend.
- Reject malformed percent escapes and raw URI punctuation in the viewer before
  System.Uri can normalize them into a different address.
- Handle SIGTERM through the CLI's graceful cancellation path.
- Align backend, CLI help, viewer assembly, release archives, and documentation
  on 3.0.0. Add isolated viewer policy tests and desktop ZIP packaging.
- Preserve wire/configuration version 2, ALPN deep/2, app/1, Proxy/1, identities,
  and explicit proxy/viewer preferences. HellNet 3.3.1 adds release compatibility.


## 2.3.3

- Accept internal underscores in node labels across the protocol, certificates, CLI, and optional viewer. Network labels keep their existing grammar. No network-specific aliases or proxy defaults were added.

## 2.3.2 - 2026-10-03

- Make the native proxy a single optional top-level setting with no default
  address, port, provider or network selector.
- Remove per-network proxy configuration and the CLI --network flag.
- Route all requests through an explicitly configured proxy without fallback;
  unset restores direct-adapter routing. Empty client configurations are valid.
- Keep Proxy/1, DEEP TLS, the independent server/client and optional viewer unchanged.

## 2.3.1 - 2026-10-02

- Add an explicit native DEEP proxy per network, with set/status/unset commands.
- Add generic ProxyAdapter and DialProxy APIs and the documented Proxy/1 handshake.
- Require explicit proxy configuration; missing or unreachable proxies fail
  without falling back to another adapter.
- Preserve end-to-end DEEP TLS, pinned identity checks and application behavior.
- Keep the viewer optional and the DEEP V2/app/1 wire formats unchanged.

## 2.3.0 - 2026-10-01

- Make the bundled viewer opt-in through viewer enable/disable/status.
- Keep protocol, adapters, CLI requests, and Go APIs independent of the viewer.
- Honor activation for direct viewer launches and the registered URI dispatcher.
- Document external browser/program integration without automatic handler takeover.
- Retain wire version 2, app/1, and existing identities/configuration.

## 2.2.0 - 2026-09-30

- Add optional app/1 requests with methods, headers, verified bodies, response
  statuses, and duplicate headers. Keep V2 FETCH and its security profile.
- Add a bounded loopback HTTP provider and deep request stdin bridge.
- Support website forms, redirects, and in-memory sessions in the Windows viewer.
- Document limits and validate the Flask workflow through HellNet's port adapter.

## 2.1.0 - September 29, 2026

- Add the Windows DEEP website viewer with native deep:// resource loading,
  navigation controls, and HTML/CSS/image/font/JavaScript support.
- Keep the DEEP V2 wire format, authentication, and adapter contract unchanged.
- Prefer index.html for directory URLs, with index.txt fallback; allow validated
  static cache-busting queries and consistent browser MIME types.
- Add browse and preview commands. Registered links use the graphical viewer
  when installed; terminal-only installations retain escaped previews.
- Enforce complete verification before rendering, same-origin resource loading,
  browser permissions and content policies, and bounded resource fetching.
- Add a sample website, renderer integration tests, and desktop build guidance.

## 2.0.0 - September 26, 2026

First official DEEP release line.

### Breaking changes

- Framing version 2, application version 2, ALPN `deep/2`, and configuration/resolver version 2. V1 is rejected rather than downgraded.
- ML-DSA-65 identities replace Ed25519. Server and client certificates have distinct roles; regenerate credentials and redistribute trusted pins.
- Source builds require Go 1.27.1 or later.
- Node initialization defaults to private mutual TLS. Public access requires an explicit choice.
- Configuration parsing rejects case aliases, nulls, malformed Unicode, and missing required fields.

### Security and behavior

- Actual hybrid X25519MLKEM768 key exchange plus ML-DSA-65 authentication.
- Explicit client-pin allowlists, credential inspection, and additional client identity generation.
- Protected identity directories and startup checks keeping known credentials outside the served root.
- Per-peer/global connection caps, bounded peer budgets, request rates, separate deadlines, total session lifetime, resource limits, and session request counts.
- Nonblocking Unix resource opens, observed symlink rejection, and opened-file type/identity checks.
- Safe terminal previews and control-free protocol errors.
- Rejection of transports that cannot install required deadlines; bounded session close.
- Shared frame conformance vectors, independent Python V2/mTLS probe, and negative security tests.
- Local release archives with SHA-256 checksums, CI configuration, migration instructions, and a threat model.

See [V2 validation](docs/VALIDATION-V2.md) for completed checks and their limits.

## 1.0.0

Experimental Go implementation with native DEEP framing, reusable streamed transfers,
network adapters, TLS 1.3 hybrid key exchange, and pinned Ed25519 server identities.
