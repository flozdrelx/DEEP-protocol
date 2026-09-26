# Changelog

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
