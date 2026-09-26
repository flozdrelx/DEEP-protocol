# Roadmap

## Delivered in DEEP V2

- Versioned URI, framing, resource-transfer, and adapter specification independent of HTTP and HellNet.
- Go client and server with streaming, reusable sessions, and verified completion.
- Mandatory TLS 1.3, X25519MLKEM768, and ML-DSA-65 server authentication.
- Private nodes by default, pinned mutual TLS, separate client identities, explicit public mode.
- Strict configuration parsing, bounded operations and peer budgets, safer resource access and terminal display.
- Independent shared framing vectors and a Python TLS interoperability probe.
- English documentation, Apache 2.0 licensing, migration and operations guidance, CI, and local release tooling.

## Next: HellNet adapter

Integrate HellNet as a consumer of DEEP's adapter and transport APIs. Keep HellNet-specific
discovery, naming, and trust distribution in its own package. Establish which endpoints
are public or private, how server pins are authenticated, and how client access is managed.
Test it against the same V2 conformance and security rules as every other network.

## Later work

1. Independent complete implementations in other languages and long-running multi-host testing.
2. Authenticated distributed resolution, bootstrapping, collision policy, and signed discovery records defined by each network.
3. Live key rotation/revocation, scalable authorization, and clearer administrative tooling.
4. Uploads, multiplexing, resumption, or other operations only through a specified and tested protocol evolution.
5. A visual client with a defined origin, permission, and content-execution model before active HTML or scripts.
6. Public repository hosting, private vulnerability reporting, release signing, and reproducible-build comparisons.
7. Independent security review, prolonged fuzzing, performance measurements, and operational experience.
8. Public URI/ALPN registration when the project is ready for that process.

An official project release does not imply external audit, anonymous routing,
automatic decentralization, or approval as an Internet standard.
