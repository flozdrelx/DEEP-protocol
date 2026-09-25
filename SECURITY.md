# DEEP V1 security

DEEP V1 is intended for testing. It avoids implementing its own cryptographic primitives and uses Go's `crypto/tls`, `crypto/x509`, `crypto/ed25519`, and `crypto/sha256`. It has not received an independent audit.

## Where PQC is used

The V1 profile requires **TLS 1.3 and X25519MLKEM768** on every connection. This group combines classical X25519 key exchange with ML-KEM-768, a post-quantum key encapsulation mechanism. The implementation checks `ConnectionState.CurveID` after the handshake and rejects connections that did not negotiate this group; it does not report PQC based solely on configuration. It also requires ALPN `deep/1`, disables tickets, and does not allow fallback to earlier TLS versions or classical-only key exchange.

Content is protected by the authenticated encryption negotiated by TLS 1.3, such as AES-GCM or ChaCha20-Poly1305. DEEP adds no separate encryption layer. SHA-256 verifies the received resource; it is not a publisher signature or proof of provenance outside the TLS session.

## Identity and trust

The server identity is an **Ed25519** key with an X.509 certificate containing the DEEP authority. The client requires the hexadecimal SHA-256 fingerprint of that identity's **SubjectPublicKeyInfo DER**, supplied by its trusted adapter. The fingerprint is not a hash of the entire certificate.

The client verifies the fingerprint, certificate name, validity period, and Ed25519 key type. It does not depend on Web certificate authorities. The internal use of `InsecureSkipVerify` enables this pinning policy: a mandatory verifier replaces default public-PKI verification. There is no CLI option to bypass identity checks.

**Ed25519 authentication is classical. V1 provides hybrid post-quantum key exchange, not fully post-quantum authentication.** It also does not authenticate the client. Adding ML-DSA would require an interoperable identity profile, tests, and key distribution; arbitrarily signing chunks is not sufficient.

## Test operation

- Distribute `client.json` and its fingerprints through a trusted channel. An adapter that supplies an attacker's address and fingerprint changes the identity trusted by the client.
- Keep `identity.key` outside the served content. `init` already uses separate directories. Effective Windows permissions depend on directory ACLs, not the Unix permission bits requested when creating files.
- The `exec` adapter is a local program running with your permissions. Its configuration is trusted code; DEEP does not download or execute adapters from a link.
- Use `--output` when you need to retain only complete, verified resources. A failed transfer to stdout may already have delivered partial bytes.
- The file server confines access to its root and does not list directories. Changing files during a transfer can cause an error; content snapshots are not provided.

The implementation bounds message and resource sizes, timeouts, and concurrent connections. This does not replace DDoS protection, per-user quotas, key revocation, client authentication, access control, auditing, or signed updates. It also does not hide the network destination, SNI, traffic sizes, or timing.

## Reporting issues

A private disclosure channel has not yet been configured. Before public release, the maintainer should provide a verifiable contact here or enable private repository advisories. Do not include private keys or sensitive information in reports. Include the version, platform, minimal reproduction steps, and observed impact.

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final).
- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html).
- [Go `crypto/tls`: configuration and connection state](https://pkg.go.dev/crypto/tls).
- [Go 1.25: negotiated group exposed through `ConnectionState.CurveID`](https://go.dev/doc/go1.25).
