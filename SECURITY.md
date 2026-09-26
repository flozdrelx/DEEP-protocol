# DEEP V2 security

DEEP 2.0.0 provides authenticated resource transfer with explicit trust configuration and bounded server operation. Security primitives come from Go's standard library. Use Go 1.27.1 or later and keep the toolchain patched when rebuilding.

This release has automated security and interoperability tests. It has not received an independent cryptographic or deployment audit. The exact checks performed locally are recorded in [Validation](docs/VALIDATION-V2.md).

## Threat model

The design assumes an attacker can control the network, send malformed messages, reconnect, stall transfers, and operate an untrusted peer. TLS protects against interception and alteration when the expected public-key pins were distributed correctly. Private servers require an approved client key before processing DEEP requests.

The following remain trusted: the operating system, the server operator and content directory, local configuration, installed adapters, private-key storage, custom resource handlers, and custom transports. A hostile resolver can return both an attacker's endpoint and pin; DEEP cannot distinguish that from a trusted administrator changing the identity. A program launched as an adapter has the user's local permissions even though the resolver request does not contain credentials.

## Cryptographic profile

Every connection requires:

- TLS 1.3 with a fresh `X25519MLKEM768` exchange, combining X25519 and ML-KEM-768.
- ALPN `deep/2`, with no V1, HTTP, plaintext, or classical-only fallback.
- ML-DSA-65 server authentication, verified by Go TLS and the mandatory identity validator.
- For private servers, an ML-DSA-65 client certificate whose SPKI pin is on the explicit allowlist.
- No session tickets, resumption, or 0-RTT.

The negotiated group is checked through `ConnectionState.CurveID`. That field proves the key-exchange selection, not the signature algorithm. Authentication is enforced by accepting only the ML-DSA-65 leaf profile and by Go TLS verifying possession of its private key. The security report is intended for connections created with DEEP's TLS configuration factories.

TLS's negotiated AEAD protects content. SHA-256 checks transfer integrity and completion; it is not a persistent publisher signature. DEEP does not add a homemade handshake, encryption layer, or MAC.

## Identity and authorization

V2 identities contain exactly one self-signed ML-DSA-65 certificate with:

- One canonical `node.network` DNS name, no wildcard or alternative identity types.
- A valid lifetime, a verified self-signature, and no unsupported critical extensions.
- Digital-signature key usage and exactly one extended usage: server authentication or client authentication.
- No CA capability.

Server names must match both the requested authority and TLS SNI. The trusted pin is SHA-256 of DER SubjectPublicKeyInfo, not the hash of the certificate file. Pins are configured independently of the connection being authenticated; arbitrary self-signed certificates are never accepted.

The client's internal `InsecureSkipVerify` setting replaces public-Web-PKI validation with a mandatory pin and profile validator. There is no insecure CLI bypass. Local identities are also checked against their private key before use.

`init` creates a private node by default and generates separate server and client keys. Public access requires `--public`. A private node's allowlist contains at most 256 distinct client pins. Authorization applies to all resources served by the node. Removing a pin requires a server restart to apply the new policy and terminate existing sessions; there is no live revocation service or OCSP.

## Resource and connection controls

The server enforces global and per-peer active-connection caps before TLS work, a five-second default handshake deadline, separate idle and transfer deadlines, a total session lifetime, a request-count limit, and a per-peer request rate. Reconnecting does not reset the current peer budget. Up to 4,096 recent peer budgets are retained; when full, new peers are rejected until inactive entries expire. New accepted connections are limited to 240 per peer per fixed one-minute window. These controls are not a substitute for network-level DDoS protection.

TCP peers are grouped by source IP, so clients behind the same NAT share a budget. Custom transports must return stable peer identifiers and implement deadlines. Failure to set a deadline terminates the operation. Limits and operator defaults are documented in [Operations](docs/OPERATIONS.md).

Frames are bounded before allocating their payloads. Metadata rejects malformed Unicode, duplicate and unknown fields, incorrect types, and excessive nesting. Configurations and resolver responses also reject case aliases, nulls, and malformed Unicode. The client requires matching request IDs, ordered states, bounded resource sizes, and a complete verified END message.

Error codes have a restricted ASCII alphabet. Error messages reject terminal and Unicode formatting controls. The URI viewer buffers a bounded resource until verification, then escapes untrusted text. Explicit `fetch` output is raw data; do not send unknown binary or terminal-control content straight to an interactive terminal.

## Filesystem and credentials

The file provider uses `os.Root` to confine access to its resource tree. It rejects unsafe lexical paths, observed symlink components, and nonregular files. On Unix, nonblocking opening prevents FIFO races from indefinitely blocking a worker, and descriptor checks reject changed file identities.

The served tree must be operator-controlled. The observed-symlink checks are not a race-proof sandbox against a malicious local writer. Hard links, bind mounts, and administrator-created aliases can expose content within that trust boundary. Hidden-name filtering is not access control: keep every private key, configuration, and sensitive file outside the resource root. The CLI rejects known server credentials and configuration paths under that root before listening.

New identity directories use mode 0700 on Unix and an explicit current-user ACL on Windows; key files use mode 0600 where supported. Initialization fails if directory protection cannot be established. Copying credentials elsewhere requires preserving suitable permissions. Local administrators and a compromised user account remain outside this protection.

Resource handlers must respect their context, and closing a resource body must unblock reads. Custom client writers must return from writes; the library cannot safely interrupt arbitrary user code. Content modified during a transfer can cause failure; consistent snapshots are not provided.

## Remaining boundaries

DEEP does not provide anonymous routing, traffic-analysis resistance, hidden SNI, automatic decentralized trust, per-resource user roles, uploads, browser origin isolation, or automatic signed updates. It does not hide network addresses, resource sizes, or timing. V1 identities and configurations are deliberately incompatible.

Release checksums alone do not authenticate the publisher. Obtain binaries and checksums from a trusted publication channel. Public repository hosting and a release-signing identity must be selected by the maintainer before publishing.

## Reporting

A public repository security contact has not yet been configured. Before publishing, the maintainer must provide a private reporting channel or enable private security advisories. Do not post private keys or sensitive live data. Include the version, platform, minimal reproduction, and observed impact.

## References

- [Go 1.27 cryptography and TLS support](https://go.dev/doc/go1.27)
- [Go TLS configuration and verification](https://pkg.go.dev/crypto/tls)
- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [Go Root confinement and limitations](https://pkg.go.dev/os#Root)
