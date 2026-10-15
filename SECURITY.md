# DEEP security

DEEP 3.0.1 provides authenticated resource transfer with explicit trust configuration and bounded server operation. Security primitives come from Go's standard library. Use Go 1.27.1 or later and keep the toolchain patched when rebuilding.

This release has automated security and interoperability tests. It has not received an independent cryptographic or deployment audit. The exact checks performed locally are recorded in [Validation](docs/VALIDATION-V3.md).

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

DEEP does not provide anonymous routing, traffic-analysis resistance, hidden SNI, automatic decentralized trust, application user roles or automatic signed updates. It does not hide network addresses, resource sizes, or timing. V1 identities and configurations are deliberately incompatible.

Release checksums alone do not authenticate the publisher. Obtain binaries and checksums from a trusted publication channel. Public repository hosting and a release-signing identity must be selected by the maintainer before publishing.

## Reporting Bugs and Security Vulnerabilities

Feedback from users, developers, and security researchers is greatly appreciated. Reports of bugs, unexpected behavior, design weaknesses, and potential security vulnerabilities help improve DEEP.

### General Bugs

For non-security-related bugs, unexpected behavior, or documentation errors, open a GitHub Issue:

https://github.com/flozdrelx/DEEP-protocol/issues

Please include the affected version or commit, operating system, steps to reproduce the issue, expected and actual behavior, and relevant logs when available. Remove credentials, private keys, and other sensitive information before sharing logs.
Before opening a new issue, please check whether the problem has already been reported. If a related issue exists, add any new reproduction details or evidence there instead of creating a duplicate.

### Security Vulnerabilities

Please do not disclose potentially exploitable vulnerabilities in public Issues, discussions, or Pull Requests.
Use GitHub's private vulnerability reporting feature. If it is unavailable, open a public Issue requesting a private reporting channel without including technical details of the vulnerability.

A useful report should include:

- A concise description of the suspected vulnerability.
- The affected version, component, or commit.
- Reproduction steps or a minimal proof of concept, when possible.
- The potential impact and realistic attack scenario.
- Relevant evidence, with sensitive information removed.

Please test only systems you own or have explicit permission to assess. Avoid destructive tests, service disruption, and access to other users' data.

### Coordinated Disclosure

Please give the maintainer a reasonable opportunity to investigate the report, assess its impact, and prepare a fix or mitigation before public disclosure.
The maintainer will make a reasonable effort to acknowledge and investigate reports, communicate relevant findings, and publish appropriate fixes or advisories when necessary. Response and remediation times are not guaranteed.

### Recognition

All valid reports that help improve DEEP's security and reliability are sincerely appreciated.
With the reporter's consent, their contribution may be acknowledged in the documentation, release notes, or contributor credits.
There is currently no guaranteed monetary compensation or bug bounty. Reports are welcome even when the reporter cannot provide a fix.

## References

- [Go 1.27 cryptography and TLS support](https://go.dev/doc/go1.27)
- [Go TLS configuration and verification](https://pkg.go.dev/crypto/tls)
- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [Go Root confinement and limitations](https://pkg.go.dev/os#Root)

## Optional Windows website viewer (2.1)

The viewer uses the existing DEEP client and verifies complete resources before
passing them to WebView2. Its browser origin policy, CSP, local/native access
restrictions, limits, and unsupported features are documented in
[the viewer guide](docs/VIEWER.md#security-and-limits). The graphical viewer adds
the .NET and Microsoft WebView2 runtime dependencies. Keep them updated; the
protocol's cryptographic guarantees do not imply that arbitrary website code
is trustworthy or that the browser engine is free of vulnerabilities.

## Optional application profile (2.2)

app/1 allows bounded state-changing requests. The complete upload is verified
before dispatch, but a lost response does not mean a write failed. Clients
must not automatically retry writes. Application handlers own authentication,
authorization, CSRF protection, and input validation.

The optional HTTP provider connects only to its fixed numeric loopback target,
ignores proxy environment variables, filters hop-by-hop/forwarded fields, and
does not follow redirects. It buffers up to 16 MiB per response with eight
upstream slots; request bodies are limited to 1 MiB. Publishing an application
intentionally exposes that application's routes to authorized DEEP visitors.

The viewer isolates cookie jars by exact authority and window and limits
redirects to the same authority. Cookies are temporary and unavailable to
document.cookie; browser credentials/SameSite modes are not fully emulated.
The backend remains part of the trusted local environment. See
[application boundaries](docs/APPLICATIONS.md) for the complete profile.

## Optional activation (2.3)

The viewer is disabled by default and checks a per-user preference before
launching. This is a usability setting, not an authorization boundary against
local processes. Network authentication and backend access never depend on it.
External frontend authors must implement their own origin and permission model.


## Native proxy trust

The optional proxy adapter uses only an explicitly configured literal loopback
address. It authenticates no local process: the listening network application
is trusted to verify its network's identity bindings and supply the expected
server key pin, just as an exec resolver is trusted. It is not protection
against malicious local users or administrators. Do not expose the listener
on a public interface.

Resolve and connect use bounded native Proxy/1 frames and deadlines. Connect
is bound to the resolved pin; DEEP then performs its unchanged mandatory TLS
and authority checks through the byte stream. Paths, credentials and content
are not disclosed by the control messages. Missing/unreachable proxy settings
have no fallback. See [the native proxy contract](docs/DEEP-PROXY.md).

## Disclaimer

DEEP is provided for educational, research, and experimental purposes, on an "AS IS" and "AS AVAILABLE" basis, without warranties of any kind to the extent permitted by applicable law.
Users are responsible for how they use, configure, and modify the software, and for complying with applicable laws and regulations.
The project does not endorse or encourage illegal activity or misuse of the protocol. Nothing in this disclaimer excludes or limits liability that cannot legally be excluded or limited under applicable law.
