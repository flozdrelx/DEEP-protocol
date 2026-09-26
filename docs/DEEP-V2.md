# DEEP V2 - protocol specification

**Name:** Decentralized Extensible Endpoint Protocol.  
**Application and framing version:** 2.  
**Reference implementation:** 2.0.0.  
**Status:** official DEEP project release specification. No public Internet registration or external audit is implied.  
**License:** Apache 2.0.

This document defines the requirements for independent implementations to exchange DEEP resources. "MUST", "MUST NOT", and "MAY" express requirements of this specification. DEEP is not HTTP, does not define a specific network, and does not depend on HellNet. The URI scheme and ALPN identifier used here are not presented as granted public registrations.

## 1. Layers and scope

1. A **URI** identifies an authority and a resource.
2. A **network adapter** resolves the authority and provides an address and a trusted identity.
3. A **transport** opens a reliable, ordered byte stream.
4. The **V2 TLS profile** authenticates the server and protects that stream.
5. **DEEP messages** negotiate the version and transfer resources.

V2 defines the `FETCH` operation: retrieving a finite resource of known size. Sessions support multiple sequential requests to the same authority. There are no uploads, remote modifications, notifications, multiplexing, download resumption, DEEP compression, or implicit global discovery. A resource can be any sequence of bytes; the application decides how to present it.

## 2. Addresses

```text
deep://node.network/path?query#fragment
```

- The scheme and authority are accepted case-insensitively and converted to lowercase. Path, query, and fragment retain their spelling.
- The authority contains **exactly two labels**: node and network. Each label contains 1 to 63 ASCII alphanumeric characters or `-`, with alphanumeric characters at both ends. Messages and registries use the canonical lowercase form.
- Usernames, passwords, ports, literal IP addresses, and trailing dots are not allowed in the authority. The adapter supplies the transport address.
- The complete URI allows up to **4096 ASCII bytes**, with no spaces, control characters, backslashes, or literal non-ASCII characters. Characters requiring encoding are represented by valid `%HH` escapes.
- The path starts with `/`; if absent, it defaults to `/`. Path and query together, plus one separator byte when the query is nonempty, must not exceed 4096 bytes.
- Components allow alphanumeric characters and `-._~!$&'()*+,;=:@/`, as well as percent escapes. `?` is also allowed within the query and fragment. The `?` and `#` delimiters separate their components first.
- The fragment is local to the client and **MUST NOT be sent** to the server or resolver.
- The core does not decode or normalize escapes or path segments. The provider interprets the path and query and applies any required restrictions.

Example: `deep://Example.Weird/documents/a%20b.txt?q=1#section` produces authority `example.weird`, path `/documents/a%20b.txt`, query `q=1`, and local fragment `section`.

Network names belong to a local namespace of installed adapters. Registering two adapters for the same suffix is an error. The core does not resolve `.hell`, `.quit`, or `.weird` through DNS. An adapter MAY use DNS or other infrastructure to locate its endpoints.

## 3. Transport, identity, and authorization

The TCP profile connects to the adapter's `host:port`. No port is assigned by this specification. Other transports MAY provide a reliable, ordered, bidirectional byte stream supporting deadlines and cancellation; the same TLS profile is then applied.

Every connection MUST use TLS 1.3, a fresh `X25519MLKEM768` exchange, and ALPN `deep/2`. Tickets, resumption, and 0-RTT are disabled. V1, plaintext, HTTP, classical-only exchange, and classical signatures are not fallback modes.

The server MUST present exactly one self-signed ML-DSA-65 X.509 certificate. Its SubjectPublicKeyInfo MUST use ML-DSA-65. Its signature MUST verify under that key with ML-DSA-65, its issuer and subject encodings MUST match, and it MUST have:

- A currently valid lifetime (`NotBefore <= now < NotAfter`).
- Valid non-CA basic constraints.
- Exactly digital-signature key usage.
- Exactly the server-authentication extended key usage, with no unknown extended usages.
- Exactly one canonical `node.network` DNS SAN, matching the requested authority and TLS SNI.
- No IP, email, or URI SANs and no unhandled critical extensions.

The client MUST compare SHA-256 of DER SubjectPublicKeyInfo with the pin supplied through its trusted adapter, and validate the entire identity profile. Public Web PKI is not the trust source. A matching name or an arbitrary self-signed certificate is insufficient. TLS verifies possession of the pinned private key. Implementations MUST check the actually negotiated key-exchange group and ALPN, not merely their offered configuration.

Private servers additionally MUST request a client certificate during TLS, require it, and verify its SHA-256 SPKI pin against an explicit allowlist before reading DEEP messages. Client identities follow the same certificate profile with exactly the client-authentication extended usage instead of server-authentication usage. The client's canonical DNS name identifies that client and need not match the server authority. The allowlist pin grants access; the client name alone does not. A private server MUST NOT retry as public when client authentication fails.

Public servers explicitly permit clients without a certificate; server authentication, hybrid exchange, and all protocol validation remain mandatory. Local policy selects public or private access. The reference CLI defaults to private access. Private authorization covers the node's full resource set, not individual paths.

Content uses the AEAD negotiated by TLS 1.3. DEEP adds no separate encryption or MAC. ML-KEM-768 provides hybrid key establishment; ML-DSA-65 provides post-quantum authentication. The profile does not hide SNI, addresses, sizes, or timing. Local identity private keys MUST match their certificates and remain confidential. Certificate and allowlist changes require a server restart in the reference implementation; restarting terminates old sessions.

## 4. Framing

Messages are written inside the TLS stream. Each frame begins with a **20-byte** header, immediately followed by metadata and the body. All multibyte header integers are unsigned and big-endian.

| Offset | Size | Field | Rule |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `DEEP`, hexadecimal `44 45 45 50` |
| 4 | 1 | Framing version | `2` |
| 5 | 1 | Message type | Value from the message table |
| 6 | 2 | Flags | `0`; any other value is rejected |
| 8 | 4 | Request ID | Depends on the message type |
| 12 | 4 | Metadata length | Between 2 and 8192 bytes |
| 16 | 4 | Body length | Between 0 and 65536 bytes |

Receivers MUST validate the header and limits before allocating space for the content. TCP can fragment a frame or combine several frames: one read is not equivalent to one message.

Metadata is exactly one UTF-8 JSON object. Invalid UTF-8, unpaired Unicode surrogates, duplicate keys, data after the object, and nesting deeper than 16 levels are rejected. All fields listed for each message are required; unknown fields, incorrect types, and `null` values are not allowed. Integer fields must have an accepted integer JSON representation without a fraction or exponent. Key order and JSON whitespace are not significant.

Only `DATA` carries a body; its length is 1 to 65536 bytes. All other types have an empty body. A message without attributes uses `{}` metadata, not zero metadata bytes. Unknown types are rejected.

## 5. Messages and states

| Value | Name | ID | Metadata |
| ---: | --- | --- | --- |
| 1 | `HELLO` | 0 | `{"versions":[2]}` |
| 2 | `WELCOME` | 0 | `{"version":2,"max_chunk":65536}` |
| 3 | `REQUEST` | Positive | `{"authority":"node.alpha","path":"/","query":"","operation":"FETCH"}` |
| 4 | `RESPONSE` | REQUEST ID | `{"media_type":"text/plain; charset=utf-8","size":123}` |
| 5 | `DATA` | REQUEST ID | `{}` and a nonempty binary body |
| 6 | `END` | REQUEST ID | `{"size":123,"sha256":"…"}` |
| 7 | `ERROR` | 0 or active ID | `{"code":"NOT_FOUND","message":"resource is unavailable"}` |
| 8 | `CLOSE` | 0 | `{}` |

### 5.1 Opening

After completing TLS, the client sends `HELLO`. The `versions` list contains 1 to 16 distinct integers between 1 and 65535. A V2 server selects 2 if present and responds with `WELCOME`. `max_chunk` is exactly 65536 in V2. If there is no common version, the server sends `ERROR` with ID 0 and code `UNSUPPORTED_VERSION`, then closes.

Header version 2 remains mandatory during this negotiation. Including an unknown version in `HELLO` does not authorize unknown framing. The client does not send requests before receiving and validating `WELCOME`.

### 5.2 Request and transfer

The client sends a `REQUEST` with an ID between 1 and 4294967295, strictly greater than all previous IDs on that connection. IDs are not reused and wraparound is not allowed; a new connection is opened when they are exhausted. Only one request can be active. The client MUST NOT send another `REQUEST` before the previous request's `END`; pipelining is not defined.

`authority` must be the same canonical authority authenticated and served by that connection. `operation` is exactly `FETCH`. The path and query follow the URI rules; `query` is an empty string when there is no query. A fragment is not transmitted.

For a successful request, the server sends:

```text
RESPONSE → DATA* → END
```

`RESPONSE.size` is an integer between 0 and **1099511627776 bytes (1 TiB)**. `media_type` is a descriptive string of 1 to 255 printable ASCII bytes, usually a media type. It is not interpreted as an HTTP header.

The server divides the resource into nonempty chunks of at most 65536 bytes. All frames retain the request ID. The total length of `DATA` bodies MUST match `RESPONSE.size` and `END.size`. `END.sha256` contains exactly the SHA-256 of the concatenated bodies as **64 lowercase hexadecimal digits**. An empty resource has no `DATA` frames; its digest is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The receiver verifies the ID, state, size, and digest before considering the resource complete. EOF, TLS closure, timeout, cancellation, or an error before a valid `END` means the transfer failed. SHA-256 verifies consistency within the session; it does not provide a persistent content signature.

After `END`, another request for the same authority may begin. The client can end an idle session with `CLOSE`, and the server closes without an additional DEEP response. `CLOSE` is not required after a failure.

### 5.3 Errors

`ERROR` is terminal for the connection. It uses ID 0 during negotiation and the active ID during a request. `code` matches `[A-Z][A-Z0-9_]{0,63}`; `message` is at most 1024 UTF-8 bytes and MUST NOT contain Unicode Cc, Cf, Zl, or Zp characters. This excludes terminal controls, formatting/bidirectional controls, and line/paragraph separators. Both are strings and are neither executed nor interpreted as protocol content. Clients must be able to display unknown codes.

Reference implementation codes:

| Code | Meaning |
| --- | --- |
| `PROTOCOL_ERROR` | Invalid message or sequence. |
| `UNSUPPORTED_VERSION` | No common version. |
| `UNKNOWN_AUTHORITY` | The server does not serve that authority. |
| `UNSUPPORTED_OPERATION` | Operation other than FETCH. |
| `NOT_FOUND` | Resource unavailable. |
| `BAD_RESOURCE` | Path rejected by the provider. |
| `UNSUPPORTED_QUERY` | The file provider does not accept queries. |
| `TOO_LARGE` | Resource exceeds the configured or protocol limit. |
| `RESOURCE_CHANGED` | Content does not match the announced size. |
| `INTERNAL_ERROR` | Provider failure. |
| `RATE_LIMITED` | Peer request rate exceeded. |
| `SESSION_LIMIT` | Session request-count limit reached. |

A receiver detecting an invalid frame MUST close the connection. It MAY first send an `ERROR` if the state permits; responding to malformed headers, TLS failures, or disconnections is not mandatory. Sessions with errors must not be reused for other requests.

## 6. Minimal framing vectors

These bytes are plaintext **inside** TLS; they do not define a plaintext transport mode.

`HELLO`, ID 0, with `{"versions":[2]}` (16 bytes):

```text
44 45 45 50 02 01 00 00 00 00 00 00 00 00 00 10 00 00 00 00
7b 22 76 65 72 73 69 6f 6e 73 22 3a 5b 32 5d 7d
```

`DATA`, ID 1, metadata `{}`, ASCII body `abc`:

```text
44 45 45 50 02 05 00 00 00 00 00 01 00 00 00 02 00 00 00 03
7b 7d 61 62 63
```

If that is the complete resource, its size is 3 and the `END` digest is `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.

## 7. Adapter contract

Resolution receives only the canonical authority, without a path, query, or fragment. It returns:

```json
{
  "address": "127.0.0.1:9761",
  "pin_sha256": "64_ACTUAL_HEXADECIMAL_DIGITS",
  "transport": "tcp"
}
```

In the Go implementation, `address` contains 1 to 1024 printable ASCII bytes. For TCP it is `host:port` without spaces; the canonical decimal port is between 1 and 65535, and an IPv6 host is enclosed in brackets. Other transports interpret the address as an opaque string according to their own contract. The fingerprint accepts uppercase or lowercase hexadecimal digits. An absent or empty `transport` means `tcp`; explicit names start with a lowercase letter, contain lowercase letters, digits, or hyphens, and are at most 32 characters long. The example fingerprint is a placeholder, not a valid value.

`static` is a trusted local map from authorities to endpoints. `exec` launches an explicitly configured local command without a shell and supplies a newline-terminated JSON object:

```json
{"version":2,"authority":"node.weird"}
```

The program MUST exit with code zero and return exactly one endpoint object on stdout. The stdout limit is 64 KiB and the default resolution timeout is 10 seconds, shortened by an earlier client deadline. Diagnostics may be written to stderr; they never form part of the endpoint. Responses MUST be UTF-8 JSON objects with exact field names. Unknown, case-aliased or duplicate keys, nulls, malformed Unicode, and invalid endpoints are rejected. Optional fields must be omitted instead of set to null.

A resolver can discover nodes in its own network through external mechanisms. DEEP **trusts the authority/fingerprint binding returned by the adapter**. Designing authenticated decentralized resolution is that network's responsibility, not an automatic property of this interface.

The `exec` profile handles resolution. Custom transports integrate through the library: `DialFunc(context.Context, Endpoint) (net.Conn, error)` and `Server.Serve(context.Context, net.Listener)`. The returned stream still receives the core's mandatory TLS layer. The standard executable includes only TCP transport.

## 8. Provider API and local behavior

The library provides `Handler.Open(ctx, path, query) (Resource, error)`. `Resource` contains a `Body` implementing `io.ReadCloser`, `MediaType`, and `Size`. The resource must be finite and return EOF after exactly `Size` bytes. `Open` MUST respect the context and `Body.Close` MUST unblock a pending read so that cancellation and server shutdown can complete.

`FileHandler` interprets `/` as `/index.txt`, decodes escapes once, and confines access to its root. It rejects empty, hidden, or Windows-unsafe path components, nonempty queries, observed symlink components, and nonregular files. Unix opens are nonblocking to prevent FIFO stalls; opened file identity and type are checked before reads. The tree MUST be operator-controlled: observed-symlink checks are not a sandbox against hostile concurrent local writers, hard links, or mount points. This policy belongs to the file provider, not to all possible DEEP resources.

`Client.Fetch` opens and closes a session. `Client.Dial` returns a reusable `Session` for the same authority. Concurrent requests on one session are rejected with a local session-busy error; use separate sessions for concurrency. The destination `io.Writer` may have received data before an error: the caller MUST discard partial data. The CLI handles this with a temporary file when using `--output`.

Reference library defaults: 1 GiB per resource for client and server, 30 seconds per transfer and idle wait, 5 seconds for TLS handshake, 5 minutes total session lifetime, 128 requests per session, 64 global connections, and at most 16 active connections per peer (clamped to the global cap). The CLI defaults to 128 global connections, 16 per peer, a one-hour total session lifetime, and 1,000 requests per session. These operational limits are local policy and are not negotiated as capabilities.

Per-peer rate policy defaults to 120 resource requests per fixed one-minute window. Reconnection does not reset that budget. Up to 240 new connections per peer per minute are accepted before TLS. The table holds at most 4,096 peers and evicts only inactive entries whose windows expired. When capacity is exhausted, new peers are rejected. TCP peers are grouped by source IP; custom transports MUST expose stable peer identifiers to preserve this policy.

The implementation closes operations when deadlines cannot be installed. Handlers MUST honor context cancellation, body Close MUST unblock reads, and client writers MUST return from writes; arbitrary local extension code is trusted.

### 8.1 Local configuration

The reference server and client configurations use `"version":2`. V1 configurations are rejected. Configuration decoding rejects unknown/case-aliased/duplicate fields, nulls, invalid Unicode, excessive nesting, and missing required fields. Optional fields use omission.

Client configurations contain `networks` and MAY contain `client_identity` with required `certificate` and `private_key` paths relative to the configuration file. Credentials are local client state and MUST NOT appear in the resolver request or DEEP frame metadata. Their files and the configuration are trusted local inputs.

Server configurations explicitly select `access_mode` as `private` or `public`. Private mode requires 1 to 256 distinct `allowed_client_pins`; public mode has no allowlist. Startup validates the identity, authority, limits, and separation of credentials/configuration from the resource root. Configuration fields and limits are documented in [Operations](OPERATIONS.md).

## 9. Evolution and interoperability

V2 rejects unknown fields, flags, types, and operations. An incompatible extension needs a newly agreed version; it must not be introduced as undocumented optional behavior. An implementation in another language must produce the same bytes, states, and checks, even if its local API differs.

The library name, language, file paths, and CLI commands are not protocol requirements. This specification is distributed to support independent implementations. V1 peers and Ed25519 identities are incompatible with V2. Migration requires new role-specific ML-DSA-65 identities and version-2 configurations; see [Migration](MIGRATION-V2.md).

## References

- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html).
- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final).
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final).
- [Go TLS library](https://pkg.go.dev/crypto/tls).

The shared [frame vectors](../interop/frame_vectors.json) specify exact framing examples independently consumed by Go and Python tests. They validate framing and JSON syntax, not every message-state rule.

DEEP-specific URI, message, error, and adapter details are defined in this document and are not attributed to those references.
