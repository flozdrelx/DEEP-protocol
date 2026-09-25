# Roadmap

## Delivered in DEEP V1

- A message specification independent of HTTP and HellNet.
- Go client, server, URI handling, framing, and streamed resources.
- TLS 1.3 with mandatory X25519MLKEM768 and negotiated-group verification.
- Ed25519 identities pinned by SPKI fingerprint, with node-name verification.
- Networks connected through static adapters or executable resolvers in other languages.
- An interface for custom reliable transports; the executable includes the TCP profile.
- Sessions with sequential requests, verifiable sizes, and SHA-256 digests.
- A CLI for node initialization, file serving, downloads, and a two-network demo.
- Message, integration, cryptography, adapter, and CLI tests.
- Code and specification under Apache 2.0; the Python prototype retained as legacy code.

## Upcoming milestones

1. **Independent interoperability.** Implement another client or server from the specification, for example in Rust or C++, and agree on a public set of conformance vectors. Replacing Go is not necessary to achieve this.
2. **Real networks.** Integrate HellNet through its own adapter. Define discovery, identity, trust distribution, and collision resolution for each network. Add a DHT or signed records only once a model has been defined.
3. **New operations and transports.** Design uploads, dynamic queries, cancellation, and multiplexing if needed. Each incompatible change requires negotiation and another version; silently adding unknown fields would break V1.
4. **Post-quantum identity.** Evaluate an interoperable authenticated profile with ML-DSA, rotation, expiration, and revocation. Document session confidentiality and authentication separately.
5. **Visual client.** Create a viewer for DEEP content and links; define permissions and the content execution model before introducing active HTML or scripts.
6. **Open publication.** Choose repository hosting, a security contact, and a versioning policy; add continuous integration and reproducible binaries. Investigate public URI and ALPN registrations when the protocol is ready.
7. **Readiness for broader use.** External auditing, extended fuzzing, cross-platform and network testing, operational limits, and signed updates.

V1 is a functional custom protocol for experimentation. It is not presented as a registered Internet standard or production-ready infrastructure.
