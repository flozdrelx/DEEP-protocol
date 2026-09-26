# DEEP V2 validation

Reference implementation: **2.0.0**. Local verification completed on September 25–26, 2026.

## Environment and completed checks

The local host was Windows amd64. Go checks used the official **Go 1.27.1**
toolchain. The race detector used GCC from MSYS2 UCRT64. The independent client
used **Python 3.14.6 with OpenSSL 3.5.7**.

| Check | Observed result |
| --- | --- |
| Complete Go suite with race detection | Passed: 74 top-level tests, 282 passing test events including subtests and fuzz seeds, no failures or skips. |
| Go static analysis | `go vet ./...` passed. |
| Python conformance suite | All 5 unittest methods passed, including shared frame vectors and hostile streams. |
| Shared frame vectors | 31 vectors: 5 accepted and 26 rejected by independent Go and Python readers. |
| Bounded frame fuzzing | 243,679 executions in a 15-second run with two workers; no failure. |
| Official Go vulnerability scan | `govulncheck v1.8.0` reported “No vulnerabilities found” for the source with Go 1.27.1 and the available database. |
| Separate native server/client processes | A private node transferred and verified 3,145,984 bytes. |
| Unauthorized native clients | Missing client identity and an incorrect server pin were rejected without publishing a download or leaving temporary output. |
| Independent Python client against the Go server | Mutual TLS authentication and two verified FETCH requests on one connection passed. |
| Explicit public access | A separate public node served a client without a client identity while retaining the required server security profile. |

The native connection reported TLS 1.3, X25519MLKEM768,
TLS_AES_128_GCM_SHA256, and ML-DSA-65, with both post-quantum verification flags
true. The test payload's SHA-256 was
`679361bf172a2b2f3d48919ee7b2b6fea9cf6e351005736ac7274ac8fde4e0f2`.

Python's standard `ssl` API does not expose the negotiated group. The independent
probe therefore does not claim to have inspected that group itself. The Go server
enforces it on every accepted connection, and the native client independently
inspects it. The probe validates its configured test certificate and hostname;
it is test tooling, not a replacement for the native client's full identity policy.

## What the regression tests cover

Tests exercise certificate roles, validity, names, pins, signatures, client
authorization, ALPN, hybrid exchange, and rejection of incompatible peers.
They also cover strict framing and JSON, invalid states and identifiers,
truncated or corrupted transfers, configuration ambiguity, adapter boundaries,
resource paths, session reuse, concurrency, cancellation, and failed deadlines.

Hardening tests check connection caps before the TLS handshake, persistent peer
request budgets across reconnects, bounded peer bookkeeping, request-count and
resource-size limits, session expiry, idle clients, safe remote errors, and
terminal preview escaping. Windows tests exercise protected credential creation
and startup checks separating served content from credentials.

The normal Windows user token was required for the complete CLI and live-process
checks: the restricted development token could not resolve the ancestor of the
Windows temporary directory. The production path checks were retained.

## Reproduce the checks

From the source directory, with a patched Go 1.27.1 or newer toolchain:

```powershell
go test ./...
go vet ./...
go test -race ./...
python -B -m unittest discover -s interop -p "test_*.py" -v
go test -run "^$" -fuzz "^FuzzReadFrame$" -fuzztime=15s -parallel=2
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go build -trimpath -buildvcs=false -o bin/deep.exe ./cmd/deep
python -B scripts/smoke_test.py --binary bin/deep.exe --probe --public-check
```

Race detection requires a compatible C compiler. The live Python probe requires
an OpenSSL build supporting ML-DSA-65 TLS certificates and the hybrid group;
a Python version number alone does not guarantee those capabilities.
The smoke script starts loopback servers, generates temporary identities, verifies
downloads, stops its servers, and removes its temporary directories.

## Platform and assurance limits

The release builder targets Windows, Linux, and macOS on amd64 and arm64. Its
`BUILD-MANIFEST.json` lists the binaries actually built, toolchain, and archive
checksums. Cross-compilation is distinct from executing the artifacts on each
target.

Local execution was verified on Windows amd64. Linux/macOS execution and
Unix-specific FIFO tests are configured in CI but were not run on this Windows
host; remote CI results are not claimed here. ARM64 runtime behavior also needs
validation on an appropriate machine.

The shared vectors cover framing and JSON syntax, not the entire state machine.
The bounded fuzz run and vulnerability scan are useful checks, not proofs of
security. This release has no external security audit, prolonged load test,
formal verification, or publisher-signed artifacts. See the [security
model](../SECURITY.md) and [operations guide](OPERATIONS.md) for its trust
boundaries and operational requirements.
