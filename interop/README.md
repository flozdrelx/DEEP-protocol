# Independent DEEP V2 interoperability probe

`python_probe.py` implements DEEP V2 framing directly with Python's `struct`,
`json`, sockets, and SHA-256. It does not import DEEP modules or call the Go
client. Python is an optional testing tool; the DEEP executable does not need it.

## Backend requirements

The Python `ssl` module must use an OpenSSL build supporting **TLS 1.3,
X25519MLKEM768, and ML-DSA-65 certificate authentication**. Checking a Python
version alone is insufficient. The backend must support ML-DSA in TLS, not only
standalone signing. Check the installed backend with:

```powershell
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

A missing algorithm or an incompatible certificate causes a visible failure.
The probe never falls back to V1, a classical identity, plaintext, or another TLS
profile. Updating OpenSSL/Python may be necessary; the offline conformance tests
below do not require a PQC-capable backend.

## Test a private node

From the project root, initialize a node and start its server:

```powershell
.\bin\deep.exe init --authority node.alpha --dir node-alpha --address 127.0.0.1:9761
.\bin\deep.exe serve --config node-alpha/server.json
```

Initialization creates a private node and an authorized client identity. In a
second terminal, run:

```powershell
python interop/python_probe.py --address 127.0.0.1:9761 --authority node.alpha --cert node-alpha/identity.crt --client-cert node-alpha/client.crt --client-key node-alpha/client.key --repeat 2 --output copy.txt
```

For a node explicitly initialized with `--public`, omit `--client-cert` and
`--client-key`. Those two arguments must otherwise be provided together.
Keep the client private key private; supply it only to trusted clients.

The probe verifies the explicitly trusted certificate and server name, confirms
that the server certificate's SubjectPublicKeyInfo uses ML-DSA-65, and negotiates
TLS 1.3 and ALPN `deep/2`. It then sends HELLO and performs two FETCH requests on
one connection, checking IDs, message schemas, sizes, and SHA-256. Certificate
verification and TLS signatures are handled by OpenSSL.

`--path` selects a percent-encoded resource path; queries are not sent.
`--output` publishes the final verified response to a new file without replacing
an existing file. Defaults are 64 MiB per resource, 30 seconds for the entire
network operation, and two requests. `--max-bytes`, `--timeout`, and `--repeat`
change these limits; the repeat limit is 16. Resource hashes may differ between
requests if the server's content changes.

**Hybrid key-exchange verification:** Python's public `ssl` API does not expose
the negotiated group. The Go V2 server independently enforces and checks
X25519MLKEM768 before processing DEEP messages. The probe reports this limitation
explicitly; it does not invent a group result. Its authentication report follows
a successful TLS handshake and structural ML-DSA-65 SPKI check. Configuring a
client certificate does not by itself prove that a public server requested it.

The probe's `--cert` trust policy deliberately differs from the production Go
client's adapter/SPKI-pin policy. It is an independent interoperability test,
not a replacement client or resolver implementation.

## Shared conformance tests

```powershell
go test ./...
python -m unittest discover -s interop -p 'test_*.py' -v
```

Both implementations independently consume `frame_vectors.json`. It includes
valid V2 frames, Unicode and nesting boundaries, malformed headers, V1 rejection,
invalid lengths, duplicate JSON keys, invalid Unicode, and truncated frames.
These vectors cover frame syntax; Go integration tests and Python hostile-stream
tests separately check message schemas, states, IDs, size limits, and integrity.
The Python tests also check UTF-8 error limits and terminal-control rejection.

The JSON vectors are reusable by implementations in other languages. All hex
bytes describe plaintext *inside* the mandatory TLS stream, never a plaintext
transport mode.
