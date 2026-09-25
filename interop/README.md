# Independent interoperability probe

`python_probe.py` implements the DEEP V1 message format directly with
`struct`, `json`, sockets, and SHA-256 from the standard library. It does not import
DEEP modules or call the Go client. Python is used only for this test;
the DEEP V1 executable does not require it.

It requires Python with `ssl` linked to **OpenSSL 3.5 or later**, with the
`X25519MLKEM768` group available in its configuration. Local testing confirmed that
Python 3.14.6 / OpenSSL 3.5.7 offers this group by default. The Python version
alone does not demonstrate PQC support: check OpenSSL as well.

```powershell
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

From the project root, create and serve a node with the Go executable:

```powershell
.\bin\deep.exe init --authority node.alpha --dir node-alpha --address 127.0.0.1:9761
.\bin\deep.exe serve --config node-alpha/server.json
```

In another terminal:

```powershell
python interop/python_probe.py --address 127.0.0.1:9761 --authority node.alpha --cert node-alpha/identity.crt --path / --repeat 2 --output copy.txt
```

The probe negotiates TLS 1.3 and ALPN `deep/1`, verifies the supplied local
certificate and server name, sends HELLO, and performs two FETCH operations
for the same path over **one connection**. It checks IDs, sizes, types, metadata,
and SHA-256 for every response. It prints a JSON report. `--output` saves only
the last response after verification; the file must be new. Content may change
between the two requests: their hashes are not required to match.

Defaults limit each resource to 64 MiB and the entire network operation to
30 seconds. Adjust these with `--max-bytes` and `--timeout`. `--repeat` accepts
values from 1 to 16. A TLS, protocol, integrity, or write failure produces
a nonzero exit code; the connection is not downgraded and the test is not
silently skipped. A runtime without hybrid support must be upgraded to run
this test.

**Scope of PQC verification:** OpenSSL performs the hybrid key exchange. Python's
public `ssl` API cannot report the negotiated group. The Go DEEP V1 server
requires and verifies `X25519MLKEM768` before accepting messages; that server-side
check is necessary to establish that this connection used PQC. The probe's JSON
states this limitation and does not invent a negotiation result.
Do not use `set_ecdh_curve("X25519MLKEM768")`: that older API rejects the name
even when the backend supports the group.

This tool explicitly trusts the test certificate supplied with `--cert`.
It does not implement adapters, the Go client's SPKI pin policy, a new
cryptographic construction, or post-quantum authentication.
