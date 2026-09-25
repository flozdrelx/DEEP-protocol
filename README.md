# DEEP V1

**Decentralized Extensible Endpoint Protocol**: a resource protocol with `deep://` addresses, its own messages, and networks connected through adapters. DEEP is independent of HellNet and HTTP.

V1 includes a functional **Go** implementation with a client and server in one executable, chunked transfers, reusable sessions, and actual **TLS 1.3 + X25519MLKEM768** negotiation. Authentication uses Ed25519 identities and a trusted public-key fingerprint. This is a release for testing and interoperability; it does not imply public registration of `deep`, IETF approval, or a security audit.

## Try it in a minute

From this project's directory, with **Go 1.25 or later**:

```powershell
go run ./cmd/deep demo
```

The demo starts temporary servers for `deep://node.alpha/` and `deep://node.beta/`. It retrieves content, reuses each session for a larger transfer, and prints the **cryptographic group actually negotiated**. It stops the servers and removes its temporary files when finished.

To build the executable on Windows:

```powershell
.\scripts\build.ps1
.\bin\deep.exe version
.\bin\deep.exe demo
```

On Linux or macOS:

```sh
go build -trimpath -o bin/deep ./cmd/deep
./bin/deep demo
```

V1 does not require Python, external OpenSSL, or third-party Go dependencies. The earlier prototype is retained in [`legacy/python-v0.1/`](legacy/python-v0.1/).

## Create a node and retrieve content

```powershell
.\bin\deep.exe init --authority node.alpha --dir node-alpha --address 127.0.0.1:9761
.\bin\deep.exe serve --config node-alpha/server.json
```

In another terminal:

```powershell
.\bin\deep.exe fetch deep://node.alpha/ --config node-alpha/client.json --info
.\bin\deep.exe fetch deep://node.alpha/index.txt --config node-alpha/client.json --output received.txt --info
```

`init` creates a **new** directory, an identity valid for one year, and these files:

| File | Purpose |
| --- | --- |
| `server.json` | Authority, listening address, and server paths. |
| `client.json` | Network, node address, and trusted public-key fingerprint. |
| `identity.crt` | Public identity certificate. |
| `identity.key` | Private key; keep it on the server. |
| `content/index.txt` | Resource returned when requesting `/`. |

You can add files to `content/` and retrieve them by path. For example, request `content/docs/test.txt` as `deep://node.alpha/docs/test.txt`. The file server rejects queries (`?`), directories, and hidden or unsafe paths. Other resource providers can define their own behavior.

`--output` writes to a temporary file first, verifies the size and SHA-256, and publishes the result without overwriting existing files. The destination directory must support hard links, as NTFS and ext4 do. Without `--output`, bytes stream directly to stdout: if an error occurs, the receiver must discard the partial output. `--info` writes JSON to stderr, separately from the content.

The client's default limit is **1 GiB per resource**. You can adjust it with `--max-bytes 10737418240`, up to the protocol maximum of 1 TiB. `--timeout 60s` changes the client's per-operation limit; the server CLI uses 30 seconds per transfer. Ctrl+C stops the server.

To test between two computers, use a reachable address with `init --address`, run the server on that computer, and distribute `client.json` to the client through a trusted channel. Open the chosen port in your environment if necessary. Port 9761 in these examples is a local choice, not an officially assigned DEEP port.

## Connect your own network

An address has the form `deep://node.network/path?query#fragment`. The suffix selects an explicitly installed adapter. `.hell`, `.quit`, and `.weird` are network names within DEEP; they do not need to be public DNS domains.

A registry can contain multiple networks and nodes:

```json
{
  "version": 1,
  "networks": {
    "alpha": {
      "adapter": "static",
      "endpoints": {
        "node.alpha": {
          "address": "127.0.0.1:9761",
          "pin_sha256": "REPLACE_WITH_THE_REAL_64_CHARACTER_HEX_FINGERPRINT",
          "transport": "tcp"
        }
      }
    },
    "weird": {
      "adapter": "exec",
      "command": ["./my-resolver.exe", "--network", "weird"]
    }
  }
}
```

The `exec` adapter lets you write the **resolver** in any language. DEEP runs the configured command without a command interpreter. The resolver receives this on stdin:

```json
{"version":1,"authority":"mkaifl2masdh3aknd0.weird"}
```

The program responds with a single JSON object on stdout:

```json
{"address":"127.0.0.1:9761","pin_sha256":"REAL_64_CHARACTER_HEX_FINGERPRINT","transport":"tcp"}
```

The fingerprints in these examples are placeholders and must be replaced. The resolver must exit with code zero; stderr is available for diagnostics. Relative executable paths that include a path separator are resolved from the configuration directory. The resolver also uses that directory as its working directory. Only configure trusted programs.

`exec` resolves names; it does not carry resources through its pipes. The Go library also lets you register a `Client.Dialers["my-transport"]` that opens a `net.Conn` stream, and use your own `net.Listener` on the server. DEEP applies its TLS profile and messages over that stream. The distributed executable includes TCP; adding a transport requires integrating code into another client/server. Adapters do not change the DEEP wire format.

The project name expresses its goal: **V1 does not implement a DHT or automatic decentralized discovery**. Each network can implement its own resolution and trust distribution. The local registry decides which adapter handles each suffix and rejects duplicates; there is no global authority for these names.

## Open links in Windows (optional)

To have Windows send `deep://` links to this console client:

```powershell
Copy-Item node-alpha/client.json bin/config.json
.\scripts\register.ps1 -Executable .\bin\deep.exe
```

The script registers the scheme for **your user account**. If you registered the earlier prototype, add `-ReplaceExisting` to explicitly replace that handler. Registration does not run during the build. `open-uri` accepts exactly one URI, uses `config.json` beside the executable, displays the resource, and waits for Enter. It is a console viewer; it does not render HTML pages like a browser.

## Development and specification

```powershell
go test ./...
go vet ./...
```

The [DEEP V1 specification](docs/DEEP-V1.md) defines bytes, states, limits, identity, and adapters for implementations in other languages. The [independent interoperability probe](interop/README.md) implements the messages in Python for testing only; the DEEP executable does not depend on it. [SECURITY.md](SECURITY.md) describes the scope of PQC; the [roadmap](docs/ROADMAP.md) separates implemented features from future work.

The code and specification are distributed under [Apache License 2.0](LICENSE). Keep the notices in [NOTICE](NOTICE) when redistributing. Preparing these files does not automatically publish the project to any service.
