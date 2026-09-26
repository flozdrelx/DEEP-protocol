# DEEP V2

**Decentralized Extensible Endpoint Protocol - release 2.0.0**

DEEP transfers resources through `deep://node.network/path` addresses using its own versioned messages. Networks plug in through adapters. The protocol is independent of HTTP and HellNet; a network integrates with DEEP rather than becoming part of its core.

V2 requires **TLS 1.3**, hybrid **X25519 + ML-KEM-768** key establishment, and **ML-DSA-65** server authentication. Private nodes also require an authorized ML-DSA-65 client identity. The executable includes a client, file server, identity tools, and a local demo.

This is the project's first official release line. It has automated validation and a documented threat model; it has not received an external security audit and is not an IETF-approved or publicly registered Internet standard.

## Quick start

The prebuilt executable does not require Go, Python, or external OpenSSL. From the project directory on Windows:

```powershell
.\bin\deep.exe version
.\bin\deep.exe demo
```

The demo creates two independent private networks, authenticates both ends, transfers text and binary content, and reuses each session. It prints the negotiated security profile and removes its temporary resources when finished.

To build from source, use **Go 1.27.1 or later**, with the latest security patch for your Go release:

```powershell
.\scripts\build.ps1
```

On Linux or macOS:

```sh
go build -trimpath -o bin/deep ./cmd/deep
./bin/deep demo
```

There are no third-party Go runtime dependencies. Python is optional interoperability test tooling.

## Start a private node

```powershell
.\bin\deep.exe init --authority node.alpha --dir node-alpha --address 127.0.0.1:9761
.\bin\deep.exe serve --config node-alpha/server.json
```

In another terminal:

```powershell
.\bin\deep.exe fetch deep://node.alpha/ --config node-alpha/client.json --info
.\bin\deep.exe fetch deep://node.alpha/index.txt --config node-alpha/client.json --output received.txt --info
```

`init` creates a new directory and refuses to overwrite an existing one. It protects the directory with Unix permissions or a current-user Windows ACL before writing credentials.

| File | Purpose |
| --- | --- |
| `server.json` | Server authority, listen address, resource root, access mode, allowed client pins, and operational limits. |
| `client.json` | Trusted network endpoints, server pins, and paths to the client identity. |
| `identity.crt`, `identity.key` | Server-only ML-DSA-65 certificate and private key. Keep the key on the server. |
| `client.crt`, `client.key` | Initial authorized client identity. The client key grants access to this private node. |
| `content/index.txt` | Default resource returned for `/`. |

Place only intended resources inside `content/`. For example, `content/docs/test.txt` is available at `deep://node.alpha/docs/test.txt`. Private authorization covers the node's entire resource set; V2 does not define per-path roles.

`--output` writes a temporary file, checks the complete transfer's size and SHA-256, and publishes it without overwriting an existing file. Its destination must support hard links, such as NTFS or ext4. Without `--output`, `fetch` writes raw resource bytes to stdout; discard partial output if the command fails. Use the URI viewer for escaped terminal previews of untrusted content.

`--info` writes metadata and security information to stderr. The default client resource limit is 1 GiB; `--max-bytes` can change it up to the protocol maximum of 1 TiB. `--timeout 60s` changes the client operation timeout; the server enforces its own independent limits. Ctrl+C stops the server.

## Public nodes and additional clients

Public access must be selected explicitly:

```powershell
.\bin\deep.exe init --authority public.alpha --dir node-public --address 127.0.0.1:9762 --public
```

Public nodes still require the same authenticated, encrypted server connection. They allow clients without a certificate to retrieve all served resources.

Create a separate client identity for another user or device:

```powershell
.\bin\deep.exe client-init --authority laptop.alpha --dir client-laptop
.\bin\deep.exe inspect --certificate client-laptop/client.crt
```

Add its public SPKI pin to the server's `allowed_client_pins` and restart the server. Configure that client's certificate and key in its own `client.json`. Removing a pin and restarting revokes its access and closes existing sessions. Do not copy the server private key to clients.

For a different computer, select a reachable address at initialization and distribute the server pin and client configuration through a trusted channel. The default loopback address is local to one computer. Port 9761 is a configurable example, not an officially assigned DEEP port.

See [Operations](docs/OPERATIONS.md) for configuration, credential distribution, rotation, revocation, resource limits, and deployment.

## Network adapters

The suffix selects an explicitly configured adapter. Names such as `.hell`, `.quit`, and `.weird` do not need public DNS registration. A version-2 client configuration can contain multiple networks:

```json
{
  "version": 2,
  "client_identity": {
    "certificate": "client.crt",
    "private_key": "client.key"
  },
  "networks": {
    "alpha": {
      "adapter": "static",
      "endpoints": {
        "node.alpha": {
          "address": "127.0.0.1:9761",
          "pin_sha256": "REPLACE_WITH_THE_REAL_64_CHARACTER_HEX_SPKI_PIN",
          "transport": "tcp"
        }
      }
    },
    "weird": {
      "adapter": "exec",
      "command": ["./my-resolver.exe"]
    }
  }
}
```

Omit `client_identity` for a client that only uses public nodes. Identity paths and relative resolver paths are resolved from the configuration directory. The pin above is a placeholder, not a usable fingerprint.

The `exec` resolver receives only the canonical authority on stdin:

```json
{"version":2,"authority":"node.weird"}
```

It must exit successfully and return one endpoint object on stdout:

```json
{"address":"127.0.0.1:9762","pin_sha256":"REPLACE_WITH_THE_REAL_64_CHARACTER_HEX_SPKI_PIN","transport":"tcp"}
```

The program is executed directly without a shell. Its output is bounded and strictly validated. It does not receive the URI path, query, fragment, or client credentials through the resolver request. It is trusted local code running with the user's permissions.

The library supports custom reliable transports through `Client.Dialers` and `Server.Serve(ctx, net.Listener)`. DEEP applies the same TLS and framing over them. The shipped executable uses TCP. Custom connections must support deadlines and return a stable peer address for per-peer limits.

DEEP does not implement automatic DHT discovery, global name ownership, or anonymous routing. Each network is responsible for authenticated resolution and distribution of trusted server pins. HellNet integration is a separate next step.

## Optional Windows link handler

To open `deep://` links using the console viewer, place a working client configuration at `bin/config.json`. Identity paths in that copy must still resolve correctly; copying a private configuration to another directory does not copy its credentials or adjust relative paths.

```powershell
.\scripts\register.ps1 -Executable .\bin\deep.exe
```

Use `-ReplaceExisting` only when replacing another registered handler. The script registers the current user only and is never run automatically by the build. The viewer accepts exactly one URI, verifies the transfer, and displays an escaped preview of at most 1 MiB. It does not execute scripts or render HTML.

## Validation and distribution

```powershell
go test ./...
go vet ./...
go test -race ./...
python -B -m unittest discover -s interop -p "test_*.py" -v
```

The race detector requires a compatible C compiler. CI includes multiple operating systems; cross-compiling a binary alone is not evidence that it was executed on that platform.

- [Protocol specification](docs/DEEP-V2.md)
- [Security and threat model](SECURITY.md)
- [Migration from V1](docs/MIGRATION-V2.md)
- [Validation results](docs/VALIDATION-V2.md)
- [Independent interoperability probe](interop/README.md)
- [Changelog](CHANGELOG.md)
- [Roadmap](docs/ROADMAP.md)

Release archives and SHA-256 checksums are generated locally. Checksums detect changed bytes; they do not provide a publisher signature by themselves. Preparing a release does not publish it to a remote repository.

Code and specification are licensed under [Apache License 2.0](LICENSE). Preserve [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) when redistributing.
