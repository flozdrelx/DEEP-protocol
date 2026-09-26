# Migrating from DEEP V1 to V2

DEEP V2 is a breaking protocol and security-profile change. V1 peers, certificates,
and configuration files are rejected. The command never edits or upgrades old
credentials automatically. Keep the old directory until your new node works.

## Create a private V2 node

Build with Go 1.27.1 or newer, or use the matching release executable:

```powershell
.\bin\deep.exe init --authority node.alpha --dir node-alpha-v2 --address 127.0.0.1:9761
.\bin\deep.exe inspect --certificate node-alpha-v2/identity.crt
.\bin\deep.exe serve --config node-alpha-v2/server.json
```

In another terminal:

```powershell
.\bin\deep.exe fetch deep://node.alpha/ --config node-alpha-v2/client.json --info
```

The new node is **private by default**. Its server and initial client have separate
ML-DSA-65 certificates and private keys. `client.json` references the client
certificate and key. `server.json` authorizes that client's public-key pin.

Copy only your intended public resource files into the new `content/` directory.
Do not copy keys, certificates, configurations, or an entire old node directory
into `content/`. Recreate adapter settings in the V2 client configuration and
replace each old server pin with the V2 server's pin, verified through a trusted
channel. Merely changing `"version": 1` to `2` does not migrate an identity.

To create a server that intentionally accepts anonymous clients, create a new
node with `init --public`. Public mode still requires the client to verify the
server's pinned ML-DSA-65 identity and negotiate the mandatory V2 TLS profile.

## Breaking changes

| Area | V1 | V2 |
| --- | --- | --- |
| Frame version and configuration version | `1` | `2` |
| ALPN | `deep/1` | `deep/2` |
| Server certificate signatures | Ed25519 | ML-DSA-65 |
| Default CLI access | Server authentication only | Mutual TLS with allowed client pins |
| New identities | Server certificate/key | Separate server and client certificate/key |
| Runtime/build | Older Go | Go 1.27.1 or newer |
| JSON parsing | V1 schema | Exact field names; duplicates, null, unknown and missing required fields rejected |

There is no downgrade negotiation or HTTP fallback. Both V1 and V2 use the same
`deep://` URI scheme; the configured adapter and endpoint select the actual peer.

## Additional clients

On each client's machine, generate a separate identity:

```powershell
.\bin\deep.exe client-init --authority guest.alpha --dir client-guest
.\bin\deep.exe inspect --certificate client-guest/client.crt
```

Add that client's public `pin_sha256` from `identity.json` to the server's
`allowed_client_pins`, then restart the server. Add the `client_identity` object
to that client's V2 network configuration. Certificate/key paths are relative to
the configuration file, so adjust them if the config lives elsewhere. Keep the
private key on the client's machine; only the public pin is needed by the server.
The identity name is descriptive; the exact key pin grants access.

For `deep://` Windows registration, place the trusted V2 client configuration
beside the executable as `config.json`. Its credential paths must still resolve
correctly from that location. Then explicitly run `scripts/register.ps1` with
`-ReplaceExisting` if replacing an old handler. Registration does not happen
automatically. The URI viewer is a verified, escaped text preview, limited to
1 MiB; use `fetch --output` for larger or binary resources.

