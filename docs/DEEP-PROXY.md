# Optional native DEEP proxy (Proxy/1)

DEEP 2.3.2 has one generic, optional native proxy setting. There is no default
address, default port, built-in provider, or network selector. DEEP can host
and access resources using its ordinary direct adapters without a proxy or
any network application.

## Configure

Supply the address of a proxy you explicitly choose:

~~~text
deep proxy set --address IP:PORT
deep proxy status
deep proxy unset
~~~

IP:PORT is a placeholder for the provider's literal loopback address and port.
DEEP never fills it in automatically. Commands default to config.json beside
deep.exe; --config FILE selects another configuration.

Set writes only the optional top-level proxy field:

~~~json
{
  "version": 2,
  "proxy": {
    "address": "IP:PORT"
  }
}
~~~

Replace IP:PORT with your chosen address before using this example. Existing
networks and relative client-identity paths are preserved. Changed existing
configurations get a backup. No network-specific entry is needed.

With proxy configured, every authority is sent to that proxy, including
authorities for which direct adapters exist. A refused or unreachable proxy
fails without trying direct adapters, HTTP or DNS as a fallback. The provider
decides which networks it supports.

Unset removes the proxy field. DEEP then uses its explicitly configured direct
adapters. An empty configuration such as {"version":2} is valid and provides
no routes. No network application is contacted until explicitly configured.
Changing configuration affects subsequently loaded clients; close or reload
existing clients/sessions as appropriate.

This is a native TCP interface. It does not configure an HTTP/SOCKS proxy,
register a URL handler or enable the optional viewer. A conventional browser
does not gain deep:// support from its HTTP proxy settings.

## Library integration

LoadClientConfig loads the optional top-level proxy and registers its transport.
For a programmatic registry, call Registry.SetProxy(address); SetProxy("") turns
it off. NewClient includes DialProxy under the deep-proxy transport name.
ProxyAdapter remains available as a generic low-level resolver API.

The proxy address must be an explicitly supplied literal loopback IP with a
canonical port from 1 to 65535; IPv6 loopback is supported. All suffixes use
the same interface. Separate client configurations can select different proxies.

The local proxy is trusted to authenticate name-to-server-key bindings, like
an executable resolver. Proxy/1 does not authenticate the process listening on
the local port and does not defend against a malicious local user or administrator.
Do not expose it publicly. Providers define their own route and management policy.

## Wire contract

Each control frame has:

| Field | Encoding |
| --- | --- |
| Magic/version | Eight ASCII bytes DPRX0001 |
| JSON length | Unsigned 32-bit big-endian integer, 1..4096 |
| Message | Exactly that many UTF-8 JSON bytes |

Readers reject unknown or missing required fields, duplicate fields, null,
malformed Unicode and wrong types. They consume exactly the frame without
buffering away subsequent TLS bytes. Unsupported framing (including HTTP and
SOCKS) is closed. One operation is permitted per TCP connection.

Resolve request:

~~~json
{"version":1,"operation":"resolve","authority":"node.network"}
~~~

Successful response:

~~~json
{"version":1,"ok":true,"pin_sha256":"64_HEXADECIMAL_DIGITS"}
~~~

Resolve closes after the response. The DEEP adapter constructs an internal
endpoint with transport deep-proxy and address
deep-proxy://IP:PORT/node.network; this descriptor is not a website URL.

Connect opens a second connection:

~~~json
{"version":1,"operation":"connect","authority":"node.network","pin_sha256":"64_HEXADECIMAL_DIGITS"}
~~~

The proxy checks the route again, including expiry and the exact resolved pin.
After connecting to that route it sends the same success response, then
forwards a bidirectional byte stream. The client verifies that the returned
pin matches, then begins ordinary DEEP V2 TLS on that same stream.

DEEP still requires TLS 1.3, X25519MLKEM768, the pinned ML-DSA-65 server key and
the expected authority. Private services still require client authentication.
The proxy never terminates TLS. Paths, query strings, credentials, request
bodies and response bodies remain inside DEEP encryption.

Failure response:

~~~json
{"version":1,"ok":false,"error":"ROUTE_UNAVAILABLE"}
~~~

A provider can use INVALID_REQUEST, ROUTE_UNAVAILABLE or PIN_MISMATCH; the connection
then closes. Failed replies have no pin. Clients must not trust arbitrary
diagnostic text from a listener. The client control handshake defaults to five
seconds and obeys cancellation; the stream uses the normal DEEP deadlines.

