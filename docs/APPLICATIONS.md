# DEEP application profile (app/1)

DEEP 2.2 adds an optional application exchange to V2 for pages, assets, forms,
JSON requests, redirects, and response cookies. Adapters, pinned identities,
TLS 1.3, X25519MLKEM768, and ML-DSA-65 stay unchanged. The profile is generic;
the bundled loopback HTTP provider is one implementation. Other providers
implement ApplicationHandler without HTTP.

## Publish a running app

Start your app normally, keeping its templates, static files, and code in its
own directory. For Flask on port 5000, using DEEP directly:

~~~powershell
.\bin\deep.exe init --authority demo.local --dir .\app-identity --address 127.0.0.1:9761 --upstream http://127.0.0.1:5000
.\bin\deep.exe serve --config .\app-identity\server.json
~~~

In another terminal, enable the optional viewer first (DEEP 2.3+):

~~~powershell
.\bin\deep.exe viewer enable
.\bin\deep.exe browse deep://demo.local/ --config .\app-identity\client.json
~~~

This creates a private node and client identity without a content directory.
Network applications can expose this generic provider through their own
routing and hosting interfaces. Consult the chosen provider's documentation.

Server configuration accepts exactly one of root and upstream. An upstream
must be plain HTTP at a numeric loopback IP with an explicit port, for example
http://127.0.0.1:5000 or http://[::1]:5000. DNS names, remote addresses,
credentials, base paths, and queries are rejected. Bind the app to loopback
if DEEP should be its only remotely reachable content entrance.

## CLI requests

The request command reads bounded JSON from stdin. Body is canonical base64
(empty string for no body). Header names are lowercase. Header lists preserve
duplicate response fields such as Set-Cookie. Cookies and form data stay out
of command-line arguments.

~~~powershell
'{"method":"GET","headers":[],"body":""}' | .\bin\deep.exe request deep://demo.local/ --config .\app-identity\client.json --info
~~~

Stdout contains the verified body. With --info, stderr contains media_type,
size, sha256, security, status, and headers. Application 4xx/5xx statuses are
valid responses, not CLI transport failures. The CLI does not store cookies
or follow redirects. Treat response metadata as potentially sensitive.

For older remote V2 servers, only GET can fall back to FETCH after an explicit
UNSUPPORTED_OPERATION response before upload. A failed application write is
never retried automatically: its side effect may already have happened.

## Wire extension

Protocol version 2 and ALPN deep/2 stay unchanged. Original FETCH conversations
retain their layout. Older servers reject EXCHANGE before receiving its upload.
New frame type **CONTINUE = 9** has a nonzero request ID, JSON metadata, no body.

After the existing authenticated HELLO/WELCOME:

1. Client sends the original four-field REQUEST: authority, path, query, and
   operation set to EXCHANGE.
2. Server validates the request and sends CONTINUE:
   {"profile":"app/1","max_body":1048576}.
3. Client sends another REQUEST with the same ID:
   {"method":"POST","headers":[{"name":"content-type","value":"application/x-www-form-urlencoded"}],"size":8}.
4. Client sends DATA chunks and END with exact size and lowercase SHA-256.
   Even an empty body sends END. The entire upload is verified before the
   application handler runs.
5. Server sends RESPONSE with status, headers, media_type, and size, then DATA
   and END. The viewer verifies the complete response before rendering it.

Operations use strictly increasing IDs; sessions remain sequential. Existing
deadlines, rate limits, authentication, and strict JSON rules apply. Invalid
framing/schema/integrity aborts the exchange.

Methods: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS. GET/HEAD requests have no
body. HEAD responses have no body. Status is an integer 200–599.
Maximum request body: **1 MiB**. Maximum response: **16 MiB**, or a lower configured
limit. Header lists: at most 64 entries, lowercase ASCII token names of 1–64
bytes, printable ASCII values up to 4096 bytes each, and aggregate name/value
length at most 6144 bytes. Serialized metadata must also fit the existing
8192-byte frame limit. The static provider supports GET/HEAD, rejects writes
with 405, and retains existing ERROR responses for missing files.

## Loopback provider

The connection destination is fixed. Proxy environment variables and backend
redirect following are disabled. Hop-by-hop, proxy, Host, Content-Length,
Accept-Encoding, and user-supplied forwarding fields are filtered. Host and
trusted X-Forwarded-Host identify the DEEP authority; X-Forwarded-Proto is deep.
Same-authority DEEP Origin/Referer values become HTTP backend-origin values.
Configure any proxy middleware deliberately.

Relative redirects stay relative. Absolute HTTP(S) redirects to the exact
upstream host:port or DEEP authority become deep://authority links. The server
never follows other redirect targets. Use relative URLs and Flask url_for;
hardcoded localhost URLs inside HTML/CSS/JavaScript are not rewritten.

Responses are bounded and buffered, with at most eight active upstream
responses. The backend must honor Accept-Encoding: identity. Applications
remain responsible for authentication, permissions, CSRF, and input validation.
Transport identity is not an application login.

## Viewer sessions and limits

The viewer has an in-memory cookie jar per exact authority and per window.
Secure/HttpOnly cookies, paths, expiry, deletion, and duplicate Set-Cookie
fields support Flask sessions. Parent-domain cookies are rejected. Closing
the window discards its sessions. Synthetic HTTPS cookie keys are internal;
they do not create HTTP network connections.

Managed cookies are not exposed through document.cookie. Frameworks requiring
JavaScript-readable cookies, third-party cookies, persistent logins, external
OAuth flows, or full browser SameSite/credentials-mode behavior need further
integration. Form token based CSRF and same-origin Flask sessions are supported.

The same-origin CSP allows form-action self. WebSockets, SSE/streaming, service
workers, cross-origin assets, and graphical downloads remain unsupported.
This is a bounded application profile, not complete browser compatibility or
an external security audit.

The viewer follows at most ten same-origin redirects. Document 307/308 redirects
preserve POST data in a one-use request scoped to the target document. Reloading
such a document issues GET. Fetch redirect/credentials modes are not fully emulated.

## Release 3.0.0 request handling

The optional loopback application provider validates path and query separately
and rejects GET/HEAD request bodies before contacting the backend. Each backend
request uses a fresh loopback connection to prevent the HTTP transport from
silently resubmitting an action after losing its response, including requests
with Idempotency-Key. The header is still delivered to the application.
A lost response remains an error; clients must not automatically retry writes.
This does not change DEEP's native transport or session reuse.
