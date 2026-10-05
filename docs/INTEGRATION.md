# Integrating DEEP 3.0.0 into a browser or program

DEEP is a protocol backend. Its Go library, server, resource client, application
requests, identity validation, and network adapters work without WebView2, .NET,
or the bundled viewer. Version 2.3 retains wire version 2, ALPN deep/2, app/1,
and existing network configuration and keys.

The optional Windows viewer is a separate reference frontend. It is disabled
by default, including when its files are installed. An enabled viewer setting
does not affect backend requests, authentication, or which app owns deep:// links.

## Command-line integration (any language)

Launch deep.exe directly using an argument array and pipes, without a shell:

~~~text
deep request deep://node.network/path --config /absolute/client.json --info
~~~

Write one JSON object to stdin, then close stdin:

~~~json
{"method":"GET","headers":[],"body":""}
~~~

For a form or JSON request, set method, lowercase headers, and a canonical
base64 body. Headers use a list to preserve repeated response fields. See
[app/1](APPLICATIONS.md) for exact methods, sizes, and protocol semantics.

On successful transport, stdout contains the verified body and stderr contains
one JSON result with status, headers, media_type, size, sha256, and security.
An application 404 or 500 is still a valid response: inspect status. On a
nonzero process exit, discard output; stderr is a human-readable diagnostic,
not a successful JSON result. Version 2.3 does not promise machine-readable
error codes for all CLI failures.

A minimal Python integration, without the viewer:

~~~python
import json
import subprocess

result = subprocess.run(
    [
        r"C:\Tools\DEEP\bin\deep.exe", "request", "deep://node.network/",
        "--config", r"C:\Tools\DEEP\bin\config.json", "--info",
    ],
    input=json.dumps({"method": "GET", "headers": [], "body": ""}).encode(),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout=35,
    check=False,
)
if result.returncode != 0:
    raise RuntimeError(result.stderr.decode("utf-8", "replace"))
metadata = json.loads(result.stderr)
body = result.stdout
print(metadata["status"], metadata["media_type"], len(body))
~~~

For a browser integration, intercept deep:// requests in your browser engine,
forward the method, permitted headers, and body, then create a renderer response
from the verified status, headers, and body. The frontend owns cookies,
redirects, history, permissions, same-origin rules, and rendering. Do not route
unknown DEEP authorities through HTTP as a fallback. Cookies and credentials
belong on stdin, never in process arguments or routine logs.

Keep request and response pipes bounded and drained concurrently. Terminate
the process on cancellation or when the calling tab closes. Do not automatically
retry writes after timeout or connection loss: the action may have completed.
Request uploads are at most 1 MiB and app/1 responses at most 16 MiB.

The separate fetch command supports larger finite resources, but its stdout is
streamed before final integrity verification. Use request for bounded verified
rendering, or buffer fetch output until successful exit and verified completion.
For saved files, fetch --output publishes only a completed verified download.

A frontend can use direct adapters without any other application, or select
one generic native proxy with deep proxy set --address IP:PORT. There is no
default address or provider and no network selector. The proxy decides which
authorities it can route. See [Proxy/1](DEEP-PROXY.md). Enabling the bundled
viewer is never a requirement.

## Go library

Go programs can use the root deepprotocol package directly: LoadClientConfig,
Client.Exchange/Fetch, and Client.Dial for reusable Session.Exchange/Fetch.
Honor context cancellation, the session's single active operation rule, and
response limits. Custom applications implement ApplicationHandler; networks
implement the resolver/transport contracts. Until a published Go module path is
configured, use a local module replacement pointing at this checkout.

## Optional reference viewer

~~~powershell
.\bin\deep.exe viewer status
.\bin\deep.exe viewer enable
.\bin\deep.exe browse
.\bin\deep.exe viewer disable
~~~

Status accepts --json and returns version (1), enabled, available, and settings.
Enable requires the companion viewer to be installed on Windows. Backend-only
builds need neither the viewer files nor its runtime. Build the optional
companion with scripts/build.ps1 -WithViewer, then enable it explicitly.

The preference is per OS user at the user configuration directory's
DEEP/viewer.json (on Windows, %APPDATA%\DEEP\viewer.json). It is separate from
network config.json and applies across that user's DEEP installations. Missing
preferences mean disabled. Invalid preferences block viewer launches and do not
affect backend operations. Disable affects new launches; it does not forcibly
close an already open viewer.

Direct launches of DEEP.Viewer.exe also check the preference through the backend.
The bundled viewer is not a service that other browsers need to run.

## URI handler ownership

Enabling or disabling the viewer does not register a URI handler. Your browser
can register itself as the deep:// handler through its own installation/settings.

DEEP's optional Windows register.ps1 registers deep.exe open-uri, which honors
the viewer setting on each launch. It refuses to replace an unrelated handler
unless explicitly run with -ReplaceExisting. A previous direct-viewer handler
belonging to the same DEEP installation can be migrated safely. -WhatIf previews
registration without changing the registry.

When the viewer is disabled, browse/open-uri return a clear error without
fetching the link. The explicit preview command still provides a terminal
resource preview. DEEP never launches a different browser implicitly.
