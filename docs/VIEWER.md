# DEEP website viewer

DEEP 3.0.0 provides an opt-in Windows viewer with the app/1 profile.
Use DEEP's optional application provider for local port hosting; native content folders remain supported.
See [application hosting](APPLICATIONS.md) for forms, sessions, and limits.
The CLI, protocol library, and servers remain available on Windows, Linux, and
macOS. This first graphical viewer is Windows-only.

## Enable the optional viewer

The viewer is disabled by default. Install its files, then run:

~~~powershell
.\bin\deep.exe viewer enable
~~~

Use viewer status to check it and viewer disable to turn it off for new
launches. Direct launches of DEEP.Viewer.exe respect the same setting.
These commands do not change URI-handler ownership or network configuration.
Other browsers and programs use DEEP without this viewer; see
[the integration guide](INTEGRATION.md).

## Open a site

On your configured Windows installation, click a registered deep:// link, paste
one into Windows Run, or start the viewer:

~~~powershell
.\bin\deep.exe browse
.\bin\deep.exe browse deep://node.network/
.\bin\deep.exe browse deep://node.network/ --config .\node\client.json
~~~

You can also open bin/viewer/DEEP.Viewer.exe directly. Keep that whole folder
beside deep.exe. The viewer reads bin/config.json by default. Back, Forward,
Reload, Home, Ctrl+L, and F5 are available. There is no browser proxy to configure.

Register links after building/copying the viewer:

~~~powershell
.\scripts\register.ps1 -Executable .\bin\deep.exe
~~~

The script upgrades the existing terminal handler belonging to that same DEEP
executable. It still refuses to replace another application's handler without
an explicit -ReplaceExisting. The registered command calls deep.exe open-uri; the received URI is a separate
argument and the dispatcher checks the viewer setting on every launch.

The open-uri dispatcher launches the viewer only when enabled. When disabled,
it returns an error without fetching content. The explicit preview command
selects an escaped terminal preview on supported CLI platforms.

## A local website in two terminals

From the DEEP project directory:

~~~powershell
.\bin\deep.exe init --authority demo.local --dir .\node-web --address 127.0.0.1:9761
Copy-Item -Path .\examples\website\* -Destination .\node-web\content -Recurse
.\bin\deep.exe serve --config .\node-web\server.json
~~~

In the second terminal:

~~~powershell
.\bin\deep.exe browse deep://demo.local/ --config .\node-web\client.json
~~~

This uses a private local node and its generated client identity. The sample
contains HTML, CSS imports, an SVG image, JavaScript modules, relative links,
and a same-origin JSON fetch. No public tunnel or HTTP content server is needed.

## Use a network provider

Open a deep://node.network/ link using a direct adapter or the optional generic
proxy. A proxy has no default address; explicitly set the chosen provider's
IP:PORT with deep proxy set --address IP:PORT. Provider-specific discovery and
connection steps belong to that provider. See [native proxy configuration](DEEP-PROXY.md).

## Supported content

- HTML pages and relative links, including fragments.
- Stylesheets, CSS imports, images, and fonts.
- JavaScript and ES modules from the same DEEP site.
- Same-origin fetch requests for resources such as JSON.
- Directory URLs ending in /: index.html first, then index.txt for older nodes.
- Valid query strings on the file provider, such as style.css?v=2, are ignored
  for file selection. Custom protocol handlers still receive the original query.
- Predictable MIME types for HTML, CSS, JavaScript, JSON, SVG, and web fonts.

Application hosts support GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS, forms, JSON,
redirects, and in-memory login cookies. Cookies are isolated per authority and
window, discarded on close, and not exposed through document.cookie.
WebSockets, streaming/SSE, service workers, workers, frames, pop-up windows, and
embedded objects remain unsupported.
Cross-origin resources and external HTTP/HTTPS assets are blocked: store the
site's dependencies in its own app or content folder. Scripts that require eval or
Function constructors need changes because the viewer's CSP does not allow them.
User-clicked deep:// links targeting a new window open in the current window.

## Security and limits

The viewer starts the installed DEEP client with an argument list, without a
shell or page-accessible native bridge. Each fetch uses existing certificate
pins, network adapters, TLS 1.3, hybrid ML-KEM-768, and ML-DSA-65 authentication.
The renderer receives a resource only after a successful complete transfer and
size/hash verification. No certificate-warning bypass is offered.

WebView2 keeps different deep:// authorities as distinct origins. The app applies
a Content Security Policy, denies device/clipboard permission requests, blocks
local-file navigation and external web navigation, disables native host objects
and web messages, and uses an InPrivate browser profile. Script dialogs and
automatic downloads are disabled. Use deep fetch --output to save a file.

These are application protections, not an anonymity claim or an external audit.
WebView2 is a separately maintained browser runtime, with its own OS integration
and update behavior. Keep it updated. The viewer profile does not change
a network provider's transport or hide network metadata.

Per window: six concurrent fetch processes, 16 MiB per resource, 128 MiB and 512
resource requests per top-level navigation, and a 30-second fetch deadline
including queue time. DEEP servers enforce their own independent rate and size
limits; a very asset-heavy page may need server policy changes. Large downloads
should use the CLI. This version verifies resources in memory before rendering
and does not implement streaming media or byte ranges.

## Build

Install Go 1.27.1 or newer and the .NET 10 SDK, then run:

~~~powershell
.\scripts\build.ps1 -WithViewer
~~~

The viewer is published with its .NET runtime, so users do not need the .NET SDK
or a separately installed .NET runtime. It does require the
[Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).
The project pins the WebView2 SDK package and commits its NuGet lock file.
The default viewer build is Windows x64; build-viewer.ps1 -Runtime win-arm64
can publish ARM64 into a separate output directory for native testing.

The existing scripts/release.py creates CLI archives and a source archive;
it does not silently add desktop runtimes to cross-platform CLI archives.
For a Windows desktop distribution, include the built bin/deep.exe, complete
bin/viewer directory (including notices), and project documentation/licenses.
Never include bin/config.json, node credentials, or your WebView2 user profile.

## Automated renderer verification

Requires Windows, an installed WebView2 Runtime, and Python:

~~~powershell
python -B scripts/test-viewer.py --report "$env:TEMP\deep-viewer-result.json"
~~~

Choose a new report filename each run. The test starts a temporary private DEEP
node, uses generated identities, checks actual rendered styles/images/fonts,
modules, fetch, navigation, blocking policies, and rejection of a wrong server
pin. It saves a page screenshot beside the report and stops its own processes.
Its font fixture is copied temporarily from the Windows font installation and
is not included in project or release artifacts.

See [viewer validation](VALIDATION-VIEWER.md) for the checks performed for this
update.
