# DEEP 2.1 viewer validation

Verified on Windows x64 on September 29, 2026.

## Completed checks

- 76 top-level Go tests and 284 passing test events including subtests; no
  failures or skips, with the race detector enabled. Go 1.27.1.
- Go static analysis passed. Five independent Python interoperability tests passed.
- The official Go vulnerability scanner reported no vulnerabilities.
- NuGet's dependency advisory check reported no vulnerable viewer packages.
- The Windows viewer published successfully with the pinned WebView2 SDK
  1.0.4258.31 and a self-contained .NET 10 runtime. The locked build script
  also copied dependency licenses into the portable output.
- The real WebView2 renderer (153.0.4234.48) opened a temporary private DEEP
  website with an HTML document, CSS import, SVG image, font, JavaScript module
  import, and same-origin JSON fetch. Actual rendered styles and font decoding
  were checked, not just the presence of fetched files.
- Relative-link navigation, Back, Forward, Reload, and a missing-resource error
  page passed. HTTPS, file, cross-origin resource fetches, and POST requests
  were rejected by the browser profile.
- A separate renderer run with the wrong DEEP certificate pin displayed an error
  and exposed no verified page content to the renderer.
- The website and its assets also rendered through the unchanged HellNet 3.0.0
  adapter, using separate temporary host/client settings and a local WebSocket
  relay. Existing user identities and configuration were not used by that test.
- Source archive selection includes viewer code, its lock file, and the sample
  website while excluding viewer build output.

The wire version remains 2. CLI and HellNet adapter compatibility were retained.
The HTML directory index and static-query changes belong to the file provider,
not to the DEEP message framing or cryptographic profile.

## Reproduce

Build the CLI and viewer, then follow the automated test instructions in
[the viewer guide](VIEWER.md). Reports include resource URLs and a screenshot of
the rendered sample page. Test servers and their generated identities are
temporary. Keep reports private if adapting the test to real sites.

## Scope

The desktop runtime was executed on Windows x64 only. CI includes a Windows
viewer build, but no remote CI success is claimed here. No new public Cloudflare
test was necessary for this update; the HellNet transport was unchanged and
the viewer integration test used its local relay.

This is a static-site browser profile, with client-side scripting and resource
fetching. It does not add server-side forms, authentication sessions, uploads,
or live application channels. These checks are not an external security audit.
