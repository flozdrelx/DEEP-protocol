# DEEP 2.3 validation

Validated on Windows on 2026-10-01 with Go 1.27.1, .NET SDK 10.0.401,
WebView2 SDK 1.0.4258.31, and WebView2 Runtime 154.0.4258.48.

The complete Go test suites passed with the race detector for DEEP and HellNet,
with the built DEEP binary supplied to HellNet's integration tests. Static
analysis passed in both projects.

The viewer option process test confirmed:
- No preference file means disabled, and status does not create a file.
- browse/open-uri reject disabled launches.
- A verified app/1 request works with the viewer disabled.
- Direct DEEP.Viewer.exe launches also honor the preference.
- Enable/disable persists across processes using isolated test preferences.

Real renderer tests passed HTML/CSS/images/fonts, JavaScript modules, fetch,
navigation/reload, blocked external resources, and wrong-pin rejection.
The HellNet/Flask integration passed forms, 307/303 redirects, CSRF, session
cookies, login/reload/logout, and authenticated JSON with explicit viewer opt-in.

HellNet's process menu check verified the new option order, option 4 exiting,
the content-folder prompt, and invalid-port handling without creating a service.
A separate test confirms decorations do not enter JSON output.

All process tests used temporary identities/configuration/preferences and a
local relay. No public Cloudflare tunnel was created. Other operating systems,
a third-party browser, and public release signing were not exercised in this
update. Wire version 2 and app/1 were not changed.
