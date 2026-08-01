# Steam Desktop Authenticator — Tauri build

A rewrite of the tkinter app on Tauri 2 (Rust backend, WebView2 frontend).
The Python version in the parent folder still works and is untouched; both read
the same `maFiles` folder, so you can run either.

## Running it

```
npm install                 # once
npm run tauri dev           # develop
npm run tauri build         # release installer
cd src-tauri && cargo test  # 19 tests
```

Needs Rust (installed) and WebView2 (already on Windows 11). The release binary
is **8.5 MB**; the same app on Electron would ship a private Chromium and Node
and land north of 150 MB.

`npm run tauri build` produces two artifacts:

| Artifact | Path |
| --- | --- |
| Portable exe | `src-tauri/target/release/sda-tauri.exe` |
| Installer | `src-tauri/target/release/bundle/nsis/…_x64-setup.exe` |

### Finding maFiles from anywhere

A portable build run from Downloads, or an installed copy under Program Files,
is nowhere near your account files, and the automatic search only walks up from
the executable. Two things close that gap:

- The search also checks any folder **on the Desktop** that contains a
  `maFiles` child, so a build run from anywhere still finds them.
- Whichever folder the accounts actually loaded from is remembered, so picking
  one via **Settings → Open folder** sticks across launches.

## Why Tauri and not Electron

This app holds `shared_secret` and `identity_secret` — permanent Steam 2FA
credentials — which makes the runtime's attack surface the deciding factor.

- **Electron** runs Node in the renderer process. Anything that achieves script
  execution in the UI gets the filesystem with it, and the npm dependency tree
  becomes supply chain surface for a process that reads your 2FA secrets.
- **Tauri** keeps secrets in Rust. The webview only receives what an explicit
  `#[tauri::command]` returns, and this app's commands return finished codes and
  account metadata — never a secret. `mafile::AccountView` exists precisely so a
  secret cannot be serialised to the frontend by accident, and a test asserts it.

The webview is the OS WebView2, so Chromium security updates arrive through
Windows Update rather than needing a new build of this app for every CVE.

Capabilities are narrowed in `src-tauri/capabilities/default.json` to file-open
dialogs and clipboard write. A strict CSP is set in `tauri.conf.json` — the
scaffold ships `"csp": null`, which disables it.

## Layout

| Path | Purpose |
| --- | --- |
| `src-tauri/src/totp.rs` | Steam Guard code generation, confirmation keys, device IDs. |
| `src-tauri/src/mafile.rs` | `.maFile` reading, including SDA's AES-256-CBC at-rest format. |
| `src-tauri/src/enroll.rs` | Login, RSA password encryption, AddAuthenticator, Finalize. |
| `src-tauri/src/lib.rs` | App state and the IPC command surface. |
| `src/` | Frontend: one HTML file, one stylesheet, one script. No framework. |

## What's verified

`totp.rs` is pinned to the same vectors the Python was, which were themselves
cross-checked against an independent .NET HMAC-SHA1. The Rust produces
identical codes for identical inputs, so the port is provably equivalent rather
than merely plausible. The maFile tests cover an encrypted round trip against
SDA's exact PBKDF2/AES parameters, and `enroll.rs` round-trips password
encryption against a real 2048-bit key.

Two bugs surfaced during the port and are fixed:

- Steam answers a POST with no `Content-Length` with **HTTP 411**, which broke
  time sync. reqwest omits the header for an empty form, so `call()` now encodes
  the body itself and sets the length explicitly.
- The code rendered left-aligned: a `<button>` is inline-block, so
  `text-align: center` centred text inside a shrink-wrapped box.

**Still unverified:** the live enrollment conversation with Steam, exactly as in
the Python version — it needs real credentials and a real SMS code. The Python
implementation it was ported from *is* known to work against live Steam, which
makes this a port of a verified reference rather than a fresh guess, but treat
the first run as the real test and keep the revocation code to hand.

## Layout

A collapsible sidebar and a main pane, which is the shape this app wants: the
account list is a permanent left-hand fixture rather than something hidden
behind a dropdown, and it scales past two accounts.

| Section | What it holds |
| --- | --- |
| **Codes** | The live code for the selected account, countdown, copy, auto-copy. |
| **Account** | Account name, SteamID, device ID, file path, and the revocation code behind a Reveal. |
| **Settings** | Theme, auto-copy, Steam clock offset, maFiles folder. |

Adding an authenticator stays a modal dialog — it is a linear flow with a point
of no return, not somewhere you browse to.

The sidebar collapses to a 66px icon rail, remembered between runs. The toggle
stays visible when collapsed; hiding it would leave no visible way back.

The revocation code is masked until you press Reveal. It is the account's
recovery secret and this window may well be on a stream or a shared screen.

### Confirmations: built, parked

Trade and market confirmations are **implemented but disabled**, because Steam
will not grant this app a `steamcommunity.com` session. Verified directly, not
assumed — with a valid unexpired refresh token (`aud` includes `renew`, ~200
days left):

| Attempt | Result |
| --- | --- |
| `IAuthenticationService/GenerateAccessTokenForApp` | EResult 15 AccessDenied (three parameter shapes) |
| `login.steampowered.com/jwt/finalizelogin` | error 15 |
| Refresh token used directly as `steamLoginSecure` | `needauth: true` |

The likely reason is that the token minted during enrollment is scoped to the
mobile client and is not accepted for creating a web session. Finishing this
needs the app to perform its own web login — password plus a Steam Guard code
it can now generate itself — which also means asking for a password outside
enrollment, so it was left as a decision rather than done quietly.

What exists and is tested: `confirmations.rs` (request signing, the
`list`/`accept`/`reject` tags, response parsing across old and new Steam
shapes, error handling) plus the full UI section. The nav entry is commented
out in `index.html` — a nav item that cannot work is worse than no nav item.
Uncomment it to bring the section back.

## Themes and glass

The header button flips between light and dark, always against what is on
screen, and its icon shows what the click will give you. **Follow system** is a
real third state but lives in the ⋯ menu rather than the click cycle.

That split matters. Cycling system → light → dark reads as a broken button:
when "system" resolves to the theme you are already on, that click changes
nothing visible, so going dark → light appeared to need two presses while
light → dark worked first time. A control that sometimes does nothing is a bug
even when the state underneath is correct.

Only an explicit choice is stored, so "follow system" keeps tracking Windows
after a restart, and the native title bar is kept in step via `setTheme`.

Glass needs tonal variation behind it or the panels read as flat rectangles, so
the page paints a neutral wash — a broad light from above, a shadow toward the
floor — and every panel is a translucent layer blurred over it. The wash is
deliberately hueless; an earlier version used coloured blobs and they read as
decoration on a utility app.

That makes contrast the hard part: text sits on a *composite* of base → wash →
panel, and the wash varies across the window. `check-contrast.py` reads the
tokens straight out of `styles.css`, models that layer stack, and checks every
text colour against **both extremes** — the lit top and the shaded floor.
Passing both means passing everywhere between. Run it after touching any colour:

```
python check-contrast.py
```

Two findings worth keeping:

- **Dark glass must be dark.** The obvious recipe — white at ~7% alpha — barely
  tints, so whatever is behind bleeds through; with the old coloured field that
  put mid-tone text at 2.4–3.5:1. Dark mode uses a *dark* translucent panel with
  a light border, keeping the composite in a narrow band. Everything now clears
  4.5:1 in both themes, worst case 5.39:1.
- **The progress fill animates `width`, not `transform: scaleX`.** Scaling left
  a 1px seam of stale colour along the track's top edge (pixel-verified: one row
  ran to x=360 while the fill ended at x=281) and squashed the pill cap
  horizontally. The bar is 6px tall, so laying it out per frame costs nothing.

High contrast mode drops the glass entirely — `backdrop-filter` is the one
thing `forced-colors` cannot rescue, since blur survives but contrast does not.

## Motion

Every animation is meant to say something; nothing loops and nothing moves for
decoration. All of them sit in the 150–300ms band, and exits are quicker than
entrances — leaving should feel like getting out of the way, arriving like
settling into place.

| Motion | Duration | What it says |
| --- | --- | --- |
| Card rise-in | 300ms | the app is ready |
| Code slide-in | 260ms | *this is a new code* — the one animation carrying real information |
| Copy pop | 260ms | the click registered |
| Dialog / menu in | 220 / 160ms | this surface came from somewhere |
| Dialog out | 150ms | faster than its entrance |
| Wizard step | 250ms | forward progress, matching the stepper |
| Theme cross-fade | 260ms | the switch was deliberate, not a flicker |

The code animation fires only on a genuine 30-second rotation — not on first
paint and not when you switch accounts, where movement would imply something
that didn't happen.

Everything animates `transform` and `opacity` so it runs on the compositor. The
one exception is the progress fill, which animates `width`: normally an
anti-pattern, but `transform: scaleX` left a 1px seam of stale colour along the
track's top edge and squashed the pill cap, and the bar is 6px tall.

The theme cross-fade is applied only for the 320ms of the switch. Leaving that
transition on permanently would blunt every hover in the app.

All of it is disabled under `prefers-reduced-motion` — verified by forcing the
media query on and confirming every duration collapses to 0.001ms, rather than
assuming the cascade works.

## Accessibility

The tkinter build needed hand-written focus rings, keyboard handlers and a
contrast audit because canvas-drawn controls have none of it. On the web
platform most of that is native, and the CSS opts into the rest:

- Real `<button>` elements: tab order, Enter/Space and screen-reader roles for
  free. `:focus-visible` gives a keyboard-only focus ring.
- `@media (prefers-reduced-motion: reduce)` disables transitions and drops the
  countdown from per-frame animation to a once-a-second tick.
- `@media (forced-colors: active)` hands over to the Windows High Contrast
  palette — the one accessibility item the tkinter build never covered.
- The palette is the audited one from the Python build, where every text pair
  cleared 4.5:1 and control outlines 3:1.

The countdown animates from a timestamp the backend returns, so the smooth bar
costs one IPC call per 30-second rotation rather than one per frame.
