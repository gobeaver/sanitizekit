# go-beaver-tag-sanitization

A Go implementation of a safe user-content platform: users (and
LLMs acting on their behalf) author complete HTML/CSS pages, and
the platform renders them through a layered defense that treats
all input — human or model-generated — as untrusted.

Requires Go 1.25.6 or newer. `go.mod` also pins a `toolchain` floor so builds
pick up the current patched standard library.

```bash
go build ./...
go test ./...
```

## Layered defense

1. **HTML/CSS sanitization** (`usercontent/`) — allowlist parser
   profiles that strip `<script>`, event handlers, dangerous URL
   schemes, off-allowlist external resources, and unsafe CSS.
2. **CSP headers** — strict `script-src 'none'`, `frame-src 'none'`,
   `form-action 'none'`, `base-uri 'none'`, `default-src 'none'`.
3. **Origin isolation** — public pages are served from a dedicated
   user-content host that holds no session credentials.
4. **Sandboxed preview** — the editor embeds the preview in an
   `<iframe sandbox="">` with no `allow-scripts` / `allow-same-origin`.
5. **Declarative runtime** (`runtime/`) — the only JavaScript that
   ever runs on a user page is a hashed, shell-owned runtime that
   interprets reserved `data-gb-*` attributes. User content never
   becomes executable script.

Even if a sanitizer bug let something dangerous through, the CSP
and the declarative-runtime boundary are independent layers that
still stop it. See [`docs/security.md`](docs/security.md) for the
full threat model and [`docs/architecture.md`](docs/architecture.md)
for how the pieces fit together.

## Layout

```
.
├── usercontent/            The security core
│   ├── sanitizer.go        Sanitizer and New()
│   ├── profile.go          Profile, CSSPolicy, CSPPolicy, built-in presets
│   ├── report.go           Report, Removal
│   ├── errors.go           Sentinel errors
│   ├── charset.go          UTF-8 / NUL / control / bidi / invisible-char validation
│   ├── internal/html/       HTML tokenization + sanitization
│   ├── internal/css/        CSS parser + sanitization
│   ├── internal/csp/        CSP header builder
│   ├── config/              env-loaded Config -> Profile (keeps configkit
│   │                        out of the security core)
│   ├── profiles/            ProfileFullPage(), ProfileEmbed()
│   ├── corpus/               hand-curated XSS / CSS attack vectors
│   └── *_test.go, corpus_test.go, audit_test.go, fuzz_test.go
├── pageservice/             HTTP page service
│   ├── handlers/             /r/:slug, /preview/:slug, /api/save
│   ├── render/                shell template
│   ├── storage/               Page + MemoryStore
│   ├── drafts/                 signed preview tokens (HMAC)
│   ├── middleware/             host gate, credential stripping, draft headers
│   └── config.go                env-based configuration (configkit)
├── editor/                  Dashboard-side helpers
├── runtime/                 The trusted declarative runtime
├── cmd/
│   ├── pageservice/          the HTTP server entry point
│   ├── demo/                  minimal CLI showing direct sanitizer use
│   ├── corpusexport/          renders the corpus for the browser check
│   └── playground/            local web UI for trying the sanitizer
├── examples/                five runnable programs, start at 01-basic
├── browsertest/             differential check in Chromium, Firefox, WebKit
├── docs/
│   ├── architecture.md       how the layers fit together
│   ├── security.md            threat model, trust boundaries, testing methodology
│   └── maintenance.md         allowlist review process, spec-drift watchlist
├── SECURITY.md              how to report a vulnerability, and what counts as one
├── CONTRIBUTING.md          the rules that matter when changing a sanitizer
└── CHANGELOG.md
```

## Quick start

```bash
go build ./...
go test ./...
go run ./cmd/pageservice   # serves the page service on :8080
go run ./cmd/playground    # local UI for trying the sanitizer at :8081
go run ./cmd/demo          # one-shot CLI example
```

### Examples

Five runnable programs in [`examples/`](examples/), in the order worth reading
them: basic use, writing a custom profile (and watching seven attempts to
weaken it get rejected), reporting removals back to the author, the full
HTTP path, and the declarative runtime.

```bash
go run ./examples/01-basic
```

### Use the sanitizer from your own code

```go
import (
    "github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
    "github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

s, err := usercontent.New(profiles.ProfileFullPage())
if err != nil {
    log.Fatal(err)
}

html, report, err := s.SanitizeHTML(`<p>hi</p><script>alert(1)</script>`)
// html            == "<p>hi</p>"
// report.Modified == true
// report.Removed  contains the <script> removal
```

### Define a custom profile

```go
import "github.com/gobeaver/go-beaver-tag-sanitization/usercontent"

p := usercontent.Profile{
    Name:    "landing-v1",
    Version: 1,
    AllowedTags: []string{"h1", "h2", "p", "div", "a", "img"},
    AllowedAttrs: map[string][]string{
        "*":   {"class", "id"},
        "a":   {"href"},
        "img": {"src", "alt"},
    },
    URLSchemes:   []string{"https"},
    MaxHTMLBytes: 200 * 1024,
    MaxCSSBytes:  100 * 1024,
    MaxDOMDepth:  20,
    MaxDOMNodes:  2000,
    CSP: usercontent.CSPPolicy{
        DefaultSrc: "'none'",
        ScriptSrc:  "'none'",
        StyleSrc:   "'self'",
        ImgSrc:     "'self' data:",
        FrameSrc:   "'none'",
        FormAction: "'none'",
        BaseURI:    "'none'",
    },
}
s, err := usercontent.New(p) // returns an error if the profile violates an invariant
```

## Configuration

`pageservice` and `usercontent` load configuration from the
environment via [`configkit`](https://github.com/gobeaver/configkit),
never `os.Getenv` directly (enforced by `.golangci.yml`).

**`pageservice`** (prefix `BEAVER_PAGESERVICE_`):

| Env var | Default | Notes |
|---|---|---|
| `ADDR` | `:8080` | listen address |
| `PUBLIC_HOST` | `go-beaver.com` | required; the user-content host the `HostGate` middleware allows |
| `DASHBOARD_HOST` | `go-beaver.com` | allowed in CSP `frame-ancestors` |
| `READ_TIMEOUT` | `10s` | |
| `WRITE_TIMEOUT` | `10s` | |
| `IDLE_TIMEOUT` | `60s` | |
| `DRAFT_SECRET` | *(required)* | HMAC key for signed draft-preview tokens; at least 32 bytes, fails fast at startup if unset or short |
| `ADMIN_ADDR` | *(empty)* | second listener for the write API (`POST /api/save`). Empty disables the write API entirely. Must differ from `ADDR` |
| `SAVE_TOKEN` | *(empty)* | bearer token required on `POST /api/save`; at least 24 characters. Required whenever `ADMIN_ADDR` is set |

**`usercontent`** (prefix `BEAVER_USERCONTENT_`):

| Env var | Default | Notes |
|---|---|---|
| `PROFILE` | `fullpage` | `fullpage` or `embed` |
| `MAX_HTML_BYTES` | `307200` (300 KB) | |
| `MAX_CSS_BYTES` | `153600` (150 KB) | |
| `MAX_DOM_DEPTH` | `40` | |
| `MAX_DOM_NODES` | `5000` | |
| `ALLOW_DATA_IMAGES` | `true` | |
| `SHELL_NAMESPACE` | `gb-shell` | reserved id/class prefix for trusted components |
| `STRICT_NAMESPACE_COLLISIONS` | `false` | reject vs. rewrite on shell-namespace collision |
| `DATA_NAMESPACE_PREFIX` | `data-gb` | reserved `data-*` prefix for the declarative runtime |

Env-loaded limits and flags only ever *tighten* the selected
preset — they can never loosen it (see `Config.ToProfile()` in
`usercontent/config.go`).

## Running the service

`cmd/pageservice` binds two listeners, deliberately:

- **`ADDR`** serves the public, credential-free user-content origin — `/r/:slug`,
  `/preview/:slug`, `/report`. Nothing there writes, incoming `Authorization`
  and `Cookie` headers are stripped, and the `Host` header is gated.
- **`ADMIN_ADDR`** serves the editor-facing write API (`POST /api/save`) behind
  a bearer token. It is disabled unless both `ADMIN_ADDR` and `SAVE_TOKEN` are
  set, and must never be exposed to the public internet.

If you embed `pageservice/handlers` in your own binary, `Server.Authorizer`
must be set before `HandleSave` will accept anything — an unset authorizer
refuses every save rather than defaulting to open:

```go
srv.Authorizer = handlers.SaveAuthorizerFunc(func(r *http.Request, req handlers.SaveRequest) error {
    if !mySessionOwns(r, req.OwnerID, req.ID) {
        return handlers.ErrUnauthorized
    }
    return nil
})
```

`handlers.DefaultServer` and `handlers.AllowAllSaveAuthorizer` accept every
write and exist for development and tests only.

### Enabling the declarative runtime

`script-src` is `'none'` out of the box, so the runtime does not execute until
you allow its hash explicitly:

```go
p := profiles.ProfileFullPage()
p.CSP.ScriptHashes = []string{runtime.CSPHash()}   // becomes the script-src value
s, err := usercontent.New(p)
```

Embed `runtime.Runtime` verbatim; the hash covers exactly those bytes.

## Output guarantees

Whatever the input, the sanitizer promises:

- **Sanitized HTML is inert** — no script, no event handler, no
  `javascript:`/`vbscript:` URL, no forbidden element. Safe to insert via
  `template.HTML`.
- **Sanitized CSS never contains a literal `<`** — a `<` in a value is emitted
  as the CSS escape `\3c `, and a selector or at-rule prelude containing one is
  dropped. Sanitized CSS therefore cannot close the `<style>` element it is
  inlined into. Safe to insert via `template.CSS`.
- **Both are idempotent** — re-sanitizing sanitized output returns it unchanged.
  The fuzz targets assert this.
- **Errors carry no output** — a non-nil error always comes with an empty
  string, so mishandling the error cannot serve unverified content.
- **Every drop is reported** — content removed always produces a `Removal` in
  the `Report`, so the editor can tell the author what happened and why.

These are not claims resting on the package's own parser. `browsertest/` loads
every sanitized corpus vector in Chromium, Firefox and WebKit — twice, once
with the production CSP and once with **no** CSP — and fails if anything
executes, fetches, or navigates. The no-CSP pass is the important one: the
layers are meant to hold independently, so a sanitizer failure must not be
masked by a response header.

The security core's dependency surface is part of the contract too:
`usercontent` imports nothing but `golang.org/x/net/html`, enforced by
`make deps-core` in CI. The sanitization internals live under
`usercontent/internal/`, so the guarantees cannot be sidestepped by importing
past `usercontent.New`.

## Testing

```bash
go test ./...                                     # everything
go test ./usercontent/...                          # the security core only
go test -run Corpus ./usercontent/                  # corpus regressions only
go test -race ./...                                  # race detector
go test ./usercontent/ -run '^$' -fuzz FuzzSanitizeHTML -fuzztime=60s   # fuzz (slow)
go test ./usercontent/ -run '^$' -fuzz FuzzSanitizeCSS  -fuzztime=60s
make browsertest                                    # real browser engines
make golden                                          # re-pin profile output
```

`usercontent/corpus/` holds hand-curated XSS and CSS attack
vectors; every built-in profile must neutralize all of them, and
`corpus_test.go` asserts this against the *parsed* output tree
(not a substring match, which is spoofable by safely-escaped text
that happens to contain a banned word).

`usercontent/audit_test.go` is a standing regression suite: each
test traces back to a specific finding from an earlier security
review and stays in the suite permanently so the same class of bug
can't silently return.

Also available via `make`:

```bash
make check        # fmt + vet + deps-core + test + lint
make ci           # the full gate, as CI runs it
make sec          # gosec + govulncheck only
make browsertest  # Chromium/Firefox/WebKit differential check
make fuzz-long    # an hour per fuzz target
make deps-core    # assert the core's dependency surface
```

## Non-negotiable invariants

The `usercontent` package enforces these at construction time — a
profile that tries to weaken any of them is rejected by `New()`,
not silently accepted:

- No `<script>`, `<iframe>`, `<frame>`, `<frameset>`, `<object>`,
  `<embed>`, `<applet>`, `<form>`, `<input>`, `<button>`,
  `<select>`, `<textarea>`, `<link>`, `<meta>`, `<base>`, `<style>`,
  `<svg>`, `<math>`, `<video>`, `<audio>`, `<dialog>`, `<slot>`,
  `<template>`, `<noscript>`, `<noframes>`, `<noembed>`,
  `<marquee>`, `<details>`, `<keygen>`, and similar.
- No `on*` event-handler attributes, `style`, `formaction`,
  `action`, `srcdoc`, `xlink:href`, `background`, or other
  legacy script-adjacent attributes.
- No `javascript:`, `vbscript:`, or `data:text/html` URL schemes.
- No `@import`, `@charset`, `@namespace` in CSS.
- No `expression()`, `behavior()`, `-moz-binding()` in CSS.
- No attribute selectors by default (CSS-based exfiltration
  defense).
- CSP `script-src` must be `'none'` or an explicit hash list; CSP
  `default-src`, `frame-src`, `form-action`, and `base-uri` must
  include `'none'`.

The package's central claim: **safety is not a convention
consumers have to remember — it is unrepresentable in the API.**

## Sharp edges

- **SVG** is disallowed both inline and as an upload; SVG is a
  script container.
- **Mutation XSS**: output is rebuilt from the token stream, never
  produced by string-replacing the input, and foreign-content
  containers (`<svg>`, `<math>`, `<template>`) are stripped
  outright. Every result is then re-parsed and re-checked before
  being returned; if a forbidden element or attribute somehow
  survived, `SanitizeHTML` fails closed with `ErrUnsafeOutput`
  rather than returning it.
- **Character/encoding policy**: invalid UTF-8, NUL bytes, control
  characters, bidi overrides, and invisible/format characters
  (except ZWNJ/ZWJ, which some scripts require) are rejected
  outright rather than repaired — see `usercontent/charset.go`.
- **CSS/HTML id collisions**: the shell namespace (`gb-shell-*` by
  default) is reserved for trusted platform components; user
  ids/classes that start with it are rewritten, or rejected if
  `StrictNamespaceCollisions` is set.
- **Two built-in profiles, two different jobs**: `ProfileFullPage`
  is for a complete user-authored page; `ProfileEmbed` is for
  user content embedded inside an otherwise-trusted page and is
  held to the *same* UI-redressing restrictions (no `position`,
  `z-index`, or `pointer-events` in CSS) even though its tag/attr
  vocabulary is smaller. If you add a third profile, add it to
  `usercontent/audit_test.go`'s CSS-declaration coverage too.
- **Go templates**: user content is always data, never template
  source. `pageservice/render` is the only `template.Parse`
  boundary in the service, and it wraps pre-sanitized HTML/CSS in
  `template.HTML` / `template.CSS` explicitly rather than
  re-escaping it.

## Security

**Reporting:** see [SECURITY.md](SECURITY.md). Please do not open a public
issue for a vulnerability.

See [`docs/security.md`](docs/security.md) for the full threat model, trust
boundaries and testing methodology, and [CHANGELOG.md](CHANGELOG.md) for the
findings fixed in each release.

`make ci` runs the same gate as CI: vet, race tests, lint, `gosec` and
`govulncheck`.