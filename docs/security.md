# Security

This document summarizes the security model and lists the
specific threats the platform is designed to resist.

## Threat model

| Threat | Vector | Mitigation |
|--------|--------|------------|
| Stored XSS | User submits `<script>` in HTML | Allowlist sanitizer + CSP `script-src 'none'` |
| Reflected XSS | Stored XSS served to other users | Same as above; output is escaped input is not |
| DOM XSS | User-modified JS in the app | The app never runs user JS; the runtime is a closed, hashed blob |
| Mutation XSS | Sanitizer output re-parsed differently by browser | Output is rebuilt from the token stream, never string-replaced; foreign-content containers (`<svg>`, `<math>`, `<template>`) are stripped; the result is then re-parsed and re-checked before being returned |
| JavaScript URL | `href="javascript:..."` | URL validator rejects `javascript:`, `vbscript:`, `data:text/html` regardless of case/whitespace |
| Event handler | `onclick="alert(1)"` | Stripped unconditionally |
| External resource | `<img src="https://evil.com/x">` | Asset prefix allowlist + CSP `img-src 'self' data:` |
| CSS exfiltration | `input[value^="a"] { background: url(...) }` | Attribute selectors disallowed by default; CSP `font-src`/`img-src` block leakage |
| `@import` | External CSS fetched on render | `@import` always rejected; CSP blocks external styles |
| `expression()` | Legacy IE CSS | Function always rejected |
| Form exfiltration | `<form action="evil.com">` | `<form>` always forbidden; CSP `form-action 'none'` |
| Clickjacking | Page framed by attacker | CSP `frame-ancestors 'self'`; `X-Frame-Options` (optional) |
| CDN compromise | External `<script>` | `script-src 'none'`; no external script paths |
| CSRF | State-changing request from attacker origin | `SameSite` cookies + the editor flow uses tokens, not sessions |
| Phishing | User page looks like a login page | No forms; moderation/report-abuse link in shell |
| SVG script | `<svg onload="alert(1)">` | `<svg>` always forbidden |
| `<base>` hijack | `<base href="https://evil.com">` | `<base>` always forbidden |
| Refusal to render | Browser refuses to apply CSP | Modern browsers support CSP; we test on Chrome, Firefox, Safari |
| Unicode/encoding | `Java\x00script:`, `&#106;avascript:` | URL parser normalizes; HTML entity decoder is the browser's |
| Encoding trick | `JaVaScRiPt:alert(1)` | URL parser lowercases scheme |
| Whitespace in scheme | `java\tscript:alert(1)` | URL parser normalizes whitespace |
| Data URL smuggling | `data:text/html,<script>alert(1)</script>` | `data:` URLs restricted to `data:image/(png|jpeg|webp|gif)` |
| Fragment-only | `<svg><script>alert(1)</script></svg>` | `<svg>` and `<script>` both forbidden; skipped subtree propagates through tokenizer |
| Profile tampering | User-supplied profile that allows script | `New()` rejects the profile at construction time |
| `<style>` breakout | `</style><img src=x onerror=alert(1)>{color:red}` in user CSS | Sanitized CSS never contains a literal `<`: values escape it as `\3c `, selectors and at-rule preludes are validated against a character allowlist that excludes it, and `Sanitize` fails closed if one reaches the output |
| Tabnabbing | `<a rel="opener" target="_blank">` | The required `noopener noreferrer nofollow ugc` tokens are merged into the author's `rel`; `opener` is dropped |
| Asset allowlist bypass via `srcset` | `srcset="/ok.png 1x, https://evil.com/x.png 2x"` | Every candidate URL is validated separately |
| Serving unverified output | Caller ignores the sanitizer's error | A non-nil error always comes with an empty string; there is no partial output to mishandle |
| Draft token forgery | Guessed or brute-forced preview token | HMAC-SHA256 over a versioned payload with a key of at least 32 bytes; the page ID is base64url-encoded so it cannot collide with the separator |
| Unauthenticated writes | `POST /api/save` from anywhere | Refused unless the application supplies a `SaveAuthorizer`; body size, host and slug are all validated; `cmd/pageservice` serves it on a separate token-gated listener |

## Trust boundaries

1. **Untrusted input**: user prompt, user-pasted HTML/CSS, LLM-
   generated HTML/CSS.
2. **Untrusted at rest**: `raw_html` / `raw_css` columns. Editor
   only.
3. **Trusted at rest**: `sanitized_html` / `sanitized_css`
   columns. The only thing served.
4. **Trusted at runtime**: the shell, the URL routing, the
   CSP, the iframe sandbox.
5. **Trusted at the page**: the runtime JS (hashed,
   built-in).

The sanitizer is the only path from 1 to 3. Every other transit
between layers is in-process.

## Defense in depth

The CSP alone blocks:
- script execution (even via `<script>` that survived
  sanitization)
- external stylesheets
- external fonts
- form submissions
- `<base>` URL hijacking
- Iframe embedding by other origins
- Pointer events to sensitive APIs

If the sanitizer, the URL validator, and the host gate all
failed simultaneously, the CSP still produces a static document
with no script, no network, no forms.

## Security invariants

The `usercontent.Profile` struct enforces these at compile time
(via `validate()` in `New()`):

```go
// Never allowed by any profile:
script, iframe, frame, frameset, object, embed, applet,
form, input, button, select, textarea, link, meta, base,
style, svg, math, video, audio, dialog, slot, template,
noscript, noframes, noembed, marquee, details, keygen, ...

// Never allowed by any attribute:
on*, style, formaction, action, srcdoc, xlink:href, background,
dynsrc, lowsrc, ...

// Never allowed by any scheme:
javascript, vbscript, data:text/html

// Never allowed by any CSS rule:
@import, @charset, @namespace
expression(), behavior(), -moz-binding()
```

A profile that tries to enable any of these is rejected by the
package's public API. The invariant is not a convention; it is
unrepresentable.

## Reporting

See [SECURITY.md](../SECURITY.md) for the disclosure process,
what information to include, and the precise list of promises
whose breach counts as a vulnerability. **Do not open a public
issue for a security problem.**

## Testing methodology

Three test layers, per the spec:

1. **Unit**: each sanitization function in isolation.
2. **Integration**: end-to-end save → sanitize → store → render.
3. **End-to-end**: real browser engines. `cmd/corpusexport` renders
   every corpus vector and fuzz seed through the actual page shell,
   and `browsertest/check.mjs` loads each one in Chromium, Firefox
   and WebKit, asserting that nothing executes, nothing is fetched,
   nothing navigates, and the live DOM holds no forbidden element,
   `on*` attribute or dangerous URL.

   Each page is loaded twice: once with the production CSP, and once
   with no CSP at all. The second pass isolates the sanitizer. The
   layers are supposed to hold independently, so a sanitizer failure
   must never be masked by a response header — and a CSP violation
   report counts as a failure in its own right, because it proves
   markup that wanted to execute survived sanitization.

   This exists because the Go-side check (`verifyOutputHTML`)
   re-parses with `golang.org/x/net/html` — the same parser that
   produced the output. That is a correlated check: if x/net/html
   ever disagrees with a browser, the sanitizer and its own safety
   net share the blind spot. Only an engine can settle it.

The codebase includes Go fuzz targets in
`usercontent/fuzz_test.go`. They assert three properties for
arbitrary input:

- the sanitized HTML, **re-parsed as a DOM**, contains no
  forbidden element, no `on*` attribute and no dangerous URL
  scheme (a DOM check rather than a substring match: escaped text
  that happens to contain `javascript:` is inert, and a substring
  match would flag it while missing an entity-encoded scheme);
- the sanitized CSS contains no literal `<`;
- both are **idempotent** — re-sanitizing sanitized output
  returns it unchanged. This is the property that makes stored
  sanitized content safe to re-serve and re-sanitize on a policy
  bump, and it has caught real bugs (a stray `(` in a declaration
  value, and `<a/>` being emitted as a complete element where a
  browser reads it as an open one).

Run them with:

```bash
make fuzz                    # 60s per target
make fuzz FUZZTIME=10m
```

Corpus regressions live in `usercontent/corpus/`, and every
finding from a security review gets a permanent test in
`usercontent/regression_test.go` or
`pageservice/handlers/regression_test.go`.

## What is NOT covered (out of scope)

- SSRF in the user's own page (the page is a static document).
- DoS via the editor (handled by rate limiting on `/api/save`,
  configured outside this package).
- Compromise of the Go runtime itself. `go.mod` pins a
  `toolchain` floor so builds pick up standard-library fixes, and
  CI runs `govulncheck` weekly, but keeping the deployed toolchain
  current is the operator's responsibility.
- Tailwind-style vendor-prefix tricks that produce a policy
  bypass — the property allowlist is curated by hand. See
  [maintenance.md](maintenance.md) for the review process that keeps
  it current.
