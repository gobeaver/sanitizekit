# Architecture

This document explains the layered defense of the user-content
platform and how the Go modules fit together.

## High-level flow

```
                  User / LLM
                      │
                      ▼
              ┌──────────────────┐
              │ HTML / CSS input │
              └────────┬─────────┘
                       │
                       ▼
   ┌────────────────────────────────────────┐
   │ usercontent.Sanitizer                  │
   │  ├─ HTML policy (allowlist)            │
   │  ├─ CSS  policy (allowlist)            │
   │  ├─ URL  policy (scheme + origin)       │
   │  └─ DOM  depth / node limits            │
   └────────────┬───────────────────────────┘
                │
                ▼
   ┌────────────────────────────────────────┐
   │  raw_*  +  sanitized_*  +  Report      │
   │  + sanitizer_version                   │
   └────────────┬───────────────────────────┘
                │
                ▼
   ┌────────────────────────────────────────┐
   │ pageservice storage                   │
   │  (raw_* is editor-only;                │
   │   sanitized_* is the only one served)  │
   └────────────┬───────────────────────────┘
                │
                ▼
   ┌────────────────────────────────────────┐
   │ pageservice render                     │
   │  html/template shell +                │
   │  template.HTML(sanitizedHTML)         │
   │  + CSP + Referrer-Policy + ...         │
   └────────────┬───────────────────────────┘
                │
                ▼
   ┌────────────────────────────────────────┐
   │ Public Page                            │
   │  served on pages.go-beaver.com         │
   │  (no cookies, no Authorization)        │
   └────────────────────────────────────────┘
```

The AI path is identical:
```
LLM
 ↓
HTML / CSS
 ↓
SAME sanitizer
 ↓
SAME save flow
 ↓
SAME renderer
```

The LLM is never a security boundary.

## Defense in depth

The spec numbers five layers. Each layer assumes the one above
it has failed.

| # | Layer | Mechanism | Where it lives |
|---|-------|-----------|-----------------|
| 1 | HTML sanitization | Custom bluemonday-style allowlist policy | `usercontent/html` |
| 2 | CSS sanitization | Property + at-rule + selector allowlist | `usercontent/css` |
| 3 | CSP response header | `script-src 'none'`, etc. | `usercontent/csp` + `pageservice/handlers` |
| 4 | Origin isolation | Dedicated `pages.go-beaver.com` host | `pageservice/middleware` (host gate) |
| 5 | Sandboxed preview | `<iframe sandbox="">` no allow-scripts/same-origin | `editor` |

The CSP is the enforcement backstop. If a sanitizer bug allowed
`<script>` through, the CSP still denies script execution. The
defense is in depth.

## Module boundaries

```
usercontent (security core)
├─ html        — tokenization + sanitization
├─ css         — parser + sanitization
├─ csp         — CSP header builder
├─ profiles    — ProfileFullPage, ProfileEmbed
└─ corpus      — regression inputs

pageservice (HTTP service)
├─ handlers    — /r/:slug and /preview/:slug (public listener),
│                /api/save (separate, authorized listener)
├─ render      — html/template shell
├─ storage     — Page + MemoryStore (DB-ready interface)
├─ drafts      — signed preview tokens
└─ middleware  — host gate, credential stripping

editor (dashboard helpers)
runtime (declarative runtime, M5)
```

`usercontent` knows nothing about the page service. The editor
knows nothing about the renderer. The package boundaries mirror
the spec.

The read and write paths are separate listeners, not just
separate routes: `cmd/pageservice` serves the public, credential
-free origin on `ADDR` and the write API on `ADMIN_ADDR` behind a
bearer token, and `handlers.Server` refuses every save until an
application supplies a `SaveAuthorizer`.

## Sanitizer internals

The HTML sanitizer is a [custom tokenizer-driven
walker](https://github.com/golang/net/html) rather than a
DOM-parse-then-serialize approach. The reason is mutation XSS
(mXSS): a parse-serialize round-trip can re-interpret the
sanitized string in a way that re-introduces script. The
tokenizer-driven approach emits safe HTML directly from the
token stream, no serialization.

The CSS sanitizer is a hand-rolled recursive-descent parser. It
recognizes:

- at-rules (`@media`, `@keyframes`, `@font-face`, etc.) — but
  rejects `@import`, `@charset`, `@namespace` always.
- rules with selectors and declaration blocks.
- `url(...)` with origin + scheme validation.
- function calls with allowlist enforcement.

Property values are walked and dangerous functions
(`expression()`, `behavior()`, `-moz-binding()`) are stripped.

## Profiles

`Profile` is the only way to customize the sanitizer. Profiles
can only be narrower than the baseline; `New()` rejects any
profile that would weaken a non-negotiable invariant.

Two built-in profiles:

- `ProfileFullPage`: the rich default for a complete page
  (h1-h6, div, span, table, etc.).
- `ProfileEmbed`: tighter vocabulary for an embedded user
  block inside an otherwise-native page.

Consumers define their own profiles by copying a built-in and
tightening:

```go
p := profiles.ProfileFullPage()
p.Name = "invitations-v1"
p.Version = 2
p.AllowedTags = append(p.AllowedTags, "time") // from §5 example
s, err := usercontent.New(p)
```

## Sanitizer versioning

Every `Profile` has a `Version`. The page service stores the
version that produced the sanitized content. On serve, the page
service compares the stored version to the current version; if
the policy moved, the page is re-sanitized lazily and the
result is persisted.

This means a security fix in the sanitizer is automatically
applied to every page on next visit, without a migration.

## Origin isolation in detail

The page service is wired with the `HostGate` middleware, which
rejects any request whose `Host` header is not in the allowlist
(e.g. `pages.go-beaver.com`). The dashboard origin (e.g.
`dashboard.go-beaver.com`) can never serve user markup as a
document — the host gate short-circuits with 403.

The page service also strips `Authorization` and `Cookie`
headers from every request. The user-content origin holds no
credentials.

In the worst case (a full sanitizer bypass), the rogue script
executes in an origin that owns nothing. The blast radius is
limited to the page itself.

## Sandboxed preview

The editor renders the preview in a `<iframe sandbox="">` with
no `allow-scripts` or `allow-same-origin`. The preview URL is
on the `pages.go-beaver.com` origin, so it is cross-origin from
the dashboard.

The iframe sandbox is the dashboard's strongest defense against
a sandbox-escape bug in the sanitizer. The page's own CSP is a
second layer inside the iframe.

## Declarative runtime (M5)

The only JavaScript that runs on a user page is the shell-owned
runtime, embedded as a build-time constant. The runtime
interprets reserved `data-gb-*` attributes:

- `data-gb-animate="fade-up"` — fade up on first reveal.
- `data-gb-countdown="<iso>"` — countdown to the given date.
- `data-gb-lightbox` — click-to-zoom on contained images.

The runtime has no network, no `eval`, no `innerHTML` writes
to user-provided strings. The CSP `script-src` references the
runtime by hash, never `'unsafe-inline'`, never a path the user
could reference. The hash comes from `runtime.CSPHash()`:

```go
p := profiles.ProfileFullPage()
p.CSP.ScriptHashes = []string{runtime.CSPHash()}
```

Until a profile does that, `script-src` stays `'none'` and the
runtime does not execute at all.

## Why the model is untrusted

Prompts can be steered by anything the model reads:

- The user's prompt itself.
- Pasted content.
- Uploaded images (OCR).
- Other pages in the same conversation.

So "prompt said no script" is worth exactly nothing. The system
prompt constrains the model as a UX measure (less mangling
through the sanitizer, fewer surprises in the editor), but the
sanitizer is the security boundary.

## Future-scope (deliberately not in v1)

- Structured-output validation (JSON Schema / closed-vocabulary).
- Outbound-link allowlisting + rewriting.
- HTML email profile (no CSP available; the sanitizer carries
  the full load).
