**Status:** Draft for team review
**Scope:** General go-beaver.com platform capability: a product-agnostic core (`usercontent` package) plus a generic pages/rendering service. Individual products — invitation pages, bio pages, portfolios, microsites — adopt it later as thin consumers with their own profiles (§11). No product wiring is part of the core.
**Owner:** TBD · **Reviewer:** TBD

## 1. Goal

Let users (or an LLM acting on their behalf) author complete pages, and render them safely:

- **AI full-page generation** — the model produces a complete HTML/CSS page, not just a JSON config for a closed-vocabulary designer.
- **Custom code** — the owner pastes or uploads their own HTML + CSS.

Both share one hard rule: a published page must never execute JavaScript, load anything from a third-party host (no CDNs), embed frames, open popups, or contain forms. Custom HTML and custom CSS are allowed; JS is not (v1 ships zero JS — §9 answers "limited interactivity" without user JS).

This is deliberately a platform capability, not a feature of any one product. Anything that needs "public user-authored page" is a future consumer.

## 2. Does Go template rendering make this safe? No.

The most important thing to internalize before building:

- `html/template` contextual auto-escaping protects our templates from user *data* (`{{.PageTitle}}` gets escaped). That is the right tool for the page shell (title, OG tags, meta).
- It does nothing for user-authored *markup*. The moment we output the owner's HTML we must mark it `template.HTML`, which bypasses escaping entirely — by design. Whatever is in that string ships verbatim.
- Never parse user input as a template (`template.Parse(userInput)`). Go templates aren't RCE the way Jinja2 SSTI is, but a user submitting `{{.}}` can dump whatever data context we pass in, and pathological templates are a DoS vector.

So the architecture is: `html/template` for our shell + sanitization + CSP + origin isolation for the user's code (§4).

## 3. Core principle: the model is not a security boundary

An LLM can be steered by anything it reads — the user's prompt, pasted content, uploaded images with embedded text. Prompt injection means "the AI was instructed not to emit `<script>`" is worth nothing. Model output must be treated exactly like user-pasted input: hostile until proven otherwise by an algorithmic safeguard — deterministic, versioned, testable code that does not involve a model.

Practical consequence: AI-generated pages and user-pasted code go through the same sanitize pipeline. There is no "trusted because our model generated it" path. We constrain the generation prompt to the allowed vocabulary so sanitization rarely changes anything (good UX), but we never rely on the prompt for safety.

## 4. Defense in depth — five layers

A sanitizer bug must not be game-over. Each layer below assumes the ones above it have failed.

| # | Layer | What it stops | Mechanism |
|---|-------|---------------|-----------|
| 1 | HTML sanitization | `<script>`, event handlers, `javascript:` URLs, `<iframe>`, `<object>`, `<form>`, `<meta>`, `<base>` | bluemonday custom policy, server-side, on save and on serve (§5) |
| 2 | CSS sanitization | `@import`, external `url()`, `expression()`, exfil selectors | CSS parse + property/value allowlist (§6) |
| 3 | CSP response header | Script execution, any third-party load, framing, form posts — even if 1–2 are bypassed | Strict CSP on every served page (§7). This — not the sanitizer — is what enforces "no JS / no CDN / no iframe" |
| 4 | Origin isolation | Session/token theft if everything else fails | Published pages served from a dedicated hostname that holds no credentials (§8) |
| 5 | Sandboxed preview | Dashboard compromise during editing | Editor preview only via `<iframe sandbox>` pointing at the isolated origin, never `dangerouslySetInnerHTML` on the app origin |

## 5. HTML sanitization policy (bluemonday)

Sanitize with `github.com/microcosm-cc/bluemonday`, custom policy — do not start from `UGCPolicy()` and subtract; build up from empty.

**Allowed elements:** `h1`–`h6`, `p`, `div`, `span`, `section`, `header`, `footer`, `main`, `article`, `br`, `hr`, `ul`, `ol`, `li`, `blockquote`, `strong`, `em`, `b`, `i`, `u`, `s`, `small`, `sup`, `sub`, `a`, `img`, `figure`, `figcaption`, `table`, `thead`, `tbody`, `tr`, `th`, `td`, `time`, `address`, `picture`, `source`

**Allowed attributes:**

- Global: `class`, `id` (prefixed/namespaced on render to avoid colliding with the shell), `dir`, `lang`, `title`, `aria-*`, `role`, plus one reserved data-attribute namespace declared by the profile (e.g. `data-gb-*`) for our declarative runtime (§9)
- `a`: `href` — schemes `https`, `mailto`, `tel`, and same-site relative only. Force `rel="noopener noreferrer nofollow ugc"`; allow `target="_blank"` only with that rel (note: with zero JS this only opens a tab — if "no popups" means no new windows at all, strip `target` entirely; decide in review)
- `img`/`source`: `src`, `srcset`, `alt`, `width`, `height`, `loading` — same-origin asset paths only (profile `AssetPrefixes`) or `data:image/(png|jpeg|webp|gif)`. No external image hosts (the tracking-pixel/CDN rule). No SVG (script-capable; §12)
- `style` attribute: **stripped in v1.** All styling goes through the separate CSS field (§6). One sanitizer path for CSS, not two.

**Always stripped (non-negotiable):** `script`, `iframe`, `frame`, `object`, `embed`, `applet`, `form`, `input`, `button`, `select`, `textarea`, `link`, `meta`, `base`, `style` (tag), `svg`, `math`, `video`, `audio`, `dialog`, `slot`, `template`, all `on*` attributes, all `javascript:`/`vbscript:`/`data:text/html` URLs, HTML comments, conditional comments.

**Why no forms/inputs:** phishing ("enter your password to continue"). Anything interactive — RSVP, contact, subscribe, follow — is a shell-owned component injected by the consumer product, never user markup.

**Process rules:**

- Sanitize on save (store the result) and enforce on serve (never serve a blob whose `sanitizer_version != current`; re-sanitize lazily on version bump).
- Store `raw_*` (for re-editing) and `sanitized_*` separately. Raw is never served to anyone but the owning editor, and even the editor preview renders the sanitized version.
- Sanitize after any decoding (the sanitizer must see exactly the bytes that will be served). No post-sanitization string surgery — that's how mutation-XSS bugs happen.

## 6. CSS sanitization policy

CSS is allowed but is not harmless — it can load external resources (`url()`), exfiltrate via attribute selectors + per-keystroke background requests, and redress UI. Since the rendered result is a full user page (no our-UI to redress) with no forms/inputs, residual risk is low once external loads are blocked.

- Parse with a real CSS parser and **reject unparseable input** — never "best effort" pass it through. `github.com/aymerick/douceur` works today but is barely maintained; keep the parser behind a small internal interface so it can be swapped (`tdewolff/parse` is the likely replacement).
- Block: `@import`, `expression()`, `behavior`, `-moz-binding`, any `url()` that isn't an allowlisted same-origin asset prefix or `data:image/*`, `@font-face` `src` to external hosts.
- Allow: the normal layout/typography/color/animation property set, `@media`, `@keyframes`, `@supports`, custom properties. External font CDNs cannot be linked (CDN rule) — offer a curated set of self-hosted fonts served from our origin instead.
- Serve as one `<style>` block inside the shell or as a same-origin stylesheet URL, size-capped.
- Even if a hostile `url()` slips through, CSP `img-src`/`font-src` (§7) blocks the fetch. That's the point of layering.

## 7. CSP — the enforcement backstop

Every served page gets, from the Go handler:

```
Content-Security-Policy: default-src 'none';
  img-src 'self' data:;
  style-src 'self' 'unsafe-inline';
  font-src 'self';
  media-src 'none';
  script-src 'none';
  frame-src 'none';
  frame-ancestors 'self' https://<dashboard-origin>;   (only our editor preview iframe)
  form-action 'none';
  base-uri 'none';
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), fullscreen=(self)
Cross-Origin-Opener-Policy: same-origin
```

This is what actually guarantees the requirements even under sanitizer bypass: `script-src 'none'` = no JS, `default-src 'none'` + self-only sources = no CDN, `frame-src 'none'` = no iframes, no JS + `form-action 'none'` + forced `noopener` = no popups/redirect tricks.

Tightening (cheap, do when convenient): drop `'unsafe-inline'` by serving the sanitized CSS from a same-origin URL (`style-src 'self'`) or by hashing the single shell-emitted `<style>` block. Low risk either way — the block is sanitizer-produced — but it's a free win.

If/when we ship our own runtime (§9), `script-src` moves to a hash/nonce of our shell-injected script only — never `'unsafe-inline'`, never a path the user's markup could reference.

## 8. Serving architecture & origin isolation

Pages are rendered and served by a small Go service (can live in the existing API binary behind a Host gate):

- `GET /r/:slug` — `html/template` shell (escaped title, OG/meta, self-hosted fonts, the consumer's shell components, optional runtime) + `template.HTML(sanitized_html)` + sanitized CSS. Headers from §7.
- **Dedicated user-content hostname**, e.g. `pages.go-beaver.com` → same Go app, but: never sets cookies, ignores `Authorization`, serves only the public render + asset routes (Host-based route gate). Per-brand vanity hosts can CNAME onto the same credential-less service; lookup key is `(host, slug)`. The dashboard and API origins never serve user markup as a document. A worst-case full bypass then executes in an origin that owns nothing.
- Consumers flip their entity to `render_mode = "custom-code"` and redirect/link their existing public route to the isolated host. Existing closed-vocabulary/JSON render paths are untouched.
- Editor preview in the dashboard: `<iframe sandbox="" src="https://pages.go-beaver.com/r/:slug?draft=...">` with a short-lived signed draft token (`Referrer-Policy: no-referrer` keeps it out of referrers; add `X-Robots-Tag: noindex` on draft renders). `sandbox` without `allow-scripts`/`allow-same-origin` — belt and suspenders on top of the page's own CSP.

**Generic schema** (a `user_pages` table; consumers reference a row or embed equivalent columns):

```
user_pages(
  id, owner_id, product, host, slug,
  raw_html   TEXT,   raw_css   TEXT,     -- owner's source, editor-only
  sanitized_html TEXT, sanitized_css TEXT, -- the only thing ever served
  sanitizer_version INT, profile TEXT,
  status, created_at, updated_at
)
```

**Limits:** raw HTML ≤ 300 KB, CSS ≤ 150 KB (post-decode); reject deeper than ~40 DOM levels and > ~5,000 nodes (sanitizer DoS guard). Existing auth + rate limits apply to save; the render endpoint gets the public limiter + cache headers.

## 9. "Limited interactivity" — our runtime, not user JS

Don't ship user-authored JS at all. Expose our capabilities declaratively: sanitizer-allowed reserved data attributes (`data-gb-animate="fade-up"`, `data-gb-countdown="<iso>"`, `data-gb-lightbox`) interpreted by our shell-injected, CSP-hashed runtime. Users get motion, countdowns, galleries — the only executable code on the page is ours. This is the same trick a closed-vocabulary JSON designer plays, moved down to the markup level.

If arbitrary user JS is ever truly demanded, that's a separate project (sandboxed iframe island on a second isolated origin, no credentials, `allow-scripts` only) — explicitly out of scope now.

## 10. The `usercontent` package — the core deliverable

Build layers 1–3 as one reusable, stateless Go package from day one (its own module, e.g. `go-beaver.com/usercontent`). It knows nothing about any product; products consume it through profiles.

### API sketch

```go
package usercontent

type Profile struct {
    Name            string   // e.g. "fullpage-v1"
    Version         int      // bump on any policy change; consumers persist it
    AllowedTags     []string
    AllowedAttrs    map[string][]string // tag -> attrs; "*" for global
    URLSchemes      []string            // e.g. https, mailto, tel
    AssetPrefixes   []string            // same-origin URL prefixes allowed in src/url()
    AllowDataImages bool
    MaxHTMLBytes    int
    MaxCSSBytes     int
    MaxDOMDepth     int
    MaxDOMNodes     int
    CSS             CSSPolicy
    CSP             CSPPolicy
}

type Report struct {
    Modified bool
    Removed  []Removal // what was stripped/rewritten and why — powers editor UX
}

func New(p Profile) (*Sanitizer, error)          // validates the profile

func (s *Sanitizer) SanitizeHTML(html string) (string, Report, error)
func (s *Sanitizer) SanitizeCSS(css string) (string, Report, error)
func (s *Sanitizer) CSPHeaders() map[string]string
```

Built-in starting profiles: `ProfileFullPage`, `ProfileEmbed`. Products define their own (e.g. `invitation-v1`, `bio-v1`) by copying and tightening. The `Report` powers editor UX: "we removed a `<script>` tag and 2 external images" beats silent mangling.

### Non-negotiable invariants (enforced by the package, not the profile)

Profiles can only **narrow** the policy. No profile can ever allow: `script`/`iframe`/`object`/`embed`/`base`/`meta`/`link`/`form`/inputs/inline `svg`/`math`; any `on*` attribute; `javascript:`/`vbscript:`/`data:text/html` URLs; CSS `@import`/`expression()`/non-allowlisted `url()` origins; a CSP `script-src` other than `'none'` or explicit hashes supplied by the consumer's own shell. `New()` returns an error for a profile that tries. Safety is not a convention consumers must remember — it is unrepresentable in the API.

### Shipped test corpus

The package commits a corpus (`usercontent/corpus/`) of known-hostile inputs — OWASP XSS vectors, mutation-XSS nesting cases, encoding tricks, CSS exfiltration patterns, and real captured LLM prompt-injection outputs. `go test` asserts every corpus entry is fully neutralized by every built-in profile; consumers run custom profiles against the same corpus with `usercontent.TestProfileAgainstCorpus(t, myProfile)`. New attack classes get added to the corpus centrally; every consumer inherits the regression test on upgrade.

### Future scope (explicitly not v1)

- Structured-output validation: JSON-Schema / closed-vocabulary validator for LLM structured output.
- URL/link policy module: outbound-link allowlisting + rewriting as a standalone helper.
- Email-template profile: stricter variant for HTML email (no CSP available there — the sanitizer carries the full load).

## 11. Consumers & use cases

The core is stateless and product-blind. A consumer integration is deliberately small:

1. Pick or derive a `Profile` (copy a built-in, tighten, name it `product-v1`).
2. Wire save → `SanitizeHTML`/`SanitizeCSS` → store blobs + version + `Report`.
3. Point the product's entity at a `user_pages` row (or embed the columns).
4. Route the public URL to the isolated host; brand the shell (fonts, footer, product components such as an RSVP or follow button).
5. Hook publish into moderation / report-abuse.

Candidate consumers — each is a future project on its own timeline; none of them is this plan:

- Event invitation pages (the request that prompted this proposal; likely first adopter)
- Bio / link-in-bio pages
- Portfolio and profile pages
- Landing pages / microsites for AI page-builder output
- Embedded user blocks inside otherwise-native pages (`ProfileEmbed`)
- HTML email templates (future; needs the stricter no-CSP profile above)

## 12. Known sharp edges (call out in review)

- **SVG:** disallowed inline and as an upload for custom pages — SVG is a script container. If asset uploads ever accept SVG, serve with `Content-Security-Policy: sandbox; script-src 'none'` and `nosniff`, or rasterize.
- **Mutation XSS:** never modify HTML after sanitization; sanitizer output is final. Bump `sanitizer_version` on every policy change and re-sanitize before serve.
- **Unicode/encoding tricks:** decode once, sanitize what you serve, serve `charset=utf-8` explicitly.
- **`id`/`class` collisions with the shell:** prefix shell classes (`gb-shell-*`), scope user CSS by wrapping user markup in a container, and consider rejecting user selectors that target `gb-shell-*`.
- **Phishing text:** CSS+HTML can still look like a login page even with no working form. Mitigations: no forms (already), report-abuse link in the shell footer, moderation hook on publish.
- **Go templates:** user content is data, never template source. Grep-gate in CI: no `template.Parse` on request-derived strings.

## 13. Acceptance criteria

- **XSS corpus test:** every payload in the OWASP XSS cheat-sheet vectors plus the repo-committed corpus (script-tag variants, `on*` handlers, `javascript:`/`data:text/html` hrefs, `<svg onload>`, `<iframe>`, `<object>`, `<base>`, `<meta refresh>`, `<form>`, mXSS nesting cases, `@import`, `expression()`, external `url()`) produces sanitized output containing none of them. Runs in CI as unit tests against the `usercontent` package.
- Rendered page headers match §7 exactly (integration test hits `GET /r/:slug`).
- A published page loads **zero third-party requests** and executes **zero scripts** with our runtime disabled (E2E: headless browser, fail on any CSP report or external request).
- Raw HTML/CSS is unreachable by any non-owner request path.
- Editor preview works only through the sandboxed iframe; `dangerouslySetInnerHTML` of user content appears nowhere in any web frontend.
- Sanitizer `Report` surfaces in the editor UI when content was modified.
- `gosec` / `govulncheck` clean per repo policy.

## 14. Milestones

- **M1 — `usercontent` package + corpus tests.** The security core. No product wiring.
- **M2 — Pages service:** `user_pages` schema, save/sanitize flow, `GET /r/:slug` shell render + headers, Host gate for the user-content domain. (M1+M2 is the minimal shippable core.)
- **M3 — First consumer end-to-end:** editor "Custom code" mode (paste/upload, sanitizer report, sandboxed preview) and public-route redirect. Consumer chosen at kickoff — invitations are the current front-runner, not a dependency.
- **M4 — AI:** full-page generation piped through the same save path as pasted code.
- **M5 — Runtime (optional):** `data-gb-*` declarative runtime with CSP hash.

