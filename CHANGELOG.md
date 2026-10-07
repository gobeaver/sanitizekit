# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release-candidate pass over the whole package: a security audit, the
fixes it produced, and the release scaffolding the repository was missing.

### Security

- **CSS could escape its `<style>` element (critical).** Selectors, at-rule
  preludes, string values and `--custom-property` values were emitted verbatim,
  so CSS such as `</style><img src=x onerror=alert(1)>{color:red}` closed the
  shell's `<style>` element and injected arbitrary markup into the trusted
  page. Sanitized CSS now never contains a literal `<`: values escape it as
  `\3c `, selectors and preludes are validated against a character allowlist,
  and `Sanitize` fails closed if one somehow reaches the output.
- **`GET /r/:slug` served content that failed sanitization.** The lazy
  re-sanitize path discarded the sanitizer's error and served the returned
  string, which on the output-verification path is exactly the markup that
  verification rejected. The handler now fails with 500, and `SanitizeHTML` /
  `SanitizeCSS` return an empty string with every error so no caller can repeat
  the mistake.
- **`POST /api/save` was unauthenticated.** Any request could overwrite any
  page: owner, host and slug all came from the request body. Saves are now
  refused unless a `SaveAuthorizer` is wired to the `Server`, the body is
  bounded by `MaxSaveBytes` before being buffered, and host and slug are
  validated. `cmd/pageservice` serves the write API on a separate listener
  behind a bearer token, and not at all unless configured.
- **Data race on every stale page render.** `MemoryStore` handed out pointers
  into its own state which handlers then mutated. Stores now return `Clone()`d
  pages and `Put` stores a copy.
- **`rel` supplied by the author defeated the tabnabbing guard.**
  `<a rel="opener" target="_blank">` passed through untouched. The required
  `noopener noreferrer nofollow ugc` tokens are now merged into whatever the
  author wrote, and `opener` is dropped.
- **`srcset` bypassed the asset-origin allowlist.** The attribute was validated
  as a single URL, so a multi-candidate list parsed as an unparseable relative
  reference and was allowed. Each candidate is now validated separately.
- **Empty `AssetPrefixes` allowed any origin.** It now allows none:
  `AssetPrefixes` is an allowlist, and an empty allowlist permits nothing.
- **Prefix attributes leaked across tags.** `data-gb-*` or `aria-*` declared
  for one tag was accepted on every tag. Prefixes now apply only to the tag
  that declared them, or to all tags when declared under `"*"`.
- **Draft tokens accepted weak keys and ambiguous page IDs.**
  `drafts.NewSigner` now requires a key of at least `MinKeyLen` bytes and
  returns an error, page IDs are base64url-encoded inside the payload so they
  cannot collide with the separator, and the payload carries a version tag.
- **`storage.generateToken` returned the constant `"t-fallback"`** when the
  entropy source failed, making every draft token predictable.
  `Page.NewDraftToken` now returns an error instead.
- **Unterminated numeric character references bypassed the character policy.**
  `validateCharset` only checked `&#NN;` with its semicolon, but HTML decodes
  `&#NN` without one — so `&#x202E` smuggled a bidi override, and `&#1A` put a
  raw U+0001 into the output. Both forms are validated now, and
  `verifyOutputHTML` additionally re-checks every decoded text node and
  attribute value, so no encoding path can leak a forbidden character.
  Found by the fuzzer.
- **The pseudo-class allowlist was never enforced.** `AllowedPseudoClasses` was
  configured on every profile and consulted nowhere; selectors are now checked
  against it.
- Bumped `golang.org/x/net` to v0.58.0 and pinned a `toolchain go1.26.6` floor.
  `govulncheck ./...` reports no vulnerabilities.

### Added — high-assurance hardening

- **Differential browser testing.** `verifyOutputHTML` re-parses with
  `golang.org/x/net/html` — the same parser that produced the output, so a
  divergence between that parser and a real browser would be invisible to both
  the sanitizer and its own safety net. `cmd/corpusexport` now renders every
  corpus vector and fuzz seed through the real page shell, and
  `browsertest/check.mjs` loads each one in Chromium, Firefox and WebKit,
  asserting nothing executes, nothing is fetched and nothing navigates. Each
  page is loaded twice — with the production CSP and with none at all — because
  the layers are meant to hold independently and a sanitizer failure must not
  be masked by a header.
- **The sanitization internals are `internal/` now.** `usercontent/html`,
  `/css` and `/csp` were public API despite doc comments claiming otherwise, and
  a consumer could import past `usercontent.New` and supply a permissive
  `URLPolicy` — producing `<a href="javascript:alert(1)">` with no error,
  because the output verification lives in the parent package. Moved to
  `usercontent/internal/`, so the compiler now enforces what the docs promised.
- **The security core has no third-party dependencies.** `usercontent` pulled in
  `github.com/gobeaver/configkit` (three packages) purely for env loading, and
  every consumer inherited it. Config moved to `usercontent/config`; the core
  now imports nothing but `golang.org/x/net/html`, checked by `make deps-core`
  in CI and published per release as `usercontent-deps.txt`.
- **Golden output fixtures per profile.** `Profile.Version` drives lazy
  re-sanitization of stored pages, which makes output a compatibility surface.
  `usercontent/testdata/golden/` pins it; changing it requires a version bump.
- **Nightly deep fuzzing** (`.github/workflows/fuzz.yml`) — an hour per target
  with the corpus cached between runs, opening an issue with the reproducer on
  failure. The 60s CI run catches regressions; it does not find new bugs.
- **Release provenance** (`.github/workflows/release.yml`) — CycloneDX SBOM,
  dependency manifests, checksums and SLSA build attestation on every tag.
- **`docs/maintenance.md`** — the quarterly allowlist review process and the
  watchlist of deliberately-excluded features (`popover`, `@scope`, anchor
  positioning, `:has()`, container style queries). An allowlist sanitizer rots
  when browsers change, not when the code does.
- **`runtime.CSPHash()` is pinned by a test.** Operators put that hash in their
  CSP; an unnoticed edit to `Runtime` would silently stop the runtime executing
  on every deployed page.
- Coverage on the serving path: storage 31% → 92%, middleware 48% → 100%,
  render 40% → 90%, editor → 90%, runtime → 100%.

### Added

- `runtime.CSPHash()` returns the CSP source expression for the declarative
  runtime. The README described the runtime as "hashed at compile time and
  referenced by the CSP", but nothing computed the hash, so the runtime could
  never actually be allowed to run.
- `CSPPolicy.ScriptHashes` now drives the emitted `script-src`. It was
  validated and then ignored.
- `usercontent.ErrUnsafeOutput` for output that fails its own verification pass.
- `handlers.SaveAuthorizer`, `SaveAuthorizerFunc` and `AllowAllSaveAuthorizer`.
- `storage.Page.Clone`.
- `pageservice.Config.AdminAddr` / `SaveToken` and `Config.Validate`.
- Regression suites in `usercontent/regression_test.go` and
  `pageservice/handlers/regression_test.go`; the fuzz targets now assert
  idempotence and the no-`<` invariant, and carry a seed corpus.
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and a CI workflow running
  build, vet, race tests, `gofmt`, `go mod tidy`, golangci-lint, gosec,
  govulncheck and a fuzz smoke test on Linux, macOS and Windows.

### Fixed

- **`@media` and `@supports` were silently dropped in full.** A `break` inside
  a `switch` broke the switch rather than the prelude scan, so every
  conditional group rule parsed as an empty at-rule and vanished — reporting no
  removals, so nothing surfaced to the author. Group rules now keep their
  prelude and their nested rules, and nest correctly.
- At-rule preludes were discarded even when the rule survived, producing
  invalid CSS such as `@media{...}`. A comma in a prelude
  (`@media screen, print`) also terminated the rule.
- CSS comments are stripped before parsing rather than being partly preserved;
  an unterminated comment is now a parse error instead of silently swallowing
  the rest of the stylesheet.
- Declaration splitting now respects strings, parentheses and nested braces.
- Custom property *names* were unvalidated, so `--x</style>:1` was emitted as a
  property name.
- A structural character in a declaration value (`(`, `{`, `;`, `@`) was
  emitted verbatim, which broke idempotence — re-sanitizing grew the output.
  Found by the fuzzer.
- `cmd/pageservice` ignored the configured `DRAFT_SECRET` entirely and used an
  ephemeral random key from `handlers.DefaultServer`, so preview links broke on
  restart and across instances. It also now honours `DASHBOARD_HOST` in
  `frame-ancestors` and shuts down gracefully.
- `HandlePreview` now binds a token to the request's host as well as its slug.
- `render.HasShellNamespace` hardcoded `"gb-shell-"` instead of using
  `usercontent.ShellNamespacePrefix`.
- Removed a write-only `openLine` map whose `currentLine` helper rescanned the
  entire output buffer on every opening tag, making sanitization quadratic in
  output size.
- Removed the playground's dead `escapeHTML`, every replacement in which was an
  identity (`.replace(/&/g, '&')`), and bounded its request body.
- `Profile.StripComments` is forced true by `normalize()` and documented as
  reserved, instead of being a field that read as configurable and did nothing.
- `New` now normalizes before validating, so validation sees the profile that
  will actually be used.
- `.golangci.yml` was missing golangci-lint v2's required `version` key, so
  `make lint` and any CI lint step failed to load the config and never ran a
  single check. With it fixed, the config reported 59 issues, all now resolved:
  `golangci-lint run ./...` is clean.
- `Config.ToProfile` **widened** the preset it documented as only ever
  tightening. The env defaults are larger than the fullpage preset's limits, so
  the default configuration tripled `MaxHTMLBytes`. Limits are now overlaid
  with `min()` and flags only in the safe direction.
- `isHashToken` converted a rune to a byte when validating base64, so a
  multi-byte character could truncate into something that passed for a base64
  digit. It iterates bytes now.
- Numeric HTML entity validation could overflow a `rune` on a long digit run;
  values beyond the Unicode range are now rejected before that can happen.
- `editor.Save` read an unbounded response body and Go-quoted (`%q`) the iframe
  `src` where HTML escaping was needed; it now carries the write API's bearer
  token via `Editor.SaveToken`.
- `cmd/playground` read `PLAYGROUND_ADDR` via `os.Getenv`, which the project's
  own lint config forbids, and served without a `ReadHeaderTimeout`.
- Removed `css.FullPageAllowed` and its four tables: ~130 lines of dead code
  that were a *second, divergent* copy of the CSS allowlist. It permitted
  `position`, `z-index` and `pointer-events`, which the real profiles exclude
  for UI-redressing reasons — exactly the trap where someone edits the wrong
  allowlist.
- Deduplicated six hand-written copies of the same CSS string-literal scanner
  into one `skipString` helper.
- Every file is `gofmt`-clean; 10 were not.

### Changed

These are breaking changes to a pre-1.0 API, each closing a footgun.

- `drafts.NewSigner` returns `(*Signer, error)`.
- `storage.Page.NewDraftToken` returns `(string, error)`.
- `SanitizeHTML` / `SanitizeCSS` return an empty string with any error.
- `handlers.Server` gained `Authorizer`, which must be set for saves to work.
- `html.Profile` and `css.Profile` dropped the URL and asset fields they never
  consumed; URL policy lives solely in `usercontent`'s `urlPolicy`.
- `render.SanitizedInputs` and `NeedsResanitize` removed; unused.
- The `go` directive is `1.25.6` rather than the patch-pinned `1.26.4`, which
  had forced a toolchain download on every consumer.
