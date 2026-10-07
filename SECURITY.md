# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's [private vulnerability
reporting](https://github.com/gobeaver/go-beaver-tag-sanitization/security/advisories/new)
on this repository. If that is unavailable to you, open a public issue that
says only "security report, please provide a contact" — with no details — and a
maintainer will follow up.

Please include:

- the sanitizer profile in use (`ProfileFullPage`, `ProfileEmbed`, or a custom
  `Profile` — the literal is most useful),
- the exact input string,
- the sanitized output you observed,
- what a browser does with it.

We aim to acknowledge within 3 working days and to ship a fix or a mitigation
within 30 days for anything that meets the bar below.

## What counts as a vulnerability

The package makes a small number of hard promises. A reproducible break of any
of them is a vulnerability, regardless of whether CSP would also have caught it
— the layers are independent on purpose, and a sanitizer bug is a sanitizer bug.

1. **`SanitizeHTML` output is inert.** Given any input, the returned HTML must
   contain no script, no event handler, no `javascript:`/`vbscript:` URL, and
   no element from the always-forbidden list, when parsed by any current
   browser. It is safe to insert via `template.HTML`.
2. **`SanitizeCSS` output cannot escape its `<style>` element.** The returned
   CSS never contains a literal `<`. It is safe to insert via `template.CSS`.
3. **Both are idempotent.** Re-sanitizing sanitized output returns it unchanged.
4. **Errors carry no output.** A non-nil error always comes with an empty
   string, so mishandling the error cannot serve unverified content.
5. **Allowlists are allowlists.** No profile can re-enable a forbidden element,
   an `on*` attribute, a `javascript:` scheme, `expression()`, `@import`, or a
   `script-src` other than `'none'` or explicit hashes. `New` rejects such a
   profile.
6. **Asset origins fail closed.** An asset URL that matches no entry in
   `AssetPrefixes` is rejected, including when the list is empty.
7. **Draft tokens are unforgeable.** A preview token authorizes exactly one
   page ID until it expires.

Also in scope: parser differentials that make the sanitizer and a browser
disagree about the same bytes (mutation XSS), and inputs that drive
super-linear time or memory inside the configured `MaxHTMLBytes` /
`MaxCSSBytes` / `MaxDOMNodes` limits.

## What does not count

- Findings against the example programs under `cmd/` used outside their
  documented purpose. `cmd/playground` and `handlers.DefaultServer` are
  development tools; `AllowAllSaveAuthorizer` is documented as accepting every
  write.
- Missing authentication on `POST /api/save` when the application has not
  supplied a `SaveAuthorizer`. The endpoint refuses every request until one is
  wired, by design.
- Behaviour a profile explicitly opted into (e.g. permitting an external asset
  origin by listing it in `AssetPrefixes`).
- Vulnerabilities in the Go standard library. Report those upstream; this
  repository pins a `toolchain` floor so builds pick up the fixes.

## Supported versions

The latest tagged minor release receives security fixes. The package is
pre-1.0; consumers should track the latest tag.

## Defence in depth

Sanitization is the first layer, not the only one. A deployment should also
serve user content from a dedicated origin that holds no session credentials,
apply the headers from `Sanitizer.CSPHeaders()`, and sandbox any editor
preview. See [`docs/security.md`](docs/security.md) for the full threat model.
