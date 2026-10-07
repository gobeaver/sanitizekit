# Maintenance

An allowlist sanitizer is not finished software. HTML and CSS keep growing, and
a feature that is harmless today can become a bypass tomorrow — not because the
code changed, but because browsers did. This is the process that keeps the
allowlists honest.

## The standing risk

Every allowlist in this package is hand-curated:

| What | Where |
|---|---|
| Allowed elements | `Profile.AllowedTags`, and `alwaysForbiddenTags` in `usercontent/profile.go` |
| Allowed attributes | `Profile.AllowedAttrs`, `forbiddenAttrs` |
| Allowed CSS properties | `Profile.CSS.AllowedDeclarations` |
| Allowed CSS functions | `Profile.CSS.AllowedFunctions`, `forbiddenCSSFunctions` |
| Allowed at-rules | `Profile.CSS.AllowedAtRules`, `forbiddenCSSAtRules` |
| Allowed pseudo-classes | `Profile.CSS.AllowedPseudoClasses` |
| Group at-rules (contain nested rules) | `isGroupRule` in `usercontent/internal/css/sanitizer.go` |
| Void elements | `isVoidElement` in `usercontent/internal/html/sanitizer.go` |
| Selector character allowlist | `isSafeSelectorByte` |

Two distinct failure modes, and they need different responses:

- **A new element or attribute becomes dangerous.** Because tags and attributes
  are allowlisted, a *new* one is denied by default. This is the safe direction:
  the sanitizer fails closed on features it has never heard of.
- **An existing allowed feature gains dangerous behaviour.** This is the real
  risk, and the allowlist does not protect against it. `<details>` is the worked
  example: an ordinary disclosure element that shipped an `ontoggle` handler and
  became an XSS vector, which is why it sits in `alwaysForbiddenTags` today.

## Quarterly review

Once a quarter, and before any release that widens an allowlist:

1. **Read the changelogs.** [WHATWG HTML](https://github.com/whatwg/html/commits/main),
   [CSSWG resolutions](https://github.com/w3c/csswg-drafts/labels/Commenter%20Response%20Pending),
   and the Chrome/Firefox/Safari release notes for the quarter.
2. **For every newly shipped feature, ask three questions:**
   - Can it load a subresource? (→ exfiltration, tracking)
   - Can it run script, or run a handler that script can observe? (→ XSS)
   - Can it move, cover, or impersonate trusted UI? (→ UI redressing)

   Any yes means the feature stays out, or is added only with an explicit
   mitigation and a regression test.
3. **Re-check features already on the allowlist** that changed behaviour. This
   is the step that actually matters and the one that is easiest to skip.
4. **Record the review** in `CHANGELOG.md` under the release, even when the
   answer is "no changes". A silent quarter and a skipped quarter look
   identical otherwise.

## Features currently excluded on purpose

Worth re-checking each cycle, because the reasoning could change:

- **`popover` / `command` / `commandfor`** — declarative activation that can
  raise content over the shell. Not allowlisted.
- **`@scope`, anchor positioning (`anchor()`, `position-anchor`)** — can attach
  user content to trusted elements. Not in `AllowedAtRules` / declarations.
- **`:has()`** — a relational selector powerful enough to build an
  attribute-value oracle. In the embed profile's list, *not* in full-page.
- **`@container` style queries** — read computed state; a leakage channel worth
  watching. Present in `isGroupRule` for parsing, absent from the default
  profiles.
- **`<details>`, `<dialog>`, `<video>`, `<audio>`, `<marquee>`** — all
  permanently in `alwaysForbiddenTags`; each has shipped an event handler or a
  network fetch.
- **Inline `style`** — permanently forbidden; styling goes through the CSS
  field, which is parsed and allowlisted.
- **SVG and MathML** — script containers and the classic mutation-XSS route.

## When a browser bug is the cause

If a browser parses sanitized output differently from
`golang.org/x/net/html`, the browser is right and this package is wrong,
regardless of what the spec says. The differential harness in `browsertest/`
exists to catch exactly this; a failure there is a security bug, not a flaky
test. Report it through [SECURITY.md](../SECURITY.md).

## Dependency hygiene

- `usercontent` — the security core — must depend on nothing but
  `golang.org/x/net/html`. `go list -deps ./usercontent` is checked in the
  release workflow and published as `usercontent-deps.txt`. Adding a dependency
  there needs a much better reason than convenience.
- `govulncheck` runs on every push and weekly on a schedule, so an advisory
  against a pinned version surfaces without anyone needing to look.
- `go.mod` pins a `toolchain` floor so builds pick up standard-library fixes.
  Bump it when a Go patch release fixes anything in `net/http`, `net/url`,
  `html/template` or `crypto/tls`.

## Before widening any allowlist

The bar, from [CONTRIBUTING.md](../CONTRIBUTING.md):

> Never widen an allowlist without a test that shows what stays out.

Concretely, a pull request that adds an entry must:

1. say what an attacker could do with it, and why that is acceptable;
2. add a corpus vector under `usercontent/corpus/` for the abuse case;
3. add a fuzz seed in `usercontent/fuzz_test.go` if it introduces a new emit
   path;
4. bump `Profile.Version` and regenerate the golden files
   (`go test ./usercontent/ -run TestGolden -update`) — stored pages are
   re-sanitized when that version moves, so the change is a compatibility event.
