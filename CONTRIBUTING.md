# Contributing

Thanks for helping. This is a security package, so a few of the rules below are
stricter than you might expect from a general-purpose Go library.

**Found a vulnerability? Do not open a pull request or an issue.** Follow
[SECURITY.md](SECURITY.md) instead — a public patch is a public disclosure.

## Getting set up

```bash
git clone https://github.com/gobeaver/go-beaver-tag-sanitization
cd go-beaver-tag-sanitization
make check     # vet + test + lint
```

`go.mod` pins a `toolchain` floor, so Go will fetch a matching toolchain
automatically the first time you build.

Before opening a pull request:

```bash
make ci        # what CI runs: vet, race tests, lint, gosec, govulncheck
```

`make ci` must pass. CI additionally enforces `gofmt -l .` being empty and
`go mod tidy` being a no-op.

## The rules that matter

**Never widen an allowlist without a test that shows what stays out.** Adding a
tag, attribute, CSS property, function, at-rule or URL scheme is a policy
change. The pull request must say what an attacker could do with it and why
that is acceptable.

**Never loosen `validate()`.** The invariants in `Profile.validate` are the
package's whole value proposition: they make unsafe configuration
unrepresentable rather than merely discouraged. Adding one is welcome; removing
one needs a very good argument.

**Fail closed.** When you are unsure whether to keep or drop something, drop it
and record a `Removal` so the author can see why. Never return usable output
alongside an error.

**Report every drop.** Content that disappears without a `Removal` entry is a
bug: the editor has no way to tell the author what happened, and the silence
hides sanitizer bugs (an entire class of `@media` rules was being discarded
without a single reported removal until someone looked).

**Preserve the output invariants.** Sanitized HTML is inert; sanitized CSS
contains no literal `<`; both are idempotent. If your change touches an emit
path, add a fuzz seed for it.

## Adding a regression test

Every fix needs a test that fails before it and passes after. Put security
regressions in `usercontent/regression_test.go` (sanitizer) or
`pageservice/handlers/regression_test.go` (service), name them after the
property rather than the bug, and say in a comment what used to go wrong.

Attack strings that are worth keeping permanently belong in
`usercontent/corpus/xss/vectors.txt` or `usercontent/corpus/css/vectors.txt`;
`corpus_test.go` runs the whole corpus against every profile.

New emit paths should also get a seed in `usercontent/fuzz_test.go`. To fuzz
locally:

```bash
go test ./usercontent/ -run '^$' -fuzz FuzzSanitizeHTML -fuzztime=5m
go test ./usercontent/ -run '^$' -fuzz FuzzSanitizeCSS  -fuzztime=5m
```

## Style

Match the surrounding code. Comments explain *why* a rule exists — the "what"
is already in the code, and in a sanitizer the reason a check is there is the
part that stops someone deleting it later.

Keep the layering intact: `usercontent/html` and `usercontent/css` must not
import the parent package, and URL policy decisions live in exactly one place
(`urlPolicy` in `usercontent/sanitizer.go`).
