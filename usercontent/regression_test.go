package usercontent_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

func newFullPage(t *testing.T) *usercontent.Sanitizer {
	t.Helper()
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// Sanitized CSS must never contain a literal '<'. A '<' would let
// user CSS close the <style> element it is inlined into and inject
// arbitrary markup into the trusted shell.
func TestCSSCannotEscapeStyleElement(t *testing.T) {
	s := newFullPage(t)
	inputs := []string{
		`</style><img src=x onerror=alert(1)>{color:red}`,
		`p { color: "</style><img src=x onerror=alert(1)>" }`,
		`p { color: red; } </style> q { color: blue }`,
		`p{color:red;--x:</style><b>}`,
		`p{color:red;--x</style>:1}`,
		`p{background:url(/assets/a<b.png)}`,
		`p{content:'\3c /style>'}`,
		`@media screen { </style><b>{color:red} }`,
		`@media </style> { p{color:red} }`,
		`p{font-family:"</STYLE><script>alert(1)</script>"}`,
	}
	for _, in := range inputs {
		out, _, err := s.SanitizeCSS(in)
		if err != nil {
			continue // rejected outright is also a correct outcome
		}
		if strings.ContainsAny(out, "<") {
			t.Errorf("SanitizeCSS(%q) leaked '<': %q", in, out)
		}
	}
}

// Conditional group rules must survive sanitization with their
// prelude and nested rules intact. They used to be silently
// dropped whole, with nothing reported as removed.
func TestConditionalGroupRulesSurvive(t *testing.T) {
	s := newFullPage(t)
	cases := []struct{ in, want string }{
		{"@media screen { p { color: red; } }", "@media screen{p{color:red;}}"},
		{"@supports (display:grid) { p { color: red; } }", "@supports (display:grid){p{color:red;}}"},
		{
			"@media screen and (min-width: 600px), print { p { color: red } }",
			"@media screen and (min-width: 600px), print{p{color:red;}}",
		},
		{"@media screen { @media print { p { color: red } } }", "@media screen{@media print{p{color:red;}}}"},
	}
	for _, c := range cases {
		out, rep, err := s.SanitizeCSS(c.in)
		if err != nil {
			t.Errorf("SanitizeCSS(%q): %v", c.in, err)
			continue
		}
		if out != c.want {
			t.Errorf("SanitizeCSS(%q)\n got %q\nwant %q", c.in, out, c.want)
		}
		if len(rep.Removed) != 0 {
			t.Errorf("SanitizeCSS(%q): unexpected removals %+v", c.in, rep.Removed)
		}
	}
}

// A dropped rule must always be reported, so the editor can tell
// the author why their CSS vanished.
func TestDroppedCSSIsReported(t *testing.T) {
	s := newFullPage(t)
	for _, in := range []string{
		"@import url('https://evil.example.com/x.css');",
		"* { color: red }",
		".gb-shell-main { color: red }",
		"input[value^=a] { color: red }",
		"p { color: expression(alert(1)) }",
		"p { background: url(https://evil.example.com/a.png) }",
	} {
		_, rep, err := s.SanitizeCSS(in)
		if err != nil {
			t.Errorf("SanitizeCSS(%q): %v", in, err)
			continue
		}
		if len(rep.Removed) == 0 {
			t.Errorf("SanitizeCSS(%q): dropped content without reporting a removal", in)
		}
	}
}

// Comments must never reach the output, and an unterminated one is
// an error rather than a silent truncation.
func TestCSSComments(t *testing.T) {
	s := newFullPage(t)
	out, _, err := s.SanitizeCSS("/* c */ p /* c */ { color: red /* c */ }")
	if err != nil {
		t.Fatalf("SanitizeCSS: %v", err)
	}
	if strings.Contains(out, "/*") || out != "p{color:red;}" {
		t.Errorf("comments not stripped cleanly: %q", out)
	}
	if _, _, err := s.SanitizeCSS("p { color: red } /* unterminated"); !errors.Is(err, usercontent.ErrUnparseableCSS) {
		t.Errorf("unterminated comment: want ErrUnparseableCSS, got %v", err)
	}
}

// A pseudo-class outside the profile's allowlist must be dropped:
// the allowlist used to be configured but never consulted.
func TestPseudoClassAllowlistIsEnforced(t *testing.T) {
	s := newFullPage(t)
	out, _, err := s.SanitizeCSS("p:hover{color:red}")
	if err != nil || out == "" {
		t.Fatalf("allowed pseudo-class was dropped: out=%q err=%v", out, err)
	}
	// :has is not in the full-page profile's allowlist.
	out, rep, err := s.SanitizeCSS("p:has(a){color:red}")
	if err != nil {
		t.Fatalf("SanitizeCSS: %v", err)
	}
	if out != "" {
		t.Errorf("disallowed pseudo-class survived: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Error("disallowed pseudo-class dropped without a removal")
	}
}

// target="_blank" must always end up with the full rel token set,
// even when the author supplied a rel of their own.
func TestTargetBlankAlwaysGetsNoopener(t *testing.T) {
	s := newFullPage(t)
	for _, in := range []string{
		`<a href="/x" target="_blank">x</a>`,
		`<a href="/x" rel="opener" target="_blank">x</a>`,
		`<a href="/x" target="_blank" rel="opener">x</a>`,
		`<a href="/x" rel="author" target="_blank">x</a>`,
		`<a href="/x" rel="" target="_blank">x</a>`,
	} {
		out, _, err := s.SanitizeHTML(in)
		if err != nil {
			t.Fatalf("SanitizeHTML(%q): %v", in, err)
		}
		for _, tok := range []string{"noopener", "noreferrer", "nofollow", "ugc"} {
			if !strings.Contains(out, tok) {
				t.Errorf("SanitizeHTML(%q) = %q: missing rel token %q", in, out, tok)
			}
		}
		if strings.Contains(out, `"opener`) || strings.Contains(out, ` opener`) {
			t.Errorf("SanitizeHTML(%q) = %q: kept rel=opener", in, out)
		}
	}
}

// Every candidate in a srcset must be validated, not just the
// attribute as a whole.
func TestSrcsetValidatesEachCandidate(t *testing.T) {
	p := profiles.ProfileEmbed()
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}
	// All candidates on-allowlist: kept.
	out, _, err := s.SanitizeHTML(`<source srcset="/assets/a.png 1x, /assets/b.png 2x">`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "srcset=") {
		t.Errorf("valid multi-candidate srcset was dropped: %q", out)
	}
	// One off-allowlist candidate: the whole attribute goes.
	for _, in := range []string{
		`<source srcset="https://evil.example.com/a.png 1x, https://evil.example.com/b.png 2x">`,
		`<source srcset="/assets/a.png 1x, https://evil.example.com/b.png 2x">`,
	} {
		out, rep, err := s.SanitizeHTML(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "evil.example.com") {
			t.Errorf("SanitizeHTML(%q) = %q: off-allowlist candidate survived", in, out)
		}
		if len(rep.Removed) == 0 {
			t.Errorf("SanitizeHTML(%q): dropped srcset without reporting it", in)
		}
	}
}

// An error must never come back with usable output: a caller that
// mishandles the error should get nothing, not partial markup that
// skipped the output verification pass.
func TestErrorsCarryNoOutput(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.MaxDOMDepth = 3
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := s.SanitizeHTML(strings.Repeat("<div>", 10) + "x" + strings.Repeat("</div>", 10))
	if !errors.Is(err, usercontent.ErrTooDeep) {
		t.Fatalf("want ErrTooDeep, got %v", err)
	}
	if out != "" {
		t.Errorf("depth error returned output %q; want empty", out)
	}

	big := strings.Repeat("<p>a</p>", 200000)
	if out, _, err := s.SanitizeHTML(big); !errors.Is(err, usercontent.ErrInputTooLarge) || out != "" {
		t.Errorf("oversized input: out=%q err=%v", out, err)
	}
}

// Prefix attributes must not leak from the tag they were declared
// on to every other tag.
func TestPrefixAttrsAreScopedToTheirTag(t *testing.T) {
	p := usercontent.Profile{
		Name:         "prefix-scope-v1",
		Version:      1,
		AllowedTags:  []string{"p", "div"},
		AllowedAttrs: map[string][]string{"div": {"data-gb-*"}, "p": {"class"}},
		URLSchemes:   []string{"https"},
		MaxHTMLBytes: 4096,
		MaxCSSBytes:  4096,
		MaxDOMDepth:  10,
		MaxDOMNodes:  100,
		CSS:          usercontent.CSSPolicy{AllowedDeclarations: []string{"color"}},
		CSP: usercontent.CSPPolicy{
			DefaultSrc: "'none'", ScriptSrc: "'none'", StyleSrc: "'self'",
			ImgSrc: "'self'", FrameSrc: "'none'", FormAction: "'none'", BaseURI: "'none'",
		},
	}
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := s.SanitizeHTML(`<div data-gb-animate="x"></div><p data-gb-animate="x"></p>`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `<div data-gb-animate="x">`) {
		t.Errorf("prefix attribute dropped from the tag that declared it: %q", out)
	}
	if strings.Contains(out, `<p data-gb-animate`) {
		t.Errorf("prefix attribute leaked to a tag that did not declare it: %q", out)
	}
}

// AssetPrefixes is an allowlist: an empty list permits no
// cross-origin assets at all.
func TestEmptyAssetPrefixesFailsClosed(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.AssetPrefixes = nil
	p.CSS.AssetPrefixes = nil
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := s.SanitizeHTML(`<img src="https://cdn.example.com/a.png">`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "cdn.example.com") {
		t.Errorf("empty AssetPrefixes allowed a cross-origin asset: %q", out)
	}
	// Same-origin relative assets stay usable.
	out, _, err = s.SanitizeHTML(`<img src="/a.png">`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `src="/a.png"`) {
		t.Errorf("empty AssetPrefixes blocked a same-origin asset: %q", out)
	}
}

// Comments are always stripped in v1; the profile field must say so
// rather than advertising a knob that does nothing.
func TestStripCommentsIsForced(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.StripComments = false
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatalf("New should normalize StripComments, not fail: %v", err)
	}
	if !s.Profile().StripComments {
		t.Error("normalize did not force StripComments")
	}
	out, rep, err := s.SanitizeHTML("<p>a<!-- c -->b</p>")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "<!--") || strings.Contains(out, "c ") {
		t.Errorf("comment survived: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Error("comment stripped without a removal")
	}
}

// Script hashes, when present, become the script-src value.
func TestScriptHashesDriveScriptSrc(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.CSP.ScriptHashes = []string{"'sha256-AAAA'"}
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}
	got := s.CSPHeaders()["Content-Security-Policy"]
	if !strings.Contains(got, "script-src 'sha256-AAAA'") {
		t.Errorf("script-src did not pick up the hash: %q", got)
	}
	if strings.Contains(got, "script-src 'none'") {
		t.Errorf("script-src still says 'none' alongside a hash: %q", got)
	}

	p.CSP.ScriptHashes = []string{"not-a-hash"}
	if _, err := usercontent.New(p); err == nil {
		t.Error("an invalid script hash was accepted")
	}
}

// The classic bypass set must stay closed.
func TestKnownBypassesStayClosed(t *testing.T) {
	s := newFullPage(t)
	for _, in := range []string{
		`<a href="java&#9;script:alert(1)">x</a>`,
		`<a href="java&#10;script:alert(1)">x</a>`,
		`<a href="JaVaScRiPt:alert(1)">x</a>`,
		`<a href="&#x6a;avascript:alert(1)">x</a>`,
		`<a href=" javascript:alert(1)">x</a>`,
		`<a href="//evil.example.com">x</a>`,
		`<img src="data:image/svg+xml,<svg onload=alert(1)>">`,
		`<svg><script>alert(1)</script></svg>`,
		`<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`,
		`<template><img src=x onerror=alert(1)></template>`,
		`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`,
		`<details ontoggle=alert(1) open>x</details>`,
		`<form action="https://evil.example.com"><input name=x>`,
		`<base href="https://evil.example.com">`,
		`<meta http-equiv="refresh" content="0;url=https://evil.example.com">`,
	} {
		out, _, err := s.SanitizeHTML(in)
		if err != nil {
			continue
		}
		low := strings.ToLower(out)
		for _, bad := range []string{"javascript:", "onerror", "ontoggle", "onload", "<script", "<svg", "<math", "<form", "<base", "<meta", "//evil.example.com"} {
			if strings.Contains(low, bad) {
				t.Errorf("SanitizeHTML(%q) = %q: leaked %q", in, out, bad)
			}
		}
	}
}

// A rejected @font-face source is reported as an external font, not
// as a generic external stylesheet, so the editor can explain it.
func TestFontFaceReportsExternalFont(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.CSS.AllowedAtRules = append(p.CSS.AllowedAtRules, "font-face")
	p.CSS.AllowedDeclarations = append(p.CSS.AllowedDeclarations, "src", "font-display")
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}

	out, rep, err := s.SanitizeCSS(`@font-face{font-family:"X";src:url(https://evil.example.com/f.woff2)}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "evil.example.com") {
		t.Errorf("off-allowlist font survived: %q", out)
	}
	var found bool
	for _, r := range rep.Removed {
		if r.Kind == usercontent.RemovalKindExternalFont {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an external_font removal, got %+v", rep.Removed)
	}

	// A same-origin font is kept, prelude and all.
	out, _, err = s.SanitizeCSS(`@font-face{font-family:"X";src:url(/assets/f.woff2)}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "/assets/f.woff2") {
		t.Errorf("same-origin font was dropped: %q", out)
	}
}

// HTML decodes a numeric character reference with or without its
// terminating semicolon. Both forms must face the character
// policy, or an unterminated one smuggles a control or bidi
// character past it.
func TestUnterminatedNumericEntitiesAreValidated(t *testing.T) {
	s := newFullPage(t)
	for _, in := range []string{
		"<p>&#1A</p>",    // U+0001 followed by 'A'
		"<p>&#x1A</p>",   // U+001A
		"<p>&#x202E</p>", // bidi override, unterminated
		"<p>&#8238</p>",  // the same, in decimal
		"<p>&#x200B</p>", // zero-width space
		`<a href="&#1A">x</a>`,
		"<p>&#1;</p>", // the terminated form still fails
		"<p>&#0;</p>",
	} {
		out, _, err := s.SanitizeHTML(in)
		if err == nil {
			t.Errorf("SanitizeHTML(%q) = %q: expected rejection, got none", in, out)
			continue
		}
		if !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("SanitizeHTML(%q): want ErrInvalidCharacter, got %v", in, err)
		}
		if out != "" {
			t.Errorf("SanitizeHTML(%q) returned output %q with an error", in, out)
		}
	}

	// "&#" with no digits is not a character reference, and a
	// reference to an allowed character still works.
	for _, in := range []string{"<p>a &# b</p>", "<p>&#65B</p>", "<p>&amp;</p>"} {
		if _, _, err := s.SanitizeHTML(in); err != nil {
			t.Errorf("SanitizeHTML(%q): unexpected rejection %v", in, err)
		}
	}
}

// Removing a node can bring two individually harmless characters
// together into a sequence the input validator rejects, which
// would otherwise be a way to smuggle one into the output.
func TestRemovalCannotForgeForbiddenSequences(t *testing.T) {
	s := newFullPage(t)
	for _, in := range []string{
		`\<!>0`,      // backslash + bogus comment + zero -> "\0"
		`\<!>x00`,    // -> "\x00"
		`\<!-- -->0`, // the same via a real comment
		`<p>\<!>0</p>`,
	} {
		out, _, err := s.SanitizeHTML(in)
		if err == nil {
			t.Errorf("SanitizeHTML(%q) = %q: expected rejection", in, out)
		}
		if out != "" {
			t.Errorf("SanitizeHTML(%q) returned output %q with an error", in, out)
		}
	}

	// A lone backslash, and a backslash not forming an escape, are
	// still fine.
	for _, in := range []string{`<p>C:\dir</p>`, `<p>a \ b</p>`, `<p>\</p>`} {
		if _, _, err := s.SanitizeHTML(in); err != nil {
			t.Errorf("SanitizeHTML(%q): unexpected rejection %v", in, err)
		}
	}
}
