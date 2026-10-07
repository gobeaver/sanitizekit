package usercontent_test

import (
	"strings"
	"testing"

	nethtml "golang.org/x/net/html"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// htmlSeeds are the shapes most likely to break a tokenizer-driven
// sanitizer: unbalanced tags, foreign content, raw-text elements
// and entity-encoded scheme separators.
var htmlSeeds = []string{
	"",
	"<p>hello</p>",
	"<p><script>alert(1)</script></p>",
	`<a href="javascript:alert(1)">x</a>`,
	`<a href="java&#9;script:alert(1)">x</a>`,
	`<img src=x onerror=alert(1)>`,
	"<svg><foreignObject><p>x</p></foreignObject></svg>",
	"<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
	"<template><p>x</p></template>",
	"<noscript><p title=\"</noscript><img src=x>\">",
	"<div><div><div><p>deep</p>",
	"</p></div></span>",
	"<p a=\"<\" b='>' c=`d`>",
	"<!-- <script> -->",
	"<!DOCTYPE html><p>x</p>",
	"<a href=\"/x\" rel=opener target=_blank>x</a>",
	"<source srcset=\"/assets/a.png 1x, https://evil.example.com/b.png 2x\">",
}

// cssSeeds cover the constructs that decide whether sanitized CSS
// can escape the <style> element it is inlined into.
var cssSeeds = []string{
	"",
	"p{color:red}",
	"@media screen{p{color:red}}",
	"@media screen and (min-width:600px),print{p{color:red}}",
	"@supports (display:grid){p{color:red}}",
	"@import url('https://evil.example.com/x.css');",
	"</style><img src=x onerror=alert(1)>{color:red}",
	`p{color:"</style><img src=x>"}`,
	"p{color:red;--x:</style><b>}",
	"p{background:url(https://evil.example.com/a.png)}",
	"p{width:expression(alert(1))}",
	"input[value^=a]{background:url(https://evil.example.com/?c=a)}",
	"* { color: red }",
	".gb-shell-main{color:red}",
	"/* unterminated",
	"p{color:red;",
	"@media{",
	"p{content:'a;b'}",
	strings.Repeat("@media screen{", 20) + "p{color:red}" + strings.Repeat("}", 20),
}

// FuzzSanitizeHTML asserts the sanitizer's hard output invariants
// for arbitrary input: it must not panic, must never emit a script
// or a javascript: URL, and must be idempotent — re-sanitizing its
// own output must be a no-op, which is what makes the output safe
// to store and re-serve.
func FuzzSanitizeHTML(f *testing.F) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range htmlSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		out, _, err := s.SanitizeHTML(data)
		if err != nil {
			// Errors must never come with usable output.
			if out != "" {
				t.Errorf("error returned output: %q -> %q (%v)", data, out, err)
			}
			return
		}
		if reason := unsafeInParsedHTML(t, out); reason != "" {
			t.Errorf("unsafe output: %q -> %q (%s)", data, out, reason)
		}
		again, _, err := s.SanitizeHTML(out)
		if err != nil {
			t.Errorf("sanitized output was rejected on re-sanitize: %q -> %q (%v)", data, out, err)
			return
		}
		if again != out {
			t.Errorf("not idempotent: %q -> %q -> %q", data, out, again)
		}
	})
}

// FuzzSanitizeCSS asserts the CSS invariants: no panic, never a
// literal '<' in the output (which would let the CSS close the
// <style> element it is inlined into), and idempotence.
func FuzzSanitizeCSS(f *testing.F) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range cssSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		out, _, err := s.SanitizeCSS(data)
		if err != nil {
			if out != "" {
				t.Errorf("error returned output: %q -> %q (%v)", data, out, err)
			}
			return
		}
		if strings.IndexByte(out, '<') >= 0 {
			t.Errorf("'<' in sanitized CSS: %q -> %q", data, out)
		}
		again, _, err := s.SanitizeCSS(out)
		if err != nil {
			t.Errorf("sanitized output was rejected on re-sanitize: %q -> %q (%v)", data, out, err)
			return
		}
		if again != out {
			t.Errorf("not idempotent: %q -> %q -> %q", data, out, again)
		}
	})
}

// unsafeInParsedHTML re-parses sanitized HTML the way a browser
// would and reports the first thing that must never be there. It
// checks the DOM rather than the string: "javascript:" appearing
// in escaped *text* is inert, and a substring match on the output
// would flag it while missing a scheme hidden by entity encoding.
func unsafeInParsedHTML(t *testing.T, out string) string {
	t.Helper()
	doc, err := nethtml.Parse(strings.NewReader(out))
	if err != nil {
		return "output does not parse: " + err.Error()
	}
	var reason string
	var walk func(*nethtml.Node)
	walk = func(n *nethtml.Node) {
		if reason != "" {
			return
		}
		if n.Type == nethtml.ElementNode {
			if forbiddenFuzzElements[strings.ToLower(n.Data)] {
				reason = "forbidden element <" + n.Data + ">"
				return
			}
			for _, a := range n.Attr {
				key := strings.ToLower(a.Key)
				if strings.HasPrefix(key, "on") {
					reason = "event handler " + a.Key
					return
				}
				switch key {
				case "href", "src", "srcset", "poster", "cite", "formaction", "action", "srcdoc":
					v := strings.ToLower(strings.TrimSpace(a.Val))
					// Browsers strip C0 controls and spaces from URLs
					// before resolving the scheme, so strip them here
					// too before looking at the prefix.
					v = strings.Map(func(r rune) rune {
						if r <= 0x20 || r == 0x7f {
							return -1
						}
						return r
					}, v)
					if strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "vbscript:") ||
						strings.HasPrefix(v, "data:text/html") {
						reason = "dangerous scheme in " + a.Key
						return
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return reason
}

var forbiddenFuzzElements = map[string]bool{
	"script": true, "iframe": true, "frame": true, "frameset": true,
	"object": true, "embed": true, "applet": true, "form": true,
	"input": true, "button": true, "select": true, "textarea": true,
	"link": true, "meta": true, "base": true, "style": true,
	"svg": true, "math": true, "video": true, "audio": true,
	"dialog": true, "slot": true, "template": true, "noscript": true,
	"noframes": true, "noembed": true, "marquee": true, "details": true,
	"keygen": true, "xmp": true, "plaintext": true, "listing": true,
}
