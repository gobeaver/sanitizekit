package usercontent_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// =============================================================
// not-fixed.md #1: Stripped-subtree containment
// =============================================================

func TestNotFixed_SubtreeContainment_DivLeaked(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	// Exact input from not-fixed.md line 14
	in := `<form><div>LEAKED</form><p>x</p>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML: %v", err)
	}
	if strings.Contains(out, "LEAKED") {
		t.Errorf("subtree content LEAKED through: %q", out)
	}
}

func TestNotFixed_SubtreeContainment_SpanSecret(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	// Exact input from not-fixed.md line 18
	in := `<form><span>SECRET</div>VISIBLE</span></form>`
	out, _, err := s.SanitizeHTML(in)
	if err != nil {
		t.Fatalf("SanitizeHTML: %v", err)
	}
	if strings.Contains(out, "SECRET") || strings.Contains(out, "VISIBLE") {
		t.Errorf("subtree content leaked: %q", out)
	}
}

// =============================================================
// not-fixed.md #2: Invalid UTF-8
// =============================================================

func TestNotFixed_InvalidUTF8(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.SanitizeHTML("a\xff\xfe\xfdb")
	if err == nil {
		t.Error("expected error for invalid UTF-8, got nil")
	}
	if !errors.Is(err, usercontent.ErrInvalidUTF8) {
		t.Errorf("expected ErrInvalidUTF8, got %v", err)
	}
}

// =============================================================
// not-fixed.md #3: NUL rejection
// =============================================================

func TestNotFixed_NUL(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.SanitizeHTML("<p>a\x00b</p>")
	if err == nil {
		t.Error("expected error for NUL byte, got nil")
	}
	if !errors.Is(err, usercontent.ErrInvalidCharacter) {
		t.Errorf("expected ErrInvalidCharacter, got %v", err)
	}
}

// =============================================================
// not-fixed.md #4: Control character rejection
// =============================================================

func TestNotFixed_ControlCharacters(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []byte{0x01, 0x02, 0x08, 0x0B, 0x0C, 0x0E, 0x1F, 0x7F} {
		input := "a" + string([]byte{c}) + "b"
		_, _, err := s.SanitizeHTML(input)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("expected ErrInvalidCharacter for control char 0x%02X, got: %v", c, err)
		}
	}
}

// =============================================================
// not-fixed.md #5: Bidi override rejection
// =============================================================

func TestNotFixed_BidiOverride(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{0x202E, 0x202D, 0x202A, 0x202B, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069} {
		input := "test" + string(r) + "value"
		_, _, err := s.SanitizeHTML(input)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("expected ErrInvalidCharacter for bidi U+%04X, got: %v", r, err)
		}
	}
}

// =============================================================
// not-fixed.md #6: Invisible character rejection
// =============================================================

func TestNotFixed_InvisibleChars(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}

	// These MUST be rejected
	for _, r := range []rune{0x200B, 0xFEFF, 0x2060} {
		input := "test" + string(r) + "value"
		_, _, err := s.SanitizeHTML(input)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("expected ErrInvalidCharacter for invisible U+%04X, got: %v", r, err)
		}
	}

	// These MUST be preserved (ZWNJ/ZWJ for Arabic/Indic scripts)
	for _, r := range []rune{0x200C, 0x200D} {
		input := "test" + string(r) + "value"
		_, _, err := s.SanitizeHTML(input)
		if err != nil {
			t.Errorf("ZWNJ/ZWJ U+%04X should be preserved, got error: %v", r, err)
		}
	}
}

// =============================================================
// not-fixed.md #7: U+2028 / U+2029 rejection
// =============================================================

func TestNotFixed_LineParagraphSeparators(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{0x2028, 0x2029} {
		input := "Hello" + string(r) + "World"
		_, _, err := s.SanitizeHTML(input)
		if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
			t.Errorf("expected ErrInvalidCharacter for U+%04X, got: %v", r, err)
		}
	}
}

// =============================================================
// not-fixed.md #8: Homoglyph/IDN host rejection
// =============================================================

func TestNotFixed_HomoglyphIDN(t *testing.T) {
	p := profiles.ProfileFullPage()
	p.AssetPrefixes = []string{"https://google.com/"}
	s, err := usercontent.New(p)
	if err != nil {
		t.Fatal(err)
	}

	// Valid ASCII host should pass
	out, _, err := s.SanitizeHTML(`<img src="https://google.com/image.png">`)
	if err != nil {
		t.Fatalf("ASCII host should pass: %v", err)
	}
	if !strings.Contains(out, "google.com") {
		t.Errorf("expected google.com in output: %q", out)
	}

	// Cyrillic 'о' homoglyph should be rejected
	out2, rep, err := s.SanitizeHTML(`<img src="https://g` + "\u043e" + `ogle.com/image.png">`)
	if err != nil {
		t.Fatalf("unexpected infrastructure error: %v", err)
	}
	_ = out2
	if len(rep.Removed) == 0 {
		t.Error("expected removal for homoglyph host, got none")
	}
}

// =============================================================
// not-fixed.md #9: CSS tests via SanitizeCSS directly
// =============================================================

func TestNotFixed_CSS_AtRules(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	out, rep, err := s.SanitizeCSS(`@import url("https://evil.com/s.css"); p{color:red}`)
	if err != nil {
		t.Fatalf("SanitizeCSS: %v", err)
	}
	if strings.Contains(out, "@import") {
		t.Errorf("@import survived: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Error("expected removal for @import")
	}
}

func TestNotFixed_CSS_ForbiddenFunctions(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := s.SanitizeCSS(`div{width:expression(alert(1))}`)
	if err != nil {
		t.Fatalf("SanitizeCSS: %v", err)
	}
	if strings.Contains(out, "expression") {
		t.Errorf("expression() survived: %q", out)
	}
}

func TestNotFixed_CSS_ShellNamespace(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	out, rep, err := s.SanitizeCSS(`.gb-shell-field{display:none}`)
	if err != nil {
		t.Fatalf("SanitizeCSS: %v", err)
	}
	if strings.Contains(out, ".gb-shell-field") {
		t.Errorf("shell namespace selector survived: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Error("expected removal for shell namespace")
	}
}

func TestNotFixed_CSS_AttributeSelector(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	out, rep, err := s.SanitizeCSS(`input[value^="a"]{background:url(//evil)}`)
	if err != nil {
		t.Fatalf("SanitizeCSS: %v", err)
	}
	if strings.Contains(out, "[") {
		t.Errorf("attribute selector survived: %q", out)
	}
	if len(rep.Removed) == 0 {
		t.Error("expected removal for attribute selector")
	}
}

// =============================================================
// not-fixed.md #10: Shell namespace in CSS
// (covered by TestNotFixed_CSS_ShellNamespace above)
// =============================================================

// =============================================================
// upgrading-the-project.md: CSS declaration tightening
// position, z-index, transform, pointer-events, opacity
// =============================================================

func TestUpgrading_CSS_UIRedressing(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}

	// These dangerous properties should be stripped
	dangerous := []string{
		`div{position:fixed}`,
		`div{position:absolute}`,
		`div{z-index:999999}`,
		`div{pointer-events:none}`,
	}
	for _, css := range dangerous {
		out, _, err := s.SanitizeCSS(css)
		if err != nil {
			t.Fatalf("SanitizeCSS(%q): %v", css, err)
		}
		// Check if the dangerous property survived
		if strings.Contains(out, "position") || strings.Contains(out, "z-index") || strings.Contains(out, "pointer-events") {
			t.Errorf("dangerous CSS property survived: input=%q output=%q", css, out)
		}
	}
}

func TestUpgrading_CSS_UniversalSelector(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := s.SanitizeCSS(`*{display:none}`)
	if err != nil {
		t.Fatalf("SanitizeCSS: %v", err)
	}
	// Universal selector should be blocked
	if strings.Contains(out, "display:none") || strings.Contains(out, "display: none") {
		t.Errorf("universal selector * rule survived: %q", out)
	}
}

// =============================================================
// upgrading-the-project.md: Output re-parse verification
// =============================================================

func TestUpgrading_OutputReParseVerification(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	// Safe input should produce safe output
	out, _, err := s.SanitizeHTML(`<p>Hello <strong>world</strong></p>`)
	if err != nil {
		t.Fatalf("SanitizeHTML safe input: %v", err)
	}
	if !strings.Contains(out, "Hello") {
		t.Errorf("safe output missing content: %q", out)
	}
}

// =============================================================
// upgrading-the-project.md: Idempotence
// =============================================================

func TestUpgrading_Idempotence(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{
		`<p>Hello <strong>world</strong></p>`,
		`<h1>Title</h1><p>Body text</p>`,
		`<ul><li>one</li><li>two</li></ul>`,
		`<a href="https://example.com">link</a>`,
	}
	for _, in := range inputs {
		out1, _, err := s.SanitizeHTML(in)
		if err != nil {
			t.Fatalf("SanitizeHTML first pass: %v", err)
		}
		out2, _, err := s.SanitizeHTML(out1)
		if err != nil {
			t.Fatalf("SanitizeHTML second pass: %v", err)
		}
		if out1 != out2 {
			t.Errorf("not idempotent:\n  in:  %q\n  1st: %q\n  2nd: %q", in, out1, out2)
		}
	}
}

// =============================================================
// upgrading-the-project.md: Charset validation in CSS too
// =============================================================

func TestNotFixed_CSS_InvalidUTF8(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.SanitizeCSS("p{color:\xff\xfe}")
	if err == nil || !errors.Is(err, usercontent.ErrInvalidUTF8) {
		t.Errorf("expected ErrInvalidUTF8 for CSS, got: %v", err)
	}
}

func TestNotFixed_CSS_BidiInCSS(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.SanitizeCSS("p{content:'\u202E'}")
	if err == nil || !errors.Is(err, usercontent.ErrInvalidCharacter) {
		t.Errorf("expected ErrInvalidCharacter for bidi in CSS, got: %v", err)
	}
}

// =============================================================
// Embed profile CSS declaration allowlist must match fullpage's
// UI-redressing restrictions. Found during pre-publish review:
// embedTextDeclarations() had drifted from fullPageCSS() and
// still allowed position/z-index/pointer-events/transform.
// =============================================================

func TestEmbedProfile_UIRedressing(t *testing.T) {
	s, err := usercontent.New(usercontent.DefaultEmbedProfile())
	if err != nil {
		t.Fatal(err)
	}

	dangerous := []string{
		`div{position:fixed}`,
		`div{position:absolute}`,
		`div{z-index:999999}`,
		`div{pointer-events:none}`,
	}
	for _, css := range dangerous {
		out, _, err := s.SanitizeCSS(css)
		if err != nil {
			t.Fatalf("SanitizeCSS(%q): %v", css, err)
		}
		if strings.Contains(out, "position") || strings.Contains(out, "z-index") || strings.Contains(out, "pointer-events") {
			t.Errorf("dangerous CSS property survived in embed profile: input=%q output=%q", css, out)
		}
	}
}
