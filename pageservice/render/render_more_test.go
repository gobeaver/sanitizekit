package render_test

import (
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/render"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// The shell's own metadata is attacker-adjacent too: a slug or a
// title comes from the page record. html/template must escape it,
// and it must not be able to break out of the attribute or element
// it lands in.
func TestShellMetadataIsEscaped(t *testing.T) {
	hostile := `" onload="alert(1)`
	doc, err := render.SafeRender(
		hostile+"<script>alert(1)</script>",
		hostile,
		"https://pages.example.com/r/"+hostile,
		hostile,
		"<p>body</p>", "p{color:red}", "fullpage-v1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, "<script>") {
		t.Errorf("metadata injected a script tag:\n%s", doc)
	}
	if strings.Contains(doc, `onload="alert(1)"`) {
		t.Errorf("metadata broke out of an attribute:\n%s", doc)
	}
	// The user-content region must still contain the sanitized body.
	if !strings.Contains(doc, "<p>body</p>") {
		t.Error("sanitized body missing from the rendered page")
	}
}

// The shell must always ship the structure the CSP and the
// stylesheet depend on.
func TestShellStructure(t *testing.T) {
	doc, err := render.SafeRender("t", "d", "https://x/y", "", "<p>hi</p>", "p{color:red}", "fullpage-v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<!DOCTYPE html>", `<html lang="en">`, `<meta charset="utf-8">`,
		`<body class="gb-shell-page">`, `<main class="gb-shell-main">`, "<style>p{color:red}</style>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	if n := strings.Count(doc, "</style>"); n != 1 {
		t.Errorf("expected exactly one </style>, got %d", n)
	}
}

// Sanitized CSS is inserted as template.CSS, which opts out of
// escaping. That is only safe because sanitized CSS contains no
// '<' — this pins the pairing so neither side drifts alone.
func TestSanitizedCSSCannotCloseTheStyleElement(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		`</style><img src=x onerror=alert(1)>{color:red}`,
		`p{color:"</style><svg onload=alert(1)>"}`,
		`p{color:red;--x:</style>}`,
	} {
		css, _, err := s.SanitizeCSS(in)
		if err != nil {
			continue // rejected outright is a pass
		}
		doc, err := render.SafeRender("t", "d", "https://x/y", "", "", css, "fullpage-v1")
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(doc, "</style>"); n != 1 {
			t.Errorf("input %q produced %d </style> in the page:\n%s", in, n, doc)
		}
	}
}

func TestCanonicalURL(t *testing.T) {
	for _, tc := range []struct{ host, slug, want string }{
		{"pages.example.com", "my-page", "https://pages.example.com/r/my-page"},
		{"pages.example.com", "a b", "https://pages.example.com/r/a%20b"},
	} {
		if got := render.CanonicalURL(tc.host, tc.slug); got != tc.want {
			t.Errorf("CanonicalURL(%q, %q) = %q, want %q", tc.host, tc.slug, got, tc.want)
		}
	}
}

func TestHasShellNamespace(t *testing.T) {
	for in, want := range map[string]bool{
		"gb-shell-main": true,
		"gb-shell-":     true,
		"mine":          false,
		"":              false,
		"x-gb-shell-":   false,
	} {
		if got := render.HasShellNamespace(in); got != want {
			t.Errorf("HasShellNamespace(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidateProfile(t *testing.T) {
	if err := render.ValidateProfile(profiles.ProfileFullPage()); err != nil {
		t.Errorf("built-in profile rejected: %v", err)
	}
	// A profile that tries to allow a forbidden element must not
	// pass, whichever door it comes through.
	bad := profiles.ProfileFullPage()
	bad.AllowedTags = append(bad.AllowedTags, "script")
	if err := render.ValidateProfile(bad); err == nil {
		t.Error("a profile allowing <script> was accepted")
	}
}
