package usercontent_test

import (
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

func TestSanitizeCSS_DirectPolicyRules(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}

	// 1. @import forbidden
	inImport := `@import url("https://evil.com/style.css"); p { color: red; }`
	outImport, repImport, err := s.SanitizeCSS(inImport)
	if err != nil {
		t.Fatalf("SanitizeCSS error: %v", err)
	}
	if strings.Contains(outImport, "@import") {
		t.Errorf("@import survived: %q", outImport)
	}
	if len(repImport.Removed) == 0 {
		t.Errorf("expected removal for @import")
	}

	// 2. Forbidden functions (expression, behavior, -moz-binding)
	inFunc := `div { width: expression(alert(1)); behavior: url(x.htc); -moz-binding: url(x.xml); }`
	outFunc, repFunc, err := s.SanitizeCSS(inFunc)
	if err != nil {
		t.Fatalf("SanitizeCSS error: %v", err)
	}
	if strings.Contains(outFunc, "expression") || strings.Contains(outFunc, "behavior") || strings.Contains(outFunc, "-moz-binding") {
		t.Errorf("forbidden function survived: %q", outFunc)
	}
	if len(repFunc.Removed) == 0 {
		t.Errorf("expected removal for forbidden CSS functions")
	}

	// 3. Disallowed attribute selectors
	inAttrSel := `input[type="text"] { color: red; }`
	outAttrSel, repAttrSel, err := s.SanitizeCSS(inAttrSel)
	if err != nil {
		t.Fatalf("SanitizeCSS error: %v", err)
	}
	if strings.Contains(outAttrSel, "[") || strings.Contains(outAttrSel, "]") {
		t.Errorf("attribute selector survived: %q", outAttrSel)
	}
	if len(repAttrSel.Removed) == 0 {
		t.Errorf("expected removal for attribute selector")
	}

	// 4. Shell namespace protection
	inShell := `.gb-shell-field { display: none; }`
	outShell, repShell, err := s.SanitizeCSS(inShell)
	if err != nil {
		t.Fatalf("SanitizeCSS error: %v", err)
	}
	if strings.Contains(outShell, ".gb-shell-field") {
		t.Errorf("shell namespace selector survived: %q", outShell)
	}
	if len(repShell.Removed) == 0 {
		t.Errorf("expected removal for shell namespace selector")
	}
}
