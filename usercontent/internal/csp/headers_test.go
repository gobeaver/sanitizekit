package csp

import (
	"strings"
	"testing"
)

func TestBuild_FullPage(t *testing.T) {
	headers := Build(Policy{
		DefaultSrc:     "'none'",
		ScriptSrc:      "'none'",
		StyleSrc:       "'self' 'unsafe-inline'",
		ImgSrc:         "'self' data:",
		FontSrc:        "'self'",
		FrameSrc:       "'none'",
		FrameAncestors: "'self' https://dashboard.example.com",
		FormAction:     "'none'",
		BaseURI:        "'none'",
		MediaSrc:       "'none'",
	})
	hdr, ok := headers["Content-Security-Policy"]
	if !ok {
		t.Fatal("Content-Security-Policy header missing")
	}
	for _, must := range []string{
		"default-src 'none'",
		"script-src 'none'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self'",
		"frame-src 'none'",
		"frame-ancestors 'self' https://dashboard.example.com",
		"form-action 'none'",
		"base-uri 'none'",
		"media-src 'none'",
	} {
		if !strings.Contains(hdr, must) {
			t.Errorf("CSP missing %q\nheader was: %s", must, hdr)
		}
	}
}

func TestBuild_HashOnlyScriptSrc(t *testing.T) {
	headers := Build(Policy{
		DefaultSrc: "'none'",
		ScriptSrc:  "'sha256-abc' 'sha384-def'",
		StyleSrc:   "'self'",
		ImgSrc:     "'self'",
		FrameSrc:   "'none'",
		FormAction: "'none'",
		BaseURI:    "'none'",
	})
	hdr := headers["Content-Security-Policy"]
	if !strings.Contains(hdr, "'sha256-abc'") {
		t.Errorf("expected hash in CSP, got %s", hdr)
	}
}

func TestBuild_EmptyPolicy(t *testing.T) {
	headers := Build(Policy{})
	if v, ok := headers["Content-Security-Policy"]; ok {
		t.Errorf("expected no header for empty policy, got %q", v)
	}
}
