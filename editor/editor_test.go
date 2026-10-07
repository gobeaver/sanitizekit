package editor_test

import (
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/editor"
)

func TestEditor_PreviewURL(t *testing.T) {
	e := editor.NewEditor("http://localhost:8080/api/save", "pages.go-beaver.com", "dashboard.go-beaver.com")
	got := e.PreviewURL("alice-wedding", "abc123")
	if !strings.HasPrefix(got, "https://pages.go-beaver.com/preview/alice-wedding") {
		t.Errorf("unexpected preview URL: %s", got)
	}
	if !strings.Contains(got, "token=abc123") {
		t.Errorf("token missing: %s", got)
	}
}

func TestEditor_IframeHTML(t *testing.T) {
	e := editor.NewEditor("http://localhost:8080/api/save", "pages.go-beaver.com", "dashboard.go-beaver.com")
	got := e.IframeHTML("alice-wedding", "abc123")
	if !strings.Contains(got, "<iframe sandbox=") {
		t.Errorf("iframe sandbox missing: %s", got)
	}
	// Critical: no allow-scripts, no allow-same-origin.
	if strings.Contains(got, "allow-scripts") || strings.Contains(got, "allow-same-origin") {
		t.Errorf("iframe sandbox too permissive: %s", got)
	}
}

func TestEditor_ReportURL(t *testing.T) {
	e := editor.NewEditor("http://localhost:8080/api/save", "pages.go-beaver.com", "dashboard.go-beaver.com")
	got := e.ReportURL("https://pages.go-beaver.com/r/somepage")
	if !strings.HasPrefix(got, "https://dashboard.go-beaver.com/report") {
		t.Errorf("unexpected report URL: %s", got)
	}
}

func TestEditor_RenderTemplate(t *testing.T) {
	e := editor.NewEditor("http://localhost:8080/api/save", "pages.go-beaver.com", "dashboard.go-beaver.com")
	tmpl := e.RenderEditor("alice", "tok", "<h1>raw</h1>", "h1{}", "<h1>safe</h1>", "h1{x}", "modified 1 element")
	if !strings.Contains(tmpl.PreviewIframe, "alice") {
		t.Errorf("preview iframe missing slug: %s", tmpl.PreviewIframe)
	}
	if tmpl.SanitizedHTML != "<h1>safe</h1>" {
		t.Errorf("sanitized html wrong: %s", tmpl.SanitizedHTML)
	}
}
