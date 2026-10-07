package editor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/editor"
)

// The preview iframe is the dashboard's strongest boundary against
// user content: an empty sandbox means no scripts, no same-origin
// access, no forms, no top-level navigation.
func TestIframeIsFullySandboxed(t *testing.T) {
	e := editor.NewEditor("https://svc.example.com/api/save", "pages.example.com", "dash.example.com")
	got := e.IframeHTML("my-page", "tok123")

	if !strings.Contains(got, `sandbox=""`) {
		t.Errorf("iframe is not sandboxed: %s", got)
	}
	for _, forbidden := range []string{"allow-scripts", "allow-same-origin", "allow-top-navigation", "allow-forms"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("sandbox grants %q: %s", forbidden, got)
		}
	}
	if !strings.Contains(got, "https://pages.example.com/preview/my-page") {
		t.Errorf("iframe does not point at the preview origin: %s", got)
	}
}

// The src is built from operator config and a token; it must be
// HTML-escaped, not Go-quoted, or a quote closes the attribute.
func TestIframeSrcIsHTMLEscaped(t *testing.T) {
	e := editor.NewEditor("", `pages.example.com`, "")
	got := e.IframeHTML(`x`, `" onload="alert(1)`)
	if strings.Contains(got, `onload="alert(1)"`) {
		t.Errorf("token broke out of the src attribute: %s", got)
	}
	if strings.Contains(got, `\"`) {
		t.Errorf("src was Go-quoted rather than HTML-escaped: %s", got)
	}
}

func TestPreviewAndReportURLs(t *testing.T) {
	e := editor.NewEditor("", "pages.example.com", "dash.example.com")

	got := e.PreviewURL("slug", "a b&c")
	if !strings.HasPrefix(got, "https://pages.example.com/preview/slug?token=") {
		t.Errorf("PreviewURL = %q", got)
	}
	if strings.Contains(got, " ") || strings.Contains(got, "&c") {
		t.Errorf("token was not query-escaped: %q", got)
	}

	rep := e.ReportURL("https://pages.example.com/r/slug")
	if !strings.HasPrefix(rep, "https://dash.example.com/report?url=") {
		t.Errorf("ReportURL = %q", rep)
	}
	if strings.Contains(rep, "://pages.example.com/r/slug") {
		t.Errorf("target URL was not escaped into the query: %q", rep)
	}
}

func TestSave_RequiresEndpoint(t *testing.T) {
	e := &editor.Editor{}
	if _, err := e.Save(context.Background(), editor.SaveRequest{}); err == nil {
		t.Error("Save with no endpoint should fail")
	}
}

func TestSave_SendsTokenAndDecodes(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sanitized_html": "<p>ok</p>",
			"draft_token":    "t1",
		})
	}))
	defer srv.Close()

	e := editor.NewEditor(srv.URL, "pages.example.com", "dash.example.com")
	e.SaveToken = "secret-token"
	resp, err := e.Save(context.Background(), editor.SaveRequest{ID: "p1", HTML: "<p>hi</p>"})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want bearer token", gotAuth)
	}
	if !strings.Contains(gotBody, `"id":"p1"`) {
		t.Errorf("request body = %q", gotBody)
	}
	if resp.SanitizedHTML != "<p>ok</p>" || resp.DraftToken != "t1" {
		t.Errorf("response not decoded: %+v", resp)
	}
}

func TestSave_NoTokenMeansNoHeader(t *testing.T) {
	var hadAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadAuth = r.Header["Authorization"]
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	e := editor.NewEditor(srv.URL, "p", "d")
	if _, err := e.Save(context.Background(), editor.SaveRequest{}); err != nil {
		t.Fatal(err)
	}
	if hadAuth {
		t.Error("an Authorization header was sent with no token configured")
	}
}

func TestSave_NonOKStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	e := editor.NewEditor(srv.URL, "p", "d")
	if _, err := e.Save(context.Background(), editor.SaveRequest{}); err == nil {
		t.Error("a 403 should surface as an error")
	}
}

// A hostile or broken page service must not be able to exhaust the
// dashboard by streaming an unbounded body.
func TestSave_ResponseIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sanitized_html":"`))
		chunk := strings.Repeat("A", 1<<16)
		for i := 0; i < (editor.MaxSaveResponseBytes/len(chunk))+8; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	e := editor.NewEditor(srv.URL, "p", "d")
	if _, err := e.Save(context.Background(), editor.SaveRequest{}); err == nil {
		t.Error("an oversized response should fail rather than being buffered whole")
	}
}

func TestRenderEditor(t *testing.T) {
	e := editor.NewEditor("https://svc/api/save", "pages.example.com", "dash.example.com")
	got := e.RenderEditor("slug", "tok", "<raw>", "raw{}", "<p>clean</p>", "p{}", "report text")
	if !strings.Contains(got.PreviewIframe, "sandbox=\"\"") {
		t.Error("RenderEditor did not embed the sandboxed iframe")
	}
	if got.RawHTML != "<raw>" || got.SanitizedHTML != "<p>clean</p>" || got.Report != "report text" {
		t.Errorf("RenderEditor dropped fields: %+v", got)
	}
}
