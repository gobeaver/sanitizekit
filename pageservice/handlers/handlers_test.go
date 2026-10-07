package handlers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/handlers"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/storage"
)

func newTestServer(t *testing.T) *handlers.Server {
	t.Helper()
	s, err := handlers.DefaultServer()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func saveDraft(t *testing.T, srv *handlers.Server, id, slug, html, css string, publish bool) handlers.SaveResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"id":       id,
		"owner_id": "u1",
		"product":  "invitations",
		"host":     "pages.go-beaver.com",
		"slug":     slug,
		"html":     html,
		"css":      css,
		"publish":  publish,
	})
	req := httptest.NewRequest("POST", "/api/save", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	srv.HandleSave(w, req)
	if w.Code != 200 {
		t.Fatalf("save: code=%d body=%s", w.Code, w.Body.String())
	}
	var resp handlers.SaveResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHandleSave_StripsScriptAndPersists(t *testing.T) {
	srv := newTestServer(t)
	resp := saveDraft(t, srv, "p1", "alice-wedding", "<h1>Hi</h1><script>alert(1)</script>", "h1 { color: red; }", true)
	if resp.Page.SanitizerVersion == 0 {
		t.Errorf("sanitizer version not set")
	}
	if !strings.Contains(resp.SanitizedHTML, "<h1>Hi</h1>") {
		t.Errorf("sanitized html missing h1: %q", resp.SanitizedHTML)
	}
	if strings.Contains(resp.SanitizedHTML, "<script") {
		t.Errorf("script leaked: %q", resp.SanitizedHTML)
	}
	if !resp.Report.Modified {
		t.Errorf("expected modified report")
	}
	if resp.DraftToken == "" {
		t.Errorf("expected draft token")
	}
}

func TestHandleRender_ServesWithCSP(t *testing.T) {
	srv := newTestServer(t)
	saveDraft(t, srv, "r1", "demo", "<h1>Hello</h1>", "h1 { color: blue; }", true)

	req := httptest.NewRequest("GET", "/r/demo", http.NoBody)
	req.Host = "pages.go-beaver.com"
	w := httptest.NewRecorder()
	srv.HandleRender(w, req)
	if w.Code != 200 {
		t.Fatalf("render: code=%d body=%s", w.Code, w.Body.String())
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'none'") {
		t.Errorf("CSP missing script-src 'none': %s", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP missing default-src 'none': %s", csp)
	}
	if !strings.Contains(w.Body.String(), "Hello") {
		t.Errorf("body missing content: %s", w.Body.String())
	}
}

func TestHandleRender_404OnMissing(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/r/nonexistent", http.NoBody)
	req.Host = "pages.go-beaver.com"
	w := httptest.NewRecorder()
	srv.HandleRender(w, req)
	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandlePreview_RequiresToken(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/preview/x", http.NoBody)
	w := httptest.NewRecorder()
	srv.HandlePreview(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandlePreview_AppliesNoStore(t *testing.T) {
	srv := newTestServer(t)
	resp := saveDraft(t, srv, "d1", "draft1", "<h1>Preview</h1>", "", false)

	req := httptest.NewRequest("GET", "/preview/draft1?token="+resp.DraftToken, http.NoBody)
	req.Host = "pages.go-beaver.com"
	w := httptest.NewRecorder()
	srv.HandlePreview(w, req)
	if w.Code != 200 {
		t.Fatalf("preview: code=%d body=%s", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("missing no-store: %s", cc)
	}
	if ri := w.Header().Get("X-Robots-Tag"); !strings.Contains(ri, "noindex") {
		t.Errorf("missing noindex: %s", ri)
	}
}

func TestHandleSave_RejectsScriptTagInput(t *testing.T) {
	srv := newTestServer(t)
	resp := saveDraft(t, srv, "p2", "x", "<script>alert(1)</script>", "", false)
	if strings.Contains(resp.SanitizedHTML, "<script") {
		t.Errorf("script leaked into sanitized HTML: %q", resp.SanitizedHTML)
	}
}

func TestHandleSave_DraftTokenDistinct(t *testing.T) {
	srv := newTestServer(t)
	resp := saveDraft(t, srv, "p3", "y", "<p>x</p>", "", false)
	if resp.DraftToken == "" {
		t.Fatal("no draft token")
	}
	if len(resp.DraftToken) < 8 {
		t.Errorf("token too short: %q", resp.DraftToken)
	}
}

func TestHandlePreview_RejectsTamperedToken(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/preview/x?token=invalid.token", http.NoBody)
	w := httptest.NewRecorder()
	srv.HandlePreview(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// Round-trip: save -> render via the URL the editor would use.
func TestRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	saveDraft(t, srv, "rt1", "roundtrip", "<h1>OK</h1>", "h1 { color: green; }", true)

	req := httptest.NewRequest("GET", "/r/roundtrip", http.NoBody)
	req.Host = "pages.go-beaver.com"
	w := httptest.NewRecorder()
	srv.HandleRender(w, req)
	if w.Code != 200 {
		t.Fatalf("render: %d", w.Code)
	}
	doc := w.Body.String()
	if !strings.Contains(doc, "OK") {
		t.Errorf("missing content: %s", doc)
	}
	if !strings.Contains(doc, "color:") {
		t.Errorf("missing CSS: %s", doc)
	}
	body, _ := io.ReadAll(w.Body)
	_ = body
}

// Save rejects external asset URLs.
func TestHandleSave_RejectsExternalAsset(t *testing.T) {
	srv := newTestServer(t)
	resp := saveDraft(t, srv, "rt2", "external", `<img src="https://evil.com/pixel.png">`, "", false)
	if strings.Contains(resp.SanitizedHTML, "evil.com") {
		t.Errorf("external asset leaked: %s", resp.SanitizedHTML)
	}
}

// Round-trip via the in-memory store directly.
func TestStore_RoundTrip(t *testing.T) {
	store := storage.NewMemoryStore()
	p := &storage.Page{
		ID:            "x",
		OwnerID:       "u1",
		Host:          "pages.go-beaver.com",
		Slug:          "hello",
		SanitizedHTML: "<h1>hi</h1>",
		Status:        "published",
	}
	if err := store.Put(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetByHostSlug(t.Context(), "pages.go-beaver.com", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if got.SanitizedHTML != "<h1>hi</h1>" {
		t.Errorf("got %q", got.SanitizedHTML)
	}
}
