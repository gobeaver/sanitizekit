package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/handlers"
	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/storage"
)

func quietServer(t *testing.T) *handlers.Server {
	t.Helper()
	s, err := handlers.DefaultServer()
	if err != nil {
		t.Fatalf("DefaultServer: %v", err)
	}
	s.Logger = log.New(&bytes.Buffer{}, "", 0)
	return s
}

func post(t *testing.T, s *handlers.Server, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/save", bytes.NewReader(b))
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.HandleSave(w, r)
	return w
}

// A Server with no Authorizer must refuse every save. An
// unauthenticated write endpoint would let anyone replace any page.
func TestSaveRefusedWithoutAuthorizer(t *testing.T) {
	s := quietServer(t)
	s.Authorizer = nil
	w := post(t, s, handlers.SaveRequest{ID: "p1", Host: "localhost", Slug: "s1", HTML: "<p>x</p>"})
	if w.Code != http.StatusForbidden {
		t.Errorf("save with no Authorizer: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestSaveHonoursAuthorizer(t *testing.T) {
	s := quietServer(t)
	var sawOwner string
	s.Authorizer = handlers.SaveAuthorizerFunc(func(_ *http.Request, req handlers.SaveRequest) error {
		sawOwner = req.OwnerID
		if req.OwnerID != "owner-1" {
			return handlers.ErrUnauthorized
		}
		return nil
	})

	if w := post(t, s, handlers.SaveRequest{ID: "p1", OwnerID: "someone-else", Host: "localhost", Slug: "s1"}); w.Code != http.StatusForbidden {
		t.Errorf("denied save: got %d, want 403", w.Code)
	}
	if sawOwner != "someone-else" {
		t.Errorf("authorizer did not see the request body: %q", sawOwner)
	}
	if w := post(t, s, handlers.SaveRequest{ID: "p1", OwnerID: "owner-1", Host: "localhost", Slug: "s1", HTML: "<p>x</p>"}); w.Code != http.StatusOK {
		t.Errorf("allowed save: got %d (%s), want 200", w.Code, w.Body.String())
	}
}

// The body must be bounded before it is buffered.
func TestSaveRejectsOversizedBody(t *testing.T) {
	s := quietServer(t)
	body := `{"id":"p1","host":"localhost","slug":"s1","html":"` + strings.Repeat("a", handlers.MaxSaveBytes+1024) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/save", strings.NewReader(body))
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.HandleSave(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: got %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestSaveValidatesSlugAndHost(t *testing.T) {
	s := quietServer(t)
	for _, tc := range []struct {
		name string
		req  handlers.SaveRequest
	}{
		{"slug with slash", handlers.SaveRequest{ID: "p", Host: "localhost", Slug: "a/b"}},
		{"slug with dotdot", handlers.SaveRequest{ID: "p", Host: "localhost", Slug: ".."}},
		{"slug with uppercase", handlers.SaveRequest{ID: "p", Host: "localhost", Slug: "AB"}},
		{"unserved host", handlers.SaveRequest{ID: "p", Host: "evil.example.com", Slug: "s1"}},
		{"missing id", handlers.SaveRequest{Host: "localhost", Slug: "s1"}},
	} {
		if w := post(t, s, tc.req); w.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", tc.name, w.Code)
		}
	}
}

// Concurrent renders of a stale page must not race on the stored
// record. The store hands out copies precisely so they cannot.
func TestConcurrentRenderIsRaceFree(t *testing.T) {
	s := quietServer(t)
	if err := s.Store.Put(context.Background(), &storage.Page{
		ID: "p1", Host: "localhost", Slug: "s1", Status: "published",
		RawHTML: "<p>hi</p>", RawCSS: "p{color:red}",
		SanitizerVersion: 0, ProfileName: s.Profile.Name,
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/r/s1", http.NoBody)
			r.Host = "localhost"
			w := httptest.NewRecorder()
			s.HandleRender(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("render: got %d", w.Code)
			}
		}()
	}
	wg.Wait()
}

// A store must never hand out a pointer into its own state.
func TestStoreReturnsCopies(t *testing.T) {
	st := storage.NewMemoryStore()
	ctx := context.Background()
	orig := &storage.Page{ID: "p1", Host: "h", Slug: "s", DraftTokens: []string{"t1"}}
	if err := st.Put(ctx, orig); err != nil {
		t.Fatal(err)
	}

	// Mutating the value passed to Put must not change the store.
	orig.Slug = "mutated"
	orig.DraftTokens[0] = "mutated"

	got, err := st.GetByID(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Slug != "s" || got.DraftTokens[0] != "t1" {
		t.Errorf("store aliased the caller's page: %+v", got)
	}

	// Mutating a value returned by Get must not change the store.
	got.Slug = "mutated-again"
	again, err := st.GetByID(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Slug != "s" {
		t.Errorf("store handed out its own pointer: %+v", again)
	}
}

// If re-sanitization fails on serve, the handler must fail rather
// than serve content the current policy has not approved.
func TestRenderFailsClosedWhenResanitizeFails(t *testing.T) {
	s := quietServer(t)
	s.Profile.Version = 99 // force the lazy re-sanitize path
	// RawHTML that the sanitizer rejects outright (a NUL byte).
	if err := s.Store.Put(context.Background(), &storage.Page{
		ID: "p1", Host: "localhost", Slug: "s1", Status: "published",
		RawHTML:          "<p>ok\x00</p>",
		SanitizedHTML:    "<p>stale but harmless</p>",
		SanitizerVersion: 1, ProfileName: s.Profile.Name,
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/r/s1", http.NoBody)
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.HandleRender(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("failed re-sanitize: got %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "stale but harmless") {
		t.Error("served stale content after re-sanitization failed")
	}
}

// A preview token is bound to one page; it must not open another
// page's slug, or the same page on a different host.
func TestPreviewTokenIsBound(t *testing.T) {
	s := quietServer(t)
	ctx := context.Background()
	for _, p := range []*storage.Page{
		{ID: "p1", Host: "localhost", Slug: "one", Status: "draft", ProfileName: s.Profile.Name},
		{ID: "p2", Host: "localhost", Slug: "two", Status: "draft", ProfileName: s.Profile.Name},
	} {
		if err := s.Store.Put(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	tok := s.Signer.Sign("p1")

	get := func(path, host string) int {
		r := httptest.NewRequest(http.MethodGet, path+"?token="+tok, http.NoBody)
		r.Host = host
		w := httptest.NewRecorder()
		s.HandlePreview(w, r)
		return w.Code
	}
	if code := get("/preview/one", "localhost"); code != http.StatusOK {
		t.Errorf("valid preview: got %d, want 200", code)
	}
	if code := get("/preview/two", "localhost"); code != http.StatusNotFound {
		t.Errorf("token reused for another slug: got %d, want 404", code)
	}
	if code := get("/preview/one", "pages.go-beaver.com"); code != http.StatusNotFound {
		t.Errorf("token reused on another host: got %d, want 404", code)
	}

	r := httptest.NewRequest(http.MethodGet, "/preview/one", http.NoBody)
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.HandlePreview(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token: got %d, want 401", w.Code)
	}
}

// Drafts must never be reachable through the public render route.
func TestRenderServesOnlyPublishedPages(t *testing.T) {
	s := quietServer(t)
	if err := s.Store.Put(context.Background(), &storage.Page{
		ID: "p1", Host: "localhost", Slug: "s1", Status: "draft",
		SanitizedHTML: "<p>secret</p>", SanitizerVersion: s.Profile.Version,
		ProfileName: s.Profile.Name,
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/r/s1", http.NoBody)
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.HandleRender(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("draft on public route: got %d, want 404", w.Code)
	}
}

// Every served page must carry the full security header set.
func TestSecurityHeadersOnEveryServedPage(t *testing.T) {
	s := quietServer(t)
	if err := s.Store.Put(context.Background(), &storage.Page{
		ID: "p1", Host: "localhost", Slug: "s1", Status: "published",
		SanitizedHTML: "<p>x</p>", SanitizerVersion: s.Profile.Version,
		ProfileName: s.Profile.Name,
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/r/s1", http.NoBody)
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.HandleRender(w, r)

	for _, h := range []string{
		"Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options",
		"Permissions-Policy", "Cross-Origin-Opener-Policy",
	} {
		if w.Header().Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'none'", "frame-src 'none'", "form-action 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q missing %q", csp, want)
		}
	}
}

// The end-to-end path: a hostile page saved and then served must
// come back with nothing executable in it.
func TestSaveThenRenderIsInert(t *testing.T) {
	s := quietServer(t)
	hostile := handlers.SaveRequest{
		ID: "p1", Host: "localhost", Slug: "s1", Publish: true,
		HTML: `<h1>Hi</h1><script>alert(1)</script><img src=x onerror=alert(1)>` +
			`<a href="javascript:alert(1)">x</a><iframe src="https://evil.example.com"></iframe>`,
		CSS: `</style><img src=x onerror=alert(1)>{color:red}` + "\n" +
			`p{background:url(https://evil.example.com/x.png)}`,
	}
	if w := post(t, s, hostile); w.Code != http.StatusOK {
		t.Fatalf("save: got %d (%s)", w.Code, w.Body.String())
	}

	r := httptest.NewRequest(http.MethodGet, "/r/s1", http.NoBody)
	r.Host = "localhost"
	w := httptest.NewRecorder()
	s.HandleRender(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("render: got %d", w.Code)
	}
	body := strings.ToLower(w.Body.String())
	for _, bad := range []string{"<script", "onerror", "javascript:", "<iframe", "evil.example.com"} {
		if strings.Contains(body, bad) {
			t.Errorf("served page contains %q:\n%s", bad, w.Body.String())
		}
	}
	// The shell's own <style> element must still be intact and empty
	// of injected markup.
	if n := strings.Count(body, "</style>"); n != 1 {
		t.Errorf("expected exactly one </style>, found %d", n)
	}
}

func TestSaveRejectsWrongMethod(t *testing.T) {
	s := quietServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/save", http.NoBody)
	w := httptest.NewRecorder()
	s.HandleSave(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/save: got %d, want 405", w.Code)
	}
	if got := w.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow header: got %q, want POST", got)
	}
}

func TestNewServerRejectsMissingDependencies(t *testing.T) {
	s := quietServer(t)
	if _, err := handlers.NewServer(nil, s.Signer, s.Profile); err == nil {
		t.Error("NewServer accepted a nil store")
	}
	if _, err := handlers.NewServer(storage.NewMemoryStore(), nil, s.Profile); err == nil {
		t.Error("NewServer accepted a nil signer")
	}
}

// An authorizer error must not leak into the response body.
func TestAuthorizerErrorIsNotLeaked(t *testing.T) {
	s := quietServer(t)
	s.Authorizer = handlers.SaveAuthorizerFunc(func(*http.Request, handlers.SaveRequest) error {
		return fmt.Errorf("%w: internal detail user=%s db=%s", handlers.ErrUnauthorized, "alice", "prod-1")
	})
	w := post(t, s, handlers.SaveRequest{ID: "p1", Host: "localhost", Slug: "s1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "internal detail") {
		t.Errorf("authorizer error leaked to the client: %q", w.Body.String())
	}
}
