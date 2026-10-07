package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/middleware"
)

func ok() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// The host gate is what keeps user content off the dashboard
// origin, so it must match on the host alone — not on a port, and
// not on letter case an attacker controls.
func TestHostGate(t *testing.T) {
	h := middleware.HostGate("pages.example.com", "localhost")(ok())
	for _, tc := range []struct {
		host string
		want int
	}{
		{"pages.example.com", http.StatusOK},
		{"pages.example.com:8080", http.StatusOK},
		{"PAGES.EXAMPLE.COM", http.StatusOK},
		{"localhost:3000", http.StatusOK},
		{"evil.example.com", http.StatusForbidden},
		{"pages.example.com.evil.example.com", http.StatusForbidden},
		{"", http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodGet, "/r/x", http.NoBody)
		r.Host = tc.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("host %q: got %d, want %d", tc.host, w.Code, tc.want)
		}
	}
}

// An empty allowlist must reject everything rather than wave it
// through: a misconfigured gate should fail closed.
func TestHostGate_EmptyAllowlistFailsClosed(t *testing.T) {
	h := middleware.HostGate()(ok())
	r := httptest.NewRequest(http.MethodGet, "/r/x", http.NoBody)
	r.Host = "anything.example.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("empty allowlist: got %d, want 403", w.Code)
	}
}

// The user-content origin must never see the caller's session, so
// credentials are stripped before any handler runs.
func TestStripCredentials(t *testing.T) {
	var saw http.Header
	h := middleware.StripCredentials()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		saw = r.Header.Clone()
	}))
	r := httptest.NewRequest(http.MethodGet, "/r/x", http.NoBody)
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("Cookie", "session=secret")
	r.Header.Set("X-Keep", "kept")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if got := saw.Get("Authorization"); got != "" {
		t.Errorf("Authorization survived: %q", got)
	}
	if got := saw.Get("Cookie"); got != "" {
		t.Errorf("Cookie survived: %q", got)
	}
	if got := saw.Get("X-Keep"); got != "kept" {
		t.Errorf("unrelated header was dropped: %q", got)
	}
}

func TestDraftHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/preview/x", http.NoBody)

	w := httptest.NewRecorder()
	middleware.NoStoreForDrafts(ok()).ServeHTTP(w, r)
	if got := w.Header().Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Errorf("Cache-Control = %q", got)
	}

	w = httptest.NewRecorder()
	middleware.RobotsNoIndexForDrafts(ok()).ServeHTTP(w, r)
	if got := w.Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
		t.Errorf("X-Robots-Tag = %q", got)
	}
}
