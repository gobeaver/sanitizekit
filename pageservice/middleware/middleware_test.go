package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostGate(t *testing.T) {
	gate := HostGate("example.com")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/", http.NoBody)
	gate(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	recForbidden := httptest.NewRecorder()
	reqForbidden := httptest.NewRequest("GET", "http://evil.com/", http.NoBody)
	gate(next).ServeHTTP(recForbidden, reqForbidden)
	if recForbidden.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", recForbidden.Code)
	}
}
