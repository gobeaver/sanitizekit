// Package middleware contains HTTP middleware for the page service:
// host gate, credentials-stripping, rate-limiting, and security
// headers.
package middleware

import (
	"net/http"
	"strings"
)

// HostGate returns a middleware that only allows requests whose
// Host header is in the allowlist. This enforces the per-product
// user-content origin isolation: pages.go-beaver.com can serve
// content, but the dashboard origin can never serve user markup
// as the document.
func HostGate(allowedHosts ...string) func(http.Handler) http.Handler {
	set := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		set[strings.ToLower(h)] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.ToLower(r.Host)
			// strip port
			if i := strings.IndexByte(host, ':'); i >= 0 {
				host = host[:i]
			}
			if !set[host] {
				http.Error(w, "forbidden host", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// StripCredentials removes any incoming Authorization and
// Cookie headers. The user-content origin must not be
// authenticated to the user's session; tokens are checked
// separately via the draft-token mechanism.
func StripCredentials() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del("Authorization")
			r.Header.Del("Cookie")
			next.ServeHTTP(w, r)
		})
	}
}

// NoStoreForDrafts adds Cache-Control: no-store for draft preview
// responses, since drafts may change at any time.
func NoStoreForDrafts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		next.ServeHTTP(w, r)
	})
}

// RobotsNoIndexForDrafts sets X-Robots-Tag: noindex on draft
// responses so search engines don't crawl preview URLs.
func RobotsNoIndexForDrafts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		next.ServeHTTP(w, r)
	})
}
