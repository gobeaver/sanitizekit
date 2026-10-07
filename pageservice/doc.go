// Package pageservice is the M2 layer of the user-content
// platform: the small Go HTTP service that renders user-authored
// pages behind strict CSP and origin isolation.
//
// The service runs on a dedicated user-content hostname
// (e.g. pages.go-beaver.com) that holds no credentials, ignores
// Authorization, and serves only public user content. A
// Host-based route gate keeps dashboard and API routes off
// this origin even though they may share the same binary.
//
// Save flow:
//
//	request → auth → rate-limit → size check →
//	  SanitizeHTML / SanitizeCSS (usercontent) →
//	  store raw + sanitized + sanitizer_version + profile →
//	  return Report
//
// Serve flow (re-sanitize on version bump, never serve an
// obsolete sanitizer_version):
//
//	stored version == current ? serve : re-sanitize : serve
//
// Public assets must match the profile's AssetPrefixes; the
// service never proxies arbitrary external resources. Drafts
// use short-lived signed tokens and are served with
// X-Robots-Tag: noindex + Referrer-Policy: no-referrer.
//
// Configuration is loaded via GetConfig (BEAVER_PAGESERVICE_*
// env vars). Builder.WithPrefix overrides the prefix for
// multi-instance deployments. The package main entry point lives
// in cmd/pageservice, not in this directory.
//
// Sub-packages:
//
//	pageservice/handlers — HTTP route handlers (the public API)
//	pageservice/middleware — Host gate, credential stripping
//	pageservice/render — html/template shell rendering
//	pageservice/storage — Page model + MemoryStore
//	pageservice/drafts — signed draft preview tokens
package pageservice
