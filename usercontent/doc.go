// Package usercontent is the security core of the user-content
// platform. It sanitizes untrusted HTML and CSS through a
// strict, profile-driven policy, emits the security headers
// every published page must carry, and refuses at construction
// time any profile that would weaken a non-negotiable invariant
// (no <script>, no <iframe>, no javascript: URLs, no external
// resources, CSP script-src 'none').
//
// The package is product-blind: it knows nothing about any
// consumer. A caller picks or derives a Profile (see
// usercontent/profiles for built-in starting points), passes it
// to New, and gets back a *Sanitizer that is safe for concurrent
// use. All HTTP services, editors, and AI pipelines in this
// repository route their input through this package — never
// around it.
//
// Basic usage:
//
//	import (
//	    "github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
//	    "github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
//	)
//
//	san, err := usercontent.New(profiles.ProfileFullPage())
//	if err != nil { /* profile violated an invariant */ }
//
//	html, report, err := san.SanitizeHTML("<p>ok</p><script>x</script>")
//	// html   == "<p>ok</p>"
//	// report.Removed describes what was stripped and why
//
//	csp := san.CSPHeaders()  // map[string]string of strict headers
//
// Subpackages — csp, css, html, profiles — exist because they
// each have a single, well-defined concern; the canonical
// GoBeaver package layout keeps them as flat files at this
// module's root in the next refactor.
package usercontent
