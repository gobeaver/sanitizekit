// Example 03: tell the author what happened to their content.
//
// Silently deleting someone's markup is a bad experience and it hides
// sanitizer bugs. Every drop produces a Removal, so an editor can
// explain itself. This example groups a Report by kind and renders
// the sort of summary you would put next to a "Save" button.
//
//	go run ./examples/03-removal-report
package main

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// explain turns a RemovalKind into something an author can act on.
// The kinds are stable strings, so this mapping is yours to write and
// to translate.
func explain(k usercontent.RemovalKind) string {
	switch k {
	case usercontent.RemovalKindForbiddenElement:
		return "Tags that can run code or load other pages aren't allowed."
	case usercontent.RemovalKindEventHandler:
		return "Inline event handlers (onclick, onerror, …) aren't allowed."
	case usercontent.RemovalKindForbiddenURL:
		return "That link scheme isn't allowed. Use https:// or a relative path."
	case usercontent.RemovalKindExternalResource:
		return "Images must come from this site. Upload the file instead of hotlinking."
	case usercontent.RemovalKindForbiddenAttribute:
		return "That attribute isn't allowed on that tag."
	case usercontent.RemovalKindInlineStyle:
		return "Use the CSS box instead of a style=\"\" attribute."
	case usercontent.RemovalKindForbiddenCSSRule:
		return "That CSS rule or property isn't allowed."
	case usercontent.RemovalKindForbiddenCSSFunction:
		return "That CSS function isn't allowed."
	case usercontent.RemovalKindExternalCSS, usercontent.RemovalKindExternalFont:
		return "Stylesheets and fonts must come from this site."
	case usercontent.RemovalKindNamespaceCollision:
		return "That id or class is reserved by the page template."
	case usercontent.RemovalKindComment:
		return "HTML comments are stripped."
	case usercontent.RemovalKindMalformed:
		return "That fragment couldn't be parsed, so it was dropped."
	default:
		return "Removed by the content policy."
	}
}

func main() {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		log.Fatal(err)
	}

	const authorHTML = `<h1>Sale!</h1>
<p style="color:red">Big news <!-- internal note --></p>
<img src="https://cdn.example.net/banner.png" alt="banner">
<a href="javascript:void(0)" onclick="track()">Details</a>
<iframe src="https://ads.example.net/unit"></iframe>
<p id="gb-shell-header">Reserved id</p>`

	const authorCSS = `h1 { color: crimson; font-family: Futura, sans-serif }
@import url("https://fonts.example.net/futura.css");
.badge { position: fixed; top: 0; z-index: 9999 }
p { background: url("https://cdn.example.net/tile.png") }`

	htmlOut, htmlReport, err := s.SanitizeHTML(authorHTML)
	if err != nil {
		log.Fatalf("input rejected entirely: %v", err)
	}
	cssOut, cssReport, err := s.SanitizeCSS(authorCSS)
	if err != nil {
		log.Fatalf("css rejected entirely: %v", err)
	}

	// A Report is per-call, so combine them for a single summary.
	combined := htmlReport
	combined.Removed = append(combined.Removed, cssReport.Removed...)

	fmt.Printf("Saved. %d bytes in, %d bytes out.\n\n",
		len(authorHTML)+len(authorCSS), len(htmlOut)+len(cssOut))

	if len(combined.Removed) == 0 {
		fmt.Println("Nothing was changed.")
		return
	}

	// Group by kind so the author sees five explanations, not fifty
	// lines. Within a kind, list the distinct values that triggered it.
	byKind := map[usercontent.RemovalKind][]string{}
	for _, r := range combined.Removed {
		byKind[r.Kind] = append(byKind[r.Kind], r.Value)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)

	fmt.Printf("We changed %d thing(s) to keep your page safe:\n\n", len(combined.Removed))
	for _, k := range kinds {
		kind := usercontent.RemovalKind(k)
		fmt.Printf("  %s\n    %s\n", strings.ReplaceAll(k, "_", " "), explain(kind))
		for _, v := range dedupe(byKind[kind]) {
			fmt.Printf("      - %s\n", truncate(v, 60))
		}
		fmt.Println()
	}

	// Report.Modified is the quick check for "did anything change?",
	// e.g. to decide whether to show this panel at all.
	fmt.Printf("Report.Modified = %v\n", combined.Modified || len(combined.Removed) > 0)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
