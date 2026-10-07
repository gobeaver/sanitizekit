// Example 02: write your own profile, and see what you cannot do.
//
// A Profile is the only way to change sanitizer behaviour — there is
// no constructor that takes arbitrary policy fragments. The point of
// that design is the second half of this example: a profile can only
// ever be *narrower* than the baseline. Attempts to widen it past the
// package's invariants are rejected by New(), at startup, with an
// error naming the field.
//
//	go run ./examples/02-custom-profile
package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
)

// commentProfile is a deliberately tiny policy: the vocabulary you
// would allow in a comment box. No images, no layout, no CSS beyond
// a couple of text properties.
func commentProfile() usercontent.Profile {
	return usercontent.Profile{
		Name:    "comment-v1",
		Version: 1,

		AllowedTags: []string{"p", "br", "strong", "em", "code", "a", "ul", "ol", "li", "blockquote"},
		AllowedAttrs: map[string][]string{
			"*": {"class"},
			"a": {"href"},
		},

		// Relative links and https only. No mailto, no tel.
		URLSchemes:       []string{"https"},
		SameSiteRelative: true,

		// No images at all, so no asset origins are needed. An empty
		// AssetPrefixes is an empty allowlist: it permits nothing.
		AssetPrefixes:   nil,
		AllowDataImages: false,

		// Comments should not open new tabs on the reader's behalf.
		AllowTargetBlank: false,

		MaxHTMLBytes: 16 * 1024,
		MaxCSSBytes:  4 * 1024,
		MaxDOMDepth:  8,
		MaxDOMNodes:  200,

		CSS: usercontent.CSSPolicy{
			AllowedDeclarations:        []string{"color", "font-style", "font-weight", "text-decoration"},
			AllowedPseudoClasses:       []string{":hover"},
			DisallowAttributeSelectors: true,
		},

		CSP: usercontent.CSPPolicy{
			DefaultSrc: "'none'",
			ScriptSrc:  "'none'",
			StyleSrc:   "'self'",
			ImgSrc:     "'none'",
			FrameSrc:   "'none'",
			FormAction: "'none'",
			BaseURI:    "'none'",
		},
	}
}

func main() {
	s, err := usercontent.New(commentProfile())
	if err != nil {
		log.Fatal(err)
	}

	out, report, err := s.SanitizeHTML(
		`<p>Nice post! See <a href="https://example.com" target="_blank">this</a>.</p>` +
			`<img src="/tracker.gif"><div class="layout">not allowed here</div>`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("=== comment profile output ===")
	fmt.Println(out)
	for _, r := range report.Removed {
		fmt.Printf("  removed %-22s %-24q %s\n", r.Kind, r.Value, r.Reason)
	}

	fmt.Println("\n=== what a profile is not allowed to do ===")
	for _, attempt := range []struct {
		what string
		edit func(*usercontent.Profile)
	}{
		{"allow <script>", func(p *usercontent.Profile) {
			p.AllowedTags = append(p.AllowedTags, "script")
		}},
		{"allow an onclick handler", func(p *usercontent.Profile) {
			p.AllowedAttrs["a"] = append(p.AllowedAttrs["a"], "onclick")
		}},
		{"allow the javascript: scheme", func(p *usercontent.Profile) {
			p.URLSchemes = append(p.URLSchemes, "javascript")
		}},
		{"allow @import in CSS", func(p *usercontent.Profile) {
			p.CSS.AllowedAtRules = append(p.CSS.AllowedAtRules, "import")
		}},
		{"allow expression() in CSS", func(p *usercontent.Profile) {
			p.CSS.AllowedFunctions = append(p.CSS.AllowedFunctions, "expression")
		}},
		{"loosen CSP to 'unsafe-inline'", func(p *usercontent.Profile) {
			p.CSP.ScriptSrc = "'unsafe-inline'"
		}},
		{"drop 'none' from base-uri", func(p *usercontent.Profile) {
			p.CSP.BaseURI = "'self'"
		}},
	} {
		p := commentProfile()
		attempt.edit(&p)

		_, err := usercontent.New(p)
		switch {
		case err == nil:
			fmt.Printf("  %-34s ACCEPTED  <- this would be a bug\n", attempt.what)
		case errors.Is(err, usercontent.ErrInvalidProfile):
			fmt.Printf("  %-34s rejected: %v\n", attempt.what, err)
		default:
			fmt.Printf("  %-34s rejected: %v\n", attempt.what, err)
		}
	}

	// The lesson: safety here is not a convention you have to
	// remember. A profile that would weaken it cannot be constructed,
	// so the mistake surfaces at startup instead of in production.
}
