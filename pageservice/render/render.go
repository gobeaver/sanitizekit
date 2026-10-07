// Package render builds the safe HTML document served at the
// public endpoint. The shell is rendered with html/template so
// the platform's own metadata is escaped; the user-authored body
// is inserted verbatim only after sanitization.
package render

import (
	"bytes"
	"html/template"
	"net/url"
	"strings"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
)

// Page is the data the page template needs.
type Page struct {
	Title          string
	Description    string
	Canonical      string
	OGImage        string
	SanitizedHTML  template.HTML
	SanitizedCSS   template.CSS
	ProfileName    string
	SpinnerMessage string
}

// shellTemplate is the trusted page shell. Every {{ }} value comes
// from the platform's own metadata (Title, Description, etc.),
// which is escaped by html/template. The user-author content is
// inserted through template.HTML / template.CSS, which are NOT
// re-escaped — they have already been sanitized upstream.
const shellTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<meta name="description" content="{{.Description}}">
<link rel="canonical" href="{{.Canonical}}">
<meta property="og:title" content="{{.Title}}">
<meta property="og:description" content="{{.Description}}">
<meta property="og:url" content="{{.Canonical}}">
<meta property="og:image" content="{{.OGImage}}">
<meta name="robots" content="index,follow">
<style>{{.SanitizedCSS}}</style>
</head>
<body class="gb-shell-page">
<main class="gb-shell-main">
{{.SanitizedHTML}}
</main>
<footer class="gb-shell-footer">
<a href="/report" class="gb-shell-report">Report this page</a>
</footer>
</body>
</html>`

var tmpl = template.Must(template.New("shell").Parse(shellTemplate))

// Render renders the page shell around a sanitized Page.
func Render(p Page) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SafeRender builds a Page from sanitizer outputs and returns the
// final HTML string. The sanitized HTML and CSS are wrapped in
// template.HTML / template.CSS to opt out of re-escaping.
func SafeRender(title, description, canonical, ogImage, sanitizedHTML, sanitizedCSS, profileName string) (string, error) {
	return Render(Page{
		Title:       title,
		Description: description,
		Canonical:   canonical,
		OGImage:     ogImage,
		// These two conversions are the package's single trust
		// boundary, and they are why the sanitizer's output
		// guarantees are stated as hard invariants: sanitized HTML
		// is inert and re-verified, and sanitized CSS contains no
		// literal '<' so it cannot close the <style> element below.
		// Anything reaching here that did not come from
		// usercontent.Sanitizer is a bug in the caller.
		SanitizedHTML: template.HTML(sanitizedHTML), // #nosec G203 -- pre-sanitized and re-verified
		SanitizedCSS:  template.CSS(sanitizedCSS),   // #nosec G203 -- pre-sanitized; contains no '<'
		ProfileName:   profileName,
	})
}

// CanonicalURL builds the canonical URL for a (host, slug) pair.
func CanonicalURL(host, slug string) string {
	u := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/r/" + slug,
	}
	return u.String()
}

// ValidateProfile reports whether a profile is acceptable to the
// sanitizer, without building one. Useful for validating operator
// configuration at startup.
func ValidateProfile(p usercontent.Profile) error {
	_, err := usercontent.New(p)
	return err
}

// HasShellNamespace returns true if the given id, class or CSS
// selector fragment falls inside the reserved shell namespace.
func HasShellNamespace(s string) bool {
	return strings.HasPrefix(s, usercontent.ShellNamespacePrefix)
}
