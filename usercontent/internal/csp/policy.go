// Package csp builds the Content-Security-Policy HTTP header
// from a Policy. The package is the single source of truth for
// the platform's CSP text; the page service applies the header
// verbatim.
//
// The header is constructed from canonical directives documented
// in the platform specification §7. The package intentionally
// does not import the usercontent package, so that the parent
// package can call into it without an import cycle.
package csp

import "strings"

// Policy is the CSP configuration consumed by Build. It mirrors
// usercontent.CSPPolicy field-for-field so the parent package can
// convert at the boundary without crossing the import graph.
type Policy struct {
	DefaultSrc     string
	ScriptSrc      string
	ScriptHashes   []string
	StyleSrc       string
	ImgSrc         string
	FontSrc        string
	FrameSrc       string
	FrameAncestors string
	FormAction     string
	BaseURI        string
	MediaSrc       string
}

// Build returns the response headers implied by the CSP policy.
// The map always contains a "Content-Security-Policy" key; the
// caller should compose it with the other immutable headers
// (Referrer-Policy, etc.) itself.
func Build(p Policy) map[string]string {
	out := make(map[string]string, 1)

	value := joinNonEmpty("; ", pairs(p)...)
	if value != "" {
		out["Content-Security-Policy"] = value
	}
	return out
}

// pairs returns the canonical (directive, value) pairs in the
// order browsers prefer to read them.
func pairs(p Policy) [][2]string {
	parts := make([][2]string, 0, 12)
	if p.DefaultSrc != "" {
		parts = append(parts, [2]string{"default-src", p.DefaultSrc})
	}
	if src := scriptSrc(p); src != "" {
		parts = append(parts, [2]string{"script-src", src})
	}
	if p.StyleSrc != "" {
		parts = append(parts, [2]string{"style-src", p.StyleSrc})
	}
	if p.ImgSrc != "" {
		parts = append(parts, [2]string{"img-src", p.ImgSrc})
	}
	if p.FontSrc != "" {
		parts = append(parts, [2]string{"font-src", p.FontSrc})
	}
	if p.MediaSrc != "" {
		parts = append(parts, [2]string{"media-src", p.MediaSrc})
	}
	if p.FrameSrc != "" {
		parts = append(parts, [2]string{"frame-src", p.FrameSrc})
	}
	if p.FrameAncestors != "" {
		parts = append(parts, [2]string{"frame-ancestors", p.FrameAncestors})
	}
	if p.FormAction != "" {
		parts = append(parts, [2]string{"form-action", p.FormAction})
	}
	if p.BaseURI != "" {
		parts = append(parts, [2]string{"base-uri", p.BaseURI})
	}
	return parts
}

// scriptSrc returns the script-src value. When ScriptHashes is
// non-empty the hashes are the value: 'none' alongside other
// sources is ignored by browsers, so the two cannot be combined.
func scriptSrc(p Policy) string {
	if len(p.ScriptHashes) == 0 {
		return p.ScriptSrc
	}
	quoted := make([]string, 0, len(p.ScriptHashes))
	for _, h := range p.ScriptHashes {
		if h == "" {
			continue
		}
		if h[0] != '\'' {
			h = "'" + h + "'"
		}
		quoted = append(quoted, h)
	}
	if len(quoted) == 0 {
		return p.ScriptSrc
	}
	return strings.Join(quoted, " ")
}

// joinNonEmpty joins "name value" pairs with the given separator,
// skipping empty entries.
func joinNonEmpty(sep string, pairs ...[2]string) string {
	if len(pairs) == 0 {
		return ""
	}
	// estimate capacity
	n := 0
	for _, p := range pairs {
		if p[0] != "" && p[1] != "" {
			n += len(p[0]) + 1 + len(p[1]) + len(sep)
		}
	}
	buf := make([]byte, 0, n)
	first := true
	for _, p := range pairs {
		if p[0] == "" || p[1] == "" {
			continue
		}
		if !first {
			buf = append(buf, sep...)
		}
		first = false
		buf = append(buf, p[0]...)
		buf = append(buf, ' ')
		buf = append(buf, p[1]...)
	}
	return string(buf)
}
