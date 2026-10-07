package usercontent

import (
	"strconv"
)

// Report describes what a sanitizer changed. The package emits
// structured Removals so the editor can explain to authors why
// their content was modified ("we removed a <script> tag and 2
// external images") rather than silently mangling input.
//
// Reports are part of the editor UX in M3.
type Report struct {
	// Modified is true if the sanitizer changed anything. Reports
	// with Modified == false have an empty Removed slice.
	Modified bool

	// Removed lists every distinct removal or rewrite the sanitizer
	// performed on this input.
	Removed []Removal

	// InputBytes is the byte length of the input that was sanitized.
	// Useful for surfacing size warnings in the editor.
	InputBytes int

	// OutputBytes is the byte length of the sanitized output.
	OutputBytes int
}

// RemovalKind classifies what was removed/rewritten. The string
// values are stable for editor UI and should be treated as an
// enum-like API.
type RemovalKind string

const (
	// RemovalKindForbiddenElement is a tag that is always forbidden
	// (script, iframe, form, etc.).
	RemovalKindForbiddenElement RemovalKind = "forbidden_element"

	// RemovalKindEventHandler is an on*= attribute.
	RemovalKindEventHandler RemovalKind = "event_handler"

	// RemovalKindForbiddenURL is a URL with a dangerous scheme
	// (javascript:, vbscript:, data:text/html, ...) or to an
	// external host not on the asset prefix list.
	RemovalKindForbiddenURL RemovalKind = "forbidden_url"

	// RemovalKindExternalResource is an asset URL pointing off-origin.
	RemovalKindExternalResource RemovalKind = "external_resource"

	// RemovalKindForbiddenAttribute is an attribute that is not in
	// the allowlist for its tag.
	RemovalKindForbiddenAttribute RemovalKind = "forbidden_attribute"

	// RemovalKindInlineStyle is a style="..." attribute (v1 policy).
	RemovalKindInlineStyle RemovalKind = "inline_style"

	// RemovalKindForbiddenCSSRule is a CSS @-rule we don't allow
	// (@import, @charset, etc.).
	RemovalKindForbiddenCSSRule RemovalKind = "forbidden_css_rule"

	// RemovalKindForbiddenCSSFunction is a CSS function we don't
	// allow (expression(), behavior, -moz-binding, url() to an
	// external host).
	RemovalKindForbiddenCSSFunction RemovalKind = "forbidden_css_function"

	// RemovalKindExternalCSS is a CSS resource URL pointing off-origin.
	RemovalKindExternalCSS RemovalKind = "external_css"

	// RemovalKindExternalFont is a CSS @font-face src pointing off-origin.
	RemovalKindExternalFont RemovalKind = "external_font"

	// RemovalKindComment is an HTML comment (including conditional
	// comments).
	RemovalKindComment RemovalKind = "comment"

	// RemovalKindNamespaceCollision is an id/class that collides
	// with the shell namespace (gb-shell-*) or other reserved
	// namespaces.
	RemovalKindNamespaceCollision RemovalKind = "namespace_collision"

	// RemovalKindMalformed is a malformed input fragment that was
	// skipped rather than repaired.
	RemovalKindMalformed RemovalKind = "malformed"
)

// Removal records one sanitizer decision.
type Removal struct {
	// Kind classifies the removal (see RemovalKind).
	Kind RemovalKind

	// Value is the offending text the sanitizer saw. For element
	// removals, this is the tag name. For attribute removals, the
	// attribute name. For URL removals, the URL value. For comments,
	// the comment contents (truncated).
	Value string

	// Reason is a human-readable explanation. Suitable for surfacing
	// directly in the editor UI.
	Reason string

	// Line is a 1-based line number when the parser can determine
	// one. 0 means "unknown".
	Line int
}

// Summary returns a one-line human summary of the report such as
// "removed 1 script tag, 2 event handlers, 1 external image".
// Editor UI should call this for the banner message.
func (r Report) Summary() string {
	if !r.Modified || len(r.Removed) == 0 {
		return "no changes"
	}
	// group by Kind -> count
	counts := make(map[RemovalKind]int)
	for _, rem := range r.Removed {
		counts[rem.Kind]++
	}
	// canonical order for stable UI
	order := []RemovalKind{
		RemovalKindForbiddenElement,
		RemovalKindEventHandler,
		RemovalKindForbiddenURL,
		RemovalKindExternalResource,
		RemovalKindForbiddenAttribute,
		RemovalKindInlineStyle,
		RemovalKindForbiddenCSSRule,
		RemovalKindForbiddenCSSFunction,
		RemovalKindExternalCSS,
		RemovalKindExternalFont,
		RemovalKindNamespaceCollision,
		RemovalKindComment,
		RemovalKindMalformed,
	}
	labels := map[RemovalKind]string{
		RemovalKindForbiddenElement:     "forbidden element",
		RemovalKindEventHandler:         "event handler",
		RemovalKindForbiddenURL:         "forbidden URL",
		RemovalKindExternalResource:     "external resource",
		RemovalKindForbiddenAttribute:   "forbidden attribute",
		RemovalKindInlineStyle:          "inline style",
		RemovalKindForbiddenCSSRule:     "forbidden CSS rule",
		RemovalKindForbiddenCSSFunction: "forbidden CSS function",
		RemovalKindExternalCSS:          "external CSS resource",
		RemovalKindExternalFont:         "external font",
		RemovalKindNamespaceCollision:   "namespace collision",
		RemovalKindComment:              "comment",
		RemovalKindMalformed:            "malformed input",
	}
	parts := make([]string, 0, len(counts))
	for _, k := range order {
		if n, ok := counts[k]; ok && n > 0 {
			parts = append(parts, fmtCount(n, labels[k]))
		}
	}
	return joinComma(parts)
}

func fmtCount(n int, label string) string {
	if n == 1 {
		return "1 " + label
	}
	return strconv.Itoa(n) + " " + label + "s"
}

func joinComma(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		out := parts[0]
		for i := 1; i < len(parts)-1; i++ {
			out += ", " + parts[i]
		}
		return out + ", and " + parts[len(parts)-1]
	}
}
