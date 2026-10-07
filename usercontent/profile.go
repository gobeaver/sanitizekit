package usercontent

import (
	"fmt"
	"sort"
	"strings"
)

// CSSPolicy configures CSS sanitization.
type CSSPolicy struct {
	// AllowedAtRules is the explicit allowlist of @-rules
	// (e.g. "media", "keyframes", "supports", "font-face",
	// "container"). "@import" and "@charset" are always denied.
	AllowedAtRules []string

	// AllowedDeclarations is the explicit allowlist of property
	// names ("color", "font-size", "animation", ...). Empty means
	// no properties allowed (use profile defaults).
	AllowedDeclarations []string

	// AllowedFunctions is the allowlist of CSS function names
	// (e.g. "rgb", "rgba", "hsl", "calc", "var"). "url" is
	// handled separately; it is allowed only when the URL passes
	// origin validation.
	AllowedFunctions []string

	// AllowedPseudoClasses is the allowlist of pseudo-classes
	// (":hover", ":focus", ...). We block attribute-selector
	// exfiltration by also requiring selector-shape validation.
	AllowedPseudoClasses []string

	// AssetPrefixes is the same-origin URL prefix allowlist for
	// url() and @font-face src. Same semantics as the HTML
	// AssetPrefixes.
	AssetPrefixes []string

	// AllowDataImages mirrors Profile.AllowDataImages for CSS.
	AllowDataImages bool

	// DisallowAttributeSelectors rejects any selector that uses
	// square-bracket attribute matching. This is the strongest
	// defense against CSS exfiltration; consumers can tighten it
	// per profile.
	DisallowAttributeSelectors bool
}

// CSPPolicy configures the response headers emitted by the page
// service. The package guarantees certain invariants: script-src
// may only be 'none' or an explicit list of hashes supplied by
// the consumer's own shell.
type CSPPolicy struct {
	// DefaultSrc is the default-src directive value. Almost
	// always "'none'".
	DefaultSrc string

	// ScriptSrc is the script-src directive. Must be "'none'" or
	// a list of explicit hashes ('sha256-...', 'sha384-...',
	// 'sha512-...'); never 'unsafe-inline', never 'self', never
	// arbitrary URLs.
	ScriptSrc string

	// ScriptHashes is the optional list of allowed script hashes,
	// each of the form "sha256-<base64>" / "sha384-<base64>" /
	// "sha512-<base64>", with or without surrounding quotes.
	//
	// When it is non-empty it *becomes* the script-src value: a
	// browser ignores 'none' when a source list also names other
	// sources, so the two cannot be combined. This is how the
	// trusted declarative runtime is enabled — see runtime.CSPHash.
	ScriptHashes []string

	// StyleSrc is the style-src directive. ProfileFullPage uses
	// "'self' 'unsafe-inline'". This is acceptable because the
	// inline styles are sanitizer-produced, but v1 may tighten
	// to a hash of the single shell-emitted <style> block.
	StyleSrc string

	// ImgSrc is the img-src directive. ProfileFullPage uses
	// "'self' data:".
	ImgSrc string

	// FontSrc is the font-src directive. ProfileFullPage uses
	// "'self'".
	FontSrc string

	// FrameSrc is the frame-src directive. ProfileFullPage uses
	// "'none'".
	FrameSrc string

	// FrameAncestors is the frame-ancestors directive. ProfileFullPage
	// uses "'self' <dashboard-origin>". Empty means "'self'".
	FrameAncestors string

	// FormAction is the form-action directive. ProfileFullPage uses
	// "'none'".
	FormAction string

	// BaseURI is the base-uri directive. ProfileFullPage uses
	// "'none'".
	BaseURI string

	// MediaSrc is the media-src directive. ProfileFullPage uses
	// "'none'".
	MediaSrc string
}

// Profile configures a Sanitizer. Profiles are the only way to
// customize the sanitizer; there is no constructor that takes
// arbitrary policy fragments. Every Profile must satisfy the
// package's non-negotiable invariants (see validate).
type Profile struct {
	// Name is a stable identifier for this profile ("fullpage-v1",
	// "embed-v1", "invitation-v1"). Stored alongside sanitized
	// content so future re-sanitization can pick the right policy.
	Name string

	// Version is bumped on every change to the policy. The render
	// path re-sanitizes lazily when stored < current.
	Version int

	// AllowedTags is the explicit tag allowlist. Empty means no
	// tags allowed (the profile must provide at least some).
	AllowedTags []string

	// AllowedAttrs maps each allowed tag to its allowed attributes.
	// "*" is a wildcard for "all allowed tags". Attribute names
	// should be lowercase. Prefix-friendly attributes:
	//   - "aria-*" matches any aria- attribute
	//   - "data-gb-*" matches declarative runtime attributes
	AllowedAttrs map[string][]string

	// URLSchemes is the explicit URL scheme allowlist for href/src.
	// examples: "https", "mailto", "tel". Relative URLs are always
	// permitted when same-site is true.
	URLSchemes []string

	// AssetPrefixes is the allowlist of URL prefixes that assets
	// (src/srcset/poster/url()) may come from. A prefix beginning
	// with "/" constrains same-origin paths; an absolute prefix
	// such as "https://cdn.example.com/" permits that origin.
	// Anything that matches no prefix is rejected.
	//
	// An empty AssetPrefixes therefore permits no external assets
	// at all, and (with SameSiteRelative) any same-origin path.
	// The list is an allowlist, not an optional filter: leaving it
	// empty never widens what is accepted.
	AssetPrefixes []string

	// AllowDataImages permits data:image/* assets. When true, the
	// sanitizer restricts to the data image allowlist (PNG, JPEG,
	// WebP, GIF). No SVG.
	AllowDataImages bool

	// SameSiteRelative allows relative URLs (no scheme) in href/src.
	// Nearly always true.
	SameSiteRelative bool

	// AllowTargetBlank controls whether the sanitizer permits
	// target="_blank" on <a>. When true, the link is force-tagged
	// with rel="noopener noreferrer nofollow ugc". When false,
	// target="..." is stripped entirely.
	AllowTargetBlank bool

	// MaxHTMLBytes is the maximum input HTML size in bytes
	// (post-decode). Default 300 KiB.
	MaxHTMLBytes int

	// MaxCSSBytes is the maximum input CSS size in bytes
	// (post-decode). Default 150 KiB.
	MaxCSSBytes int

	// MaxDOMDepth is the maximum allowed DOM nesting depth.
	// Default 40.
	MaxDOMDepth int

	// MaxDOMNodes is the maximum allowed DOM node count.
	// Default 5000.
	MaxDOMNodes int

	// CSS is the CSS policy. Embedded struct so policies can be
	// swapped out without breaking the public API.
	CSS CSSPolicy

	// CSP is the content security policy applied to pages rendered
	// under this profile.
	CSP CSPPolicy

	// StrictNamespaceCollisions rejects (rather than rewrites)
	// ids/classes that start with the shell namespace prefix
	// ("gb-shell-"). v1 ships with rewrite; this lets consumers
	// tighten to reject.
	StrictNamespaceCollisions bool

	// StripComments removes HTML comments.
	//
	// v1 always strips comments, because a comment is a parsing
	// state change that browsers disagree about and that has a
	// long mutation-XSS history. normalize() forces this field to
	// true and validate() rejects a profile that sets it false, so
	// no profile can silently believe comments are preserved. The
	// field exists so a future version can offer the choice
	// without an API break.
	StripComments bool

	// DataNamespacePrefix is the reserved data-* namespace. The
	// runtime will hook into this. Default "data-gb-".
	DataNamespacePrefix string

	// ShellNamespace overrides the reserved namespace prefix for
	// this profile. Defaults to "gb-shell-".
	ShellNamespace string
}

// ShellNamespacePrefix is the namespace reserved for the trusted
// shell. All ids/classes that start with this prefix are reserved;
// user markup that uses them is rewritten (or rejected with
// StrictNamespaceCollisions).
const ShellNamespacePrefix = "gb-shell-"

// validate checks the profile against the package's
// non-negotiable invariants. A profile that passes validate can
// only be narrower than the baseline; it cannot re-enable
// forbidden elements or weaken the CSP below safe.
//
//nolint:gocyclo // profile validation rule checker
func (p Profile) validate() error {
	if p.Name == "" {
		return &ProfileError{Field: "Name", Reason: "required"}
	}
	if p.Version <= 0 {
		return &ProfileError{Field: "Version", Reason: "must be > 0"}
	}
	if p.MaxHTMLBytes <= 0 {
		return &ProfileError{Field: "MaxHTMLBytes", Reason: "must be > 0"}
	}
	if p.MaxCSSBytes <= 0 {
		return &ProfileError{Field: "MaxCSSBytes", Reason: "must be > 0"}
	}
	if p.MaxDOMDepth <= 0 {
		return &ProfileError{Field: "MaxDOMDepth", Reason: "must be > 0"}
	}
	if p.MaxDOMNodes <= 0 {
		return &ProfileError{Field: "MaxDOMNodes", Reason: "must be > 0"}
	}
	if !p.StripComments {
		return &ProfileError{
			Field:  "StripComments",
			Reason: "v1 always strips HTML comments; normalize() sets this and it must not be cleared afterwards",
		}
	}

	// Tag allowlist must not include any of the always-forbidden tags.
	allowed := make(map[string]bool, len(p.AllowedTags))
	for _, t := range p.AllowedTags {
		lt := strings.ToLower(t)
		if alwaysForbiddenTags[lt] {
			return &ProfileError{
				Field:  "AllowedTags",
				Reason: fmt.Sprintf("tag %s is always forbidden", t),
			}
		}
		allowed[lt] = true
	}
	if len(allowed) == 0 {
		return &ProfileError{Field: "AllowedTags", Reason: "at least one tag required"}
	}

	// Attributes: must not include any on* (event handlers).
	for tag, attrs := range p.AllowedAttrs {
		lt := strings.ToLower(tag)
		if !allowed[lt] && lt != "*" {
			return &ProfileError{
				Field:  "AllowedAttrs",
				Reason: fmt.Sprintf("tag %s not in AllowedTags", tag),
			}
		}
		for _, a := range attrs {
			la := strings.ToLower(a)
			if strings.HasPrefix(la, "on") {
				return &ProfileError{
					Field:  "AllowedAttrs",
					Reason: fmt.Sprintf("event handler attributes are forbidden (got %s on %s)", a, tag),
				}
			}
			if forbiddenAttrs[la] {
				return &ProfileError{
					Field:  "AllowedAttrs",
					Reason: fmt.Sprintf("attribute %s is always forbidden", a),
				}
			}
		}
	}

	// URL schemes must not include javascript/vbscript/data (except
	// data:image when AllowDataImages is true).
	for _, s := range p.URLSchemes {
		ls := strings.ToLower(s)
		if ls == "javascript" || ls == "vbscript" {
			return &ProfileError{
				Field:  "URLSchemes",
				Reason: fmt.Sprintf("scheme %s is always forbidden", s),
			}
		}
	}

	// CSP: script-src must be 'none' or hashes; never 'unsafe-inline',
	// never 'unsafe-eval', never arbitrary URLs.
	if err := validateScriptSrc(p.CSP); err != nil {
		return err
	}
	if p.CSP.StyleSrc == "" {
		return &ProfileError{Field: "CSP.StyleSrc", Reason: "empty"}
	}
	if p.CSP.ImgSrc == "" {
		return &ProfileError{Field: "CSP.ImgSrc", Reason: "empty"}
	}
	if p.CSP.FormAction == "" || !strings.Contains(strings.ReplaceAll(p.CSP.FormAction, " ", ""), "'none'") {
		return &ProfileError{Field: "CSP.FormAction", Reason: "must include 'none'"}
	}
	if p.CSP.BaseURI == "" || !strings.Contains(strings.ReplaceAll(p.CSP.BaseURI, " ", ""), "'none'") {
		return &ProfileError{Field: "CSP.BaseURI", Reason: "must include 'none'"}
	}
	if p.CSP.FrameSrc == "" || !strings.Contains(strings.ReplaceAll(p.CSP.FrameSrc, " ", ""), "'none'") {
		return &ProfileError{Field: "CSP.FrameSrc", Reason: "must include 'none'"}
	}
	if p.CSP.DefaultSrc == "" || !strings.Contains(strings.ReplaceAll(p.CSP.DefaultSrc, " ", ""), "'none'") {
		return &ProfileError{Field: "CSP.DefaultSrc", Reason: "must include 'none'"}
	}

	// CSS policy: must not allow @import, must not allow expression.
	for _, r := range p.CSS.AllowedAtRules {
		lr := strings.ToLower(r)
		if forbiddenCSSAtRules[lr] {
			return &ProfileError{
				Field:  "CSS.AllowedAtRules",
				Reason: fmt.Sprintf("@%s is always forbidden", r),
			}
		}
	}
	for _, fn := range p.CSS.AllowedFunctions {
		lf := strings.ToLower(fn)
		if forbiddenCSSFunctions[lf] {
			return &ProfileError{
				Field:  "CSS.AllowedFunctions",
				Reason: fmt.Sprintf("%s() is always forbidden", fn),
			}
		}
	}

	return nil
}

func validateScriptSrc(p CSPPolicy) error {
	// Hashes are validated whether or not they are in use, so a
	// typo cannot silently disable the runtime.
	for _, h := range p.ScriptHashes {
		if !isHashToken(h) {
			return &ProfileError{
				Field:  "CSP.ScriptHashes",
				Reason: fmt.Sprintf("invalid hash token %q", h),
			}
		}
	}
	src := strings.TrimSpace(p.ScriptSrc)
	if src == "" {
		return &ProfileError{Field: "CSP.ScriptSrc", Reason: "must be 'none' or a list of hashes"}
	}
	if src == "'none'" {
		return nil
	}
	// must be a list of hashes only.
	parts := strings.Fields(src)
	if len(parts) == 0 {
		return &ProfileError{Field: "CSP.ScriptSrc", Reason: "must be 'none' or a list of hashes"}
	}
	for _, part := range parts {
		if !isHashToken(part) {
			return &ProfileError{
				Field:  "CSP.ScriptSrc",
				Reason: fmt.Sprintf("only 'none' or sha256-/sha384-/sha512- hashes are allowed; got %q", part),
			}
		}
	}
	return nil
}

// isHashToken returns true if the token is of the form
// 'sha256-<base64>' / 'sha384-<base64>' / 'sha512-<base64>'.
func isHashToken(t string) bool {
	// strip optional quotes
	if len(t) >= 2 && t[0] == '\'' && t[len(t)-1] == '\'' {
		t = t[1 : len(t)-1]
	}
	for _, prefix := range []string{"sha256-", "sha384-", "sha512-"} {
		if strings.HasPrefix(t, prefix) {
			rest := t[len(prefix):]
			if rest == "" {
				return false
			}
			// Iterate bytes, not runes: converting a multi-byte rune
			// to a byte could truncate it into something that passes
			// for a base64 character.
			for i := 0; i < len(rest); i++ {
				if !isBase64Char(rest[i]) {
					return false
				}
			}
			return true
		}
	}
	return false
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '='
}

// alwaysForbiddenTags is the set of HTML tags that may never be
// allowed by any profile. The list is exhaustive (per spec §8).
var alwaysForbiddenTags = map[string]bool{
	"script":    true,
	"iframe":    true,
	"frame":     true,
	"frameset":  true,
	"object":    true,
	"embed":     true,
	"applet":    true,
	"form":      true,
	"input":     true,
	"button":    true,
	"select":    true,
	"textarea":  true,
	"link":      true,
	"meta":      true,
	"base":      true,
	"style":     true,
	"svg":       true,
	"math":      true,
	"video":     true,
	"audio":     true,
	"dialog":    true,
	"slot":      true,
	"template":  true,
	"noscript":  true,
	"noframes":  true,
	"noembed":   true,
	"marquee":   true,
	"details":   true, // <details ontoggle=...> is a known XSS vector
	"keygen":    true,
	"xmp":       true,
	"plaintext": true,
	"listing":   true,
}

// forbiddenAttrs is the set of attributes that are always rejected.
var forbiddenAttrs = map[string]bool{
	"style":      true, // v1: inline style goes through the CSS field
	"formaction": true,
	"action":     true,
	"srcdoc":     true,
	"xlink:href": true,
	"background": true,
	"dynsrc":     true,
	"lowsrc":     true,
}

// forbiddenCSSAtRules is the set of @-rules that may never be
// allowed in user CSS.
var forbiddenCSSAtRules = map[string]bool{
	"import":    true,
	"charset":   true,
	"namespace": true,
}

// forbiddenCSSFunctions is the set of CSS functions that may never
// be allowed in user CSS.
var forbiddenCSSFunctions = map[string]bool{
	"expression":   true,
	"behavior":     true,
	"-moz-binding": true,
}

// normalize returns a copy of the profile with default values
// filled in. validate() must be called on the result.
func (p Profile) normalize() Profile {
	if p.AllowedTags == nil {
		p.AllowedTags = []string{}
	}
	if p.AllowedAttrs == nil {
		p.AllowedAttrs = map[string][]string{}
	}
	if p.URLSchemes == nil {
		p.URLSchemes = []string{}
	}
	if p.AssetPrefixes == nil {
		p.AssetPrefixes = []string{}
	}
	if p.CSS.AllowedAtRules == nil {
		p.CSS.AllowedAtRules = []string{}
	}
	if p.CSS.AllowedDeclarations == nil {
		p.CSS.AllowedDeclarations = []string{}
	}
	if p.CSS.AllowedFunctions == nil {
		p.CSS.AllowedFunctions = []string{}
	}
	if p.CSS.AllowedPseudoClasses == nil {
		p.CSS.AllowedPseudoClasses = []string{}
	}
	if p.CSS.AssetPrefixes == nil {
		p.CSS.AssetPrefixes = []string{}
	}
	if p.DataNamespacePrefix == "" {
		p.DataNamespacePrefix = "data-gb-"
	}
	if p.ShellNamespace == "" {
		p.ShellNamespace = ShellNamespacePrefix
	}
	// v1 has no code path that emits a comment; make the profile
	// say so rather than advertising a knob that does nothing.
	p.StripComments = true
	// Merge profile AssetPrefixes into CSS AssetPrefixes for url().
	p.CSS.AssetPrefixes = mergePrefixes(p.CSS.AssetPrefixes, p.AssetPrefixes)
	return p
}

// DefaultFullPageProfile is the canonical default full-page profile.
func DefaultFullPageProfile() Profile {
	return Profile{
		Name:    "fullpage-v1",
		Version: 1,

		AllowedTags: []string{
			"h1", "h2", "h3", "h4", "h5", "h6",
			"p", "div", "span", "section", "header", "footer",
			"main", "article", "aside", "nav", "figure", "figcaption",
			"br", "hr",
			"ul", "ol", "li",
			"strong", "em", "b", "i", "u", "s", "small",
			"sup", "sub",
			"a", "img", "picture", "source",
			"table", "thead", "tbody", "tr", "th", "td",
		},
		AllowedAttrs: map[string][]string{
			"*": {
				"class", "id", "dir", "lang", "title",
				"aria-*", "role",
				"data-gb-*",
			},
			"a":      {"href", "target", "rel"},
			"img":    {"src", "alt", "width", "height"},
			"source": {"src", "type"},
			"th":     {"scope", "colspan", "rowspan"},
			"td":     {"colspan", "rowspan"},
			"ol":     {"start", "type", "reversed"},
			"li":     {"value"},
		},

		URLSchemes: []string{"https", "mailto", "tel"},

		AssetPrefixes: []string{
			"/r/", "/assets/", "/pages/",
		},

		AllowDataImages:  true,
		SameSiteRelative: true,
		AllowTargetBlank: true,

		MaxHTMLBytes: 100 * 1024,
		MaxCSSBytes:  50 * 1024,
		MaxDOMDepth:  20,
		MaxDOMNodes:  1500,

		CSS: fullPageCSS(),

		CSP: CSPPolicy{
			DefaultSrc:     "'none'",
			ScriptSrc:      "'none'",
			StyleSrc:       "'self' 'unsafe-inline'",
			ImgSrc:         "'self' data:",
			FontSrc:        "'self'",
			MediaSrc:       "'none'",
			FrameSrc:       "'none'",
			FrameAncestors: "'self' https://dashboard.go-beaver.com",
			FormAction:     "'none'",
			BaseURI:        "'none'",
		},
	}
}

func fullPageCSS() CSSPolicy {
	return CSSPolicy{
		AllowedAtRules: []string{
			"media", "supports",
		},
		AllowedFunctions: []string{
			"rgb", "rgba", "hsl", "hsla", "hwb",
			"calc", "var", "min", "max", "clamp",
			"round", "mod", "rem", "abs", "sign",
			"linear-gradient", "radial-gradient", "conic-gradient",
			"repeating-linear-gradient", "repeating-radial-gradient",
			"blur", "drop-shadow", "opacity",
			"translate", "scale", "rotate",
			"counter", "counters", "attr",
		},
		AllowedPseudoClasses: []string{
			":hover", ":focus", ":active",
			":first-child", ":last-child",
			":not", ":is", ":where",
		},
		AllowedDeclarations:        append(layoutDeclarations(), textDeclarations()...),
		AllowDataImages:            true,
		DisallowAttributeSelectors: true,
	}
}

func layoutDeclarations() []string {
	return []string{
		"margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
		"padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
		"width", "height", "min-width", "min-height", "max-width", "max-height",
		"box-sizing", "display", "visibility", "overflow", "overflow-x", "overflow-y",
		"float", "clear", "aspect-ratio",
		"flex", "flex-direction", "flex-wrap", "flex-flow",
		"flex-grow", "flex-shrink", "flex-basis",
		"justify-content", "align-items", "align-self", "align-content",
		"order", "gap", "row-gap", "column-gap",
		"place-items", "place-content",
		"grid", "grid-template", "grid-template-columns", "grid-template-rows",
		"grid-template-areas", "grid-area", "grid-column", "grid-row",
		"grid-auto-columns", "grid-auto-rows", "grid-auto-flow",
	}
}

func textDeclarations() []string {
	return []string{
		"font", "font-family", "font-size", "font-weight", "font-style",
		"font-variant", "line-height", "letter-spacing", "word-spacing",
		"text-align", "text-decoration", "text-decoration-color",
		"text-decoration-line", "text-decoration-style",
		"text-transform", "text-indent", "text-shadow", "white-space",
		"vertical-align",
		"color", "background", "background-color", "background-image",
		"background-position", "background-size", "background-repeat",
		"border", "border-top", "border-right", "border-bottom", "border-left",
		"border-width", "border-style", "border-color", "border-radius",
		"border-top-left-radius", "border-top-right-radius",
		"border-bottom-left-radius", "border-bottom-right-radius",
		"outline", "outline-color", "outline-style", "outline-width", "outline-offset",
		"box-shadow", "opacity", "filter", "backdrop-filter",
		"border-collapse", "border-spacing", "caption-side", "empty-cells",
		"table-layout",
		"cursor", "user-select",
		"transition", "transition-property", "transition-duration",
		"transition-timing-function", "transition-delay",
	}
}

// DefaultEmbedProfile is the canonical default embed profile.
func DefaultEmbedProfile() Profile {
	return Profile{
		Name:    "embed-v1",
		Version: 1,

		AllowedTags: []string{
			"h1", "h2", "h3", "h4", "h5", "h6",
			"p", "div", "span", "br", "hr",
			"ul", "ol", "li", "dl", "dt", "dd",
			"blockquote", "q", "cite", "abbr", "dfn",
			"strong", "em", "b", "i", "u", "s", "small",
			"sup", "sub", "mark", "kbd", "samp", "var", "code",
			"del", "ins", "time", "address",
			"a", "img", "figure", "figcaption",
			"picture", "source",
		},

		AllowedAttrs: map[string][]string{
			"*":      {"class", "aria-*", "role", "title"},
			"a":      {"href"},
			"img":    {"src", "alt", "width", "height", "loading"},
			"source": {"src", "srcset", "type", "media", "sizes"},
			"cite":   {"title"},
			"abbr":   {"title"},
			"time":   {"datetime"},
		},

		URLSchemes:       []string{"https", "mailto"},
		AssetPrefixes:    []string{"/assets/"},
		AllowDataImages:  true,
		SameSiteRelative: true,
		AllowTargetBlank: false,

		MaxHTMLBytes: 100 * 1024,
		MaxCSSBytes:  50 * 1024,
		MaxDOMDepth:  20,
		MaxDOMNodes:  1500,

		CSS: CSSPolicy{
			AllowedAtRules: []string{"media", "supports"},
			AllowedFunctions: []string{
				"rgb", "rgba", "hsl", "hsla", "hwb",
				"lab", "lch", "oklab", "oklch", "color-mix",
				"calc", "var", "min", "max", "clamp",
				"linear-gradient", "radial-gradient", "conic-gradient",
				"blur", "brightness", "contrast", "drop-shadow",
				"grayscale", "hue-rotate", "invert", "opacity",
				"saturate", "sepia",
				"steps", "cubic-bezier",
				"path", "polygon", "circle", "ellipse", "inset",
			},
			AllowedPseudoClasses: []string{
				":hover", ":focus", ":focus-visible",
				":first-child", ":last-child",
				":not", ":is", ":where", ":has",
				"::before", "::after", "::placeholder", "::selection",
				"::first-letter", "::first-line", "::marker",
			},
			AllowedDeclarations:        embedTextDeclarations(),
			AllowDataImages:            true,
			DisallowAttributeSelectors: true,
		},

		CSP: CSPPolicy{
			DefaultSrc:     "'none'",
			ScriptSrc:      "'none'",
			StyleSrc:       "'self' 'unsafe-inline'",
			ImgSrc:         "'self' data:",
			FontSrc:        "'self'",
			MediaSrc:       "'none'",
			FrameSrc:       "'none'",
			FrameAncestors: "'self'",
			FormAction:     "'none'",
			BaseURI:        "'none'",
		},
	}
}

func embedTextDeclarations() []string {
	return []string{
		"color", "background", "background-color",
		"font", "font-family", "font-size", "font-weight", "font-style",
		"line-height", "letter-spacing", "text-align", "text-decoration",
		"text-decoration-color", "text-decoration-line", "text-decoration-style", "text-decoration-thickness",
		"text-transform", "text-shadow", "white-space", "caret-color",
		"hyphens", "tab-size", "text-emphasis", "text-emphasis-color", "text-emphasis-style",
		"margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
		"padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
		"width", "height", "max-width", "max-height", "min-width", "min-height",
		"display", "visibility", "overflow", "overflow-x", "overflow-y",
		"border", "border-width", "border-style", "border-color", "border-radius",
		"opacity", "filter", "backdrop-filter",
		"box-shadow", "text-shadow",
		"aspect-ratio", "object-fit", "object-position",
		"transition", "transition-property", "transition-duration",
		"transition-timing-function", "transition-delay",
		"animation", "animation-name", "animation-duration",
		"animation-timing-function", "animation-delay",
		"animation-iteration-count", "animation-direction",
		"animation-fill-mode", "animation-play-state",
		"cursor", "user-select",
		"clip-path", "shape-outside", "shape-margin",
		"columns", "column-count", "column-width", "column-gap",
		"column-rule", "column-rule-color", "column-rule-style", "column-rule-width",
		"column-span", "column-fill", "gap", "row-gap",
	}
}

// mergePrefixes returns a sorted, deduplicated union.
func mergePrefixes(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, p := range a {
		seen[p] = true
	}
	for _, p := range b {
		seen[p] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
