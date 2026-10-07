package usercontent

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	nethtml "golang.org/x/net/html"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/internal/csp"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/internal/css"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/internal/html"
)

// Sanitizer performs all HTML/CSS sanitization for a single
// profile. Sanitizers are stateless after construction and are
// safe for concurrent use across many requests; each Sanitize*
// call allocates its own internal buffers.
type Sanitizer struct {
	profile Profile
	// pre-parsed policy structures
	htmlPolicy *html.Policy
	cssPolicy  *css.Policy
	urlPolicy  *urlPolicy
}

// New constructs a Sanitizer for the given profile. New returns
// an error if the profile violates a non-negotiable invariant,
// because the package's whole point is that safety should be
// unrepresentable in the API rather than relying on consumers
// to remember the rules.
func New(p Profile) (*Sanitizer, error) {
	// Normalize first so validate() checks the profile that will
	// actually be used, defaults included, rather than the literal
	// the caller wrote.
	p = p.normalize()
	if err := p.validate(); err != nil {
		return nil, err
	}
	hp, err := html.NewPolicy(profileToHTML(p))
	if err != nil {
		return nil, fmt.Errorf("build html policy: %w", err)
	}
	cp, err := css.NewPolicy(profileToCSS(p))
	if err != nil {
		return nil, fmt.Errorf("build css policy: %w", err)
	}
	up := newURLPolicy(p)
	return &Sanitizer{
		profile:    p,
		htmlPolicy: hp,
		cssPolicy:  cp,
		urlPolicy:  up,
	}, nil
}

// profileToHTML copies a usercontent.Profile into a html.Profile,
// the minimal contract the html package needs.
func profileToHTML(p Profile) html.Profile {
	return html.Profile{
		Name:                      p.Name,
		AllowedTags:               p.AllowedTags,
		AllowedAttrs:              p.AllowedAttrs,
		AllowTargetBlank:          p.AllowTargetBlank,
		MaxDOMDepth:               p.MaxDOMDepth,
		MaxDOMNodes:               p.MaxDOMNodes,
		ShellNamespace:            p.ShellNamespace,
		StrictNamespaceCollisions: p.StrictNamespaceCollisions,
	}
}

// profileToCSS copies a usercontent.Profile into a css.Profile,
// the minimal contract the css package needs.
func profileToCSS(p Profile) css.Profile {
	return css.Profile{
		Name:                       p.Name,
		AllowedAtRules:             p.CSS.AllowedAtRules,
		AllowedDeclarations:        p.CSS.AllowedDeclarations,
		AllowedFunctions:           p.CSS.AllowedFunctions,
		AllowedPseudoClasses:       p.CSS.AllowedPseudoClasses,
		DisallowAttributeSelectors: p.CSS.DisallowAttributeSelectors,
		ShellNamespace:             p.ShellNamespace,
	}
}

// Profile returns the sanitiser's profile (a copy). Useful for
// introspecting the configured policy from the editor UI.
func (s *Sanitizer) Profile() Profile { return s.profile }

// SanitizeHTML sanitizes a user-supplied HTML string. The first
// return value is the sanitized HTML; the second is a structured
// Report describing what was removed; the third is an error only
// on infrastructure failures (input too large, limits exceeded,
// output verification failure).
//
// When the error is non-nil the returned HTML is always empty, so
// a caller that mishandles the error cannot accidentally serve
// unverified markup. The sanitized HTML is safe to insert into
// the trusted shell via template.HTML.
func (s *Sanitizer) SanitizeHTML(htmlInput string) (string, Report, error) {
	r := Report{InputBytes: len(htmlInput)}
	if err := validateCharset(htmlInput); err != nil {
		return "", r, err
	}
	if len(htmlInput) > s.profile.MaxHTMLBytes {
		return "", r, fmt.Errorf("%w: %d bytes (max %d)", ErrInputTooLarge, len(htmlInput), s.profile.MaxHTMLBytes)
	}
	out, removals, err := html.Sanitize(htmlInput, s.htmlPolicy, s.urlPolicy)
	for _, rem := range removals {
		r.Removed = append(r.Removed, Removal{
			Kind:   RemovalKind(rem.Kind),
			Value:  rem.Value,
			Reason: rem.Reason,
			Line:   rem.Line,
		})
	}
	if err != nil {
		// Map the html package's sentinels to the public
		// usercontent sentinels so callers can use errors.Is.
		// The partial output is deliberately discarded: a caller
		// that ignored the error would otherwise serve markup that
		// never reached the output verification pass.
		if errors.Is(err, html.ErrDepthExceeded) {
			return "", r, fmt.Errorf("html: %w", ErrTooDeep)
		}
		if errors.Is(err, html.ErrNodesExceeded) {
			return "", r, fmt.Errorf("html: %w", ErrTooManyNodes)
		}
		return "", r, err
	}
	if err := verifyOutputHTML(out); err != nil {
		return "", r, fmt.Errorf("html: %w: %w", ErrUnsafeOutput, err)
	}
	r.OutputBytes = len(out)
	r.Modified = len(r.Removed) > 0
	return out, r, nil
}

// SanitizeCSS sanitizes a user-supplied CSS string. Unparseable
// CSS is rejected (per spec §6); never "best effort" passed
// through. As with SanitizeHTML, a non-nil error always comes
// with an empty result.
//
// The returned CSS never contains a literal '<', so it is safe to
// inline into a <style> element via template.CSS.
func (s *Sanitizer) SanitizeCSS(cssInput string) (string, Report, error) {
	r := Report{InputBytes: len(cssInput)}
	if err := validateCharset(cssInput); err != nil {
		return "", r, err
	}
	if len(cssInput) > s.profile.MaxCSSBytes {
		return "", r, fmt.Errorf("%w: %d bytes (max %d)", ErrInputTooLarge, len(cssInput), s.profile.MaxCSSBytes)
	}
	out, removals, err := css.Sanitize(cssInput, s.cssPolicy, s.urlPolicy)
	for _, rem := range removals {
		r.Removed = append(r.Removed, Removal{
			Kind:   RemovalKind(rem.Kind),
			Value:  rem.Value,
			Reason: rem.Reason,
			Line:   rem.Line,
		})
	}
	if err != nil {
		if errors.Is(err, css.ErrUnparseable) {
			return "", r, fmt.Errorf("css: %w", ErrUnparseableCSS)
		}
		if errors.Is(err, css.ErrUnsafeOutput) {
			return "", r, fmt.Errorf("css: %w: %w", ErrUnsafeOutput, err)
		}
		return "", r, err
	}
	r.OutputBytes = len(out)
	r.Modified = len(r.Removed) > 0
	return out, r, nil
}

// CSPHeaders returns the security headers this sanitizer expects
// the page service to apply to every served page. The package
// emits the immutable headers; the page service composes any
// per-request headers (e.g. cache) on top.
func (s *Sanitizer) CSPHeaders() map[string]string {
	headers := csp.Build(csp.Policy{
		DefaultSrc:     s.profile.CSP.DefaultSrc,
		ScriptSrc:      s.profile.CSP.ScriptSrc,
		ScriptHashes:   s.profile.CSP.ScriptHashes,
		StyleSrc:       s.profile.CSP.StyleSrc,
		ImgSrc:         s.profile.CSP.ImgSrc,
		FontSrc:        s.profile.CSP.FontSrc,
		FrameSrc:       s.profile.CSP.FrameSrc,
		FrameAncestors: s.profile.CSP.FrameAncestors,
		FormAction:     s.profile.CSP.FormAction,
		BaseURI:        s.profile.CSP.BaseURI,
		MediaSrc:       s.profile.CSP.MediaSrc,
	})
	headers["Referrer-Policy"] = "no-referrer"
	headers["X-Content-Type-Options"] = "nosniff"
	headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), fullscreen=(self)"
	headers["Cross-Origin-Opener-Policy"] = "same-origin"
	return headers
}

// urlPolicy validates URL-scheme and origin rules. It exposes
// only the methods the html and css packages need, so the
// internal type stays unexported.
type urlPolicy struct {
	schemes       map[string]bool
	prefixes      []string
	allowDataImg  bool
	allowRelative bool
}

// ValidateURL is the exported entry point used by the html and
// css packages. It is exported (rather than unexported) so the
// interface checks in those packages succeed.
func (u *urlPolicy) ValidateURL(raw string, isAsset bool) (string, error) {
	return u.validateURL(raw, isAsset)
}

func newURLPolicy(p Profile) *urlPolicy {
	schemes := make(map[string]bool, len(p.URLSchemes))
	for _, s := range p.URLSchemes {
		schemes[strings.ToLower(s)] = true
	}
	return &urlPolicy{
		schemes:       schemes,
		prefixes:      p.AssetPrefixes,
		allowDataImg:  p.AllowDataImages,
		allowRelative: p.SameSiteRelative,
	}
}

// validateURL returns nil if the URL is acceptable for the given
// context (link href vs asset src vs CSS url()).
func (u *urlPolicy) validateURL(raw string, isAsset bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if u.allowRelative {
			return "", nil
		}
		return "", fmt.Errorf("%w: empty URL", ErrInvalidURL)
	}

	if strings.HasPrefix(raw, "//") {
		return "protocol-relative URLs are forbidden", ErrInvalidURL
	}
	if strings.HasPrefix(strings.ToLower(raw), "data:") {
		return u.validateDataURL(raw, isAsset)
	}

	// url.Parse rejects any ASCII control character, which is what
	// closes the "java\tscript:" family of bypasses: browsers strip
	// those characters before resolving the scheme, so a URL that
	// contains one must never be emitted.
	parsed, err := url.Parse(raw)
	if err != nil {
		return "unparseable URL", ErrInvalidURL
	}

	if parsed.Host != "" && !isASCIIHost(parsed.Host) {
		return "host contains non-ASCII or homoglyph characters; punycode required", ErrInvalidURL
	}

	if parsed.Scheme == "" {
		if u.allowRelative {
			return "", nil
		}
		return "relative URLs not allowed", ErrInvalidURL
	}

	ls := strings.ToLower(parsed.Scheme)
	switch ls {
	case "javascript", "vbscript", "data":
		return "forbidden URL scheme: " + ls, ErrInvalidURL
	}

	if isAsset {
		return u.validateAssetURL(parsed, ls)
	}
	if !u.schemes[ls] {
		return "URL scheme not in allowlist: " + ls, ErrInvalidURL
	}
	return "", nil
}

// validateDataURL accepts only the small set of raster image media
// types, and only where an asset is expected. No SVG: an SVG is a
// script container.
func (u *urlPolicy) validateDataURL(raw string, isAsset bool) (string, error) {
	if !isAsset || !u.allowDataImg {
		return "data: URL not allowed in this context", ErrInvalidURL
	}
	comma := strings.IndexByte(raw, ',')
	if comma < 0 {
		return "malformed data: URL", ErrInvalidURL
	}
	mediatype := strings.ToLower(strings.TrimSpace(raw[len("data:"):comma]))
	mediatype = strings.TrimSuffix(mediatype, ";base64")
	switch mediatype {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
		return "", nil
	}
	return "data: media type not allowed", ErrInvalidURL
}

// validateAssetURL applies the stricter rules for a URL the page
// will fetch on its own: http(s) only, and inside the asset
// prefix allowlist.
func (u *urlPolicy) validateAssetURL(parsed *url.URL, scheme string) (string, error) {
	if scheme != "https" && scheme != "http" {
		return "asset URL must be http(s)", ErrInvalidURL
	}
	if !u.schemes[scheme] {
		return "asset URL scheme not in allowlist: " + scheme, ErrInvalidURL
	}
	if !u.hostMatchesAny(parsed) {
		return "asset URL does not match any allowed prefix", ErrInvalidURL
	}
	return "", nil
}

// hostMatchesAny returns true if the URL's host+path matches any
// configured asset prefix.
func (u *urlPolicy) hostMatchesAny(parsed *url.URL) bool {
	host := parsed.Host
	if host == "" {
		if !u.allowRelative {
			return false
		}
		for _, p := range u.prefixes {
			if p != "" && strings.HasPrefix(parsed.Path, p) {
				return true
			}
		}
		// A same-origin path is allowed when the profile lists no
		// path prefixes to constrain it to.
		return !u.hasPathPrefix()
	}
	full := parsed.Scheme + "://" + host + parsed.Path
	for _, p := range u.prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(full, p) {
			return true
		}
	}
	// No prefix matched. A profile that configures no asset
	// prefixes at all permits no cross-origin assets: failing
	// closed here is what makes AssetPrefixes an allowlist rather
	// than an optional filter.
	return false
}

// hasPathPrefix reports whether any configured asset prefix
// constrains same-origin paths (as opposed to naming an absolute
// external origin).
func (u *urlPolicy) hasPathPrefix() bool {
	for _, p := range u.prefixes {
		if strings.HasPrefix(p, "/") {
			return true
		}
	}
	return false
}

func isASCIIHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] > 127 {
			return false
		}
	}
	return true
}

func verifyOutputHTML(out string) error {
	doc, err := nethtml.Parse(strings.NewReader(out))
	if err != nil {
		return err
	}
	var check func(*nethtml.Node) error
	check = func(n *nethtml.Node) error {
		if err := verifyNode(n); err != nil {
			return err
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := check(c); err != nil {
				return err
			}
		}
		return nil
	}
	return check(doc)
}

// verifyNode checks a single node of the sanitized DOM.
func verifyNode(n *nethtml.Node) error {
	// Text is checked against the same character policy the input
	// had to pass. The input check works on the encoded bytes; this
	// one works on what the browser actually decodes, so no
	// encoding trick can put a control, bidi or invisible character
	// into the output.
	if n.Type == nethtml.TextNode {
		return verifyText(n.Data, "text")
	}
	if n.Type != nethtml.ElementNode {
		return nil
	}

	tag := strings.ToLower(n.Data)
	if verifyForbiddenElements[tag] {
		return fmt.Errorf("forbidden element <%s> present in sanitized DOM", tag)
	}
	for _, attr := range n.Attr {
		if err := verifyText(attr.Val, attr.Key+" attribute"); err != nil {
			return err
		}
		if err := verifyAttr(tag, attr); err != nil {
			return err
		}
	}
	return nil
}

func verifyAttr(tag string, attr nethtml.Attribute) error {
	key := strings.ToLower(attr.Key)
	if strings.HasPrefix(key, "on") || key == "formaction" || key == "srcdoc" {
		return fmt.Errorf("forbidden attribute %q present on <%s> in sanitized DOM", attr.Key, tag)
	}
	if key != "href" && key != "src" {
		return nil
	}
	val := strings.ToLower(strings.TrimSpace(attr.Val))
	if strings.HasPrefix(val, "javascript:") || strings.HasPrefix(val, "vbscript:") {
		return fmt.Errorf("forbidden scheme in %s=%q on <%s>", attr.Key, attr.Val, tag)
	}
	return nil
}

// verifyText applies the input character policy to a piece of the
// sanitized output.
//
// The escape check matters here as well as on the input, because
// removing a node can bring two individually harmless characters
// together: "\<!>0" carries a backslash, a bogus comment and a
// zero, each fine on its own, and stripping the comment leaves the
// "\0" sequence the input validator rejects. Checking the output
// closes that route rather than trusting that no future removal
// can create one.
func verifyText(s, where string) error {
	for _, r := range s {
		if err := validateRune(r); err != nil {
			return fmt.Errorf("in %s: %w", where, err)
		}
	}
	if err := validateEscapes(s); err != nil {
		return fmt.Errorf("in %s: %w", where, err)
	}
	return nil
}

// verifyForbiddenElements is the set of elements that must never
// appear in a sanitized DOM, whatever the profile said.
var verifyForbiddenElements = map[string]bool{
	"script": true, "iframe": true, "frame": true, "frameset": true,
	"object": true, "embed": true, "applet": true, "form": true,
	"input": true, "button": true, "select": true, "textarea": true,
	"link": true, "meta": true, "base": true, "style": true,
	"svg": true, "math": true, "video": true, "audio": true,
	"dialog": true, "slot": true, "template": true, "noscript": true,
	"noframes": true, "noembed": true, "marquee": true, "details": true,
	"keygen": true, "xmp": true, "plaintext": true, "listing": true,
}
