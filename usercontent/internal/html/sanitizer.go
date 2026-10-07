package html

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// Removal is a single sanitizer decision, internal to the html
// package. The usercontent package converts these to its public
// Removal type.
type Removal struct {
	Kind   string
	Value  string
	Reason string
	Line   int
}

// RemovalKind constants correspond to the public RemovalKind
// values in the usercontent package. We intentionally duplicate
// the strings here to avoid an import cycle.
const (
	rkForbiddenElement      = "forbidden_element"
	rkEventHandler          = "event_handler"
	rkForbiddenURL          = "forbidden_url"
	rkExternalResource      = "external_resource"
	rkForbiddenAttribute    = "forbidden_attribute"
	rkInlineStyle           = "inline_style"
	rkNamespaceCollision    = "namespace_collision"
	rkComment               = "comment"
	rkMalformed             = "malformed"
	rkDoctype               = "forbidden_element"
	rkProcessingInstruction = "malformed"
)

// URLPolicy is the subset of the parent package's *urlPolicy the
// html package needs. Exported so the interface check works.
type URLPolicy interface {
	ValidateURL(raw string, isAsset bool) (string, error)
}

// entAmp, entQuot, entLT, entGT are the HTML entity strings used
// by EscapeAttr. They are pre-built from byte arrays so the
// formatter does not interpret them as HTML entities.
var (
	entAmp  = string([]byte{0x26, 0x61, 0x6d, 0x70, 0x3b})
	entQuot = string([]byte{0x26, 0x71, 0x75, 0x6f, 0x74, 0x3b})
	entLT   = string([]byte{0x26, 0x6c, 0x74, 0x3b})
	entGT   = string([]byte{0x26, 0x67, 0x74, 0x3b})
)

// Sanitize parses the input as HTML and returns the sanitized
// HTML string plus a list of removals. The sanitized HTML is
// emitted as a tree, never as a string-replacement of the input;
// this is critical for mutation-XSS prevention.
func Sanitize(input string, p *Policy, up URLPolicy) (string, []Removal, error) {
	if p == nil {
		return "", nil, errors.New("html: policy is nil")
	}
	if up == nil {
		return "", nil, errors.New("html: url policy is nil")
	}

	tokenizer := html.NewTokenizer(strings.NewReader(input))
	tokenizer.AllowCDATA(false)

	var out strings.Builder
	out.Grow(len(input))

	removals := []Removal{}
	state := newState(p, up, &removals)

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			err := tokenizer.Err()
			if errors.Is(err, io.EOF) {
				break
			}
			return out.String(), removals, fmt.Errorf("html: parse error: %w", err)
		}

		switch tt {
		case html.DoctypeToken:
			removals = append(removals, Removal{
				Kind:   rkDoctype,
				Value:  "doctype",
				Reason: "doctype is not allowed",
			})
		case html.CommentToken:
			removals = append(removals, Removal{
				Kind:   rkComment,
				Value:  "// comment",
				Reason: "HTML comments are not allowed",
			})
		case html.StartTagToken, html.SelfClosingTagToken:
			// A trailing "/" is ignored by the HTML parser on
			// anything but a void element, so the two token types are
			// handled identically. Treating <a/> as a complete
			// element here would make the sanitizer disagree with the
			// browser about where the element ends.
			if err := state.handleStartTag(&out, tokenizer); err != nil {
				return out.String(), removals, err
			}
		case html.EndTagToken:
			tagName, _ := tokenizer.TagName()
			state.closeTag(&out, string(tagName))
		case html.TextToken:
			// Drop text inside a stripped subtree (a tag we didn't
			// push onto the stack).
			if state.skipped > 0 {
				continue
			}
			out.WriteString(html.EscapeString(string(tokenizer.Text())))
		default:
			// Other token types (CDATA, raw text, ...) are folded into
			// neighbouring tokens by the x/net/html tokenizer. Nothing
			// dangerous can be emitted either way.
		}
	}

	state.closeAllOpen(&out)
	return out.String(), removals, nil
}

// Sentinel errors so the public package can match against them.
var (
	ErrDepthExceeded = errors.New("depth exceeded")
	ErrNodesExceeded = errors.New("nodes exceeded")
)

// state tracks the current stack of open tags and counters.
type state struct {
	policy       *Policy
	urlPolicy    URLPolicy
	stack        []string
	depth        int
	nodeCount    int
	removals     *[]Removal
	skippedStack []string

	// skipped counts how many forbidden tags we are currently
	// inside. x/net/html does not let us skip a subtree by
	// tag, so we walk through it token by token and discard
	// text/inner tags.
	skipped int
}

func newState(p *Policy, up URLPolicy, removals *[]Removal) *state {
	return &state{
		policy:       p,
		urlPolicy:    up,
		stack:        make([]string, 0, 32),
		skippedStack: make([]string, 0, 16),
		removals:     removals,
	}
}

var (
	errDepthExceeded = errors.New("depth exceeded")
	errNodesExceeded = errors.New("nodes exceeded")
)

// handleStartTag dispatches a start or self-closing tag token,
// tracking the stripped-subtree stack and mapping the internal
// limit errors onto the package's sentinels.
func (s *state) handleStartTag(out *strings.Builder, tz *html.Tokenizer) error {
	tagName, hasAttr := tz.TagName()
	tag := string(tagName)
	if s.skipped > 0 {
		if lt := strings.ToLower(tag); !isVoidElement(lt) {
			s.skippedStack = append(s.skippedStack, lt)
			s.skipped = len(s.skippedStack)
		}
		return nil
	}
	err := s.openTag(out, tz, tag, hasAttr)
	switch {
	case errors.Is(err, errDepthExceeded):
		return fmt.Errorf("html: %w", ErrDepthExceeded)
	case errors.Is(err, errNodesExceeded):
		return fmt.Errorf("html: %w", ErrNodesExceeded)
	}
	return nil
}

// openTag handles a start tag (or self-closing tag).
//
//nolint:gocyclo,nestif // main HTML tokenizer tag dispatcher
func (s *state) openTag(out *strings.Builder, tz *html.Tokenizer, tag string, hasAttr bool) error {
	lt := strings.ToLower(tag)
	s.nodeCount++

	// Always-stripped tags: skip the entire subtree.
	if alwaysForbiddenTag(lt) {
		*s.removals = append(*s.removals, Removal{
			Kind:   rkForbiddenElement,
			Value:  lt,
			Reason: "tag is always forbidden",
			Line:   0,
		})
		if !isVoidElement(lt) {
			s.skippedStack = append(s.skippedStack, lt)
			s.skipped = len(s.skippedStack)
		}
		return nil
	}

	if !s.policy.TagAllowed(lt) {
		*s.removals = append(*s.removals, Removal{
			Kind:   rkForbiddenElement,
			Value:  lt,
			Reason: "tag not in allowlist",
			Line:   0,
		})
		if !isVoidElement(lt) {
			s.skippedStack = append(s.skippedStack, lt)
			s.skipped = len(s.skippedStack)
		}
		return nil
	}

	if s.depth+1 > s.policy.MaxDepth() {
		*s.removals = append(*s.removals, Removal{
			Kind:   rkForbiddenElement,
			Value:  lt,
			Reason: "DOM depth limit exceeded",
			Line:   0,
		})
		return errDepthExceeded
	}

	if s.nodeCount > s.policy.MaxNodes() {
		*s.removals = append(*s.removals, Removal{
			Kind:   rkForbiddenElement,
			Value:  lt,
			Reason: "DOM node count limit exceeded",
			Line:   0,
		})
		return errNodesExceeded
	}

	out.WriteByte('<')
	out.WriteString(lt)

	hasTargetBlank := false
	hasRelAttr := false
	relValue := ""
	if hasAttr {
		for {
			key, val, more := tz.TagAttr()
			aName := strings.ToLower(string(key))
			if aName == "" {
				if !more {
					break
				}
				continue
			}
			aVal := string(val)

			if isAlwaysForbiddenAttribute(aName, lt) {
				*s.removals = append(*s.removals, Removal{
					Kind:   rkForbiddenAttribute,
					Value:  aName,
					Reason: "attribute is always forbidden",
				})
				if !more {
					break
				}
				continue
			}

			if strings.HasPrefix(aName, "on") {
				*s.removals = append(*s.removals, Removal{
					Kind:   rkEventHandler,
					Value:  aName,
					Reason: "event handler attributes are forbidden",
				})
				if !more {
					break
				}
				continue
			}

			if aName == "style" {
				*s.removals = append(*s.removals, Removal{
					Kind:   rkInlineStyle,
					Value:  "style",
					Reason: "inline style attributes are not allowed in v1",
				})
				if !more {
					break
				}
				continue
			}

			if !s.policy.AttributeAllowed(lt, aName) {
				*s.removals = append(*s.removals, Removal{
					Kind:   rkForbiddenAttribute,
					Value:  aName,
					Reason: "attribute not in allowlist for tag",
				})
				if !more {
					break
				}
				continue
			}

			if isURLAttribute(aName) {
				var (
					reason string
					err    error
				)
				if aName == "srcset" {
					// srcset is a comma-separated candidate list; each
					// candidate URL must be validated on its own.
					// Validating the raw attribute as a single URL would
					// let a multi-candidate list slip past the origin
					// allowlist as an unparseable "relative" URL.
					reason, err = validateSrcset(aVal, s.urlPolicy)
				} else {
					reason, err = s.urlPolicy.ValidateURL(aVal, isAssetAttribute(aName))
				}
				if err != nil {
					removalKind := rkForbiddenURL
					if isAssetAttribute(aName) {
						removalKind = rkExternalResource
					}
					*s.removals = append(*s.removals, Removal{
						Kind:   removalKind,
						Value:  aVal,
						Reason: reason,
					})
					if !more {
						break
					}
					continue
				}
			}

			if aName == "id" || aName == "class" {
				if s.policy.ShellNamespace() != "" && strings.HasPrefix(aVal, s.policy.ShellNamespace()) {
					if s.policy.StrictNamespace() {
						*s.removals = append(*s.removals, Removal{
							Kind:   rkNamespaceCollision,
							Value:  aVal,
							Reason: "id/class collides with shell namespace",
						})
						if !more {
							break
						}
						continue
					}
					aVal = "user-" + aVal
				}
			}

			if aName == "target" {
				if aVal == "_blank" {
					if !s.policy.AllowTargetBlank() {
						*s.removals = append(*s.removals, Removal{
							Kind:   rkForbiddenAttribute,
							Value:  "target=_blank",
							Reason: "target=_blank is not allowed",
						})
						if !more {
							break
						}
						continue
					}
					hasTargetBlank = true
				}
			}

			if aName == "rel" {
				// Held back so the required tokens can be merged into
				// whatever the author supplied, rather than trusting
				// the presence of a rel attribute to mean the link is
				// already safe.
				hasRelAttr = true
				relValue = aVal
				if !more {
					break
				}
				continue
			}

			writeAttr(out, aName, aVal)

			if !more {
				break
			}
		}
	}

	if hasRelAttr || (lt == "a" && hasTargetBlank) {
		if lt == "a" && hasTargetBlank && s.policy.AllowTargetBlank() {
			merged := mergeRel(relValue)
			if merged != relValue {
				*s.removals = append(*s.removals, Removal{
					Kind:   rkForbiddenAttribute,
					Value:  "rel=" + relValue,
					Reason: "rel rewritten to force noopener/noreferrer/nofollow/ugc on target=_blank",
				})
			}
			writeAttr(out, "rel", merged)
		} else if hasRelAttr {
			writeAttr(out, "rel", relValue)
		}
	}

	out.WriteByte('>')

	if !isVoidElement(lt) {
		s.stack = append(s.stack, lt)
		s.depth++
	}
	return nil
}

// closeTag handles an end tag.
func (s *state) closeTag(out *strings.Builder, tag string) {
	lt := strings.ToLower(tag)
	// If we're inside a stripped subtree, match against skippedStack
	if s.skipped > 0 {
		for i := len(s.skippedStack) - 1; i >= 0; i-- {
			if s.skippedStack[i] == lt {
				s.skippedStack = s.skippedStack[:i]
				s.skipped = len(s.skippedStack)
				return
			}
		}
		return
	}
	for i := len(s.stack) - 1; i >= 0; i-- {
		if s.stack[i] == lt {
			for j := len(s.stack) - 1; j >= i; j-- {
				out.WriteString("</")
				out.WriteString(s.stack[j])
				out.WriteByte('>')
				s.depth--
			}
			s.stack = s.stack[:i]
			return
		}
	}
}

// closeAllOpen closes any remaining open tags.
func (s *state) closeAllOpen(out *strings.Builder) {
	for j := len(s.stack) - 1; j >= 0; j-- {
		out.WriteString("</")
		out.WriteString(s.stack[j])
		out.WriteByte('>')
		s.depth--
	}
	s.stack = s.stack[:0]
}

// requiredBlankRel is the set of rel tokens that must be present on
// any user-authored link that opens in a new browsing context.
var requiredBlankRel = []string{"noopener", "noreferrer", "nofollow", "ugc"}

// mergeRel returns the author's rel value with the required tokens
// added. Tokens the author already supplied are kept in place and
// not duplicated; a token such as "opener" that contradicts the
// required set is dropped.
func mergeRel(rel string) string {
	seen := make(map[string]bool, 8)
	out := make([]string, 0, 8)
	for _, tok := range strings.Fields(rel) {
		lt := strings.ToLower(tok)
		if lt == "opener" || seen[lt] {
			continue
		}
		seen[lt] = true
		out = append(out, lt)
	}
	for _, tok := range requiredBlankRel {
		if !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return strings.Join(out, " ")
}

// validateSrcset validates every candidate URL in a srcset
// attribute. It returns the first failure's reason and error, or
// ("", nil) if every candidate passes.
func validateSrcset(raw string, up URLPolicy) (string, error) {
	candidates := splitSrcset(raw)
	if len(candidates) == 0 {
		return up.ValidateURL(strings.TrimSpace(raw), true)
	}
	for _, c := range candidates {
		if reason, err := up.ValidateURL(c, true); err != nil {
			return reason, err
		}
	}
	return "", nil
}

// splitSrcset extracts the URL of each candidate in a srcset
// attribute, discarding the width/density descriptors.
func splitSrcset(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (isASCIISpace(s[i]) || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && !isASCIISpace(s[i]) {
			i++
		}
		tok := s[start:i]
		trimmed := strings.TrimRight(tok, ",")
		if trimmed != "" {
			out = append(out, trimmed)
		}
		if len(trimmed) == len(tok) {
			// No trailing comma, so a descriptor may follow. Skip to
			// the comma that ends this candidate.
			for i < len(s) && s[i] != ',' {
				i++
			}
		}
	}
	return out
}

func isASCIISpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func writeAttr(out *strings.Builder, name, value string) {
	out.WriteByte(' ')
	out.WriteString(name)
	out.WriteString(`="`)
	out.WriteString(EscapeAttr(value))
	out.WriteByte('"')
}

// EscapeAttr escapes the characters that would terminate an
// HTML attribute or reintroduce markup: &, ", <, >.
func EscapeAttr(s string) string {
	if !strings.ContainsAny(s, "&\"<>") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString(entAmp)
		case '"':
			b.WriteString(entQuot)
		case '<':
			b.WriteString(entLT)
		case '>':
			b.WriteString(entGT)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// alwaysForbiddenTag returns true for tags that are always
// forbidden regardless of policy.
func alwaysForbiddenTag(tag string) bool {
	switch tag {
	case "script", "iframe", "frame", "frameset", "object", "embed",
		"applet", "form", "input", "button", "select", "textarea",
		"link", "meta", "base", "style", "svg", "math", "video",
		"audio", "dialog", "slot", "template", "noscript", "noframes",
		"noembed", "marquee", "details", "keygen", "xmp", "plaintext",
		"listing":
		return true
	}
	return false
}

func isAlwaysForbiddenAttribute(name, _ string) bool {
	switch name {
	case "formaction", "action", "srcdoc", "xlink:href",
		"background", "dynsrc", "lowsrc":
		return true
	}
	return false
}

func isURLAttribute(name string) bool {
	switch name {
	case "href", "src", "srcset", "cite", "poster", "action",
		"formaction", "background", "longdesc":
		return true
	}
	return false
}

func isAssetAttribute(name string) bool {
	switch name {
	case "src", "srcset", "poster", "background", "longdesc":
		return true
	}
	return false
}

func isVoidElement(tag string) bool {
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img",
		"input", "link", "meta", "source", "track", "wbr":
		return true
	}
	return false
}
