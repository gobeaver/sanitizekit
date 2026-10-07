// Package html implements the HTML sanitization layer of the
// usercontent platform. It exposes a small policy type built
// from a usercontent.Profile, plus a Sanitize function that walks
// the x/net/html tokenizer and emits a safe HTML string.
//
// The package is internal to the usercontent module; consumers
// do not import it directly. They use usercontent.Sanitizer.
//
// The package intentionally does not import the usercontent
// package (to avoid an import cycle through the parent package);
// it duplicates the small set of constants it needs.
package html

import (
	"fmt"
	"strings"
)

// ShellNamespacePrefix is the namespace reserved for the trusted
// shell. All ids/classes that start with this prefix are
// reserved. Kept in sync with usercontent.ShellNamespacePrefix
// (they must be the same string).
const ShellNamespacePrefix = "gb-shell-"

// DefaultDataNamespacePrefix is the default reserved data-*
// namespace the runtime will hook into.
const DefaultDataNamespacePrefix = "data-gb-"

// Profile is the minimal contract the html package needs from
// usercontent.Profile. We accept a struct of fields rather than
// importing the full type to avoid the import cycle.
// URL scheme and origin fields are deliberately absent: those
// rules are enforced once, by the parent package's urlPolicy,
// which this package receives as a URLPolicy.
type Profile struct {
	Name                      string
	AllowedTags               []string
	AllowedAttrs              map[string][]string
	AllowTargetBlank          bool
	MaxDOMDepth               int
	MaxDOMNodes               int
	ShellNamespace            string
	StrictNamespaceCollisions bool
}

// Policy is the pre-parsed HTML policy. URL scheme and origin
// rules deliberately live in the parent package's urlPolicy, not
// here, so there is exactly one place that decides whether a URL
// is acceptable.
type Policy struct {
	allowedTags   map[string]bool
	allowedAttrs  map[string]map[string]bool
	wildcardAttrs map[string]bool

	// prefixAttrs maps a tag (or "*") to the attribute-name
	// prefixes allowed on it, e.g. "aria-" or "data-gb-". A prefix
	// declared for one tag does not leak to the others.
	prefixAttrs map[string][]string

	allowTargetBlank bool
	maxDepth         int
	maxNodes         int
	shellNamespace   string
	strictNamespace  bool
}

// NewPolicy pre-parses a profile into an HTML policy.
func NewPolicy(p Profile) (*Policy, error) {
	if p.MaxDOMDepth <= 0 {
		return nil, fmt.Errorf("html: maxDOMDepth must be > 0")
	}
	if p.MaxDOMNodes <= 0 {
		return nil, fmt.Errorf("html: maxDOMNodes must be > 0")
	}
	shellNS := p.ShellNamespace
	if shellNS == "" {
		shellNS = ShellNamespacePrefix
	}
	hp := &Policy{
		allowedTags:      make(map[string]bool, len(p.AllowedTags)),
		allowedAttrs:     make(map[string]map[string]bool, len(p.AllowedTags)),
		wildcardAttrs:    make(map[string]bool),
		prefixAttrs:      make(map[string][]string),
		allowTargetBlank: p.AllowTargetBlank,
		maxDepth:         p.MaxDOMDepth,
		maxNodes:         p.MaxDOMNodes,
		shellNamespace:   shellNS,
		strictNamespace:  p.StrictNamespaceCollisions,
	}
	for _, t := range p.AllowedTags {
		hp.allowedTags[strings.ToLower(t)] = true
	}
	for tag, attrs := range p.AllowedAttrs {
		lt := strings.ToLower(tag)
		m := make(map[string]bool, len(attrs))
		for _, a := range attrs {
			la := strings.ToLower(a)
			if isPrefixAttribute(la) {
				hp.prefixAttrs[lt] = append(hp.prefixAttrs[lt], strings.TrimSuffix(la, "*"))
				continue
			}
			m[la] = true
		}
		if lt == "*" {
			for k := range m {
				hp.wildcardAttrs[k] = true
			}
		} else {
			hp.allowedAttrs[lt] = m
		}
	}
	return hp, nil
}

// isPrefixAttribute returns true if the attribute name is a
// prefix-style entry (e.g. "aria-*", "data-gb-*").
func isPrefixAttribute(name string) bool {
	return strings.HasSuffix(name, "-*")
}

// AttributeAllowed returns true if the given attribute may appear
// on the given tag. Prefix entries ("aria-*", "data-gb-*") only
// apply to the tag they were declared for, or to every tag when
// declared under "*".
func (p *Policy) AttributeAllowed(tag, attr string) bool {
	la := strings.ToLower(attr)
	lt := strings.ToLower(tag)
	if strings.HasPrefix(la, "on") {
		return false
	}
	if isPrefixAttribute(la) {
		return false
	}
	if m, ok := p.allowedAttrs[lt]; ok && m[la] {
		return true
	}
	if p.wildcardAttrs[la] {
		return true
	}
	for _, prefix := range p.prefixAttrs[lt] {
		if prefix != "" && strings.HasPrefix(la, prefix) {
			return true
		}
	}
	for _, prefix := range p.prefixAttrs["*"] {
		if prefix != "" && strings.HasPrefix(la, prefix) {
			return true
		}
	}
	return false
}

// TagAllowed returns true if the tag is in the allowlist.
func (p *Policy) TagAllowed(tag string) bool {
	return p.allowedTags[strings.ToLower(tag)]
}

// MaxDepth returns the configured maximum nesting depth.
func (p *Policy) MaxDepth() int { return p.maxDepth }

// MaxNodes returns the configured maximum node count.
func (p *Policy) MaxNodes() int { return p.maxNodes }

// ShellNamespace returns the reserved id/class prefix.
func (p *Policy) ShellNamespace() string { return p.shellNamespace }

// StrictNamespace returns true if id/class collisions should
// reject rather than rewrite.
func (p *Policy) StrictNamespace() bool { return p.strictNamespace }

// AllowTargetBlank returns true if target="_blank" is permitted.
func (p *Policy) AllowTargetBlank() bool { return p.allowTargetBlank }
