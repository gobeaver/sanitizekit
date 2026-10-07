// Package css implements the CSS sanitization layer of the
// usercontent platform. It exposes a small policy type built
// from a usercontent.Profile, plus a Sanitize function that walks
// a hand-written CSS tokenizer and emits a sanitized CSS string.
//
// The package is internal to the usercontent module; consumers
// do not import it directly.
//
// The package does not import the usercontent package (to avoid
// an import cycle through the parent package); it duplicates the
// smallest contract it needs.
package css

import (
	"fmt"
	"strings"
)

// Policy is the pre-parsed CSS policy. Constructed from a
// usercontent.Profile by NewPolicy.
type Policy struct {
	allowedAtRules             map[string]bool
	allowedDeclarations        map[string]bool
	allowedFunctions           map[string]bool
	allowedPseudoClasses       map[string]bool
	disallowAttributeSelectors bool
	shellNamespace             string
}

// Profile is the minimal contract the css package needs from
// usercontent.Profile. We accept a struct of fields rather than
// importing the full type to avoid an import cycle.
type Profile struct {
	Name                       string
	AllowedAtRules             []string
	AllowedDeclarations        []string
	AllowedFunctions           []string
	AllowedPseudoClasses       []string
	DisallowAttributeSelectors bool
	ShellNamespace             string
}

// NewPolicy pre-parses a profile into a css policy.
func NewPolicy(p Profile) (*Policy, error) {
	if len(p.AllowedDeclarations) == 0 {
		return nil, fmt.Errorf("css: AllowedDeclarations must not be empty")
	}
	return &Policy{
		allowedAtRules:             toLowerSet(p.AllowedAtRules),
		allowedDeclarations:        toLowerSet(p.AllowedDeclarations),
		allowedFunctions:           toLowerSet(p.AllowedFunctions),
		allowedPseudoClasses:       toLowerSet(p.AllowedPseudoClasses),
		disallowAttributeSelectors: p.DisallowAttributeSelectors,
		shellNamespace:             p.ShellNamespace,
	}, nil
}

func toLowerSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, x := range s {
		m[strings.ToLower(strings.TrimSpace(x))] = true
	}
	return m
}
