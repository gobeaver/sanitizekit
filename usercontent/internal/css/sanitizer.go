package css

import (
	"errors"
	"fmt"
	"strings"
)

// Removal is a single CSS sanitizer decision. The usercontent
// package converts these to its public Removal type.
type Removal struct {
	Kind   string
	Value  string
	Reason string
	Line   int
}

// RemovalKind constants correspond to the public RemovalKind
// values in the usercontent package.
const (
	rkForbiddenCSSRule     = "forbidden_css_rule"
	rkForbiddenCSSFunction = "forbidden_css_function"
	rkExternalCSS          = "external_css"
	rkExternalFont         = "external_font"
	rkMalformed            = "malformed"
)

// URLPolicy is the subset of *urlPolicy (parent) the css
// package needs. Defined here to keep the parent package's
// surface area small.
type URLPolicy interface {
	ValidateURL(raw string, isAsset bool) (string, error)
}

// maxNestingDepth bounds how deeply conditional group rules
// (@media, @supports, @container, ...) may nest, so a pathological
// stylesheet cannot drive unbounded recursion.
const maxNestingDepth = 8

// Sentinel errors so the parent package can match against them.
var (
	// ErrUnparseable indicates the CSS could not be parsed. Per
	// spec §6 unparseable CSS is rejected, never passed through
	// on a best-effort basis.
	ErrUnparseable = errors.New("unparseable CSS")

	// ErrUnsafeOutput indicates the sanitized CSS still contained a
	// '<' byte, which could terminate the <style> element the CSS
	// is embedded in. It must never happen: it is the CSS-side
	// counterpart of the HTML output re-verification pass, and it
	// fails closed.
	ErrUnsafeOutput = errors.New("sanitized CSS contains a markup-significant character")
)

// Sanitize is the main CSS sanitizer. It parses the input as a
// rule list and rewrites it according to the policy. Unparseable
// CSS is rejected per spec §6.
//
// The output satisfies one hard invariant: it never contains a
// literal '<' byte. Any '<' in a value is emitted as the CSS
// escape "\3c ", and any selector or at-rule prelude containing
// one is dropped. That makes it impossible for sanitized CSS to
// close the <style> element it is embedded in, regardless of how
// the consumer inlines it.
func Sanitize(input string, p *Policy, up URLPolicy) (string, []Removal, error) {
	if p == nil {
		return "", nil, errors.New("css: policy is nil")
	}
	if up == nil {
		return "", nil, errors.New("css: url policy is nil")
	}

	// Comments are stripped before parsing. They are never emitted,
	// and removing them up front keeps every downstream scanner from
	// having to reason about them.
	stripped, err := stripComments(input)
	if err != nil {
		return "", nil, fmt.Errorf("css: %w: %w", ErrUnparseable, err)
	}

	out, removals, err := sanitizeRuleList(stripped, p, up, 0)
	if err != nil {
		return "", removals, err
	}
	if strings.IndexByte(out, '<') >= 0 {
		return "", removals, fmt.Errorf("css: %w", ErrUnsafeOutput)
	}
	return out, removals, nil
}

// sanitizeRuleList sanitizes a sequence of statements (the
// top-level stylesheet, or the body of a conditional group rule).
func sanitizeRuleList(input string, p *Policy, up URLPolicy, depth int) (string, []Removal, error) {
	removals := []Removal{}
	if depth > maxNestingDepth {
		return "", append(removals, Removal{
			Kind:   rkForbiddenCSSRule,
			Value:  "@-rule",
			Reason: "nesting depth limit exceeded",
		}), nil
	}

	ps, err := parse(input)
	if err != nil {
		return "", removals, fmt.Errorf("css: %w: %w", ErrUnparseable, err)
	}

	var out strings.Builder
	out.Grow(len(input))
	for _, st := range ps.statements {
		var (
			text string
			rems []Removal
		)
		switch st.kind {
		case stmtAtRule:
			text, rems, err = sanitizeAtRule(st, p, up, depth)
		case stmtRule:
			text, rems = sanitizeRule(st, p, up)
		}
		removals = append(removals, rems...)
		if err != nil {
			return "", removals, err
		}
		out.WriteString(text)
	}
	return out.String(), removals, nil
}

// sanitizeAtRule sanitizes a single @-rule.
func sanitizeAtRule(st statement, p *Policy, up URLPolicy, depth int) (string, []Removal, error) {
	removals := []Removal{}
	at := strings.ToLower(st.at)

	if !p.allowedAtRules[at] {
		return "", append(removals, Removal{
			Kind:   rkForbiddenCSSRule,
			Value:  "@" + st.at,
			Reason: "@-rule not in allowlist",
		}), nil
	}
	if !st.hasBlock {
		// Statement at-rules carry their payload entirely in the
		// prelude (@import, @charset, @namespace). Those are always
		// forbidden, and any other block-less at-rule has nothing we
		// can vouch for.
		return "", append(removals, Removal{
			Kind:   rkForbiddenCSSRule,
			Value:  "@" + st.at,
			Reason: "@-rule without a block is not allowed",
		}), nil
	}

	prelude := strings.TrimSpace(st.prelude)
	if prelude != "" {
		if reason, ok := validatePreludeText(prelude); !ok {
			return "", append(removals, Removal{
				Kind:   rkForbiddenCSSRule,
				Value:  prelude,
				Reason: reason,
			}), nil
		}
	}

	var body string
	if isGroupRule(at) {
		inner, rems, err := sanitizeRuleList(innerBlock(st.block), p, up, depth+1)
		removals = append(removals, rems...)
		if err != nil {
			return "", removals, err
		}
		if strings.TrimSpace(inner) == "" {
			return "", removals, nil
		}
		body = "{" + inner + "}"
	} else {
		b, rems := sanitizeBlock(st.block, p, up, at)
		removals = append(removals, rems...)
		if b == "" {
			return "", removals, nil
		}
		body = b
	}

	var out strings.Builder
	out.WriteByte('@')
	out.WriteString(at)
	if prelude != "" {
		out.WriteByte(' ')
		out.WriteString(prelude)
	}
	out.WriteString(body)
	return out.String(), removals, nil
}

// sanitizeRule sanitizes a single qualified rule (selector + block).
func sanitizeRule(st statement, p *Policy, up URLPolicy) (string, []Removal) {
	removals := []Removal{}
	sel := strings.TrimSpace(st.selector)
	if reason, ok := validateSelector(sel, p); !ok {
		return "", append(removals, Removal{
			Kind:   rkForbiddenCSSRule,
			Value:  sel,
			Reason: reason,
		})
	}
	block, rems := sanitizeBlock(st.block, p, up, "")
	removals = append(removals, rems...)
	if block == "" {
		return "", removals
	}
	return sel + block, removals
}

// isGroupRule reports whether an at-rule's block contains nested
// rules (rather than a flat declaration list).
func isGroupRule(at string) bool {
	switch at {
	case "media", "supports", "container", "layer", "scope",
		"keyframes", "-webkit-keyframes", "-moz-keyframes":
		return true
	}
	return false
}

// innerBlock strips the outer braces from a `{ ... }` block.
func innerBlock(block string) string {
	b := strings.TrimSpace(block)
	b = strings.TrimPrefix(b, "{")
	b = strings.TrimSuffix(b, "}")
	return b
}

// =================================================================
// Selector / prelude validation.
// =================================================================

// validateSelector applies every selector-level rule: the shell
// namespace reservation, the universal-selector ban, the optional
// attribute-selector ban, the pseudo-class allowlist, and the
// character allowlist that keeps markup out of the output.
func validateSelector(sel string, p *Policy) (string, bool) {
	if sel == "" {
		return "empty selector", false
	}
	if p.shellNamespace != "" && strings.Contains(sel, p.shellNamespace) {
		return "selector targets shell namespace", false
	}
	if isUniversalSelector(sel) {
		return "universal selector is forbidden", false
	}
	if p.disallowAttributeSelectors && strings.ContainsAny(sel, "[]") {
		return "attribute selectors are not allowed", false
	}
	if reason, ok := validatePreludeText(sel); !ok {
		return reason, false
	}
	if name, ok := firstDisallowedPseudo(sel, p); !ok {
		return "pseudo-class " + name + " not in allowlist", false
	}
	return "", true
}

// isUniversalSelector reports whether any comma-separated part of
// the selector is a bare universal selector, which would let user
// CSS restyle the trusted shell.
func isUniversalSelector(sel string) bool {
	for _, part := range strings.Split(sel, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || strings.HasPrefix(part, "* ") || strings.HasPrefix(part, "*>") {
			return true
		}
	}
	return false
}

// validatePreludeText enforces the character allowlist shared by
// selectors and at-rule preludes. '<' is deliberately absent: it
// has no meaning in either, and excluding it is what makes a
// "</style>" breakout structurally impossible.
func validatePreludeText(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if !isSafeSelectorByte(s[i]) {
			return fmt.Sprintf("selector contains forbidden character %q", s[i]), false
		}
	}
	return "", true
}

func isSafeSelectorByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c >= 0x80:
		// Non-ASCII identifiers. The charset validator upstream has
		// already rejected control, bidi and invisible characters.
		return true
	}
	switch c {
	case ' ', '\t', '\n', '\r', '\f',
		'-', '_', '.', '#', '*', ':', ',', '>', '+', '~',
		'[', ']', '=', '^', '$', '|', '(', ')', '%', '/',
		'"', '\'', '&', '!', '\\':
		return true
	}
	return false
}

// firstDisallowedPseudo returns the first pseudo-class or
// pseudo-element in the selector that is not in the policy's
// allowlist. An empty allowlist disables the check.
func firstDisallowedPseudo(sel string, p *Policy) (string, bool) {
	if len(p.allowedPseudoClasses) == 0 {
		return "", true
	}
	for i := 0; i < len(sel); i++ {
		if sel[i] != ':' {
			continue
		}
		start := i
		i++
		if i < len(sel) && sel[i] == ':' {
			i++
		}
		j := i
		for j < len(sel) && isIdentCont(sel[j]) {
			j++
		}
		if j == i {
			// A stray ':' with no name following it.
			return ":", false
		}
		name := strings.ToLower(sel[start:j])
		if !p.allowedPseudoClasses[name] {
			return name, false
		}
		i = j - 1
	}
	return "", true
}

// =================================================================
// Declaration blocks.
// =================================================================

// sanitizeBlock rewrites a `{ ... }` declaration block, dropping
// any declaration whose property or value violates the policy.
// The returned string includes the surrounding braces, or is
// empty if nothing survived.
func sanitizeBlock(block string, p *Policy, up URLPolicy, atRule string) (string, []Removal) {
	removals := []Removal{}
	body := innerBlock(block)
	if strings.TrimSpace(body) == "" {
		return "", removals
	}

	var out strings.Builder
	out.WriteString("{")
	kept := 0
	for _, d := range parseDeclarations(body) {
		prop := strings.ToLower(strings.TrimSpace(d.prop))
		custom := strings.HasPrefix(prop, "--")
		if custom && !isValidCustomProperty(prop) {
			removals = append(removals, Removal{
				Kind:   rkForbiddenCSSRule,
				Value:  prop,
				Reason: "malformed custom property name",
			})
			continue
		}
		if !custom && !p.allowedDeclarations[prop] {
			removals = append(removals, Removal{
				Kind:   rkForbiddenCSSRule,
				Value:  prop,
				Reason: "property not in allowlist",
			})
			continue
		}
		val, valRemovals := sanitizeValue(d.value, p, up, atRule)
		removals = append(removals, valRemovals...)
		// Trim before emitting: dropping a function from the middle
		// of a value can leave whitespace at either end, which the
		// next sanitize pass would trim, breaking idempotence.
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		out.WriteString(prop)
		out.WriteString(":")
		out.WriteString(val)
		out.WriteString(";")
		kept++
	}
	out.WriteString("}")
	if kept == 0 {
		return "", removals
	}
	return out.String(), removals
}

// isValidCustomProperty reports whether a `--name` custom property
// is well formed. Custom properties bypass the declaration
// allowlist, so their names must be constrained explicitly.
func isValidCustomProperty(prop string) bool {
	if len(prop) < 3 || !strings.HasPrefix(prop, "--") {
		return false
	}
	for i := 2; i < len(prop); i++ {
		c := prop[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// sanitizeValue checks a declaration value for url() calls and
// other dangerous functions. Returns the (possibly rewritten)
// value and a list of removals. Every byte it emits goes through
// writeCSSText, so a '<' can never reach the output.
func sanitizeValue(value string, p *Policy, up URLPolicy, atRule string) (string, []Removal) {
	removals := []Removal{}
	var out strings.Builder
	i := 0
	for i < len(value) {
		c := value[i]
		switch {
		case isIdentStart(c):
			j := i
			for j < len(value) && isIdentCont(value[j]) {
				j++
			}
			if j < len(value) && value[j] == '(' {
				next, rems, ok := writeFunctionCall(&out, value, i, j, p, up, atRule)
				removals = append(removals, rems...)
				if !ok {
					return "", removals
				}
				i = next
				continue
			}
			writeCSSText(&out, value[i:j])
			i = j
		case c == '"' || c == '\'':
			j := skipString(value, i)
			if j >= len(value) {
				removals = append(removals, Removal{
					Kind:   rkMalformed,
					Value:  value[i:],
					Reason: "unterminated string",
				})
				return "", removals
			}
			writeCSSText(&out, value[i:j+1])
			i = j + 1
		case isStructuralByte(c):
			// A structural character that reached here is not part of
			// a function call, a string or an identifier, so the value
			// is malformed. Emitting it would also break idempotence:
			// a stray '(' or '{' changes how the next pass splits
			// declarations.
			removals = append(removals, Removal{
				Kind:   rkMalformed,
				Value:  value,
				Reason: fmt.Sprintf("unexpected %q in declaration value", c),
			})
			return "", removals
		default:
			writeCSSText(&out, value[i:i+1])
			i++
		}
	}
	if len(removals) > 0 && strings.TrimSpace(out.String()) == "" {
		return "", removals
	}
	return out.String(), removals
}

// writeFunctionCall handles one `name(...)` in a declaration value:
// url() goes through the URL policy, anything else must be in the
// function allowlist and has its arguments sanitized recursively.
// It returns the index just past the call, and false if the whole
// value must be dropped.
func writeFunctionCall(out *strings.Builder, value string, start, paren int, p *Policy, up URLPolicy, atRule string) (int, []Removal, bool) {
	removals := []Removal{}
	ident := value[start:paren]
	name := strings.ToLower(ident)

	closeIdx := findMatching(value, paren)
	if closeIdx < 0 {
		return 0, append(removals, Removal{
			Kind:   rkMalformed,
			Value:  ident + "()",
			Reason: "unclosed function call",
		}), false
	}

	if name == "url" {
		arg := strings.TrimSpace(value[paren+1 : closeIdx])
		if len(arg) >= 2 && (arg[0] == '"' || arg[0] == '\'') && arg[len(arg)-1] == arg[0] {
			arg = arg[1 : len(arg)-1]
		}
		reason, err := up.ValidateURL(arg, true)
		if err != nil {
			kind := rkExternalCSS
			if atRule == "font-face" {
				kind = rkExternalFont
			}
			return closeIdx + 1, append(removals, Removal{
				Kind:   kind,
				Value:  arg,
				Reason: reason,
			}), true
		}
		writeCSSText(out, value[start:closeIdx+1])
		return closeIdx + 1, removals, true
	}

	if !p.allowedFunctions[name] {
		return closeIdx + 1, append(removals, Removal{
			Kind:   rkForbiddenCSSFunction,
			Value:  name,
			Reason: "function not in allowlist",
		}), true
	}

	args, argRems := sanitizeValue(strings.TrimSpace(value[paren+1:closeIdx]), p, up, atRule)
	removals = append(removals, argRems...)
	writeCSSText(out, ident)
	out.WriteByte('(')
	out.WriteString(args)
	out.WriteByte(')')
	return closeIdx + 1, removals, true
}

// isStructuralByte reports whether a byte carries CSS structure
// that a declaration value must not contain on its own. Function
// calls, strings and identifiers are consumed by their own
// branches before this test is reached.
func isStructuralByte(c byte) bool {
	switch c {
	case '(', ')', '{', '}', ';', '@':
		return true
	}
	return false
}

// writeCSSText writes s to out, replacing every '<' with the CSS
// escape "\3c " (which renders identically). This is the single
// choke point that guarantees sanitized CSS can never terminate
// the <style> element it is embedded in.
func writeCSSText(out *strings.Builder, s string) {
	if strings.IndexByte(s, '<') < 0 {
		out.WriteString(s)
		return
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '<' {
			out.WriteString(`\3c `)
			continue
		}
		out.WriteByte(s[i])
	}
}

// findMatching finds the index of the matching ')' for the '(' at
// index open in s. Returns -1 if not found.
func findMatching(s string, open int) int {
	depth := 1
	for i := open + 1; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\'' {
			j := skipString(s, i)
			if j >= len(s) {
				return -1
			}
			i = j
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipString returns the index of the quote that closes the string
// literal opening at index i, or len(s) if it is unterminated.
// Every scanner in this file needs the same rule — a quote ends a
// string, a backslash escapes the next byte — so they share it
// rather than each carrying a copy to get subtly wrong.
func skipString(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			return j
		}
	}
	return len(s)
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == '*'
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// isSpaceByte is a byte-wise whitespace test. It deliberately does
// not widen to a rune: doing so would treat UTF-8 continuation
// bytes as Latin-1 whitespace.
func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// =================================================================
// CSS parser (very small subset).
// =================================================================

type statement struct {
	kind     int
	at       string
	prelude  string
	selector string
	block    string
	hasBlock bool
}

const (
	stmtAtRule = iota
	stmtRule
)

type parsed struct {
	statements []statement
}

type decl struct {
	prop  string
	value string
}

// stripComments removes /* ... */ comments, replacing each with a
// single space so tokens either side stay separated. Comments
// inside string literals are left alone. An unterminated comment
// is an error: the remainder of the stylesheet would otherwise be
// silently swallowed.
func stripComments(input string) (string, error) {
	if !strings.Contains(input, "/*") {
		return input, nil
	}
	var out strings.Builder
	out.Grow(len(input))
	for i := 0; i < len(input); {
		c := input[i]
		if c == '"' || c == '\'' {
			j := skipString(input, i)
			if j >= len(input) {
				// Let the rule parser report the unterminated string.
				out.WriteString(input[i:])
				return out.String(), nil
			}
			out.WriteString(input[i : j+1])
			i = j + 1
			continue
		}
		if c == '/' && i+1 < len(input) && input[i+1] == '*' {
			end := strings.Index(input[i+2:], "*/")
			if end < 0 {
				return "", errors.New("unterminated comment")
			}
			out.WriteByte(' ')
			i += 2 + end + 2
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.String(), nil
}

func parse(input string) (*parsed, error) {
	p := &parsed{}
	i := 0
	for i < len(input) {
		for i < len(input) && isSpaceByte(input[i]) {
			i++
		}
		if i >= len(input) {
			break
		}
		if input[i] == '@' {
			st, next, err := parseAtRule(input, i)
			if err != nil {
				return nil, err
			}
			p.statements = append(p.statements, st)
			i = next
			continue
		}
		sel, block, next, err := parseRule(input, i)
		if err != nil {
			// Recover by skipping to the next statement boundary.
			// Skipping is fail-closed: the skipped text is dropped,
			// never emitted.
			j := strings.IndexAny(input[i:], ";}")
			if j < 0 {
				return nil, err
			}
			i += j + 1
			continue
		}
		if strings.TrimSpace(sel) == "" {
			i = next
			continue
		}
		p.statements = append(p.statements, statement{
			kind:     stmtRule,
			selector: sel,
			block:    block,
		})
		i = next
	}
	return p, nil
}

// parseAtRule parses an @-rule starting at the '@' in input[start].
// It returns the at-keyword, the prelude (everything between the
// keyword and the block or terminating ';'), the block including
// its braces, whether a block was present, and the index just past
// the rule.
func parseAtRule(input string, start int) (st statement, next int, err error) {
	i := start + 1
	j := i
	for j < len(input) && !isAtRuleHeadStop(input[j]) {
		j++
	}
	st = statement{kind: stmtAtRule, at: input[i:j]}
	if st.at == "" {
		return st, j, errors.New("empty @-rule name")
	}

	end, kind := scanPrelude(input, j)
	st.prelude = strings.TrimSpace(input[j:end])
	switch kind {
	case preludeSemicolon:
		return st, end + 1, nil
	case preludeBlock:
		blockEnd, ok := matchBrace(input, end)
		if !ok {
			st.block, st.hasBlock = input[end:], true
			return st, len(input), errors.New("unterminated @-rule block")
		}
		st.block, st.hasBlock = input[end:blockEnd], true
		return st, blockEnd, nil
	case preludeUnterminatedString:
		return st, len(input), errors.New("unterminated string in @-rule prelude")
	case preludeStrayBrace:
		return st, end, errors.New("unexpected '}' in @-rule prelude")
	default:
		return st, end, errors.New("unexpected EOF in @-rule")
	}
}

// How an at-rule prelude ended.
const (
	preludeEOF = iota
	preludeSemicolon
	preludeBlock
	preludeUnterminatedString
	preludeStrayBrace
)

// scanPrelude walks an at-rule prelude from index j and returns
// where it ended and why. Parentheses, brackets and strings are
// tracked so a ';' or '{' inside them does not end it.
func scanPrelude(input string, j int) (end, kind int) {
	depth := 0
	for j < len(input) {
		switch c := input[j]; c {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case '"', '\'':
			k := skipString(input, j)
			if k >= len(input) {
				return len(input), preludeUnterminatedString
			}
			j = k
		case ';':
			if depth == 0 {
				return j, preludeSemicolon
			}
		case '{':
			if depth == 0 {
				return j, preludeBlock
			}
		case '}':
			if depth == 0 {
				return j, preludeStrayBrace
			}
		}
		j++
	}
	return j, preludeEOF
}

// parseRule parses a qualified rule: a selector followed by a
// brace-delimited block.
func parseRule(input string, start int) (selector, block string, next int, err error) {
	i := start
	for i < len(input) {
		switch c := input[i]; c {
		case '"', '\'':
			j := skipString(input, i)
			if j >= len(input) {
				return input[start:i], "", len(input), errors.New("unterminated string")
			}
			i = j
		case '{':
			end, ok := matchBrace(input, i)
			if !ok {
				return input[start:i], input[i:], len(input), errors.New("unterminated block")
			}
			return input[start:i], input[i:end], end, nil
		case '}':
			return input[start:i], "", i + 1, errors.New("unexpected '}'")
		case ';':
			return input[start:i], "", i + 1, errors.New("unexpected ';' outside a block")
		}
		i++
	}
	return input[start:i], "", i, errors.New("expected '{'")
}

// matchBrace returns the index just past the '}' matching the '{'
// at index open, and whether a match was found. Braces inside
// string literals are ignored.
func matchBrace(s string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'':
			j := skipString(s, i)
			if j >= len(s) {
				return len(s), false
			}
			i = j
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return len(s), false
}

func isAtRuleHeadStop(c byte) bool {
	if isSpaceByte(c) {
		return true
	}
	switch c {
	case '{', '}', ';', ',', '(':
		return true
	}
	return false
}

// parseDeclarations splits a declaration block body on top-level
// semicolons. Semicolons inside strings, parentheses or nested
// braces do not split.
func parseDeclarations(body string) []decl {
	var out []decl
	depth, paren := 0, 0
	var b strings.Builder
	flush := func() {
		s := strings.TrimSpace(b.String())
		b.Reset()
		if s == "" {
			return
		}
		colon := strings.IndexByte(s, ':')
		if colon < 0 {
			return
		}
		out = append(out, decl{
			prop:  strings.TrimSpace(s[:colon]),
			value: strings.TrimSpace(s[colon+1:]),
		})
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch c {
		case '"', '\'':
			j := skipString(body, i)
			if j < len(body) {
				j++
			}
			b.WriteString(body[i:min(j, len(body))])
			i = j - 1
			continue
		case '(':
			paren++
		case ')':
			if paren > 0 {
				paren--
			}
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 && paren == 0 {
				flush()
				continue
			}
		}
		b.WriteByte(c)
	}
	flush()
	return out
}
