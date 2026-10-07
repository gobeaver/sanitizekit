package usercontent

import (
	"fmt"
	stdhtml "html"
	"unicode/utf8"
)

func validateRune(r rune) error {
	if r == 0 {
		return fmt.Errorf("%w: NUL byte", ErrInvalidCharacter)
	}
	if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7F {
		return fmt.Errorf("%w: control character U+%04X", ErrInvalidCharacter, r)
	}
	switch r {
	case '\u202E', '\u202D', '\u202A', '\u202B', '\u202C', '\u2066', '\u2067', '\u2068', '\u2069':
		return fmt.Errorf("%w: bidi override character U+%04X", ErrInvalidCharacter, r)
	case '\u200B', '\uFEFF', '\u2060':
		return fmt.Errorf("%w: invisible character U+%04X", ErrInvalidCharacter, r)
	case '\u2028', '\u2029':
		return fmt.Errorf("%w: separator character U+%04X", ErrInvalidCharacter, r)
	}
	return nil
}

// hexVal returns the value of a hex digit, or -1. It returns a
// rune so callers can accumulate a code point without a numeric
// conversion at every step.
func hexVal(c byte) rune {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0')
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10
	}
	return -1
}

// digitVal returns the value of c as a digit in the given base,
// or -1 if it is not one.
func digitVal(c byte, base rune) rune {
	v := hexVal(c)
	if v < 0 || v >= base {
		return -1
	}
	return v
}

// validateEscapes rejects backslash escape sequences that would
// decode to a forbidden character. A sequence that is truncated or
// not actually an escape is left alone: its literal bytes have
// already been checked by validateRune.
func validateEscapes(input string) error {
	for i := 0; i+1 < len(input); i++ {
		if input[i] != '\\' {
			continue
		}
		var digits int
		switch input[i+1] {
		case '0':
			return fmt.Errorf("%w: NUL byte escape \\0", ErrInvalidCharacter)
		case 'x', 'X':
			digits = 2
		case 'u':
			digits = 4
		case 'U':
			digits = 8
		default:
			continue
		}
		if err := validateHexEscape(input, i+2, digits); err != nil {
			return err
		}
	}
	return nil
}

// validateHexEscape checks the n hex digits starting at index
// start. Anything that is not n hex digits is not an escape.
func validateHexEscape(input string, start, n int) error {
	if start+n > len(input) {
		return nil
	}
	var val rune
	for k := 0; k < n; k++ {
		hv := hexVal(input[start+k])
		if hv < 0 {
			return nil
		}
		val = val*16 + hv
	}
	if n == 2 && val >= 0x80 {
		// \xNN above 0x7F is a raw byte, not a code point; it
		// cannot appear in valid UTF-8 text.
		return fmt.Errorf("%w: invalid raw byte escape \\x%02X", ErrInvalidUTF8, val)
	}
	return validateRune(val)
}

// validateNumericEntities rejects numeric HTML entities that would
// decode to a forbidden character, so an attacker cannot smuggle
// one past validateRune by encoding it.
func validateNumericEntities(input string) error {
	for i := 0; i+2 < len(input); i++ {
		if input[i] != '&' || input[i+1] != '#' {
			continue
		}
		if err := validateNumericEntityAt(input, i+2); err != nil {
			return err
		}
	}
	return nil
}

// validateNumericEntityAt validates the entity whose digits begin
// at index j (just past the "&#").
//
// The terminating ';' is deliberately not required: HTML decodes a
// numeric character reference with or without it, so "&#1A" yields
// U+0001 followed by 'A', and "&#x202E" yields a bidi override.
// Requiring the semicolon here would let either of those past the
// character policy and into the sanitized output.
func validateNumericEntityAt(input string, j int) error {
	base := rune(10)
	if input[j] == 'x' || input[j] == 'X' {
		base = 16
		j++
	}
	start := j
	var val rune
	for j < len(input) {
		d := digitVal(input[j], base)
		if d < 0 {
			break
		}
		val = val*base + d
		if val > 0x10FFFF {
			// Beyond the Unicode range: no browser decodes this to a
			// character, and continuing would overflow the rune.
			return nil
		}
		j++
	}
	if j == start {
		// "&#" with no digits after it is not a character reference.
		return nil
	}
	return validateRune(val)
}

// validateCharset verifies that the input string is valid UTF-8
// and contains no forbidden NUL bytes, control characters, bidi overrides,
// invisible characters, or JS-breaking separators (whether literal, entity-encoded, or backslash-escaped).
func validateCharset(input string) error {
	if !utf8.ValidString(input) {
		return ErrInvalidUTF8
	}

	for _, r := range input {
		if err := validateRune(r); err != nil {
			return err
		}
	}

	if err := validateEscapes(input); err != nil {
		return err
	}

	if err := validateNumericEntities(input); err != nil {
		return err
	}

	unescaped := stdhtml.UnescapeString(input)
	if unescaped != input {
		for _, r := range unescaped {
			if err := validateRune(r); err != nil {
				return err
			}
		}
	}
	return nil
}
