package usercontent

import (
	"errors"
	"fmt"
)

// Sentinel errors. Wrapped errors from this package can be checked
// with errors.Is.
var (
	// ErrInvalidConfig indicates a Config violates a constraint at
	// load time (unknown profile name, invalid value, etc.).
	ErrInvalidConfig = errors.New("usercontent: invalid config")

	// ErrInvalidProfile indicates a profile violates a non-negotiable
	// invariant (e.g. allowing <script>, javascript: URLs, or a CSP
	// script-src other than 'none'/explicit hashes).
	ErrInvalidProfile = errors.New("usercontent: invalid profile")

	// ErrInputTooLarge indicates the input exceeds the configured
	// size limits (MaxHTMLBytes / MaxCSSBytes).
	ErrInputTooLarge = errors.New("usercontent: input too large")

	// ErrTooDeep indicates the HTML DOM exceeds the configured
	// nesting depth.
	ErrTooDeep = errors.New("usercontent: DOM too deep")

	// ErrTooManyNodes indicates the HTML DOM exceeds the configured
	// node count.
	ErrTooManyNodes = errors.New("usercontent: too many DOM nodes")

	// ErrUnparseableCSS indicates the CSS input could not be parsed
	// by the configured parser. Per the spec, unparseable CSS is
	// rejected, not "best effort" passed through.
	ErrUnparseableCSS = errors.New("usercontent: unparseable CSS")

	// ErrInvalidURL indicates a URL failed scheme/origin validation.
	ErrInvalidURL = errors.New("usercontent: invalid URL")

	// ErrInvalidUTF8 indicates the input contains invalid UTF-8 bytes.
	ErrInvalidUTF8 = errors.New("usercontent: invalid UTF-8 encoding")

	// ErrInvalidCharacter indicates the input contains forbidden control or bidi characters.
	ErrInvalidCharacter = errors.New("usercontent: forbidden character in input")

	// ErrUnsafeOutput indicates the sanitizer produced output that
	// failed its own verification pass — a forbidden element or
	// attribute survived into the sanitized DOM, or the sanitized
	// CSS still contained a markup-significant character. It must
	// never happen in practice; it exists so the failure is loud
	// and fails closed rather than being served.
	ErrUnsafeOutput = errors.New("usercontent: sanitized output failed verification")
)

// ProfileError wraps ErrInvalidProfile with human-readable context
// for the profile author.
type ProfileError struct {
	Field  string
	Reason string
}

func (e *ProfileError) Error() string {
	return fmt.Sprintf("invalid profile field %q: %s", e.Field, e.Reason)
}

func (e *ProfileError) Unwrap() error { return ErrInvalidProfile }
