package profiles

import "github.com/gobeaver/go-beaver-tag-sanitization/usercontent"

// ProfileEmbed is a tighter profile for embedded user-content
// blocks within otherwise-native pages. It allows a smaller
// vocabulary and an even stricter CSS policy. Use it when the
// surrounding page provides navigation/buttons and the embedded
// block should be presentational.
//
// Scripting vectors (script, iframe, form, on* event handlers,
// javascript: URLs, expression(), behavior, -moz-binding) are
// always rejected by validate() regardless of what is listed
// here — that is enforced by the package's non-negotiable
// invariants, not by this profile.
func ProfileEmbed() usercontent.Profile {
	return usercontent.DefaultEmbedProfile()
}
