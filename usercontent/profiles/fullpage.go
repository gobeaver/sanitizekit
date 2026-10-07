// Package profiles provides ready-made profile configurations
// that consumers can use directly or copy and tighten.
package profiles

import (
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
)

// ProfileFullPage is the recommended default profile for a
// consumer rendering a complete user-authored page. It allows
// the safe, basic HTML / CSS vocabulary needed for designing a
// page (heading + paragraph + section + simple image + link,
// basic layout, basic typography, basic color), and nothing
// more. Scripting vectors are always rejected by validate()
// regardless of what is listed here; that is enforced by the
// package's non-negotiable invariants, not by this profile.
func ProfileFullPage() usercontent.Profile {
	return usercontent.DefaultFullPageProfile()
}
