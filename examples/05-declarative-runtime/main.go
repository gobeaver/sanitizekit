// Example 05: let user pages animate, without letting them run code.
//
// User content never becomes script. Instead the shell ships one
// small, fixed runtime, and users opt into its behaviours with
// reserved data-gb-* attributes. The runtime is allowed by an exact
// SHA-256 hash in script-src, so the browser will run that script and
// nothing else — not an inline handler, not an injected tag, not a
// modified copy of the runtime itself.
//
//	go run ./examples/05-declarative-runtime
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/gobeaver/go-beaver-tag-sanitization/runtime"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

func main() {
	// Out of the box script-src is 'none' and the runtime does not
	// execute at all. Opting in means naming its hash — nothing else
	// gains permission by doing so.
	p := profiles.ProfileFullPage()
	p.CSP.ScriptHashes = []string{runtime.CSPHash()}

	s, err := usercontent.New(p)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("runtime hash:", runtime.CSPHash())
	fmt.Println("script-src:  ", directive(s.CSPHeaders()["Content-Security-Policy"], "script-src"))
	fmt.Println("\nthe runtime reacts to:", strings.Join(runtime.DataGBAttrs(), ", "))

	// User markup opts into the runtime declaratively. These
	// attributes survive sanitization because the profile allowlists
	// the data-gb-* prefix; their *values* are inert data that the
	// runtime interprets, never code that it evaluates.
	const authored = `
<section data-gb-animate="fade-up">
  <h1>Launching soon</h1>
  <p data-gb-countdown="2027-01-01T00:00:00Z">loading…</p>
</section>
<figure data-gb-lightbox>
  <img src="/assets/hero.png" alt="hero">
</figure>

<!-- None of the following survives: -->
<p onclick="track()">inline handler</p>
<p data-gb-animate="fade-up" onmouseover="steal()">handler alongside a runtime attr</p>
<script>alert(1)</script>`

	out, report, err := s.SanitizeHTML(authored)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n=== sanitized ===")
	fmt.Println(strings.TrimSpace(out))

	fmt.Printf("\n=== removed (%d) ===\n", len(report.Removed))
	for _, r := range report.Removed {
		fmt.Printf("  %-20s %-16q %s\n", r.Kind, r.Value, r.Reason)
	}

	// The hash covers the runtime byte for byte. Change one character
	// and the browser refuses to run it, which is the point: an
	// attacker who could alter the served script still cannot make it
	// execute. runtime_test.go pins this value so an accidental edit
	// is caught in CI rather than in production.
	fmt.Println("\n=== integrity ===")
	tampered := strings.Replace(runtime.Runtime, "fade-up", "fade-dn", 1)
	fmt.Printf("  runtime unchanged      -> hash matches: %v\n",
		cspHashOf(runtime.Runtime) == runtime.CSPHash())
	fmt.Printf("  one character edited   -> hash matches: %v  (browser refuses to run it)\n",
		cspHashOf(tampered) == runtime.CSPHash())

	fmt.Println("\nEmbed runtime.Runtime verbatim in a <script> in your shell —")
	fmt.Println("no added or removed whitespace, or the hash will not match.")
}

// cspHashOf is what runtime.CSPHash does, applied to an arbitrary
// string so the example can show what tampering costs.
func cspHashOf(src string) string {
	sum := sha256.Sum256([]byte(src))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func directive(policy, name string) string {
	for _, part := range strings.Split(policy, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name+" ") {
			return part
		}
	}
	return "(absent)"
}
