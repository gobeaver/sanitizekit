package runtime

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRuntime_IsParseable(t *testing.T) {
	// Sanity check: the runtime is non-empty JS.
	if Runtime == "" {
		t.Fatal("Runtime is empty")
	}
	if !strings.Contains(Runtime, "data-gb-animate") {
		t.Errorf("runtime missing data-gb-animate handler")
	}
	if !strings.Contains(Runtime, "data-gb-countdown") {
		t.Errorf("runtime missing data-gb-countdown handler")
	}
	if !strings.Contains(Runtime, "data-gb-lightbox") {
		t.Errorf("runtime missing data-gb-lightbox handler")
	}
}

func TestRuntime_NoDangerousAPIs(t *testing.T) {
	// The runtime must not use any dangerous APIs that would
	// re-introduce the attack surface the CSP is closing.
	forbidden := []string{
		"eval(",
		"Function(",
		"document.write",
		"setTimeout(string",
		"setInterval(string",
		"innerHTML =",
		"outerHTML =",
		"location =",
		"location.href =",
		"fetch(",
		"XMLHttpRequest",
		"WebSocket",
		"localStorage",
		"sessionStorage",
	}
	for _, f := range forbidden {
		if strings.Contains(Runtime, f) {
			t.Errorf("runtime uses dangerous API %q", f)
		}
	}
}

func TestDataGBAttrs(t *testing.T) {
	attrs := DataGBAttrs()
	want := map[string]bool{
		"data-gb-animate":   true,
		"data-gb-countdown": true,
		"data-gb-lightbox":  true,
	}
	if len(attrs) != len(want) {
		t.Errorf("expected 3 attrs, got %d", len(attrs))
	}
	for _, a := range attrs {
		if !want[a] {
			t.Errorf("unexpected attr %q", a)
		}
	}
}

// CSPHash is a deployment contract: an operator puts it in
// Profile.CSP.ScriptHashes, and the browser refuses to run the
// runtime if the bytes it receives hash to anything else. So a
// change to Runtime must be deliberate and visible, never a
// drive-by edit — otherwise every deployed page silently stops
// running the runtime until its CSP is updated.
//
// If you changed Runtime on purpose, update this constant and say
// so in CHANGELOG.md so operators know to re-pin.
const pinnedCSPHash = `'sha256-U6S5wDGxyuiuMUQBqxZOvgsQC2NSs5w5nWneMLfZhT4='`

func TestCSPHash_Pinned(t *testing.T) {
	if got := CSPHash(); got != pinnedCSPHash {
		t.Errorf("runtime hash changed.\n got:  %s\n want: %s\n\n"+
			"Runtime was edited. If that was intended, update pinnedCSPHash "+
			"and note it in CHANGELOG.md: deployed CSPs pin this value.", got, pinnedCSPHash)
	}
}

func TestCSPHash_Format(t *testing.T) {
	h := CSPHash()
	if !strings.HasPrefix(h, "'sha256-") || !strings.HasSuffix(h, "'") {
		t.Fatalf("CSPHash must be a quoted sha256 source expression, got %q", h)
	}
	// It must be exactly the SHA-256 of Runtime, base64 std encoding,
	// or a browser will reject the script it is meant to allow.
	sum := sha256.Sum256([]byte(Runtime))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if h != want {
		t.Errorf("CSPHash does not match SHA-256 of Runtime:\n got:  %s\n want: %s", h, want)
	}
}

// Every attribute the runtime reacts to must sit inside the
// reserved data-gb- namespace, and must actually be referenced by
// the runtime source. An attribute in the list that the runtime
// ignores is a documentation lie; one outside the namespace would
// not survive sanitization.
func TestDataGBAttrs_NamespacedAndUsed(t *testing.T) {
	for _, a := range DataGBAttrs() {
		if !strings.HasPrefix(a, "data-gb-") {
			t.Errorf("attribute %q is outside the reserved data-gb- namespace", a)
		}
		if !strings.Contains(Runtime, a) {
			t.Errorf("attribute %q is advertised but never referenced by the runtime", a)
		}
	}
}

// The runtime is the only script on the page; it must not reach the
// network or hand user-controlled strings to a markup parser.
func TestRuntime_NoMarkupOrNetworkSinks(t *testing.T) {
	for _, f := range []string{
		"insertAdjacentHTML", "createContextualFragment", "srcdoc",
		"document.domain", "importScripts", "postMessage",
		"navigator.sendBeacon", "new Image(", "eval",
	} {
		if strings.Contains(Runtime, f) {
			t.Errorf("runtime uses %q", f)
		}
	}
}
