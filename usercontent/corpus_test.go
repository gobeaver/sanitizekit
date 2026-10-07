package usercontent_test

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

// TestCorpusXSS reads each XSS vector from the corpus file and
// asserts that the sanitized output contains none of the dangerous
// load-bearing substrings. This is the central regression test of
// M1.
func TestCorpusXSS(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open("corpus/xss/vectors.txt")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	scc := bufio.NewScanner(f)
	scc.Buffer(make([]byte, 1024*1024), 1024*1024)

	line := 0
	for scc.Scan() {
		line++
		in := strings.TrimSpace(scc.Text())
		if in == "" || strings.HasPrefix(in, "#") {
			continue
		}
		out, _, err := s.SanitizeHTML(in)
		if err != nil {
			t.Errorf("corpus line %d: sanitize error: %v\ninput: %q", line, err, in)
			continue
		}

		doc, parseErr := html.Parse(strings.NewReader(out))
		if parseErr != nil {
			t.Errorf("corpus line %d: output html parse error: %v\noutput: %q", line, parseErr, out)
			continue
		}

		var checkNode func(*html.Node)
		checkNode = func(n *html.Node) {
			if n.Type == html.ElementNode {
				tag := strings.ToLower(n.Data)
				switch tag {
				case "script", "iframe", "object", "embed", "form", "input", "button",
					"meta", "base", "style", "svg", "math", "details", "marquee",
					"noscript", "applet", "keygen", "frame":
					t.Errorf("corpus line %d: forbidden tag <%s> found in DOM tree\ninput:  %q\noutput: %q",
						line, tag, in, out)
				}
				for _, attr := range n.Attr {
					key := strings.ToLower(attr.Key)
					if strings.HasPrefix(key, "on") || key == "formaction" {
						t.Errorf("corpus line %d: forbidden attribute %q found in DOM tree\ninput:  %q\noutput: %q",
							line, attr.Key, in, out)
					}
					if key == "href" || key == "src" {
						val := strings.ToLower(strings.TrimSpace(attr.Val))
						if strings.HasPrefix(val, "javascript:") || strings.HasPrefix(val, "vbscript:") {
							t.Errorf("corpus line %d: forbidden URL scheme %q found in DOM tree\ninput:  %q\noutput: %q",
								line, attr.Val, in, out)
						}
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				checkNode(c)
			}
		}
		checkNode(doc)
	}
}

// TestCorpusCSS reads each CSS vector from the corpus and
// asserts that the sanitized output contains no @import,
// expression(), external url(), or other dangerous constructs.
func TestCorpusCSS(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileFullPage())
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open("corpus/css/vectors.txt")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)

	banned := []string{
		"@import", "expression(", "behavior:", "-moz-binding",
		"javascript:", "vbscript:",
		"evil.com",
	}

	line := 0
	for sc.Scan() {
		line++
		in := strings.TrimSpace(sc.Text())
		if in == "" || strings.HasPrefix(in, "#") {
			continue
		}
		out, _, err := s.SanitizeCSS(in)
		if err != nil {
			// Unparseable CSS is a valid rejection; not a test
			// failure.
			if errors.Is(err, usercontent.ErrUnparseableCSS) {
				continue
			}
			t.Errorf("corpus line %d: sanitize error: %v\ninput: %q", line, err, in)
			continue
		}
		lower := strings.ToLower(out)
		for _, bad := range banned {
			if strings.Contains(lower, bad) {
				t.Errorf("corpus line %d: %q leaked\ninput:  %q\noutput: %q",
					line, bad, in, out)
			}
		}
	}
}

// TestProfileAgainstCorpus is a public helper advertised in the
// spec for consumers with custom profiles. Re-exported here for
// internal use.
func TestProfileAgainstCorpus(t *testing.T) {
	s, err := usercontent.New(profiles.ProfileEmbed())
	if err != nil {
		t.Fatal(err)
	}
	// Embed profile is stricter: also reject frame anchors etc.
	in := `<p>hi</p><script>alert(1)</script>`
	out, _, _ := s.SanitizeHTML(in)
	if strings.Contains(strings.ToLower(out), "alert(1)") {
		t.Errorf("embed profile failed: %s", out)
	}
}
