// Command corpusexport sanitizes every attack vector in the
// corpus and writes the fully rendered pages to a directory, so
// a real browser can be pointed at them.
//
// It exists because the Go-side output verification re-parses with
// golang.org/x/net/html — the same parser that produced the
// output. That is a correlated check: if x/net/html ever disagrees
// with a browser about some input, the sanitizer and its own
// safety net share the blind spot. Only a browser engine can
// settle what a browser actually does, so the pages this writes
// are loaded by Chromium, Firefox and WebKit in CI
// (browsertest/check.mjs), which assert that nothing executes and
// nothing is fetched.
//
// Run with:
//
//	go run ./cmd/corpusexport -out browsertest/pages
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gobeaver/go-beaver-tag-sanitization/pageservice/render"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent"
	"github.com/gobeaver/go-beaver-tag-sanitization/usercontent/profiles"
)

var (
	outDir     = flag.String("out", "browsertest/pages", "directory to write rendered pages into")
	corpusDir  = flag.String("corpus", "usercontent/corpus", "directory holding the attack corpus")
	seedDir    = flag.String("seeds", "usercontent/testdata/fuzz", "directory holding the fuzz seed corpus")
	failOnSkip = flag.Bool("strict", false, "exit non-zero if any vector could not be exported")
)

// caseEntry describes one exported page for the browser harness.
type caseEntry struct {
	File    string `json:"file"`
	Kind    string `json:"kind"`    // "html" or "css"
	Profile string `json:"profile"` // profile name used
	Source  string `json:"source"`  // where the vector came from
	Input   string `json:"input"`   // the original attack string
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return err
	}

	sanitizers, err := buildSanitizers()
	if err != nil {
		return err
	}

	var (
		cases   []caseEntry
		skipped int
	)

	htmlVectors, err := readVectors(filepath.Join(*corpusDir, "xss", "vectors.txt"))
	if err != nil {
		return err
	}
	cssVectors, err := readVectors(filepath.Join(*corpusDir, "css", "vectors.txt"))
	if err != nil {
		return err
	}
	seeds := readSeeds(*seedDir)

	// Every vector is rendered under every profile: a vector that is
	// inert under one policy is not necessarily inert under another.
	for profileName, s := range sanitizers {
		got, miss := exportAll(s, profileName, htmlVectors, cssVectors, seeds)
		cases = append(cases, got...)
		skipped += miss
	}

	manifest, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), manifest, 0o600); err != nil {
		return err
	}

	fmt.Printf("exported %d pages to %s (%d vectors rejected by the sanitizer, nothing to render)\n",
		len(cases), *outDir, skipped)
	if *failOnSkip && skipped > 0 {
		return fmt.Errorf("%d vectors could not be exported", skipped)
	}
	if len(cases) == 0 {
		return fmt.Errorf("no pages exported; the corpus paths are probably wrong")
	}
	return nil
}

// buildSanitizers constructs one sanitizer per built-in profile.
func buildSanitizers() (map[string]*usercontent.Sanitizer, error) {
	out := map[string]*usercontent.Sanitizer{}
	for name, p := range map[string]func() usercontent.Profile{
		"fullpage": profiles.ProfileFullPage,
		"embed":    profiles.ProfileEmbed,
	} {
		s, err := usercontent.New(p())
		if err != nil {
			return nil, fmt.Errorf("build %s sanitizer: %w", name, err)
		}
		out[name] = s
	}
	return out, nil
}

// exportAll renders every vector under one profile, returning the
// manifest entries and the count the sanitizer rejected outright.
func exportAll(s *usercontent.Sanitizer, profileName string, htmlVectors, cssVectors, seeds []string) ([]caseEntry, int) {
	var (
		cases   []caseEntry
		skipped int
	)
	add := func(c caseEntry, ok bool) {
		if ok {
			cases = append(cases, c)
			return
		}
		skipped++
	}
	for i, in := range htmlVectors {
		add(export(s, profileName, "corpus/xss", fmt.Sprintf("%s-xss-%03d", profileName, i), in, true))
	}
	for i, in := range cssVectors {
		add(export(s, profileName, "corpus/css", fmt.Sprintf("%s-css-%03d", profileName, i), in, false))
	}
	for i, in := range seeds {
		// A seed is rendered both ways: one shaped for HTML sanitizes
		// to nothing on the CSS path, and vice versa. Neither counts
		// as a skip, since the seed was never a vector for that path.
		if c, ok := export(s, profileName, "fuzz-seed", fmt.Sprintf("%s-seedh-%03d", profileName, i), in, true); ok {
			cases = append(cases, c)
		}
		if c, ok := export(s, profileName, "fuzz-seed", fmt.Sprintf("%s-seedc-%03d", profileName, i), in, false); ok {
			cases = append(cases, c)
		}
	}
	return cases, skipped
}

// export sanitizes one vector and writes the rendered page. It
// returns false when the sanitizer rejects the input outright,
// which is a pass in its own right — there is simply no page to
// hand the browser.
func export(s *usercontent.Sanitizer, profileName, source, name, in string, asHTML bool) (caseEntry, bool) {
	var (
		htmlOut, cssOut string
		err             error
		kind            string
	)
	if asHTML {
		kind = "html"
		htmlOut, _, err = s.SanitizeHTML(in)
	} else {
		kind = "css"
		cssOut, _, err = s.SanitizeCSS(in)
	}
	if err != nil {
		return caseEntry{}, false
	}
	if strings.TrimSpace(htmlOut) == "" && strings.TrimSpace(cssOut) == "" {
		return caseEntry{}, false
	}

	doc, err := render.SafeRender(name, "browser differential test", "https://pages.example.com/r/"+name,
		"", htmlOut, cssOut, profileName)
	if err != nil {
		return caseEntry{}, false
	}
	file := name + ".html"
	if err := os.WriteFile(filepath.Join(*outDir, file), []byte(doc), 0o600); err != nil {
		return caseEntry{}, false
	}
	return caseEntry{File: file, Kind: kind, Profile: profileName, Source: source, Input: in}, true
}

// readVectors reads one attack string per line, skipping blanks
// and # comments, matching corpus_test.go.
func readVectors(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- developer tool, path from a flag
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// readSeeds pulls the raw strings out of Go's fuzz seed corpus
// files. The format is a version line followed by one
// `string("...")` literal per argument; anything that does not
// parse is skipped rather than failing the export.
func readSeeds(dir string) []string {
	root, err := os.OpenRoot(dir)
	if err != nil {
		// No seed corpus yet is not an error; the vectors alone are
		// still worth exporting.
		return nil
	}
	defer func() { _ = root.Close() }()

	var out []string
	_ = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		f, err := root.Open(path)
		if err != nil {
			return nil
		}
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(io.LimitReader(f, 1<<20))
		if err != nil {
			return nil
		}
		out = append(out, parseSeedStrings(string(b))...)
		return nil
	})
	return out
}

// parseSeedStrings pulls the `string("...")` literals out of one Go
// fuzz corpus file.
func parseSeedStrings(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `string("`) || !strings.HasSuffix(line, `")`) {
			continue
		}
		s, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "string("), ")"))
		if err == nil && s != "" {
			out = append(out, s)
		}
	}
	return out
}
