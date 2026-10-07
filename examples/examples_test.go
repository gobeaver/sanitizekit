package examples_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Examples rot silently: they compile long after the behaviour they
// demonstrate has changed. These tests actually run them and check
// the output still says what the README claims it says.
//
// The HTTP server example is excluded here — it blocks on
// ListenAndServe. It is covered by the build check below.
func TestExamplesRun(t *testing.T) {
	cases := []struct {
		dir  string
		want []string
	}{
		{
			dir: "01-basic",
			want: []string{
				"<h1>My page</h1>",
				"<a>click me</a>",     // javascript: href stripped, text kept
				"<a href=\"/about\">", // a real link survives
				"idempotent: true",
			},
		},
		{
			dir: "02-custom-profile",
			want: []string{
				`tag script is always forbidden`,
				`event handler attributes are forbidden`,
				`scheme javascript is always forbidden`,
				`@import is always forbidden`,
				`expression() is always forbidden`,
			},
		},
		{
			dir: "03-removal-report",
			want: []string{
				"event handler",
				"forbidden url",
				"inline style",
			},
		},
		{
			dir: "05-declarative-runtime",
			want: []string{
				"script-src 'sha256-",
				`data-gb-animate="fade-up"`,
				"one character edited   -> hash matches: false",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			out := runExample(t, tc.dir)
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("output of %s no longer contains %q.\n\nGot:\n%s", tc.dir, want, out)
				}
			}
			// An example that demonstrates sanitization must never
			// print something executable in its "sanitized" output.
			for _, bad := range []string{"<script>alert", "onerror=", "onclick=", "javascript:alert"} {
				if strings.Contains(out, bad) {
					t.Errorf("%s printed %q in its output", tc.dir, bad)
				}
			}
		})
	}
}

// The server example cannot be run to completion, so at minimum it
// must keep compiling.
func TestServerExampleBuilds(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "server")
	cmd := exec.Command("go", "build", "-o", bin, "./04-http-server")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("04-http-server does not build: %v\n%s", err, out)
	}
}

func runExample(t *testing.T, dir string) string {
	t.Helper()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("example %s is missing: %v", dir, err)
	}

	cmd := exec.Command("go", "run", "./"+dir)
	cmd.Dir = "."
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("example %s did not finish in time", dir)
	}
	if err != nil {
		t.Fatalf("example %s failed: %v\n%s", dir, err, out)
	}
	return string(out)
}
