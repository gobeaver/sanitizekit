package render

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	out, err := SafeRender("Title", "Desc", "https://example.com", "", "<p>hi</p>", "body{color:red;}", "fullpage-v1")
	if err != nil {
		t.Fatalf("SafeRender failed: %v", err)
	}
	if !strings.Contains(out, "Title") {
		t.Errorf("expected Title in output: %s", out)
	}
}
