package html

import (
	"testing"
)

func TestHTMLPolicy(t *testing.T) {
	p, err := NewPolicy(Profile{
		Name:         "test",
		AllowedTags:  []string{"p", "div", "a"},
		AllowedAttrs: map[string][]string{"*": {"class"}},
		MaxDOMDepth:  100,
		MaxDOMNodes:  10000,
	})
	if err != nil {
		t.Fatalf("NewPolicy failed: %v", err)
	}
	if p == nil {
		t.Fatal("nil policy")
	}
}
