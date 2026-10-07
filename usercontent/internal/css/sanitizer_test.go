package css

import (
	"testing"
)

func TestCSSPolicy(t *testing.T) {
	p, err := NewPolicy(Profile{
		Name:                "test",
		AllowedDeclarations: []string{"color", "margin"},
	})
	if err != nil {
		t.Fatalf("NewPolicy failed: %v", err)
	}
	if p == nil {
		t.Fatal("nil policy")
	}
}
