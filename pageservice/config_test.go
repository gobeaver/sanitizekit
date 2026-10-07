package pageservice

import (
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	// Verify default config constants are populated.
	if EnvPrefix == "" {
		t.Error("EnvPrefix is empty")
	}
}

func TestWithPrefix(t *testing.T) {
	b := WithPrefix("TEST_")
	if b == nil {
		t.Fatal("WithPrefix returned nil")
	}
}
