package main

import (
	"testing"
)

// TestDemoBuild verifies the demo package compiles.
func TestDemoBuild(t *testing.T) {
	// This test just verifies the package compiles with all
	// its dependencies. The demo is a CLI tool; exercising main()
	// would print to stdout, so we only verify compilation here.
	t.Log("demo package compiles ok")
}
