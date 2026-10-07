package main

import "testing"

// The exporter is a developer tool; this keeps it in the build and
// vet path so it cannot rot silently.
func TestCorpusExportBuilds(t *testing.T) {
	if *outDir == "" {
		t.Error("outDir flag lost its default")
	}
}
