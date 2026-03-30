package cmd

import (
	"strings"
	"testing"
)

func TestRoot(t *testing.T) {
	if Root() == nil {
		t.Fatal("Root() returned nil")
	}
	if Root() != rootCmd {
		t.Fatal("Root() did not return rootCmd")
	}
}

func TestRootHelpIncludesAutoSourcePriority(t *testing.T) {
	if !strings.Contains(rootCmd.Long, "hal auto [prd-path]") {
		t.Fatalf("root long help should mention hal auto entrypoint: %q", rootCmd.Long)
	}
	if !strings.Contains(rootCmd.Long, "source priority") {
		t.Fatalf("root long help should describe auto source priority: %q", rootCmd.Long)
	}
	if !strings.Contains(rootCmd.Example, "hal auto") {
		t.Fatalf("root examples should include hal auto: %q", rootCmd.Example)
	}
}
