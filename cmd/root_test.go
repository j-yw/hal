package cmd

import (
	"bytes"
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
	if !strings.Contains(rootCmd.Long, "auto.sourcePriority") {
		t.Fatalf("root long help should describe auto source priority defaults: %q", rootCmd.Long)
	}
	if !strings.Contains(rootCmd.Example, "hal auto") {
		t.Fatalf("root examples should include hal auto: %q", rootCmd.Example)
	}
}

func TestRootVersionFlag(t *testing.T) {
	origOut := rootCmd.OutOrStdout()
	origErr := rootCmd.ErrOrStderr()
	t.Cleanup(func() {
		rootCmd.SetOut(origOut)
		rootCmd.SetErr(origErr)
		rootCmd.SetArgs(nil)
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"--version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute(--version) error: %v", err)
	}
	if !strings.Contains(stdout.String(), Version) {
		t.Fatalf("--version output = %q, want version %q", stdout.String(), Version)
	}
	if stderr.String() != "" {
		t.Fatalf("--version stderr = %q, want empty", stderr.String())
	}
}
