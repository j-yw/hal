package cmd

import "testing"

func TestRoot(t *testing.T) {
	if Root() == nil {
		t.Fatal("Root() returned nil")
	}
	if Root() != rootCmd {
		t.Fatal("Root() did not return rootCmd")
	}
}
