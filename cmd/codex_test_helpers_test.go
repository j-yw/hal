package cmd

import "testing"

func setIsolatedCodexHomeFallback(t *testing.T, home string) {
	t.Helper()
	t.Setenv("CODEX_HOME", "")
	t.Setenv("HOME", home)
}
