package parallelrun

import (
	"runtime"
	"testing"
)

func TestShellCheckCommandsWrapConfiguredCommands(t *testing.T) {
	checks := ShellCheckCommands([]string{" go test ./... ", "", "make vet"})
	if len(checks) != 2 {
		t.Fatalf("checks length = %d, want 2", len(checks))
	}

	wantName := "sh"
	wantPrefix := "-c"
	if runtime.GOOS == "windows" {
		wantName = "cmd"
		wantPrefix = "/C"
	}

	if checks[0].Name != wantName || len(checks[0].Args) != 2 || checks[0].Args[0] != wantPrefix || checks[0].Args[1] != "go test ./..." {
		t.Fatalf("first check = %+v, want %s %s %q", checks[0], wantName, wantPrefix, "go test ./...")
	}
	if checks[1].Name != wantName || len(checks[1].Args) != 2 || checks[1].Args[0] != wantPrefix || checks[1].Args[1] != "make vet" {
		t.Fatalf("second check = %+v, want %s %s %q", checks[1], wantName, wantPrefix, "make vet")
	}
}
