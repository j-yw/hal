//go:build linux && microvm_assets_integration

package minimalprofile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Controlled subprocesses use this test executable, not a shell which might
// synthesize its own PATH. The integration tag isolates all process execution.
func init() {
	name := filepath.Base(os.Args[0])
	if name != "minimal-env-tool" && name != "mke2fs" && name != "debugfs" && name != "e2fsck" {
		return
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "HAL_MINIMAL_ENV_SENTINEL=") {
			fmt.Fprintln(os.Stderr, "unexpected inherited environment")
			os.Exit(23)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "-V" {
		fmt.Fprintf(os.Stderr, "%s 1.47.4 (fixture)\nUsing EXT2FS Library version 1.47.4\n", name)
	} else {
		if name == "debugfs" {
			fmt.Fprintln(os.Stderr, "debugfs 1.47.4 (fixture)")
		}
		fmt.Fprintln(os.Stdout, "clean-child-environment")
	}
	os.Exit(0)
}

func TestMinimalImageToolsDoNotInheritEnvironment(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := privateDir(t)
	for _, name := range []string{"minimal-env-tool", "mke2fs", "debugfs", "e2fsck"} {
		if err := os.Symlink(executable, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("HAL_MINIMAL_ENV_SENTINEL", "fixture-only")
	if out, err := runTool(context.Background(), 1700000000, 4096, "minimal-env-tool"); err != nil || string(out) != "clean-child-environment\n" {
		t.Fatalf("resolved tool inherited parent environment: %v", err)
	}
	if out, err := debugTool(context.Background(), 1700000000, "fixture.ext4", "-R", "fixture"); err != nil || string(out) != "clean-child-environment\n" {
		t.Fatalf("debug tool inherited parent environment: %v", err)
	}
	if err := checkImageTools(context.Background()); err != nil {
		t.Fatalf("version probes inherited parent environment: %v", err)
	}
}
