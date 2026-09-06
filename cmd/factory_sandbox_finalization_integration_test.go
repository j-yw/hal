//go:build linux && integration

package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFactoryFinalizationRecoveryScriptParses(t *testing.T) {
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(factorySandboxRecoveryArtifactScript(t.TempDir(), "local-base"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("recovery script syntax: %v: %s", err, output)
	}
}

func TestFactoryFinalizationRecoveryRealGit(t *testing.T) {
	dir, _ := factoryBundleGitFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "changed.txt"), []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	factoryBundleGit(t, dir, "add", "changed.txt")
	factoryBundleGit(t, dir, "commit", "-m", "fixture change")
	if err := os.WriteFile(filepath.Join(dir, "changed.txt"), []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "-c", factorySandboxRecoveryArtifactScript(dir, "local-base"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("recovery generation: %v: %s", err, output)
	}
	for _, name := range []string{"manifest.json", "head.txt", "branch.txt", "git-bundle.bundle", "git-format-patch.patch", "dirty.patch"} {
		data, err := os.ReadFile(filepath.Join(dir, ".hal", "recovery", name))
		if err != nil || len(data) == 0 {
			t.Fatalf("recovery artifact %s: size=%d err=%v", name, len(data), err)
		}
		if name == "manifest.json" && !json.Valid(data) {
			t.Fatal("recovery manifest is not JSON")
		}
	}
	factoryBundleGit(t, dir, "bundle", "verify", ".hal/recovery/git-bundle.bundle")
}
