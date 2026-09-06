//go:build linux && microvm_assets_integration

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeSelectedGitMetadataRetainsVerifiedBytes(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("chmod")
	}
	parent, err := openDirectory(root, true)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	repo, err := ownedChild(parent, "repo")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.close()
	stage, err := ownedChild(parent, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	defer stage.close()
	paths := []string{"tools/microvm/l5/cache.manifest", "tools/microvm/l8/cache.manifest", "tools/microvm/l8-minimal/native-sources.lock.json"}
	for _, name := range paths {
		if os.MkdirAll(filepath.Dir(filepath.Join(repo.name, name)), 0755) != nil || os.WriteFile(filepath.Join(repo.name, name), []byte("original:"+name), 0644) != nil {
			t.Fatal("fixture")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo.name}, args...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_PARAMETERS='commit.gpgsign=false'", "GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid"}
		data, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture Git: %v %s", err, data)
		}
		return strings.TrimSpace(string(data))
	}
	git("init", "-q")
	git("add", ".")
	git("commit", "-qm", "fixture")
	revision := git("rev-parse", "HEAD")
	tree := git("rev-parse", "HEAD^{tree}")
	selected, err := snapshotSource(ctx, repo.name, revision, stage)
	if err != nil {
		t.Fatal(err)
	}
	if selected.revision != revision || selected.tree != "tree-"+tree {
		t.Fatal("selected identity mismatch")
	}
	for _, name := range paths {
		if os.WriteFile(filepath.Join(stage.name, name), []byte("substituted later bytes"), 0644) != nil {
			t.Fatal("replace")
		}
		if string(selected.metadata[name]) != "original:"+name {
			t.Fatal("Git-bound metadata changed on independent file replacement")
		}
	}
}
