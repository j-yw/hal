package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestRunSandboxListIncludesStagedEntries(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() failed: %v", err)
	}
	projectDir := t.TempDir()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("Chdir(%q) failed: %v", projectDir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})

	name := "staged-worker"
	if err := sandbox.SaveInstance(&sandbox.SandboxState{Name: name, Status: sandbox.StatusRunning}); err != nil {
		t.Fatalf("SaveInstance(%q) failed: %v", name, err)
	}
	pending, err := sandbox.StageInstanceRemoval(name)
	if err != nil {
		t.Fatalf("StageInstanceRemoval(%q) failed: %v", name, err)
	}
	t.Cleanup(func() {
		_ = pending.Rollback()
	})

	var out bytes.Buffer
	if err := runSandboxList(&out, false, false); err != nil {
		t.Fatalf("runSandboxList() failed: %v", err)
	}
	if !strings.Contains(out.String(), name) {
		t.Fatalf("runSandboxList() output = %q, want sandbox %q", out.String(), name)
	}
}

func TestResolveDeleteAllIncludesStagedEntries(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	name := "staged-worker"
	if err := sandbox.SaveInstance(&sandbox.SandboxState{Name: name, Status: sandbox.StatusRunning}); err != nil {
		t.Fatalf("SaveInstance(%q) failed: %v", name, err)
	}
	pending, err := sandbox.StageInstanceRemoval(name)
	if err != nil {
		t.Fatalf("StageInstanceRemoval(%q) failed: %v", name, err)
	}
	t.Cleanup(func() {
		_ = pending.Rollback()
	})

	targets, _, err := resolveDeleteAll()
	if err != nil {
		t.Fatalf("resolveDeleteAll() failed: %v", err)
	}
	if len(targets) != 1 || targets[0].Name != name {
		t.Fatalf("resolveDeleteAll() targets = %#v, want %q", targets, name)
	}
}

func TestResolveDeleteByPatternIncludesStagedEntries(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	name := "staged-worker"
	if err := sandbox.SaveInstance(&sandbox.SandboxState{Name: name, Status: sandbox.StatusRunning}); err != nil {
		t.Fatalf("SaveInstance(%q) failed: %v", name, err)
	}
	pending, err := sandbox.StageInstanceRemoval(name)
	if err != nil {
		t.Fatalf("StageInstanceRemoval(%q) failed: %v", name, err)
	}
	t.Cleanup(func() {
		_ = pending.Rollback()
	})

	targets, _, err := resolveDeleteByPattern("staged-*")
	if err != nil {
		t.Fatalf("resolveDeleteByPattern() failed: %v", err)
	}
	if len(targets) != 1 || targets[0].Name != name {
		t.Fatalf("resolveDeleteByPattern() targets = %#v, want %q", targets, name)
	}
}

func TestResolveDeleteAutoSelectFallsBackToStagedEntries(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	name := "staged-worker"
	if err := sandbox.SaveInstance(&sandbox.SandboxState{Name: name, Status: sandbox.StatusRunning}); err != nil {
		t.Fatalf("SaveInstance(%q) failed: %v", name, err)
	}
	pending, err := sandbox.StageInstanceRemoval(name)
	if err != nil {
		t.Fatalf("StageInstanceRemoval(%q) failed: %v", name, err)
	}
	t.Cleanup(func() {
		_ = pending.Rollback()
	})

	targets, hint, err := resolveDeleteAutoSelect()
	if err != nil {
		t.Fatalf("resolveDeleteAutoSelect() failed: %v", err)
	}
	if len(targets) != 1 || targets[0].Name != name {
		t.Fatalf("resolveDeleteAutoSelect() targets = %#v, want %q", targets, name)
	}
	if hint != `Deleting only sandbox "staged-worker"...` {
		t.Fatalf("resolveDeleteAutoSelect() hint = %q, want staged fallback hint", hint)
	}
}
