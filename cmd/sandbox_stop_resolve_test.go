package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestResolveStopByNames_MapsMissingRegistryEntriesToNotFound(t *testing.T) {
	origLoad := sandboxStopLoadInstance
	sandboxStopLoadInstance = func(name string) (*sandbox.SandboxState, error) {
		return nil, fmt.Errorf("sandbox %q does not exist: %w", name, fs.ErrNotExist)
	}
	t.Cleanup(func() { sandboxStopLoadInstance = origLoad })

	_, _, err := resolveStopByNames([]string{"missing"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `sandbox "missing" not found in registry`) {
		t.Fatalf("err = %q, want not-found message", err)
	}
}

func TestResolveStopByNames_PreservesRegistryLoadErrors(t *testing.T) {
	origLoad := sandboxStopLoadInstance
	sandboxStopLoadInstance = func(name string) (*sandbox.SandboxState, error) {
		return nil, errors.New("parse sandbox file \"broken.json\": invalid character")
	}
	t.Cleanup(func() { sandboxStopLoadInstance = origLoad })

	_, _, err := resolveStopByNames([]string{"broken"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `load sandbox "broken" from registry`) {
		t.Fatalf("err = %q, want load wrapper", err)
	}
	if !strings.Contains(err.Error(), `parse sandbox file "broken.json"`) {
		t.Fatalf("err = %q, want parse detail", err)
	}
	if strings.Contains(err.Error(), "not found in registry") {
		t.Fatalf("err = %q, unexpectedly hid the load failure", err)
	}
}

func TestResolveStopTargets_IgnoresStagedRemovalEntries(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "active-box", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "staged-box", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	if _, err := sandbox.StageInstanceRemoval("staged-box"); err != nil {
		t.Fatalf("StageInstanceRemoval(staged-box): %v", err)
	}

	targets, _, err := resolveStopTargets(nil, true, "")
	if err != nil {
		t.Fatalf("resolveStopTargets(--all): %v", err)
	}
	if len(targets) != 1 || targets[0].Name != "active-box" {
		t.Fatalf("resolveStopTargets(--all) = %#v, want only active-box", targets)
	}

	_, _, err = resolveStopTargets([]string{"staged-box"}, false, "")
	if err == nil {
		t.Fatal("expected staged entry lookup to fail")
	}
	if !strings.Contains(err.Error(), `sandbox "staged-box" not found in registry`) {
		t.Fatalf("err = %q, want staged entry treated as missing", err)
	}
}

func TestResolveStopTargets_RejectsConflictingSelectors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		allFlag bool
		pattern string
	}{
		{
			name:    "names and all",
			args:    []string{"frontend"},
			allFlag: true,
		},
		{
			name:    "names and pattern",
			args:    []string{"frontend"},
			pattern: "front*",
		},
		{
			name:    "all and pattern",
			allFlag: true,
			pattern: "front*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := resolveStopTargets(tt.args, tt.allFlag, tt.pattern)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != "sandbox names, --all, and --pattern are mutually exclusive" {
				t.Fatalf("err = %q, want selector conflict error", err)
			}
		})
	}
}
