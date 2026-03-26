package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

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
