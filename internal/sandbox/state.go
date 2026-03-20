package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/template"
)

// SaveState writes the sandbox state to .hal/sandbox.json atomically.
func SaveState(halDir string, state *SandboxState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sandbox state: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(halDir, template.SandboxFile)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write sandbox state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to save sandbox state: %w", err)
	}
	return nil
}

// LoadState reads the sandbox state from .hal/sandbox.json.
// Returns a descriptive error if sandbox.json does not exist.
func LoadState(halDir string) (*SandboxState, error) {
	path := filepath.Join(halDir, template.SandboxFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no active sandbox: %s does not exist (run 'hal sandbox start' first): %w", template.SandboxFile, err)
		}
		return nil, fmt.Errorf("failed to read sandbox state: %w", err)
	}

	var state SandboxState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox state: %w", err)
	}
	if strings.TrimSpace(state.Name) == "" {
		return nil, fmt.Errorf("invalid sandbox state: required field %q is empty", "name")
	}

	// Auto-migrate legacy state: default empty Provider to "daytona" and re-save
	if state.Provider == "" {
		state.Provider = "daytona"
		if err := SaveState(halDir, &state); err != nil {
			// Best-effort migration — log but don't fail the load
			fmt.Fprintf(os.Stderr, "warning: failed to migrate sandbox state: %v\n", err)
		}
	}

	return &state, nil
}

// RemoveState deletes .hal/sandbox.json.
func RemoveState(halDir string) error {
	path := filepath.Join(halDir, template.SandboxFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove sandbox state: %w", err)
	}
	return nil
}
