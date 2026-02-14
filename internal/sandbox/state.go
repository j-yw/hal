package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
			return nil, fmt.Errorf("no active sandbox: %s does not exist (run 'hal sandbox start' first)", template.SandboxFile)
		}
		return nil, fmt.Errorf("failed to read sandbox state: %w", err)
	}

	var state SandboxState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox state: %w", err)
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
