package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

func syncMatchingLocalSandboxState(halDir string, state *sandbox.SandboxState) error {
	local, err := loadMatchingLocalSandboxState(halDir, state)
	if err != nil {
		return err
	}
	if local == nil {
		return nil
	}
	if err := sandbox.SaveState(halDir, state); err != nil {
		return fmt.Errorf("save local sandbox state: %w", err)
	}
	return nil
}

func removeMatchingLocalSandboxState(halDir string, target *sandbox.SandboxState) error {
	local, err := loadMatchingLocalSandboxState(halDir, target)
	if err != nil {
		return err
	}
	if local == nil {
		return nil
	}
	if err := sandbox.RemoveState(halDir); err != nil {
		return fmt.Errorf("remove local sandbox state: %w", err)
	}
	return nil
}

func loadMatchingLocalSandboxState(halDir string, target *sandbox.SandboxState) (*sandbox.SandboxState, error) {
	localPath := filepath.Join(halDir, template.SandboxFile)
	data, err := os.ReadFile(localPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read local sandbox state: %w", err)
	}

	var local sandbox.SandboxState
	if err := json.Unmarshal(data, &local); err != nil {
		return nil, nil
	}
	if !sandboxStateMatchesTarget(&local, target) {
		return nil, nil
	}

	return &local, nil
}

func sandboxStateMatchesTarget(local, target *sandbox.SandboxState) bool {
	if local == nil || target == nil {
		return false
	}

	seen := make(map[string]struct{}, 3)
	for _, id := range []string{
		strings.TrimSpace(local.Name),
		strings.TrimSpace(local.WorkspaceID),
		strings.TrimSpace(local.ID),
	} {
		if id != "" {
			seen[id] = struct{}{}
		}
	}

	for _, id := range []string{
		strings.TrimSpace(target.Name),
		strings.TrimSpace(target.WorkspaceID),
		strings.TrimSpace(target.ID),
	} {
		if _, ok := seen[id]; id != "" && ok {
			return true
		}
	}

	return false
}
