package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const sandboxStateFileExt = ".json"

// SaveInstance persists a sandbox instance in the global registry.
//
// The write is atomic (temp file + rename) and will fail if an entry already
// exists for the same sandbox name.
func SaveInstance(instance *SandboxState) error {
	return writeInstance(instance, false)
}

// ForceWriteInstance persists a sandbox instance in the global registry,
// replacing any existing entry with the same sandbox name.
func ForceWriteInstance(instance *SandboxState) error {
	return writeInstance(instance, true)
}

func writeInstance(instance *SandboxState, overwrite bool) error {
	if instance == nil {
		return fmt.Errorf("sandbox instance is required")
	}
	if strings.TrimSpace(instance.Name) == "" {
		return fmt.Errorf("sandbox name is required")
	}

	path, err := instancePath(instance.Name)
	if err != nil {
		return err
	}

	if err := EnsureGlobalDir(); err != nil {
		return err
	}

	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("sandbox %q already exists", instance.Name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("check sandbox %q: %w", instance.Name, err)
		}
	}

	data, err := json.MarshalIndent(instance, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sandbox %q: %w", instance.Name, err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write sandbox %q: %w", instance.Name, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save sandbox %q: %w", instance.Name, err)
	}

	return nil
}

// LoadInstance loads a sandbox instance from the global registry.
func LoadInstance(name string) (*SandboxState, error) {
	path, err := instancePath(name)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("sandbox %q does not exist: %w", name, err)
		}
		return nil, fmt.Errorf("read sandbox %q: %w", name, err)
	}

	var instance SandboxState
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, fmt.Errorf("parse sandbox %q: %w", name, err)
	}
	if strings.TrimSpace(instance.Name) == "" {
		instance.Name = name
	}

	return &instance, nil
}

// ListInstances returns all sandbox instances in the global registry,
// sorted by sandbox name.
func ListInstances() ([]*SandboxState, error) {
	entries, err := os.ReadDir(SandboxesDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sandboxes dir: %w", err)
	}

	instances := make([]*SandboxState, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != sandboxStateFileExt {
			continue
		}

		path := filepath.Join(SandboxesDir(), entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read sandbox file %q: %w", entry.Name(), err)
		}

		var instance SandboxState
		if err := json.Unmarshal(data, &instance); err != nil {
			return nil, fmt.Errorf("parse sandbox file %q: %w", entry.Name(), err)
		}
		if strings.TrimSpace(instance.Name) == "" {
			instance.Name = strings.TrimSuffix(entry.Name(), sandboxStateFileExt)
		}

		instances = append(instances, &instance)
	}

	sort.Slice(instances, func(i, j int) bool {
		return instances[i].Name < instances[j].Name
	})

	return instances, nil
}

// RemoveInstance deletes a sandbox instance from the global registry.
func RemoveInstance(name string) error {
	path, err := instancePath(name)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("sandbox %q does not exist: %w", name, err)
		}
		return fmt.Errorf("remove sandbox %q: %w", name, err)
	}
	return nil
}

func instancePath(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", fmt.Errorf("invalid sandbox name: %w", err)
	}
	return filepath.Join(SandboxesDir(), name+sandboxStateFileExt), nil
}
